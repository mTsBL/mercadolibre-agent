import time
from http.client import HTTPException

from .browser import Browser
from .detectors import Detectors, useful, equivalent
from .discovery import Discovery
from .llm import Ollama, ModelError
from .safety import Scope, SECRET_KEY
from .transport import Budget, BudgetExceeded, Transport


class Agent:
    def __init__(self, config, redactor):
        self.config, self.redactor = config, redactor
        self.budget = Budget(config.max_requests, config.max_seconds)
        self.discovery = None
        self.browser = None
        self.model = None
        self.detectors = Detectors(redactor)
        self.errors = []
        self.warnings = []
        self.auth = {"status": "not_attempted", "attempts": 0, "detail": ""}
        self.outcomes = []
        self.status = "failed"
        self.started = time.time()
        self.truncated_responses = 0
        self.failed_requests = 0

    def observe(self, response):
        self.truncated_responses += int(response.truncated)
        self.detectors.pii(response)

    def run(self):
        scope = Scope(self.config.base_url)
        self.discovery = Discovery(scope, self.config.max_endpoints)
        transport = Transport(scope, self.budget, self.config.request_timeout, self.config.max_body)
        self.model = Ollama(self.config, self.redactor, self.budget)
        self.model.preflight()
        self.browser = Browser(self.config, transport, self.discovery, self.redactor, self.observe)
        self.browser.start()
        root = self.discovery.add(scope.base, source="base_url")
        self.browser.visit(root)
        if not self.discovery.responses:
            raise RuntimeError("No HTTP response obtained from BASE_URL")
        login_attempted_pages = set()
        while True:
            self.budget.check()
            candidates, actions = self.candidates(login_attempted_pages)
            if not candidates:
                break
            action_id = self.model.choose(candidates, {
                "authentication": self.auth["status"], "endpoints": len(self.discovery.endpoints),
                "requests_remaining": self.config.max_requests - self.budget.requests,
                "recent_outcomes": self.outcomes[-3:], "findings": len(self.detectors.findings),
            })
            kind, endpoint = actions[action_id]
            outcome = {"action_id": action_id, "action": kind}
            if kind == "login":
                login_attempted_pages.add(self.browser.page.url)
                self.auth["attempts"] += 1
                success, detail = self.browser.login(self.model)
                self.auth.update(status="session_established" if success else "failed", detail=detail)
                outcome["success"] = success
                if success:
                    for known in self.discovery.endpoints.values():
                        known.tested = False  # Re-evaluate protected behavior with the new session.
                    # Revisit the entry point to discover links hidden before login.
                    self.browser.visit(root)
            elif kind == "navigate":
                outcome["success"] = self.navigate(endpoint)
            elif kind == "test_methods":
                outcome["confirmed_findings"] = self.test_methods(endpoint)
            self.outcomes.append(outcome)
        self.finish_status()

    def candidates(self, attempted_pages):
        candidates, actions = [], {}
        has_login = self.browser.has_login()
        if has_login and not self.config.username:
            self.auth.update(status="credentials_missing", detail="A login form was discovered, but credentials were not provided")
        if (has_login and self.config.username and not self.browser.authenticated
                and self.auth["attempts"] < 2 and self.browser.page.url not in attempted_pages):
            candidates.append({"id": "login", "tool": "login", "description": "Authenticate using discovered visible form and supplied credentials"})
            actions["login"] = ("login", None)
        session = "authenticated" if self.browser.authenticated else "anonymous"
        endpoints = list(self.discovery.endpoints.values())
        # Mix frontier and testing candidates so neither kind is starved.
        frontier = [e for e in endpoints if e.method == "GET" and session not in e.visited_sessions]
        frontier.sort(key=lambda e: (e.asset, e.depth, e.id))
        for endpoint in frontier[:6]:
            if self.browser.pages >= self.config.max_pages:
                break
            action_id = "visit:" + endpoint.id
            candidates.append({"id": action_id, "tool": "navigate", "url": self.redactor.url(endpoint.url)[:240],
                               "source": endpoint.source})
            actions[action_id] = ("navigate", endpoint)
        tests = [e for e in endpoints if e.observed and not e.tested and not e.asset
                 and e.url not in self.browser.login_urls and e.method in ("GET", "POST")]
        for endpoint in tests[:5]:
            action_id = "methods:" + endpoint.id
            candidates.append({"id": action_id, "tool": "test_methods", "url": self.redactor.url(endpoint.url)[:240],
                               "observed_method": endpoint.method, "declared_methods": sorted(endpoint.declared_methods)})
            actions[action_id] = ("test_methods", endpoint)
        return candidates, actions

    def navigate(self, endpoint):
        session = "authenticated" if self.browser.authenticated else "anonymous"
        endpoint.visited_sessions.add(session)  # A failed URL is not retried indefinitely.
        try:
            response = self.browser.transport.request("GET", endpoint.url,
                self.browser.headers_for(endpoint.url) if self.browser.authenticated else {},
                authenticated=self.browser.authenticated, follow=True)
            self.discovery.observe(response, depth=endpoint.depth)
            self.observe(response)
            if "html" in response.headers.get("content-type", "").lower():
                self.browser.visit(endpoint)
            return response.status < 500
        except (OSError, ValueError, HTTPException):
            self.failed_requests += 1
            return False

    def test_methods(self, endpoint):
        for sibling in self.discovery.endpoints.values():
            if sibling.url == endpoint.url:
                sibling.tested = True
        # Query tokens can authenticate an otherwise cookie-free request: do not call it anonymous.
        from urllib.parse import parse_qsl, urlsplit
        if any(SECRET_KEY.search(k) for k, _ in parse_qsl(urlsplit(endpoint.url).query)):
            self.detectors.observations.append({"url": self.redactor.url(endpoint.url), "reason": "Query authentication prevents an anonymous control"})
            return 0

        def request(method, auth=False):
            headers = self.browser.headers_for(endpoint.url) if auth else {}
            response = self.browser.transport.request(method, endpoint.url, headers, authenticated=auth)
            self.observe(response)
            return response

        before = len(self.detectors.findings)
        try:
            baseline = request("GET")
            reference = None
            if self.browser.authenticated:
                reference = request("GET", True)
                if baseline.status in (401, 403) and useful(reference):
                    self.auth["status"] = "verified"
                    self.auth["detail"] = "Session retrieves a resource denied to anonymous GET"
            options = request("OPTIONS")
            allow = options.headers.get("allow", "") or baseline.headers.get("allow", "")
            if allow:
                allowed = {m.strip().upper() for m in allow.split(",")}
                if allowed and allowed <= {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}:
                    endpoint.declared_methods.update(allowed | {"OPTIONS"} | ({"HEAD"} if "GET" in allowed else set()))
            control = request("SCANNERPROBE")
            any_confirmed = False
            # Empty-body probes avoid replaying application transactions or credentials.
            # These are ACTIVE probes and may still mutate a disposable target.
            for method in ("POST", "PUT", "PATCH", "DELETE", "HEAD"):
                probe = request(method)
                auth_mode = False
                contract_baseline, current_control = baseline, control
                if not useful(probe) and reference is not None and endpoint.declared_methods and method not in endpoint.declared_methods:
                    probe = request(method, True)
                    auth_mode = True
                    contract_baseline = reference
                    current_control = request("SCANNERPROBE", True)
                if not useful(probe) or (current_control.status == probe.status and equivalent(current_control, probe)):
                    continue
                # Only repeat plausible candidates; no model tokens spent on response bodies.
                plausible = (baseline.status in (401, 403) or endpoint.declared_methods and method not in endpoint.declared_methods)
                if not plausible:
                    continue
                confirmation = request(method, auth_mode)
                if self.detectors.method(endpoint, contract_baseline, probe, confirmation, current_control, reference):
                    any_confirmed = True
            if not any_confirmed:
                self.detectors.observations.append({"url": self.redactor.url(endpoint.url),
                    "reason": "No reproducible authorization bypass or declared-method violation confirmed"})
        except (OSError, ValueError, HTTPException):
            self.failed_requests += 1
            self.detectors.observations.append({"url": self.redactor.url(endpoint.url), "reason": "Method testing interrupted by transport error"})
        return len(self.detectors.findings) - before

    def finish_status(self):
        if self.discovery.limited:
            self.warnings.append("Endpoint discovery limit reached")
        if self.browser.pages >= self.config.max_pages:
            self.warnings.append("Browser page limit reached; frontier may remain unexplored")
        if self.truncated_responses:
            self.warnings.append("Some responses exceeded MAX_BODY_BYTES; oversized responses have incomplete coverage")
        if self.failed_requests or self.browser.failures:
            self.warnings.append("Some requests or browser navigations failed")
        guarded = any(r.status in (401, 403) for r in self.discovery.responses.values())
        if self.auth["status"] == "not_attempted":
            self.auth.update(status="not_required" if not guarded else "not_discovered",
                             detail="No login requirement observed" if not guarded else "Protected resources found, but no usable login form discovered")
        if self.auth["status"] in ("failed", "credentials_missing", "not_discovered"):
            self.warnings.append("Authenticated coverage is incomplete: " + self.auth["detail"])
        self.status = "partial" if self.warnings else "completed"

    def close(self):
        if self.browser:
            self.browser.close()

    def report(self):
        discovery, model = self.discovery, self.model
        findings = sorted(self.detectors.findings.values(), key=lambda f: f["id"])
        return self.redactor.clean({
            "schema_version": "1.0", "scanner": {"name": "Local Agentic Security Scanner", "version": "1.0.0"},
            "target": self.redactor.url(self.config.base_url), "status": self.status,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.started)),
            "duration_seconds": round(time.time() - self.started, 3), "authentication": self.auth,
            "summary": {"findings": len(findings), "endpoints_discovered": len(discovery.endpoints) if discovery else 0,
                        "requests_sent": self.budget.requests, "pages_visited": self.browser.pages if self.browser else 0,
                        "blocked_browser_requests": self.browser.blocked_requests if self.browser else 0},
            "ai": {"provider": "local_ollama", "model": self.config.model,
                   "calls": model.calls if model else 0, "prompt_tokens": model.prompt_tokens if model else 0,
                   "completion_tokens": model.completion_tokens if model else 0,
                   "decisions": model.decisions if model else []},
            "coverage": {"scope": "Exact BASE_URL origin; loopback/private local network only",
                         "endpoints": [{"id": e.id, "url": self.redactor.url(e.url), "method": e.method,
                                        "source": e.source, "observed": e.observed, "methods_tested": e.tested}
                                       for e in discovery.endpoints.values()] if discovery else [],
                         "method_observations": self.detectors.observations,
                         "limitations": ["Bounded exploration cannot prove absence of vulnerabilities.",
                                         "No CAPTCHA/MFA bypass, external identity provider, arbitrary workflow or path-parameter guessing.",
                                         "WebSockets, service workers, images, media, fonts and cross-origin resources are blocked.",
                                         "CPF detection establishes unmasked identifier exposure, not business necessity or authorization.",
                                         "Method results require exact stable response evidence; dynamic or body-dependent handlers may be missed."]},
            "errors": self.errors, "warnings": self.warnings, "findings": findings,
        })
