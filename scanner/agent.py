from http.client import HTTPException

from . import ui
from .browser import Browser
from .detectors import Detectors, cpf_matches, useful, equivalent, is_denied, grant_kind
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
        self.truncated_responses = 0
        self.failed_requests = 0
        self.anonymous_checked = set()

    def observe(self, response):
        self.truncated_responses += int(response.truncated)
        self.detectors.pii(response)
        # Severity must reflect real anonymous reachability, not crawl order: a URL only ever
        # visited after login must not be reported as authenticated-only by accident.
        if response.session == "authenticated" and response.url not in self.anonymous_checked and cpf_matches(response):
            self.anonymous_checked.add(response.url)
            try:
                probe = self.browser.transport.request("GET", response.url, {}, authenticated=False)
            except (OSError, ValueError, HTTPException):
                return
            self.truncated_responses += int(probe.truncated)
            self.detectors.pii(probe)

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
        # Phase 1: the local model drives navigation and login to uncover the full surface.
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
                    ui.ok("Login realizado com sucesso.")
                elif self.auth["attempts"] >= 2:
                    ui.fail("Não foi possível fazer login (a sessão não mudou após enviar as credenciais).")
                if success:
                    # Revisit the entry point to discover links hidden before login.
                    self.browser.visit(root)
            elif kind == "navigate":
                outcome["success"] = self.navigate(endpoint)
            self.outcomes.append(outcome)
        # Phase 2: mechanical, deterministic method testing over the whole discovered surface,
        # probing every method under each available session (anonymous, and authenticated when
        # login succeeded) in a single pass — no scarce local-model decision is spent on it.
        self.test_pending_methods()
        self.detectors.correlate()
        self.finish_status()

    def test_pending_methods(self):
        # Do not require `observed`: navigation only ever fetches GET endpoints, so a POST-only
        # form action would otherwise never get a first response and would stay untested forever.
        pending = [e for e in self.discovery.endpoints.values() if not e.tested and not e.asset
                   and e.url not in self.browser.login_urls]
        for endpoint in pending:
            self.budget.check()
            self.test_methods(endpoint)

    def candidates(self, attempted_pages):
        candidates, actions = [], {}
        has_login = self.browser.has_login()
        if has_login and not self.config.username and self.auth["status"] != "credentials_missing":
            detail = "A aplicação tem login, mas CHALLENGE_USERNAME e CHALLENGE_PASSWORD não foram encontradas no ambiente. Seguindo sem autenticação."
            self.auth.update(status="credentials_missing", detail=detail)
            ui.warn(detail)
        if (has_login and self.config.username and not self.browser.authenticated
                and self.auth["attempts"] < 2 and self.browser.page.url not in attempted_pages):
            candidates.append({"id": "login", "tool": "login", "description": "Authenticate using discovered visible form and supplied credentials"})
            actions["login"] = ("login", None)
        session = "authenticated" if self.browser.authenticated else "anonymous"
        endpoints = list(self.discovery.endpoints.values())
        frontier = [e for e in endpoints if e.method == "GET" and session not in e.visited_sessions]
        frontier.sort(key=lambda e: (e.asset, e.depth, e.id))
        for endpoint in frontier[:6]:
            if self.browser.pages >= self.config.max_pages:
                break
            action_id = "visit:" + endpoint.id
            candidates.append({"id": action_id, "tool": "navigate", "url": self.redactor.url(endpoint.url)[:240],
                               "source": endpoint.source})
            actions[action_id] = ("navigate", endpoint)
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
        url = self.redactor.url(endpoint.url)
        if any(SECRET_KEY.search(k) for k, _ in parse_qsl(urlsplit(endpoint.url).query)):
            self.detectors.observations.append({"url": url, "reason": "Query authentication prevents an anonymous control"})
            return 0

        def request(method, auth=False):
            headers = self.browser.headers_for(endpoint.url) if auth else {}
            response = self.browser.transport.request(method, endpoint.url, headers, authenticated=auth)
            self.observe(response)
            return response

        before = len(self.detectors.findings)
        methods = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
        # A pure action form (only hidden fields, e.g. a cancel/delete button with a CSRF token)
        # gets a careful ordered probe that submits the intended method WITH its token and records
        # the observable state change — enough to tell an authorization bypass from a CSRF flaw.
        form = self.discovery.forms.get(endpoint.url)
        if self.browser.authenticated and form and form["method"] == "POST" and not form["visible"] and form["hidden"]:
            try:
                if self.probe_state_change(endpoint, form, url):
                    return len(self.detectors.findings) - before
            except (OSError, ValueError, HTTPException):
                self.failed_requests += 1
        try:
            # Learn the declared contract once (Allow header via OPTIONS).
            options = request("OPTIONS")
            allow = options.headers.get("allow", "")
            if allow:
                declared = {m.strip().upper() for m in allow.split(",") if m.strip()}
                if declared <= {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}:
                    endpoint.declared_methods.update(declared | {"OPTIONS"} | ({"HEAD"} if "GET" in declared else set()))

            sessions = [False] + ([True] if self.browser.authenticated else [])
            any_confirmed = False
            # ACTIVE probes with empty bodies: they avoid replaying application transactions,
            # but a state-changing endpoint reached by the wrong method may still mutate a
            # disposable target — which is exactly the bypass being validated.
            for auth in sessions:
                responses = {m: request(m, auth) for m in methods}
                control = request("SCANNERPROBE", auth)
                denied = [m for m in methods if is_denied(responses[m])]

                # Bypass: the same actor is refused on one method but served by another.
                if denied:
                    for method in methods:
                        if method in denied:
                            continue
                        kind = grant_kind(responses[method], method, control)
                        if not kind:
                            continue
                        if kind == "data":
                            confirmation = request(method, auth)  # idempotent read: reproduce it
                            if grant_kind(confirmation, method, control) != "data" or not equivalent(responses[method], confirmation):
                                continue
                        else:
                            confirmation = request(denied[0], auth)  # do not replay a state change; prove the guard is stable
                            if not is_denied(confirmation):
                                continue
                        if self.detectors.record_bypass(endpoint, responses[denied[0]], responses[method], confirmation, control, method):
                            any_confirmed = True
                            if auth:
                                self.auth["status"] = "verified"
                                self.auth["detail"] = "Session exercises a method-dependent access control"

                # Unsafe method: a safe verb (GET) that performs a state-changing action. A 303
                # See Other from a GET means the GET executed an operation and redirected to its
                # result — a safe method must never mutate state (RFC 7231), so this is a
                # CSRF-prone method-tampering bypass of the intended write path.
                intended_write = "POST" in endpoint.declared_methods or any(
                    sibling.method in ("POST", "PUT", "PATCH", "DELETE")
                    for sibling in self.discovery.endpoints.values() if sibling.url == endpoint.url)
                get = responses["GET"]
                unsafe = get.status == 303 or (300 <= get.status < 400 and intended_write
                                               and bool(get.headers.get("location")) and not is_denied(get))
                if unsafe and not (control.status == get.status and equivalent(control, get)):
                    confirmation = request("GET", auth)  # a consistently accepted action-producing GET
                    if confirmation.status == 303 or (300 <= confirmation.status < 400 and not is_denied(confirmation)):
                        if self.detectors.record_unsafe_method(endpoint, responses["POST"], get, confirmation, control, "GET"):
                            any_confirmed = True
                            if auth:
                                self.auth["status"] = "verified"
                                self.auth["detail"] = "Session exercises a method-dependent state change"

                # Declared-method violation: an undeclared verb returns the same data as the GET baseline.
                base = responses["GET"]
                if useful(base) and endpoint.declared_methods:
                    for method in ("POST", "PUT", "PATCH", "DELETE"):
                        if method in endpoint.declared_methods or not useful(responses[method]) or not equivalent(base, responses[method]):
                            continue
                        if control.status == responses[method].status and equivalent(control, responses[method]):
                            continue
                        confirmation = request(method, auth)
                        if not useful(confirmation) or not equivalent(responses[method], confirmation):
                            continue
                        if self.detectors.record_contract(endpoint, base, responses[method], confirmation, control):
                            any_confirmed = True

                # Verify the session works: a resource denied anonymously but served with the session.
                if auth and is_denied(responses["GET"]) is False and useful(responses["GET"]) and self.auth["status"] != "verified":
                    self.auth["status"] = "verified"
                    self.auth["detail"] = "Session retrieves application data"
            if not any_confirmed:
                self.detectors.observations.append({"url": url, "reason": "No reproducible authorization bypass or declared-method violation confirmed"})
        except (OSError, ValueError, HTTPException):
            self.failed_requests += 1
            self.detectors.observations.append({"url": url, "reason": "Method testing interrupted by transport error"})
        return len(self.detectors.findings) - before

    def probe_state_change(self, endpoint, form, url):
        """Ordered probe of a pure action form. Submits the intended write WITH its CSRF token to
        learn the real authorization verdict on the original state, then the unsafe GET, recording
        the host page before and after as observable proof of the mutation. Returns True when it
        classifies the endpoint (bypass or CSRF); False to fall back to the generic method sweep."""
        from urllib.parse import urlencode
        host = form.get("page") or endpoint.url
        body = urlencode(form["hidden"]).encode()

        def page():
            response = self.browser.transport.request("GET", host, self.browser.headers_for(host),
                                                       authenticated=True, follow=True)
            self.observe(response)
            return response

        def probe(method, with_token=False):
            headers = self.browser.headers_for(endpoint.url)
            data = None
            if with_token:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                data = body
            response = self.browser.transport.request(method, endpoint.url, headers, data, authenticated=True)
            self.observe(response)
            return response

        # 1. Observable state, then the intended write with its token (original state), then GET.
        before = page()
        legit = probe("POST", with_token=True)
        after_post = page()
        control = probe("SCANNERPROBE")
        unsafe = probe("GET")
        after_get = page()
        get_action = unsafe.status == 303 or (300 <= unsafe.status < 400 and not is_denied(unsafe))
        if not get_action:
            return False  # not a state-changing GET endpoint; let the generic sweep decide
        post_denied = is_denied(legit)
        post_mutated = not equivalent(before, after_post)
        get_mutated = not equivalent(after_post, after_get)

        if post_denied and not post_mutated and get_mutated:
            # The authorized write is refused, yet the safe method performed the very mutation it
            # was refused: a genuine authorization bypass, proven by the before/after state.
            self.detectors.record_bypass(endpoint, legit, unsafe, page(), control, "GET",
                                         state_before=before, state_after=after_get)
            self.auth["status"] = "verified"
            self.auth["detail"] = "Session exercises a method-dependent authorization bypass"
            return True
        if not post_denied and (post_mutated or get_mutated):
            # The write is permitted for this actor, so it is not an authorization bypass — but the
            # safe method reaches the same mutation without the CSRF token the write path requires.
            blind = probe("POST")  # no token: shows the write path demands one
            self.detectors.record_unsafe_method(endpoint, blind, unsafe, page(), control, "GET",
                                                 legitimate=legit, state_before=before, state_after=after_post)
            return True
        return True  # state-changing but inconclusive: do not re-report via the generic sweep

    def finish_status(self):
        if self.discovery.limited:
            self.warnings.append("Limite de descoberta de endpoints atingido.")
        if self.browser.pages >= self.config.max_pages:
            self.warnings.append("Limite de páginas do navegador atingido; parte da superfície pode não ter sido explorada.")
        if self.truncated_responses:
            self.warnings.append("Algumas respostas excederam MAX_BODY_BYTES; a cobertura delas ficou incompleta.")
        if self.failed_requests or self.browser.failures:
            self.warnings.append("Algumas requisições ou navegações falharam.")
        guarded = any(r.status in (401, 403) for r in self.discovery.responses.values())
        if self.auth["status"] == "not_attempted":
            self.auth.update(status="not_required" if not guarded else "not_discovered",
                             detail="Nenhum login observado." if not guarded else "Há recursos protegidos, mas nenhum formulário de login utilizável foi descoberto.")
        if self.auth["status"] in ("failed", "credentials_missing", "not_discovered"):
            self.warnings.append("Cobertura autenticada incompleta.")
        self.status = "partial" if self.warnings else "completed"

    def close(self):
        if self.browser:
            self.browser.close()

    def report(self):
        findings = sorted(self.detectors.findings.values(), key=lambda f: f["id"])
        return self.redactor.clean({"findings": findings})
