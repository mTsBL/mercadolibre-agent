"""Browser discovery and generic login; every HTTP request uses the scoped transport."""

import re
import time
from http.client import HTTPException
from urllib.parse import urlsplit, urljoin

from .safety import DANGEROUS, SECRET_KEY, ScopeError
from .transport import BudgetExceeded


class Browser:
    def __init__(self, config, transport, discovery, redactor, on_response):
        self.config, self.transport, self.discovery = config, transport, discovery
        self.redactor, self.on_response = redactor, on_response
        self.authenticated = False
        self.submitting = False
        self.login_response_ok = False
        self.auth_headers = {}
        self.login_urls = set()
        self.blocked_requests = 0
        self.failures = 0
        self.navigation_errors = []
        self.pending_navigation = None
        self.budget_error = None
        self.depth = 0
        self.pages = 0
        self.runtime = self.browser = self.context = self.page = None

    def start(self):
        from playwright.sync_api import sync_playwright
        self.runtime = sync_playwright().start()
        self.browser = self.runtime.chromium.launch(headless=True, args=[
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--no-first-run", "--disable-default-apps", "--disable-extensions",
            "--disable-domain-reliability", "--no-proxy-server",
            "--host-resolver-rules=MAP * ~NOTFOUND",  # Browser cannot open HTTP sockets itself.
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        ])
        self.context = self.browser.new_context(service_workers="block", accept_downloads=False)
        self.context.route("**/*", self._route)
        self.context.route_web_socket("**/*", lambda ws: ws.close())
        self.context.on("page", self._page_created)
        self.page = self.context.new_page()
        self.page.on("dialog", lambda dialog: dialog.dismiss())
        self.page.set_default_timeout(self.config.request_timeout * 1000)
        return self

    def _page_created(self, page):
        if self.page is not None and page != self.page:
            page.close()  # Do not allow unbounded popups.

    def _route(self, route):
        request = route.request
        try:
            url = self.transport.scope.check(request.url)
            if DANGEROUS.search(urlsplit(url).path) or request.resource_type in ("image", "media", "font"):
                self.blocked_requests += 1
                route.abort()
                return
            headers = request.all_headers()
            for key, value in headers.items():
                if SECRET_KEY.search(key):
                    self.redactor.add(value)
            if self.submitting and request.method not in ("GET", "HEAD", "OPTIONS"):
                self.login_urls.add(url)
            for key in ("authorization", "x-csrf-token", "x-xsrf-token", "x-auth-token", "x-api-key"):
                if key in headers:
                    self.auth_headers[key] = headers[key]
            response = self.transport.request(request.method, url, headers, request.post_data_buffer,
                                              authenticated=True, follow=not request.is_navigation_request())
            if self.submitting and request.method not in ("GET", "HEAD", "OPTIONS"):
                self.login_response_ok = 200 <= response.status < 400
            response.session = "credential_exchange" if self.submitting else "authenticated" if self.authenticated else "anonymous"
            for cookie in self.transport.cookies:
                self.redactor.add(cookie.value)
            self.discovery.observe(response, depth=self.depth)
            self.on_response(response)
            self._sync_cookies()
            if response.status in (301, 302, 303, 307, 308) and "location" in response.headers:
                target = self.transport.scope.check(urljoin(url, response.headers["location"]))
                self.discovery.add(target, source="redirect", depth=self.depth)
                if request.method == "GET" or response.status == 303 or (request.method == "POST" and response.status in (301, 302)):
                    # Playwright only routes the first URL of a native redirect chain.
                    # Schedule a fresh navigation so EVERY hop crosses our pinned transport.
                    self.pending_navigation = target
                    route.fulfill(status=200, content_type="text/html", body="")
                    return
                # Preserve body/method semantics for 307/308 form submissions.
                response = self.transport.request(request.method, target, headers, request.post_data_buffer,
                                                  authenticated=True, follow=True)
                response.session = "credential_exchange" if self.submitting else "authenticated" if self.authenticated else "anonymous"
                self._sync_cookies()
                self.discovery.observe(response, depth=self.depth)
                self.on_response(response)
            # Playwright accepts newline-delimited Set-Cookie values and applies normal
            # browser cookie rules. Strip transport-only headers after bounded reading.
            excluded = {"content-length", "transfer-encoding", "connection", "content-encoding"}
            response_headers = {k: v for k, v in response.headers.items() if k not in excluded}
            route.fulfill(status=response.status, headers=response_headers, body=response.body)
        except ScopeError:
            self.blocked_requests += 1
            route.abort()
        except BudgetExceeded as exc:
            self.budget_error = exc
            route.abort()
        except (OSError, ValueError, HTTPException):
            self.failures += 1
            route.abort()

    def _sync_cookies(self):
        cookies = []
        for cookie in self.transport.cookies:
            if cookie.is_expired():
                continue
            entry = {"name": cookie.name, "value": cookie.value,
                     "domain": cookie.domain if cookie.domain_specified else self.transport.scope.host,
                     "path": cookie.path or "/", "secure": cookie.secure,
                     "httpOnly": cookie.has_nonstandard_attr("HttpOnly")}
            if cookie.expires:
                entry["expires"] = cookie.expires
            cookies.append(entry)
        if cookies:
            self.context.add_cookies(cookies)

    def settle(self):
        for _ in range(6):
            self.page.wait_for_timeout(min(self.config.settle_ms, self.transport.budget.remaining_seconds() * 1000))
            if not self.pending_navigation:
                return
            url, self.pending_navigation = self.pending_navigation, None
            self.page.goto(url, wait_until="domcontentloaded", timeout=min(
                self.config.request_timeout, self.transport.budget.remaining_seconds()) * 1000)
        raise ScopeError("Browser redirect limit exceeded")

    def visit(self, endpoint):
        self.transport.budget.check()
        self.depth = endpoint.depth
        self.pages += 1
        from playwright.sync_api import Error
        try:
            self.page.goto(endpoint.url, wait_until="domcontentloaded", timeout=min(
                self.config.request_timeout, self.transport.budget.remaining_seconds()) * 1000)
            self.settle()
            self.discover_dom()
        except Error as exc:
            self.failures += 1
            self.navigation_errors.append((endpoint.url, str(exc)))
        if self.budget_error:
            raise self.budget_error

    def discover_dom(self):
        links = self.page.locator("a[href], iframe[src]").evaluate_all(
            "els => els.slice(0, 200).map(e => e.href || e.src)"
        )
        for link in links:
            self.discovery.add(link, self.page.url, source="rendered_dom", depth=self.depth + 1)
        self.capture_forms()

    def capture_forms(self):
        # Capture write forms so method testing can submit the intended method WITH its CSRF
        # token, and tell an authorization bypass apart from a plain unsafe-method/CSRF flaw.
        from playwright.sync_api import Error
        try:
            forms = self.page.locator("form").evaluate_all("""els => els.slice(0, 30).map(f => ({
                action: f.action || location.href,
                method: (f.getAttribute('method') || 'GET').toUpperCase(),
                hidden: [...f.querySelectorAll('input')].filter(e => e.name && e.type === 'hidden').map(e => [e.name, e.value]),
                visible: [...f.querySelectorAll('input,textarea,select')].filter(e => e.name
                    && !['hidden','submit','button','image','reset'].includes(e.type) && e.getClientRects().length).length
            }))""")
        except Error:
            return
        for form in forms:
            if form.get("method") != "POST":
                continue
            try:
                action = self.transport.scope.check(form["action"])
            except (ValueError, ScopeError):
                continue
            hidden = {name: value for name, value in form.get("hidden", []) if name}
            for name, value in hidden.items():
                if SECRET_KEY.search(name) and value:
                    self.redactor.add(value)  # never let a CSRF token surface in reports or prompts
            self.discovery.record_form(action, "POST", hidden, int(form.get("visible", 0)), self.page.url)

    def fields(self):
        # Do not send field values (including hidden CSRF tokens) to the model.
        expression = """els => els.map((e, index) => ({
            index, type: e.type, name: e.name.slice(0, 80), autocomplete: e.autocomplete.slice(0, 40),
            label: (e.labels?.[0]?.innerText || e.getAttribute('aria-label') || e.placeholder || '').slice(0, 80),
            visible: !!(e.getClientRects().length) && !e.disabled
        })).filter(e => e.visible && !['hidden','submit','button','checkbox','radio'].includes(e.type)).slice(0, 20)"""
        from playwright.sync_api import Error
        for attempt in range(3):
            try:
                return self.page.locator("input").evaluate_all(expression)
            except Error:
                if attempt == 2 or self.page.is_closed():
                    raise
                self.page.wait_for_load_state("domcontentloaded")
                self.page.wait_for_timeout(100)

    def has_login(self):
        return any(f["type"] == "password" for f in self.fields())

    def login(self, model):
        fields = self.fields()
        selected = model.login_fields(fields)
        indices = {f["index"] for f in fields}
        user_index, password_index = selected["username"], selected["password"]
        if user_index not in indices or password_index not in indices or user_index == password_index:
            return False, "Local model could not identify both login fields"
        password_info = next(f for f in fields if f["index"] == password_index)
        if password_info["type"] != "password":
            return False, "Selected password input is not a password field"
        password = self.page.locator("input").nth(password_index)
        username = self.page.locator("input").nth(user_index)
        if password.get_attribute("autocomplete") == "new-password":
            return False, "Registration/password-change form skipped"
        before_cookies = {(c.name, c.value) for c in self.transport.cookies}
        before_headers = dict(self.auth_headers)
        self.login_urls.add(self.page.url)
        username.fill(self.config.username)
        password.fill(self.config.password)
        self.submitting = True
        self.login_response_ok = False
        try:
            form = password.locator("xpath=ancestor::form[1]")
            if form.count():
                buttons = form.locator('button[type="submit"], input[type="submit"], button:not([type])')
                if buttons.count() and buttons.first.is_visible():
                    buttons.first.click()
                else:
                    password.press("Enter")
            else:
                buttons = self.page.get_by_role("button", name=re.compile(r"log\s*in|sign\s*in|entrar|acessar|iniciar", re.I))
                if buttons.count():
                    buttons.first.click()
                else:
                    password.press("Enter")
            self.settle()
            # Poll boundedly: token-based SPAs may finish login after DOMContentLoaded.
            deadline = time.monotonic() + min(5, self.transport.budget.remaining_seconds())
            while time.monotonic() < deadline:
                self.page.wait_for_timeout(150)
                if not self.has_login():
                    break
            after_cookies = {(c.name, c.value) for c in self.transport.cookies}
            changed = bool(after_cookies - before_cookies) or before_headers != self.auth_headers
            # Browser-only cookies (document.cookie) must also be available to probes.
            cookies = self.context.cookies()
            changed = changed or any((c["name"], c["value"]) not in before_cookies for c in cookies)
            success = self.login_response_ok and changed and not self.has_login()
            self.authenticated = success
            self.discover_dom()
            return success, "Session established and login form left" if success else "Login was not confirmed by session and page changes"
        finally:
            self.submitting = False
            if self.budget_error:
                raise self.budget_error

    def headers_for(self, url):
        headers = dict(self.auth_headers)
        cookies = self.context.cookies(url) if self.context else []
        if cookies:
            headers["Cookie"] = "; ".join(c["name"] + "=" + c["value"] for c in cookies)
            for cookie in cookies:
                self.redactor.add(cookie["value"])
        return headers

    def close(self):
        try:
            if self.browser:
                self.browser.close()
        finally:
            if self.runtime:
                self.runtime.stop()
