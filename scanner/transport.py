"""Bounded HTTP transport shared by browser, probes and local Ollama.

No proxies, redirects are explicit, and socket connections use pinned local IPs.
"""

from dataclasses import dataclass, field
from email.message import Message
import http.client
import http.cookiejar
import socket
import ssl
import time
import re
import zlib
from urllib.parse import urlsplit, urljoin
from urllib.request import Request

from .safety import Scope, ScopeError


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Budget:
    max_requests: int
    max_seconds: int
    started: float = field(default_factory=time.monotonic)
    requests: int = 0

    def check(self):
        if time.monotonic() - self.started >= self.max_seconds:
            raise BudgetExceeded("Tempo máximo do scan esgotado.")

    def take(self):
        self.check()
        if self.requests >= self.max_requests:
            raise BudgetExceeded("Limite de requisições HTTP ao alvo esgotado.")
        self.requests += 1

    def remaining_seconds(self):
        self.check()
        return self.max_seconds - (time.monotonic() - self.started)


@dataclass
class Response:
    url: str
    method: str
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False
    elapsed_ms: int = 0
    session: str = "anonymous"

    @property
    def text(self):
        match = re.search(r"charset=[\"']?([\w-]+)", self.headers.get("content-type", ""), re.I)
        encoding = match[1] if match else "utf-8"
        try:
            return self.body.decode(encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def textual(self):
        content_type = self.headers.get("content-type", "").lower()
        return any(t in content_type for t in ("text/", "json", "javascript", "xml")) or (
            not content_type and b"\x00" not in self.body[:512]
        )


class CookieResponse:
    def __init__(self, pairs):
        self.message = Message()
        for k, v in pairs:
            self.message.add_header(k, v)

    def info(self):
        return self.message


class Transport:
    def __init__(self, scope: Scope, budget: Budget, timeout=12, max_body=1_048_576):
        self.scope, self.budget = scope, budget
        self.timeout, self.max_body = timeout, max_body
        self.cookies = http.cookiejar.CookieJar()

    def request(self, method: str, url: str, headers=None, body: bytes | None = None,
                authenticated=False, follow=False, max_redirects=5) -> Response:
        url = self.scope.check(url)
        original_headers = dict(headers or {})
        for hop in range(max_redirects + 1):
            self.budget.take()
            p = urlsplit(url)
            request_headers = {k: v for k, v in original_headers.items() if k.lower() not in (
                "host", "connection", "content-length", "accept-encoding", "proxy-authorization",
                "transfer-encoding", "upgrade",
            )}
            request_headers.update({"Host": p.netloc, "Accept-Encoding": "identity", "Connection": "close"})
            request_headers.setdefault("User-Agent", "LocalAgenticScanner/1.0")
            cookie_request = Request(url, headers=request_headers, method=method)
            if authenticated:
                self.cookies.add_cookie_header(cookie_request)
                if not any(k.lower() == "cookie" for k in request_headers) and cookie_request.has_header("Cookie"):
                    request_headers["Cookie"] = cookie_request.get_header("Cookie")
            timeout = max(0.01, min(self.timeout, self.budget.remaining_seconds()))
            connection = http.client.HTTPConnection(self.scope.host, self.scope.port, timeout=timeout)
            started = time.monotonic()
            last_error = None
            try:
                for address in self.scope.addresses:
                    try:
                        connection.sock = socket.create_connection((address, self.scope.port), timeout=timeout)
                        if p.scheme == "https":
                            connection.sock = ssl.create_default_context().wrap_socket(connection.sock, server_hostname=self.scope.host)
                        break
                    except OSError as exc:
                        last_error = exc
                        connection.close()
                if connection.sock is None:
                    raise OSError("Cannot connect to local service") from last_error
                connection.request(method, (p.path or "/") + ("?" + p.query if p.query else ""), body=body, headers=request_headers)
                active_socket = connection.sock
                raw = connection.getresponse()
                pairs = raw.getheaders()
                if authenticated:
                    self.cookies.extract_cookies(CookieResponse(pairs), cookie_request)
                chunks = []
                size = 0
                while size <= self.max_body:
                    self.budget.check()
                    if active_socket.fileno() >= 0:
                        active_socket.settimeout(max(0.01, min(timeout, self.budget.remaining_seconds())))
                    chunk = raw.read1(min(65536, self.max_body + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                payload = b"".join(chunks)
                response_headers = {}
                for k, v in pairs:
                    key = k.lower()
                    response_headers[key] = response_headers.get(key, "") + ("\n" if key in response_headers and key == "set-cookie" else ", " if key in response_headers else "") + v
                truncated = len(payload) > self.max_body
                encoding = response_headers.get("content-encoding", "").lower()
                if encoding in ("gzip", "deflate"):
                    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS)
                    payload = decoder.decompress(payload, self.max_body + 1)
                    truncated = truncated or len(payload) > self.max_body or not decoder.eof
                    response_headers.pop("content-encoding", None)
                elif encoding and encoding != "identity":
                    raise ValueError("Unsupported response content encoding")
                response = Response(url, method, raw.status, response_headers, payload[:self.max_body],
                                    truncated, int((time.monotonic() - started) * 1000),
                                    "authenticated" if authenticated else "anonymous")
            finally:
                connection.close()
            if not follow or response.status not in (301, 302, 303, 307, 308) or "location" not in response.headers:
                return response
            if hop == max_redirects:
                raise ScopeError("Redirect limit exceeded")
            url = self.scope.check(urljoin(url, response.headers["location"]))
            if response.status == 303 or response.status in (301, 302) and method == "POST":
                method, body = "GET", None
                original_headers = {k: v for k, v in original_headers.items() if k.lower() != "content-type"}
        raise AssertionError("Unreachable")
