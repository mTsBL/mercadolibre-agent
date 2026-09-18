from dataclasses import dataclass, field
from html.parser import HTMLParser
import json
import re
from urllib.parse import urljoin, urlsplit

from .safety import DANGEROUS, ScopeError, fingerprint
from .transport import Response


ASSET = re.compile(r"\.(?:css|js|mjs|map|png|jpe?g|gif|svg|ico|woff2?|ttf|mp4|webm|pdf|zip)(?:$|\?)", re.I)
HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


class HTMLDiscovery(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.base_href = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base":
            self.base_href = attrs.get("href", "")
        elif tag in ("a", "area", "iframe", "script", "link"):
            value = attrs.get("href") or attrs.get("src")
            if value:
                self.links.append((value, "GET", "html"))
        elif tag == "form":
            self.links.append((attrs.get("action", ""), attrs.get("method", "GET").upper(), "form"))


@dataclass
class Endpoint:
    id: str
    url: str
    method: str
    source: str
    depth: int = 0
    visited_sessions: set = field(default_factory=set)
    tested: bool = False
    observed: bool = False
    declared_methods: set = field(default_factory=set)

    @property
    def asset(self):
        return bool(ASSET.search(self.url))


class Discovery:
    def __init__(self, scope, limit=80):
        self.scope, self.limit = scope, limit
        self.endpoints: dict[str, Endpoint] = {}
        self.responses: dict[tuple[str, str, str], Response] = {}
        self.limited = False
        self.blocked = 0

    def add(self, value: str, base="", method="GET", source="observed", depth=0):
        if not isinstance(value, str) or len(value) > 2048 or depth > 8:
            return None
        if any(c in value for c in ("{", "}", "${", "<", ">")):
            return None  # Never invent missing path parameters.
        try:
            url = self.scope.check(urljoin(base or self.scope.base, value))
        except (ValueError, ScopeError):
            self.blocked += 1
            return None
        method = method.upper()
        if method not in HTTP_METHODS or DANGEROUS.search(urlsplit(url).path):
            return None
        key = fingerprint(f"{method} {url}")
        if key in self.endpoints:
            return self.endpoints[key]
        if len(self.endpoints) >= self.limit:
            self.limited = True
            return None
        endpoint = Endpoint(key, url, method, source, depth)
        self.endpoints[key] = endpoint
        return endpoint

    def observe(self, response: Response, source="network", depth=0):
        endpoint = self.add(response.url, method=response.method, source=source, depth=depth)
        if endpoint:
            endpoint.observed = True
            endpoint.visited_sessions.add(response.session)
            self.responses[(response.url, response.method, response.session)] = response
        if not response.textual or response.truncated or response.status >= 400:
            return endpoint
        text = response.text
        ctype = response.headers.get("content-type", "").lower()
        if "html" in ctype or text.lstrip().startswith(("<!DOCTYPE", "<!doctype", "<html")):
            parser = HTMLDiscovery()
            parser.feed(text)
            base = urljoin(response.url, parser.base_href) if parser.base_href else response.url
            for value, method, source_name in parser.links:
                self.add(value, base, method, source_name, depth + 1)
        if "javascript" in ctype or "html" in ctype or response.url.endswith((".js", ".mjs")):
            # In HTML inspect script bodies only. Attribute literals already have
            # typed HTML provenance (a POST form is not evidence of a GET endpoint).
            source_text = "\n".join(re.findall(r"<script\b[^>]*>(.*?)</script\s*>", text, flags=re.I | re.S)) if "html" in ctype else text
            # Literal URLs only; bounded extraction, no evaluation of source code.
            for match in re.finditer(r'''(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open)\s*\(\s*["']([^"'\s]+)["']''', source_text):
                if match[1].startswith(("/", "./", "../", "http")):
                    self.add(match[1], response.url, source="javascript", depth=depth + 1)
            for match in re.finditer(r'''["']((?:/|https?://)[^"'\s<>]{1,256})["']''', source_text):
                self.add(match[1], response.url, source="javascript_literal", depth=depth + 1)
        if "json" in ctype or text.lstrip().startswith(("{", "[")):
            try:
                data = json.loads(text)
            except (ValueError, RecursionError):
                return endpoint
            self._json_links(data, response.url, depth + 1)
            if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
                self._openapi(data, response.url, depth + 1)
        return endpoint

    def _json_links(self, data, base, depth, nesting=0):
        if nesting > 12:
            return
        if isinstance(data, dict):
            for key, value in list(data.items())[:200]:
                if isinstance(value, str) and value.startswith(("/", "http://", "https://")):
                    self.add(value, base, source="json_link", depth=depth)
                elif isinstance(value, (dict, list)):
                    self._json_links(value, base, depth, nesting + 1)
        elif isinstance(data, list):
            for item in data[:200]:
                self._json_links(item, base, depth, nesting + 1)

    def _openapi(self, data, base, depth):
        server = self.scope.origin
        servers = data.get("servers", [])
        if servers and isinstance(servers[0], dict):
            server = urljoin(base, servers[0].get("url", ""))
        elif data.get("basePath"):
            server += data["basePath"]
        paths = data.get("paths", {})
        if not isinstance(paths, dict):
            return
        for path, operations in list(paths.items())[:self.limit]:
            if not isinstance(operations, dict):
                continue
            methods = {m.upper() for m in operations if m.upper() in HTTP_METHODS}
            # GET implies HEAD, OPTIONS may describe the resource without being documented.
            allowed = methods | {"OPTIONS"} | ({"HEAD"} if "GET" in methods else set())
            for method in methods:
                endpoint = self.add(server.rstrip("/") + "/" + path.lstrip("/"), method=method, source="openapi", depth=depth)
                if endpoint:
                    endpoint.declared_methods.update(allowed)
                    for sibling in self.endpoints.values():
                        if sibling.url == endpoint.url:
                            sibling.declared_methods.update(allowed)
