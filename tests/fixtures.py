"""Disposable synthetic apps. No application paths are imported by scanner code."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import uuid
from urllib.parse import parse_qs, urlsplit


USERNAME = "candidate@example.test"
PASSWORD = "synthetic-test-password"
SESSION = "synthetic-session-token"
CSRF = "synthetic-csrf-token"
CPF = "529.982.247-25"  # Checksum-valid synthetic test value; no identity attached.


class QuietHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, status=200, body="", content_type="text/html", headers=()):
        payload = body if isinstance(body, bytes) else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)


def application(mode="cookie", safe=False, prefix=None):
    prefix = prefix or "/" + uuid.uuid4().hex[:10]
    seen = []

    class App(QuietHandler):
        def handle_request(self):
            path = urlsplit(self.path).path
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            seen.append((self.command, path))
            authed = "SID=" + SESSION in self.headers.get("Cookie", "") or self.headers.get("Authorization") == "Bearer " + SESSION
            if self.command == "SCANNERPROBE":
                if path == prefix + "/wildcard":
                    return self.send(body='{"message":"SPA shell"}', content_type="application/json")
                return self.send(405, "Unsupported")
            if self.command == "OPTIONS":
                return self.send(204, headers=[("Allow", "GET, HEAD, OPTIONS")])
            if path == "/":
                if self.command not in ("GET", "HEAD"):
                    return self.send(405)
                links = f'<a href="{prefix}/enter">Sign in</a><a href="{prefix}/public">Public</a><a href="{prefix}/wildcard">SPA</a><a href="{prefix}/strict">Strict</a><a href="{prefix}/contract">Contract</a>'
                if authed:
                    links += f'<a href="{prefix}/protected">Records</a>'
                return self.send(body="<!doctype html><html><body>Local fixture" + links + "</body></html>")
            if path == prefix + "/enter":
                if self.command != "GET":
                    return self.send(405)
                if authed:
                    return self.send(302, headers=[("Location", "/")])
                form = f'''<form action="{prefix}/session" method="post">
                    <input type="hidden" name="csrf" value="{CSRF}">
                    <label>Email<input name="identifier" type="email" autocomplete="username"></label>
                    <label>Password<input name="secret" type="password" autocomplete="current-password"></label>
                    <button type="submit">Sign in</button></form>'''
                if mode == "spa":
                    form += f'''<script>document.querySelector('form').onsubmit = async e => {{
                        e.preventDefault(); const f = new FormData(e.target);
                        const r = await fetch('{prefix}/session', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(Object.fromEntries(f))}});
                        if (!r.ok) return; const result = await r.json(); localStorage.setItem('access_token', result.access_token);
                        const data = await fetch('{prefix}/protected', {{headers:{{Authorization:'Bearer '+result.access_token}}}});
                        document.body.innerHTML = '<a href="{prefix}/protected">Records</a>';
                    }};</script>'''
                return self.send(body=form, headers=[("Set-Cookie", "CSRF=" + CSRF + "; Path=/; SameSite=Lax")])
            if path == prefix + "/session" and self.command == "POST":
                if "application/json" in self.headers.get("Content-Type", ""):
                    try:
                        fields = json.loads(body)
                    except ValueError:
                        fields = {}
                else:
                    fields = {k: v[0] for k, v in parse_qs(body.decode()).items()}
                if (fields.get("identifier") != USERNAME or fields.get("secret") != PASSWORD
                        or fields.get("csrf") != CSRF or "CSRF=" + CSRF not in self.headers.get("Cookie", "")):
                    return self.send(401, "Invalid login")
                if mode == "spa":
                    return self.send(body=json.dumps({"access_token": SESSION}), content_type="application/json")
                return self.send(303, headers=[("Location", "/"), ("Set-Cookie", "SID=" + SESSION + "; Path=/; HttpOnly; SameSite=Lax")])
            if path == prefix + "/public":
                if self.command not in ("GET", "HEAD"):
                    return self.send(405)
                return self.send(body=json.dumps({"cpf": "***.***.***-25" if safe else CPF}), content_type="application/json")
            if path == prefix + "/protected":
                if not authed and (self.command != "POST" or safe):
                    return self.send(401, '{"error":"authentication required"}', "application/json")
                if self.command not in (("GET", "HEAD") if safe else ("GET", "POST", "HEAD")):
                    return self.send(405)
                return self.send(body=json.dumps({"records": [{"cpf": "***.***.***-25" if safe else CPF}]}), content_type="application/json")
            if path == prefix + "/contract":
                if self.command not in (("GET", "HEAD") if safe else ("GET", "HEAD", "DELETE")):
                    return self.send(405)
                return self.send(body='{"records":[{"name":"Synthetic record"}]}', content_type="application/json")
            if path == prefix + "/strict":
                if self.command not in ("GET", "HEAD"):
                    return self.send(405)
                return self.send(body='{"records":[]}', content_type="application/json")
            if path == prefix + "/wildcard":
                return self.send(body='{"message":"SPA shell"}', content_type="application/json")
            return self.send(404, "Not found")

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_SCANNERPROBE = handle_request

    return App, prefix, seen


def fake_ollama(invalid=False):
    """Protocol stub for repeatable tests only; never used by the runtime agent."""
    prompts = []

    class Model(QuietHandler):
        def do_GET(self):
            self.send(body=json.dumps({"models": [{"name": "qwen2.5:7b"}]}), content_type="application/json")

        def do_POST(self):
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            prompts.append(data)
            task = json.loads(data["messages"][-1]["content"])
            if task["task"] == "identify_login_fields":
                fields = task["fields"]
                answer = {"username": next(f["index"] for f in fields if f["type"] == "email"),
                          "password": next(f["index"] for f in fields if f["type"] == "password")}
            else:
                candidates = task["candidates"]
                chosen = next((c for c in candidates if c["tool"] == "login"), None)
                chosen = chosen or next((c for c in candidates if c["tool"] == "navigate"), candidates[0])
                answer = {"action_id": chosen["id"], "reason": "Explore discovered surface"}
            self.send(body=json.dumps({"done": True, "message": {"content": "not JSON" if invalid else json.dumps(answer)},
                                      "prompt_eval_count": 100, "eval_count": 30}), content_type="application/json")

    return Model, prompts


@contextmanager
def serving(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
