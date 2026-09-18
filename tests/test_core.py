import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scanner.__main__ import write_report
from scanner.config import Config
from scanner.detectors import Detectors, cpf_matches, valid_cpf
from scanner.discovery import Discovery
from scanner.safety import Scope, ScopeError, Redactor, canonical, local_ip
from scanner.transport import Budget, BudgetExceeded, Response, Transport
from tests.fixtures import CPF, QuietHandler, serving


def response(body, method="GET", status=200, session="anonymous", content_type="application/json"):
    return Response("http://127.0.0.1:3000/records", method, status,
                    {"content-type": content_type}, body.encode(), session=session)


class CPFTests(unittest.TestCase):
    def test_checksum_and_format(self):
        for value in (CPF, CPF.replace(".", "").replace("-", "")):
            self.assertTrue(valid_cpf(value))
        for value in ("111.111.111-11", "00000000000", "529.982.247-24", "123", "123456789012"):
            self.assertFalse(valid_cpf(value))

    def test_context_required(self):
        self.assertEqual(len(cpf_matches(response('{"cpf":"' + CPF + '"}'))), 1)
        self.assertEqual(cpf_matches(response('{"tracking":"52998224725"}')), [])

    def test_invalid_masked_examples_and_errors(self):
        for body in ('{"cpf":"***.***.***-25"}', '{"cpf":"11111111111"}', '{"cpf":"1529982247258"}'):
            self.assertEqual(cpf_matches(response(body)), [])
        self.assertEqual(cpf_matches(response(CPF, status=500)), [])
        self.assertEqual(cpf_matches(response('const cpf="' + CPF + '";', content_type="application/javascript")), [])
        self.assertEqual(cpf_matches(response('<script>const cpf="' + CPF + '";</script>', content_type="text/html")), [])

    def test_exposure_is_deduplicated_and_redacted(self):
        detector = Detectors(Redactor())
        detector.pii(response('{"cpf":"' + CPF + '"}', session="authenticated"))
        detector.pii(response('{"cpf":"' + CPF + '"}'))
        detector.pii(response('{"cpf":"' + CPF + '"}', session="authenticated"))
        self.assertEqual(len(detector.findings), 1)
        finding = next(iter(detector.findings.values()))
        self.assertEqual(finding["severity"], "high")
        self.assertNotIn(CPF, json.dumps(finding))

    def test_credential_exchange_is_not_public_exposure(self):
        detector = Detectors(Redactor())
        detector.pii(response('{"cpf":"' + CPF + '"}', session="credential_exchange"))
        self.assertEqual(detector.findings, {})


class MethodTests(unittest.TestCase):
    def setUp(self):
        self.detector = Detectors(Redactor())
        self.endpoint = SimpleNamespace(url="http://127.0.0.1:3000/records", declared_methods=set())
        self.data = '{"records":[{"cpf":"' + CPF + '"}]}'
        self.control = response("Unsupported", method="SCANNERPROBE", status=405)

    def evaluate(self, baseline, probe, confirmation=None, control=None, reference=None):
        return self.detector.method(self.endpoint, baseline, probe, confirmation or probe,
                                    control or self.control, reference)

    def test_status_200_alone_is_not_a_finding(self):
        self.assertFalse(self.evaluate(response(self.data), response(self.data, "POST")))

    def test_authentication_bypass(self):
        self.assertTrue(self.evaluate(response('{"error":"denied"}', status=401), response(self.data, "POST")))

    def test_declared_contract_violation(self):
        self.endpoint.declared_methods = {"GET", "HEAD", "OPTIONS"}
        self.assertTrue(self.evaluate(response(self.data), response(self.data, "DELETE")))

    def test_legitimate_post_and_405_are_not_auth_bypass(self):
        self.assertFalse(self.evaluate(response("Not allowed", status=405), response(self.data, "POST")))

    def test_wildcard_is_not_method_specific(self):
        self.assertFalse(self.evaluate(response("Denied", status=401), response(self.data, "POST"),
                                       control=response(self.data, "SCANNERPROBE")))

    def test_soft_error_is_not_a_finding(self):
        self.assertFalse(self.evaluate(response("Denied", status=401), response('{"error":"Denied"}', "POST")))

    def test_confirmation_must_match(self):
        self.assertFalse(self.evaluate(response("Denied", status=401), response(self.data, "POST"),
                                       confirmation=response("Changed", "POST")))

    def test_html_login_and_empty_success_are_rejected(self):
        for body in ('<html><input type="password"></html>', '{}', '{"success":true}', ''):
            self.assertFalse(self.evaluate(response("Denied", status=401), response(body, "POST")))


class SafetyTests(unittest.TestCase):
    def test_private_and_loopback_only(self):
        for ip in ("127.0.0.1", "10.1.2.3", "172.20.1.1", "192.168.1.2", "::1", "fd00::1", "::ffff:127.0.0.1"):
            self.assertTrue(local_ip(ip))
        for ip in ("8.8.8.8", "169.254.169.254", "0.0.0.0", "224.0.0.1", "100.64.0.1", "::", "fe80::1"):
            self.assertFalse(local_ip(ip))

    def test_same_origin_and_url_validation(self):
        scope = Scope("http://127.0.0.1:3000")
        self.assertEqual(scope.check("/hello#anchor"), "http://127.0.0.1:3000/hello")
        for url in ("https://127.0.0.1:3000", "http://127.0.0.1:3001", "http://example.org", "file:///etc/passwd"):
            with self.assertRaises(ScopeError):
                scope.check(url)
        for url in ("http://user:pass@127.0.0.1", "http://127.0.0.1/\nHost:x", "http://127.0.0.1\\example.org"):
            with self.assertRaises(ValueError):
                canonical(url)

    def test_mixed_dns_is_rejected(self):
        records = [(2, 1, 6, '', ('127.0.0.1', 80)), (2, 1, 6, '', ('8.8.8.8', 80))]
        with patch("scanner.safety.socket.getaddrinfo", return_value=records), self.assertRaises(ScopeError):
            Scope("http://mixed.example")

    def test_redaction(self):
        redactor = Redactor("secret-password")
        text = json.dumps(redactor.clean({"url": "http://localhost/path?anything=secret-password&name=Alice", "text": CPF + " secret-password a@example.com"}))
        for secret in (CPF, "secret-password", "Alice", "a@example.com"):
            self.assertNotIn(secret, text)

    def test_short_credentials_do_not_corrupt_schema_or_prose(self):
        redactor = Redactor("a", "high")
        report = redactor.clean({"status": "partial", "severity": "high", "text": "password a; actual high"})
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["severity"], "high")
        self.assertEqual(report["text"], "password [REDACTED]; actual [REDACTED]")

    def test_url_inside_exception_is_redacted(self):
        value = Redactor().text("Navigation failed at http://localhost/?ticket=private-value")
        self.assertNotIn("private-value", value)

    def test_request_and_time_budget(self):
        budget = Budget(1, 10)
        budget.take()
        with self.assertRaises(BudgetExceeded):
            budget.take()
        budget.started -= 20
        with self.assertRaises(BudgetExceeded):
            budget.check()

    def test_atomic_report_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "findings.json"
            write_report(path, {"findings": []})
            self.assertEqual(json.loads(path.read_text()), {"findings": []})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_credentials_must_be_paired(self):
        with patch.dict("os.environ", {"BASE_URL": "http://localhost:3000", "CHALLENGE_USERNAME": "user", "CHALLENGE_PASSWORD": ""}):
            with self.assertRaises(ValueError):
                Config.from_env()


class DiscoveryTests(unittest.TestCase):
    def test_discovery_follows_evidence_without_guessing(self):
        discovery = Discovery(Scope("http://127.0.0.1:3000"))
        discovery.observe(response('<a href="/random">x</a><script>fetch("/data")</script><a href="https://external.test/">out</a>', content_type="text/html"))
        paths = {e.url for e in discovery.endpoints.values()}
        self.assertIn("http://127.0.0.1:3000/random", paths)
        self.assertIn("http://127.0.0.1:3000/data", paths)
        self.assertFalse(any("external" in p for p in paths))

    def test_openapi_respects_server_prefix_and_skips_templates(self):
        discovery = Discovery(Scope("http://127.0.0.1:3000"))
        discovery.observe(response(json.dumps({"openapi": "3.0.0", "servers": [{"url": "/v2"}],
                                                "paths": {"/thing": {"get": {}}, "/thing/{id}": {"get": {}}}})))
        endpoint = next(e for e in discovery.endpoints.values() if e.url.endswith("/v2/thing"))
        self.assertEqual(endpoint.declared_methods, {"GET", "HEAD", "OPTIONS"})
        self.assertFalse(any("{" in e.url for e in discovery.endpoints.values()))

    def test_endpoint_limit(self):
        discovery = Discovery(Scope("http://127.0.0.1:3000"), limit=1)
        discovery.add("/one")
        self.assertIsNone(discovery.add("/two"))
        self.assertTrue(discovery.limited)


class TransportTests(unittest.TestCase):
    def test_redirect_does_not_contact_other_origin(self):
        class Redirect(QuietHandler):
            def do_GET(self):
                self.send(302, headers=[("Location", "http://example.org/")])
        with serving(Redirect) as url:
            transport = Transport(Scope(url), Budget(5, 10))
            with self.assertRaises(ScopeError):
                transport.request("GET", url, follow=True)
            self.assertEqual(transport.budget.requests, 1)

    def test_gzip_body_is_decoded_with_size_limit(self):
        import gzip
        class Compressed(QuietHandler):
            def do_GET(self):
                self.send(body=gzip.compress(b"x" * 4000), headers=[("Content-Encoding", "gzip")])
        with serving(Compressed) as url:
            transport = Transport(Scope(url), Budget(5, 10), max_body=1024)
            result = transport.request("GET", url)
            self.assertEqual(result.body, b"x" * 1024)
            self.assertTrue(result.truncated)

    def test_cookies_and_anonymous_isolation(self):
        class Cookies(QuietHandler):
            def do_GET(self):
                self.send(body=self.headers.get("Cookie", "none"), headers=[("Set-Cookie", "SID=secret; Path=/")])
        with serving(Cookies) as url:
            transport = Transport(Scope(url), Budget(5, 10))
            transport.request("GET", url, authenticated=True)
            self.assertIn("SID=secret", transport.request("GET", url, authenticated=True).text)
            self.assertEqual(transport.request("GET", url).text, "none")


if __name__ == "__main__":
    unittest.main()
