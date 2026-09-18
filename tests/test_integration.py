import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from scanner.agent import Agent
from scanner.config import Config
from scanner.safety import Redactor
from jsonschema import Draft202012Validator, FormatChecker
from tests.fixtures import application, fake_ollama, serving, USERNAME, PASSWORD, SESSION, CPF, QuietHandler


ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(ROOT / ".runtime" / "browsers"))
SCHEMA = json.loads((ROOT / "schemas" / "findings.schema.json").read_text())


def validate_report(report):
    Draft202012Validator(SCHEMA, format_checker=FormatChecker()).validate(report)


class BrowserIntegrationTests(unittest.TestCase):
    def run_agent(self, mode="cookie", safe=False, password=PASSWORD, localhost=False):
        app, prefix, seen = application(mode, safe)
        model, prompts = fake_ollama()
        with serving(app) as base, serving(model) as ollama:
            if localhost:
                base = base.replace("127.0.0.1", "localhost")
            config = Config(base_url=base, ollama_url=ollama, username=USERNAME, password=password,
                            settle_ms=50, max_llm_calls=80, max_tokens=200_000, max_requests=400)
            agent = Agent(config, Redactor(USERNAME, password))
            try:
                agent.run()
                report = agent.report()
                validate_report(report)
            finally:
                agent.close()
        return report, prefix, seen, prompts

    def test_cookie_login_and_both_detectors(self):
        report, prefix, seen, prompts = self.run_agent()
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(report["authentication"]["status"], "verified", report["authentication"])
        types = {f["type"] for f in report["findings"]}
        self.assertEqual(types, {"sensitive_data_exposure", "http_method_tampering"})
        method_findings = [f for f in report["findings"] if f["type"] == "http_method_tampering"]
        self.assertEqual({f["evidence"]["mode"] for f in method_findings}, {"authorization_bypass", "declared_method_violation"})
        self.assertFalse(any(f["url"].endswith(("/strict", "/wildcard")) for f in report["findings"]))
        for value in (USERNAME, PASSWORD, SESSION, CPF):
            self.assertNotIn(value, json.dumps(report))
            self.assertNotIn(value, json.dumps(prompts))
        # No scanner-specific route knowledge: each fixture run has a random prefix.
        self.assertTrue(any(path == prefix + "/protected" for _, path in seen))
        self.assertGreater(report["ai"]["calls"], 0)

    def test_javascript_token_login(self):
        report, _, _, prompts = self.run_agent(mode="spa")
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(report["authentication"]["status"], "verified", report["authentication"])
        self.assertTrue(any(f["evidence"].get("mode") == "authorization_bypass" for f in report["findings"]))
        self.assertNotIn(SESSION, json.dumps(prompts))

    def test_localhost_cookie_domains_and_ipv6_fallback(self):
        report, _, _, _ = self.run_agent(localhost=True)
        self.assertEqual(report["status"], "completed", report["warnings"])
        self.assertEqual(report["authentication"]["status"], "verified")

    def test_safe_application_produces_empty_findings(self):
        report, _, _, _ = self.run_agent(safe=True)
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(report["findings"], [])

    def test_wrong_password_never_reports_successful_login(self):
        report, _, _, _ = self.run_agent(password="wrong-password")
        self.assertEqual(report["status"], "partial", report)
        self.assertEqual(report["authentication"]["status"], "failed")
        self.assertEqual(report["authentication"]["attempts"], 1)

    def test_browser_never_contacts_external_origin(self):
        external_seen = []
        class Other(QuietHandler):
            def do_GET(self):
                external_seen.append(self.path)
                self.send(body="external")
        with serving(Other) as external:
            class App(QuietHandler):
                def do_GET(self):
                    self.send(body=f'<script src="{external}/script.js"></script><iframe src="{external}/frame"></iframe><a href="{external}">out</a>')
                def do_OPTIONS(self):
                    self.send(405)
            model, _ = fake_ollama()
            with serving(App) as base, serving(model) as ollama:
                agent = Agent(Config(base_url=base, ollama_url=ollama, settle_ms=50), Redactor())
                try:
                    agent.run()
                    self.assertGreater(agent.browser.blocked_requests, 0)
                finally:
                    agent.close()
        self.assertEqual(external_seen, [])


class CLITests(unittest.TestCase):
    def run_cli(self, **variables):
        with tempfile.TemporaryDirectory() as directory:
            env = {k: v for k, v in os.environ.items() if k not in (
                "BASE_URL", "CHALLENGE_USERNAME", "CHALLENGE_PASSWORD", "OUTPUT_FILE", "OLLAMA_BASE_URL")}
            env.update(variables)
            result = subprocess.run([str(ROOT / "run.sh")], cwd=directory, env=env, capture_output=True, text=True, timeout=30)
            report = json.loads((Path(directory) / "findings.json").read_text())
            validate_report(report)
            return result, report

    def test_missing_configuration_still_produces_json(self):
        result, report = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["findings"], [])

    def test_public_target_is_rejected(self):
        result, report = self.run_cli(BASE_URL="http://8.8.8.8")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["summary"]["requests_sent"], 0)

    def test_malformed_target_still_writes_report(self):
        result, report = self.run_cli(BASE_URL="http://[invalid")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["status"], "failed")

    def test_url_credentials_are_rejected_and_not_written(self):
        result, report = self.run_cli(BASE_URL="http://embedded-user:embedded-password@localhost:3000")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("embedded-password", json.dumps(report) + result.stderr)

    def test_missing_ollama_is_failure_before_target_access(self):
        app, _, seen = application()
        model, _ = fake_ollama()
        with serving(model) as ollama:
            pass  # Keep the now-closed ephemeral port for an immediate connection refusal.
        with serving(app) as base:
            result, report = self.run_cli(BASE_URL=base, OLLAMA_BASE_URL=ollama, OLLAMA_BIN="/nonexistent/ollama")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["summary"]["requests_sent"], 0)
        self.assertEqual(seen, [])

    def test_invalid_model_response_writes_failure_report(self):
        app, _, _ = application()
        model, _ = fake_ollama(invalid=True)
        with serving(app) as base, serving(model) as ollama:
            result, report = self.run_cli(BASE_URL=base, OLLAMA_BASE_URL=ollama, BROWSER_SETTLE_MS="0")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(report["status"], "failed")
        self.assertTrue(report["errors"])

    def test_request_budget_produces_partial_report(self):
        app, _, _ = application()
        model, _ = fake_ollama()
        with serving(app) as base, serving(model) as ollama:
            result, report = self.run_cli(BASE_URL=base, OLLAMA_BASE_URL=ollama, MAX_REQUESTS="1", BROWSER_SETTLE_MS="0")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(report["status"], "partial")
        self.assertLessEqual(report["summary"]["requests_sent"], 1)


if __name__ == "__main__":
    unittest.main()
