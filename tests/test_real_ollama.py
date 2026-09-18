"""Opt-in end-to-end test against real local model weights, without protocol stubs."""
import json
import os
from pathlib import Path
import unittest

from scanner.agent import Agent
from scanner.config import Config
from scanner.safety import Redactor
from tests.fixtures import application, serving, USERNAME, PASSWORD
from tests.test_integration import validate_report


@unittest.skipUnless(os.getenv("RUN_REAL_OLLAMA") == "1", "Set RUN_REAL_OLLAMA=1 with a local model installed")
class RealOllamaTests(unittest.TestCase):
    def test_local_model_controls_browser_login_and_security_tools(self):
        app, _, _ = application(mode=os.getenv("REAL_APP_MODE", "spa"))
        with serving(app) as base:
            config = Config(base_url=base, username=USERNAME, password=PASSWORD,
                            ollama_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
                            model=os.getenv("OLLAMA_MODEL", "qwen2.5:7b"),
                            max_llm_calls=45, max_tokens=100_000, max_requests=400,
                            max_seconds=1500, llm_timeout=180, settle_ms=200)
            agent = Agent(config, Redactor(USERNAME, PASSWORD))
            try:
                agent.run()
                report = agent.report()
                validate_report(report)
                directory = Path(".runtime")
                directory.mkdir(exist_ok=True)
                (directory / "real-ollama-report.json").write_text(json.dumps(report, indent=2))
                self.assertEqual(report["status"], "completed", report["warnings"])
                self.assertEqual(report["authentication"]["status"], "verified")
                self.assertEqual({f["type"] for f in report["findings"]}, {"sensitive_data_exposure", "http_method_tampering"})
                self.assertGreater(report["ai"]["prompt_tokens"], 0)
            finally:
                agent.close()


if __name__ == "__main__":
    unittest.main()
