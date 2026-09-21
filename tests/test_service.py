"""Exercise the actual run.sh lifecycle with a disposable Ollama executable."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from tests.fixtures import QuietHandler, fake_ollama, serving
from tests.test_integration import ROOT, validate_report


class EmptyApp(QuietHandler):
    def do_GET(self):
        self.send(body='{"status":"healthy"}', content_type="application/json")


class ServiceTests(unittest.TestCase):
    def environment(self, directory, behavior="ready"):
        executable = Path(directory) / "ollama"
        marker = Path(directory) / "started.json"
        executable.write_text(f'''#!{sys.executable}
import json, os, time
from pathlib import Path
from http.server import ThreadingHTTPServer
from tests.fixtures import fake_ollama
assert os.sys.argv[1:] == ['serve']
Path({str(marker)!r}).write_text(json.dumps({{'pid': os.getpid(), 'cloud': os.environ.get('OLLAMA_NO_CLOUD'), 'credentials_inherited': 'CHALLENGE_PASSWORD' in os.environ, 'host': os.environ['OLLAMA_HOST']}}))
behavior = {behavior!r}
if behavior == 'exit':
    raise SystemExit(7)
time.sleep(30 if behavior == 'hang' else 0.3)
host, port = os.environ['OLLAMA_HOST'].rsplit(':', 1)
ThreadingHTTPServer((host, int(port)), fake_ollama()[0]).serve_forever()
''')
        executable.chmod(0o755)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        env = {k: v for k, v in os.environ.items() if k not in (
            "BASE_URL", "CHALLENGE_USERNAME", "CHALLENGE_PASSWORD", "OUTPUT_FILE", "OLLAMA_BASE_URL")}
        env.update(OLLAMA_BIN=str(executable), OLLAMA_BASE_URL=f"http://127.0.0.1:{port}",
                   OLLAMA_START_TIMEOUT="2", BROWSER_SETTLE_MS="0", CHALLENGE_USERNAME="fixture-user",
                   CHALLENGE_PASSWORD="fixture-password")
        return env, marker

    def assert_stopped(self, marker):
        data = json.loads(marker.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(data["pid"], 0)
        self.assertEqual(data["cloud"], "1")
        self.assertFalse(data["credentials_inherited"])

    def execute(self, directory, env):
        with serving(EmptyApp) as base:
            env["BASE_URL"] = base
            result = subprocess.run([str(ROOT / "run.sh")], cwd=directory, env=env,
                                    capture_output=True, text=True, timeout=20)
        report = json.loads((Path(directory) / "findings.json").read_text())
        validate_report(report)
        return result, report

    def test_single_command_starts_waits_scans_and_stops(self):
        with tempfile.TemporaryDirectory() as directory:
            env, marker = self.environment(directory)
            result, report = self.execute(directory, env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report, {"findings": []})
            self.assertIn("Scan concluído", result.stderr)
            self.assert_stopped(marker)

    def test_existing_server_is_reused_and_left_running(self):
        with tempfile.TemporaryDirectory() as directory:
            env, marker = self.environment(directory)
            model, _ = fake_ollama()
            with serving(model) as existing:
                env["OLLAMA_BASE_URL"] = existing
                result, report = self.execute(directory, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(marker.exists())
                from scanner.safety import Scope
                from scanner.transport import Transport, Budget
                self.assertEqual(Transport(Scope(existing), Budget(1, 5)).request("GET", existing + "/api/tags").status, 200)

    def test_startup_failure_preserves_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            env, marker = self.environment(directory, "exit")
            result, report = self.execute(directory, env)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(report, {"findings": []})
            self.assertIn("exit code 7", result.stderr)
            self.assert_stopped(marker)

    def test_startup_timeout_stops_child_and_preserves_report(self):
        with tempfile.TemporaryDirectory() as directory:
            env, marker = self.environment(directory, "hang")
            env["OLLAMA_START_TIMEOUT"] = "1"
            result, report = self.execute(directory, env)
            self.assertEqual(result.returncode, 1)
            self.assertIn("did not become ready", result.stderr)
            self.assert_stopped(marker)

    def test_interruption_stops_owned_server(self):
        with tempfile.TemporaryDirectory() as directory, serving(EmptyApp) as base:
            env, marker = self.environment(directory, "hang")
            env.update(BASE_URL=base, OLLAMA_START_TIMEOUT="30")
            process = subprocess.Popen([str(ROOT / "run.sh")], cwd=directory, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(marker.exists())
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=10)
                self.assertEqual(process.returncode, 130)
                report = json.loads((Path(directory) / "findings.json").read_text())
                validate_report(report)
                self.assertEqual(report, {"findings": []})
                self.assert_stopped(marker)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_invalid_target_does_not_start_service(self):
        with tempfile.TemporaryDirectory() as directory:
            env, marker = self.environment(directory)
            env["BASE_URL"] = "http://8.8.8.8"
            result = subprocess.run([str(ROOT / "run.sh")], cwd=directory, env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(marker.exists())
