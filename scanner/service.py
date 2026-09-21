"""Start a local Ollama service when needed and clean up only the owned process."""

import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

from . import ui
from .config import integer
from .safety import Scope
from .transport import Budget, Transport


class OllamaService:
    def __init__(self, config):
        self.config = config
        self.process = None
        self.log = None

    def ensure_ready(self):
        scope = Scope(self.config.ollama_url)
        timeout = min(integer("OLLAMA_START_TIMEOUT", 30, maximum=300), self.config.max_seconds)
        transport = Transport(scope, Budget(1000, timeout + 5), timeout=1, max_body=131_072)

        def ready():
            try:
                response = transport.request("GET", scope.origin + "/api/tags")
            except OSError:
                return False
            try:
                valid = response.status == 200 and not response.truncated and isinstance(json.loads(response.text).get("models"), list)
            except (ValueError, AttributeError):
                valid = False
            if not valid:
                raise RuntimeError("OLLAMA_BASE_URL responds, but does not provide a valid Ollama model list")
            return True

        if ready():
            ui.step("Modelo local (Ollama) já disponível.")
            return
        if urlsplit(scope.base).scheme != "http" or not all(ipaddress.ip_address(ip).is_loopback for ip in scope.addresses):
            raise RuntimeError("Ollama is unavailable; automatic startup requires a loopback HTTP OLLAMA_BASE_URL")
        root = Path(__file__).resolve().parents[1]
        portable = root / ".runtime" / "ollama" / "bin" / "ollama"
        configured = os.getenv("OLLAMA_BIN")
        executable = shutil.which(configured) if configured else shutil.which("ollama")
        if not configured and not executable and portable.is_file():
            executable = str(portable)
        if not executable:
            raise RuntimeError("Ollama executable not found. Install Ollama before running run.sh (or set OLLAMA_BIN).")
        env = dict(os.environ)
        address = scope.addresses[0]
        env["OLLAMA_HOST"] = f"[{address}]:{scope.port}" if ":" in address else f"{address}:{scope.port}"
        env["OLLAMA_NO_CLOUD"] = "1"
        # The daemon does not need target credentials or application configuration.
        for key in ("BASE_URL", "CHALLENGE_USERNAME", "CHALLENGE_PASSWORD"):
            env.pop(key, None)
        if Path(executable).resolve() == portable.resolve():
            env.setdefault("OLLAMA_MODELS", str(root / ".runtime" / "models"))
        self.log = tempfile.TemporaryFile()
        ui.step("Iniciando o modelo local (Ollama) e aguardando ficar pronto…")
        self.process = subprocess.Popen([executable, "serve"], env=env, stdin=subprocess.DEVNULL,
                                        stdout=self.log, stderr=self.log, start_new_session=True)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"Ollama exited during startup (exit code {self.process.returncode})")
            if ready():
                return
            time.sleep(0.1)
        raise RuntimeError(f"Ollama did not become ready within {timeout} seconds")

    def close(self):
        try:
            if self.process is not None and self.process.poll() is None:
                # A separate process group contains the owned daemon and its model workers.
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.process.wait(timeout=5)
        finally:
            if self.log:
                self.log.close()
