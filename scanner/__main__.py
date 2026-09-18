import json
import os
from pathlib import Path
import signal
import sys
import tempfile

from .agent import Agent
from .config import Config
from .safety import Redactor
from .safety import Scope
from .service import OllamaService
from .transport import BudgetExceeded


def write_report(path, report):
    path = Path(path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".findings-", delete=False) as f:
            temporary = f.name
            os.chmod(temporary, 0o600)
            json.dump(report, f, ensure_ascii=False, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main():
    redactor = Redactor(os.getenv("CHALLENGE_USERNAME", ""), os.getenv("CHALLENGE_PASSWORD", ""))
    agent = None
    service = None
    output = Path(os.getenv("OUTPUT_FILE", "findings.json"))
    exit_code = 1

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        config = Config.from_env()
        agent = Agent(config, redactor)
        if "--manage-ollama" in sys.argv[1:]:
            Scope(config.base_url)  # Reject invalid/external targets before starting a process.
            service = OllamaService(config)
            service.ensure_ready()
        print("Starting local agent; results will be written to findings.json.", file=sys.stderr)
        agent.run()
        exit_code = 0 if agent.status == "completed" else 2
    except BudgetExceeded as exc:
        if agent:
            agent.status = "partial"
            agent.warnings.append(str(exc))
        exit_code = 2
    except KeyboardInterrupt:
        if agent:
            agent.status = "partial"
            agent.warnings.append("Scan interrupted")
        exit_code = 130
    except Exception as exc:
        message = redactor.text(f"{type(exc).__name__}: {exc}")
        print(message, file=sys.stderr)
        if agent:
            agent.status = "failed"
            agent.errors.append(message)
        else:
            # Configuration failures still get a structurally valid report.
            config = Config(base_url=os.getenv("BASE_URL", "http://localhost/"), output=output)
            agent = Agent(config, redactor)
            agent.errors.append(message)
    finally:
        if agent:
            try:
                agent.close()
            except Exception:
                agent.warnings.append("Browser cleanup failed")
            if service:
                try:
                    service.close()
                except Exception:
                    agent.warnings.append("Owned Ollama service cleanup failed")
            report = agent.report()
            try:
                write_report(output, report)
                print(f"Scan {report['status']}: {len(report['findings'])} finding(s).", file=sys.stderr)
            except OSError as exc:
                print(f"Cannot write report: {redactor.text(str(exc))}", file=sys.stderr)
                exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
