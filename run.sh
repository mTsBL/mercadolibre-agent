#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$PROJECT_DIR${PYTHONPATH:+:$PYTHONPATH}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$PROJECT_DIR/.runtime/browsers}"
# This entrypoint starts Ollama if needed, waits for readiness and owns its cleanup.
if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    exec "$PROJECT_DIR/.venv/bin/python" -m scanner --manage-ollama "$@"
fi
# The stdlib entrypoint writes a failure report if dependencies have not been installed.
exec python3 -m scanner --manage-ollama "$@"
