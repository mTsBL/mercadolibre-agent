#!/usr/bin/env bash
# Online preparation only. run.sh never downloads dependencies or model weights.
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 -m venv "$PROJECT_DIR/.venv"
"$PROJECT_DIR/.venv/bin/python" -m pip install -r "$PROJECT_DIR/requirements.txt"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$PROJECT_DIR/.runtime/browsers}"
if [[ -z "${PLAYWRIGHT_HOST_PLATFORM_OVERRIDE:-}" && -r /etc/os-release ]]; then
    PROJECT_OS="$(
        . /etc/os-release
        printf '%s:%s' "$ID" "$VERSION_ID"
    )"
    if [[ "$PROJECT_OS" == "ubuntu:26.04" ]]; then
        # This fallback build is covered by the browser integration tests.
        export PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64
    fi
fi
"$PROJECT_DIR/.venv/bin/python" -m playwright install chromium
printf '%s\n' 'Python dependencies and Chromium installed.' 'Before scanning, install/start Ollama and run: ollama pull qwen2.5:7b'
