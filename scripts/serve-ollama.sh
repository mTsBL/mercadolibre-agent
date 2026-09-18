#!/usr/bin/env bash
# Start a foreground, local-only Ollama service. No downloads or system installation.
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
export OLLAMA_NO_CLOUD=1
if command -v ollama >/dev/null 2>&1; then
    exec ollama serve
elif [[ -x "$PROJECT_DIR/.runtime/ollama/bin/ollama" ]]; then
    export OLLAMA_MODELS="${OLLAMA_MODELS:-$PROJECT_DIR/.runtime/models}"
    exec "$PROJECT_DIR/.runtime/ollama/bin/ollama" serve
else
    printf '%s\n' 'Ollama is not installed. Install it and prepare a local model as described in README.md.' >&2
    exit 1
fi
