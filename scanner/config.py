from dataclasses import dataclass, field
import os
from pathlib import Path


def integer(name: str, default: int, minimum: int = 1, maximum: int = 100_000) -> int:
    value = int(os.getenv(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass
class Config:
    base_url: str
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)
    ollama_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5:7b"
    output: Path = field(default_factory=lambda: Path("findings.json"))
    max_requests: int = 1500  # Every endpoint is method-swept under each session; localhost requests are cheap.
    max_pages: int = 30
    max_endpoints: int = 80
    max_llm_calls: int = 30
    max_tokens: int = 60_000
    max_seconds: int = 900
    request_timeout: int = 12
    llm_timeout: int = 120
    max_body: int = 1_048_576
    settle_ms: int = 500

    @classmethod
    def from_env(cls):
        base = os.getenv("BASE_URL", "").strip()
        if not base:
            raise ValueError("BASE_URL is required, e.g. http://localhost:3000")
        username, password = os.getenv("CHALLENGE_USERNAME", ""), os.getenv("CHALLENGE_PASSWORD", "")
        if bool(username) != bool(password):
            raise ValueError("Provide both CHALLENGE_USERNAME and CHALLENGE_PASSWORD")
        return cls(
            base_url=base, username=username, password=password,
            ollama_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
            model=os.getenv("OLLAMA_MODEL", "qwen2.5:7b"),
            output=Path(os.getenv("OUTPUT_FILE", "findings.json")),
            max_requests=integer("MAX_REQUESTS", 1500), max_pages=integer("MAX_PAGES", 30),
            max_endpoints=integer("MAX_ENDPOINTS", 80), max_llm_calls=integer("MAX_LLM_CALLS", 30),
            max_tokens=integer("MAX_LLM_TOKENS", 60_000, maximum=1_000_000),
            max_seconds=integer("MAX_SECONDS", 900, maximum=86_400),
            request_timeout=integer("REQUEST_TIMEOUT", 12, maximum=120),
            llm_timeout=integer("OLLAMA_TIMEOUT", 120, maximum=600),
            max_body=integer("MAX_BODY_BYTES", 1_048_576, minimum=1024, maximum=8_388_608),
            settle_ms=integer("BROWSER_SETTLE_MS", 500, minimum=0, maximum=10_000),
        )
