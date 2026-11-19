import os
from dataclasses import dataclass, field


def _csv(name: str) -> list[str]:
    return [x.strip() for x in os.getenv(name, "").split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    # Any Gemini Flash model id works here, e.g. gemini-2.5-flash
    gemini_model: str = field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
    # Hard cap on characters sent to the model (logs + events + pod status)
    max_context_chars: int = field(default_factory=lambda: int(os.getenv("MAX_CONTEXT_CHARS", "60000")))
    # Empty list = all namespaces allowed. Otherwise only these.
    allowed_namespaces: list[str] = field(default_factory=lambda: _csv("ALLOWED_NAMESPACES"))
    # Returns a canned report without calling Gemini (UI demos / local dev)
    demo_mode: bool = field(default_factory=lambda: os.getenv("DEMO_MODE", "false").lower() == "true")
    cors_origins: list[str] = field(default_factory=lambda: _csv("CORS_ORIGINS"))


def get_settings() -> Settings:
    return Settings()
