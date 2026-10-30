from urllib.parse import urlparse

# Match hostnames, not arbitrary substrings, to reduce lookalike-domain false positives.
PROVIDERS = {
    "openai": {"openai.com"},
    "anthropic": {"anthropic.com"},
    "huggingface": {"huggingface.co", "hf.co"},
    "google_gemini": {"generativelanguage.googleapis.com", "aiplatform.googleapis.com"},
    "mistral": {"mistral.ai"},
    "cohere": {"cohere.com"},
    "groq": {"groq.com"},
    "perplexity": {"perplexity.ai"},
    "xai": {"x.ai"},
    "deepseek": {"deepseek.com"},
}

def _host(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else "//" + value)
    return (parsed.hostname or "").lower().rstrip(".")

def identify_provider(event: dict) -> str:
    for key in ("destination", "host", "url", "endpoint"):
        value = str(event.get(key, ""))
        host = _host(value)
        if not host:
            continue
        if host in {"localhost", "127.0.0.1", "::1"}:
            port = urlparse(value if "://" in value else "//" + value).port
            if port == 11434:
                return "ollama"
            if port == 1234:
                return "local_llm"
        for provider, domains in PROVIDERS.items():
            if any(host == domain or host.endswith("." + domain) for domain in domains):
                return provider
        # Explicit common local model servers.
        port = urlparse(value if "://" in value else "//" + value).port
        if port == 11434:
            return "ollama"
        if port == 1234 and host in {"localhost", "127.0.0.1", "::1"}:
            return "local_llm"
    return "unknown"
