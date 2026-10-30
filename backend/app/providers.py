from urllib.parse import urlparse

PROVIDERS = {
    "openai": ("openai.com", "api.openai.com"),
    "anthropic": ("anthropic.com", "api.anthropic.com"),
    "huggingface": ("huggingface.co", "api-inference.huggingface.co"),
    "ollama": ("localhost:11434", "127.0.0.1:11434"),
    "google_gemini": ("generativelanguage.googleapis.com",),
    "mistral": ("mistral.ai", "api.mistral.ai"),
    "cohere": ("cohere.com", "api.cohere.ai"),
}

def identify_provider(event: dict) -> str:
    candidates = [str(event.get(k, "")) for k in ("destination", "host", "url", "endpoint")]
    text = " ".join(candidates).lower()
    for provider, markers in PROVIDERS.items():
        if any(marker in text for marker in markers):
            return provider
    # Detect common local LLM ports from URL/host fields.
    if ":11434" in text or "ollama" in text:
        return "ollama"
    if ":1234" in text and ("localhost" in text or "127.0.0.1" in text):
        return "local_llm"
    return "unknown"
