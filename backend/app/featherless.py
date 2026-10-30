import os
import httpx
from dotenv import load_dotenv

load_dotenv()

async def explain_findings(findings: list[dict]) -> dict:
    api_key = os.getenv("FEATHERLESS_API_KEY", "").strip()
    if not api_key:
        return {"available": False, "message": "Featherless is not configured. Add FEATHERLESS_API_KEY to backend/.env."}
    base = os.getenv("FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1").rstrip("/")
    model = os.getenv("FEATHERLESS_MODEL", "Qwen/Qwen2.5-7B-Instruct")
    # Only sanitized labels/severities/evidence are sent. Never send raw prompts or detected secret values.
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are an enterprise security analyst. Give concise remediation advice. Do not claim certainty beyond the evidence."},
            {"role": "user", "content": "Review these sanitized security findings and suggest next steps: " + str(findings[:30])},
        ],
        "temperature": 0.2,
        "max_tokens": 500,
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(base + "/chat/completions", headers={"Authorization": f"Bearer {api_key}"}, json=payload)
            response.raise_for_status()
            data = response.json()
        return {"available": True, "model": model, "summary": data["choices"][0]["message"]["content"]}
    except Exception as exc:
        return {"available": False, "message": f"Featherless request failed: {type(exc).__name__}"}
