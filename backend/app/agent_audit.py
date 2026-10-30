from .detector import analyze_event

def analyze_agent_event(event: dict) -> dict:
    normalized = dict(event)
    normalized.setdefault("action", "agent_event")
    result = analyze_event(normalized)
    result["event_type"] = "agent_audit"
    return result
