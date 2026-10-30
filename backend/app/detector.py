import re
import math
from collections import Counter
from .providers import identify_provider

PATTERNS = [
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "critical"),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "high"),
    ("Email address / possible PII", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "medium"),
    ("Private key marker", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical"),
]
SEVERITY_POINTS = {"low": 10, "medium": 30, "high": 60, "critical": 90}

def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())

def analyze_event(event: dict) -> dict:
    provider = identify_provider(event)
    content = " ".join(str(event.get(k, "")) for k in ("content", "body", "prompt", "command", "file_path"))
    findings = []
    for label, pattern, severity in PATTERNS:
        if pattern.search(content):
            findings.append({"type": label, "severity": severity, "evidence": "Matching sensitive-data pattern detected; raw value withheld."})
    if re.search(r"\b(?:cat|type|Get-Content)\b.*(?:\.env|id_rsa|credentials|secrets)", content, re.I):
        findings.append({"type": "Agent reading sensitive file", "severity": "high", "evidence": "Command appears to read a sensitive file."})
    if re.search(r"\b(?:curl|wget|Invoke-WebRequest)\b.*\|\s*(?:sh|bash|powershell)", content, re.I):
        findings.append({"type": "Risky shell pipeline", "severity": "high", "evidence": "Download-and-execute pattern detected."})
    if provider != "unknown":
        findings.append({"type": "AI provider traffic", "severity": "low", "evidence": f"Destination matched provider: {provider}."})
    if event.get("action") in ("file_read", "shell_command", "credential_access"):
        findings.append({"type": "Agent activity", "severity": "medium", "evidence": f"Recorded action: {event.get('action')}."})
    score = min(100, max((SEVERITY_POINTS[f["severity"]] for f in findings), default=0) + max(0, len(findings)-1)*5)
    risk = "critical" if score >= 90 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    # Keep only event metadata and sanitized findings in the response; never echo content.
    return {
        "timestamp": event.get("timestamp", ""),
        "process": str(event.get("process", "unknown"))[:120],
        "destination": str(event.get("destination") or event.get("host") or event.get("url") or "unknown")[:240],
        "provider": provider,
        "action": str(event.get("action", "outbound_request"))[:80],
        "risk_score": score,
        "risk_level": risk,
        "findings": findings,
        "finding_count": len(findings),
    }
