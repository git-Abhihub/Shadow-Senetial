import math
import re
from collections import Counter

from .providers import identify_provider

# Patterns intentionally detect formats, not validate whether a credential is live.
PATTERNS = [
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "critical"),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "high"),
    ("Email address / possible PII", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "medium"),
    ("Private key marker", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "critical"),
]
SEVERITY_POINTS = {"low": 10, "medium": 30, "high": 60, "critical": 90}
SENSITIVE_FILE_RE = re.compile(r"(?:\.env(?:\.[\w-]+)?|id_rsa|id_ed25519|credentials(?:\.json)?|secrets?\.(?:json|ya?ml)|\.aws[/\\]credentials)", re.I)
READ_COMMAND_RE = re.compile(r"\b(?:cat|type|Get-Content|more|less|head|tail|\bmore\b)\b", re.I)
EXFIL_COMMAND_RE = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n|]*\|\s*(?:sh|bash|powershell)\b", re.I)

def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())

def _content_for_scan(event: dict) -> str:
    # Scan only fields that may contain request text or agent commands.
    keys = ("content", "body", "prompt", "command", "file_path", "arguments")
    return " ".join(str(event.get(k, ""))[:100_000] for k in keys if event.get(k) is not None)

def analyze_event(event: dict) -> dict:
    if not isinstance(event, dict):
        event = {}
    provider = identify_provider(event)
    content = _content_for_scan(event)
    findings = []
    for label, pattern, severity in PATTERNS:
        if pattern.search(content):
            findings.append({"type": label, "severity": severity, "evidence": "Credential/PII pattern matched; raw value withheld."})

    if READ_COMMAND_RE.search(content) and SENSITIVE_FILE_RE.search(content):
        findings.append({"type": "Agent reading sensitive file", "severity": "high", "evidence": "Command and path match a sensitive-file access pattern."})
    if EXFIL_COMMAND_RE.search(content):
        findings.append({"type": "Risky shell pipeline", "severity": "high", "evidence": "Download-and-execute shell pattern detected."})

    action = str(event.get("action", "")).lower()
    if action in {"file_read", "shell_command", "credential_access", "process_spawn", "network_send"}:
        severity = "high" if action in {"credential_access", "network_send"} else "medium"
        findings.append({"type": "Agent activity", "severity": severity, "evidence": f"Recorded action category: {action}."})

    if provider != "unknown":
        findings.append({"type": "AI provider traffic", "severity": "low", "evidence": f"Destination matched provider: {provider}."})

    # Entropy is a supporting signal only; never flag arbitrary high-entropy text alone.
    candidates = re.findall(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{28,}(?![A-Za-z0-9])", content)
    if any(len(token) >= 32 and _entropy(token) >= 4.2 for token in candidates):
        if not any(f["severity"] == "critical" for f in findings):
            findings.append({"type": "Possible high-entropy token", "severity": "medium", "evidence": "Long high-entropy string found; manual review needed."})

    score = min(100, max((SEVERITY_POINTS[f["severity"]] for f in findings), default=0) + max(0, len(findings) - 1) * 5)
    risk = "critical" if score >= 90 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    return {
        "timestamp": str(event.get("timestamp", ""))[:80],
        "process": str(event.get("process", "unknown"))[:120],
        "destination": str(event.get("destination") or event.get("host") or event.get("url") or "unknown")[:240],
        "provider": provider,
        "action": str(event.get("action", "outbound_request"))[:80],
        "risk_score": score,
        "risk_level": risk,
        "findings": findings,
        "finding_count": len(findings),
    }
