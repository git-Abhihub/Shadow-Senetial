from __future__ import annotations

import hashlib
import logging
import socket
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

AI_PORTS = {11434: "ollama", 1234: "local_llm", 8080: "possible_local_llm", 8000: "possible_local_llm", 5000: "possible_local_llm", 7860: "possible_local_llm"}


def _hash_cmdline(cmdline: list[str] | None) -> str | None:
    if not cmdline:
        return None
    # Hash only; never return or persist the raw command line.
    return hashlib.sha256("\\0".join(cmdline).encode("utf-8", errors="replace")).hexdigest()


def _remote_host(ip: str) -> str | None:
    if not ip or ip in {"0.0.0.0", "::", "127.0.0.1", "::1"}:
        return ip or None
    try:
        return socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except (OSError, UnicodeError):
        return None


def collect_socket_snapshot() -> dict[str, Any]:
    """Collect one best-effort T1 snapshot. This function does not inspect payloads.

    Call only after an explicit user action. OS permissions may limit attribution;
    the collector reports partial visibility rather than failing the whole scan.
    """
    try:
        import psutil
    except ImportError as exc:  # pragma: no cover - exercised in deployment
        raise RuntimeError("Install psutil to enable socket metadata collection") from exc

    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    now = datetime.now(timezone.utc).isoformat()
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        return {
            "source": "socket",
            "tier": "T1",
            "timestamp": now,
            "events": [],
            "partial_visibility": True,
            "warnings": [f"Socket table unavailable: {type(exc).__name__}"],
        }

    warned_process = False
    for conn in connections:
        if not conn.raddr or not conn.laddr:
            continue
        remote_ip = str(getattr(conn.raddr, "ip", None) or conn.raddr[0])
        remote_port = int(getattr(conn.raddr, "port", None) or conn.raddr[1])
        local_port = int(getattr(conn.laddr, "port", None) or conn.laddr[1])
        process_name = "unknown"
        exe = None
        username = None
        cmdline_hash = None
        pid = conn.pid
        if pid:
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()[:120]
                exe = proc.exe()[:300] if proc.exe() else None
                username = proc.username()[:120] if proc.username() else None
                cmdline_hash = _hash_cmdline(proc.cmdline())
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                if not warned_process:
                    warnings.append("Some process metadata is unavailable due to OS permissions or process churn.")
                    warned_process = True

        host = _remote_host(remote_ip)
        provider_hint = AI_PORTS.get(remote_port)
        # Metadata only: encrypted content is never inferred to have been inspected.
        events.append({
            "event_id": hashlib.sha256(f"{now}|{pid}|{remote_ip}|{remote_port}".encode()).hexdigest()[:32],
            "timestamp": now,
            "source": "socket",
            "tier": "T1",
            "visibility": "OBSERVED",
            "process": process_name,
            "process_meta": {"pid": pid, "exe": exe, "user": username, "cmdline_hash": cmdline_hash},
            "destination": host or remote_ip,
            "destination_ip": remote_ip,
            "destination_port": remote_port,
            "local_port": local_port,
            "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp" if conn.type == socket.SOCK_DGRAM else "unknown",
            "connection_status": str(conn.status or "UNKNOWN"),
            "provider_hint": provider_hint,
            "content_inspected": False,
        })

    return {
        "source": "socket",
        "tier": "T1",
        "timestamp": now,
        "events": events,
        "partial_visibility": bool(warnings),
        "warnings": warnings,
        "note": "Socket metadata only; TLS-encrypted request bodies are not visible.",
    }
