from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .detector import analyze_event
from .agent_audit import analyze_agent_event
from .featherless import explain_findings

app = FastAPI(title="ShadowSentinel AI", version="0.1.0", description="Privacy-conscious AI Shadow IT and agent audit MVP")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DB_FILE = DATA_DIR / "analyses.json"

def load_records() -> list[dict]:
    if not DB_FILE.exists():
        return []
    try:
        return json.loads(DB_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

def save_records(records: list[dict]) -> None:
    DB_FILE.write_text(json.dumps(records[-500:], indent=2), encoding="utf-8")

def persist(results: list[dict]) -> None:
    records = load_records()
    records.extend(results)
    save_records(records)

class EventRequest(BaseModel):
    event: dict[str, Any]

@app.get("/")
def root():
    return {"name": "ShadowSentinel AI", "status": "running", "docs": "/docs"}

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ShadowSentinel AI"}

@app.get("/api/analyses")
def analyses(limit: int = 100):
    return list(reversed(load_records()))[:max(1, min(limit, 500))]

@app.get("/api/summary")
def summary():
    records = load_records()
    return {
        "total_events": len(records),
        "flagged_events": sum(1 for r in records if r.get("finding_count", 0) > 0),
        "critical_events": sum(1 for r in records if r.get("risk_level") == "critical"),
        "providers": len(set(r.get("provider") for r in records if r.get("provider") not in (None, "unknown"))),
        "average_risk": round(sum(r.get("risk_score", 0) for r in records) / len(records), 1) if records else 0,
    }

@app.post("/api/analyze")
def analyze(request: EventRequest):
    result = analyze_event(request.event)
    persist([result])
    return result

@app.post("/api/agent-audit")
def agent_audit(request: EventRequest):
    result = analyze_agent_event(request.event)
    persist([result])
    return result

@app.post("/api/upload-json")
async def upload_json(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith((".json", ".jsonl", ".ndjson")):
        raise HTTPException(status_code=400, detail="Upload a .json, .jsonl, or .ndjson file")
    raw = await file.read()
    if len(raw) > 2_000_000:
        raise HTTPException(status_code=413, detail="File too large (maximum 2 MB)")
    try:
        text = raw.decode("utf-8")
        try:
            parsed = json.loads(text)
            events = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            events = [json.loads(line) for line in text.splitlines() if line.strip()]
        if not all(isinstance(e, dict) for e in events):
            raise ValueError("Every event must be a JSON object")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid event file: {exc}")
    results = [analyze_event(event) for event in events[:1000]]
    persist(results)
    return {"uploaded": len(results), "results": results}

@app.post("/api/investigate")
async def investigate():
    records = load_records()
    findings = [f for r in records for f in r.get("findings", [])]
    return await explain_findings(findings)

@app.post("/api/demo")
def demo():
    sample_path = Path(__file__).resolve().parent.parent / "samples" / "demo_events.json"
    events = json.loads(sample_path.read_text(encoding="utf-8"))
    results = [analyze_event(event) for event in events]
    persist(results)
    return {"loaded": len(results), "results": results}
