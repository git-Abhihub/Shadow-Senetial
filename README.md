# ShadowLens
AI Shadow IT & Agentic Data Exfiltration Scanner — hackathon MVP.

## Current capabilities
- Accepts JSON/JSONL audit events and analyzes them locally.
- Identifies known AI providers and local LLM endpoints from submitted events.\n- Offers an explicit, one-shot socket metadata snapshot (`POST /api/collector/socket-snapshot`) using `psutil`; this is T1 metadata only, not content inspection.
- Flags exposed API keys, JWTs, email addresses, and risky agent actions.
- Calculates severity and risk scores and shows findings in a dashboard.
- Optionally asks Featherless AI for a remediation summary using only sanitized findings.

> **Important limitation:** passive HTTPS packet capture normally reveals destination metadata, not encrypted prompt bodies. This MVP analyzes supplied audit/request logs and demo events; it does not silently intercept TLS or monitor the whole machine.

## Requirements
- Python 3.11+
- Node.js 18+

## Run on Windows
### Backend (terminal 1)
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```
API docs: http://127.0.0.1:8000/docs

### Frontend (terminal 2)
```powershell
cd frontend
npm install
npm run dev
```
Open the URL printed by Vite (usually http://localhost:5173).

## Spec-driven development\nThe implementation baseline and milestone gates are tracked in [`docs/SDD.md`](docs/SDD.md). This repository is a work in progress against the Unified Master Specification; not all P0 requirements are implemented yet.\n\n## Event format
Upload a JSON array, a single JSON object, or JSONL. Example:
```json
{
  "timestamp": "2026-10-30T12:00:00Z",
  "process": "python",
  "destination": "api.openai.com",
  "url": "https://api.openai.com/v1/chat/completions",
  "method": "POST",
  "content": "Please summarize this file. api_key=sk-EXAMPLE_NOT_REAL",
  "action": "outbound_request"
}
```
Only use authorized logs and test data. Never upload real secrets or personal data to a third-party model.
