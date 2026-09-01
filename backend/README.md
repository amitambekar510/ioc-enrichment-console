# Backend Flask Server (IOC Enrichment Console)

## Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate    # Mac/Linux
# venv\Scripts\activate     # Windows
pip install -r requirements.txt
python app.py
```

Server runs on `http://127.0.0.1:5000`.

## Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/api/keys` | Get saved API keys |
| POST | `/api/keys` | Save API keys |
| GET | `/api/time` | Get server time (IST) |
| POST | `/api/check-ip` | Check if an IP is private/reserved |
| POST | `/api/analyze` | Batch analyze IOCs (blocks until done) |
| POST | `/api/analyze/stream` | **SSE** — stream per-IOC results in real-time |
| POST | `/api/reports` | Rebuild CSV/text/STIX from existing results |
| GET | `/api/download/<filename>` | Download a generated report |

## SSE Stream Events

The `/api/analyze/stream` endpoint sends Server-Sent Events:

- `start` — scan begins, includes total count and warnings
- `progress` — before each IOC is queried, includes index/total
- `result` — after each IOC completes, includes the full finding dict
- `complete` — all IOCs done, includes download filenames and summary

## Files

```
app.py            Flask backend (REST + SSE endpoints)
core.py           Enrichment logic (VT/AbuseIPDB/geo calls, verdicts, reports)
config.json       Saved API keys (created on first save — don't commit)
requirements.txt  pip dependencies
static/index.html Original Flask UI (kept for backward compat)
output/           Generated CSV / text / STIX reports
```
