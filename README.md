# SecurBuddy

Paste a suspicious log, email, or note. Get a verdict, the indicators of compromise,
live threat-intelligence lookups, a plain-English explanation of what happened, and
the exact copy-paste command to block the intruder.

Built for Hacktoberfest — FastAPI backend + React/Vite frontend, powered entirely by
free-tier public APIs and a free open-weight model.

---

## What it actually does

```
pasted text
   │
   ├─ 1. Signature detection (deterministic, offline, no API keys)
   │     11 signatures: SSH brute force, SQL injection, phishing, ransomware,
   │     BEC/whaling, cloud credential abuse, C2 beaconing, port scan,
   │     privilege escalation, data exfiltration, web shell
   │
   ├─ 2. IOC extraction — IPs, URLs, emails, domains, Bitcoin wallets
   │
   ├─ 3. Live reputation (enrichment, never the verdict)
   │     AbuseIPDB  → abuse confidence, ISP, geo, Tor flag
   │     VirusTotal → vendor verdict for URLs
   │
   ├─ 4. Plain-English explanation + severity
   │
   ├─ 5. Copy-paste remediation (ufw / iptables / nftables / netsh / pf / fail2ban / AWS CLI)
   │
   └─ 6. AI copilot — streaming chat grounded in the analysis above
```

### Why the verdict never comes from the AI

The LLM is used for *explanation* and *chat*, never for classification. Detection is
regex-based, which means the same input always produces the same verdict, it works
with no API keys and no network, it is instant, and it cannot hallucinate an indicator
of compromise. The model only receives the real, extracted IOCs as context, so it has
no room to invent one either.

### Reserved IP ranges are labelled, not scored

The golden dataset uses RFC 5737 documentation addresses (`198.51.100.x`,
`203.0.113.x`). These are not routable on the public internet, so threat feeds
legitimately have no data for them. The UI says so explicitly rather than showing a
misleading "0% abuse" score. Reserved and private ranges are called out separately
from "clean".

---

## Quick start

### 1. Backend

```bash
cd Backend
pip install -r requirements.txt
```

Create `Backend/.env`:

```env
GROQ_API_KEY=gsk_...
ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

All three are optional — the app runs without them and degrades gracefully, but you
lose live threat intel, the AI copilot, or both.

```bash
uvicorn main:app --reload --port 8000
```

API docs at <http://127.0.0.1:8000/docs>, health check at `/api/health`.

### 2. Frontend

```bash
cd Frontend
npm install
npm run dev
```

Open <http://localhost:5173>. Vite proxies `/api` to the backend, so there is no CORS
configuration to set up in development.

---

## Project layout

```
Backend/
  main.py          FastAPI app, routes, SSE chat streaming
  config.py        Settings loaded from .env, model + quota constants
  dataset.py       Golden dataset loading, lookup, similarity search
  detector.py      IOC extraction + the signature engine
  intel.py         AbuseIPDB + VirusTotal clients (graceful degradation)
  remediation.py   Copy-paste block commands per attack type
  requirements.txt
Frontend/
  src/
    App.jsx              Main workbench UI
    lib/api.js           Typed API client + SSE stream parser
    index.css            Tailwind entry
  vite.config.js   Dev/preview proxy to the backend
  package.json
golden_dataset.json  Labelled attack samples (the golden set)
```

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Liveness + which integrations are configured |
| `GET` | `/api/dataset` | List all labelled golden cases |
| `POST` | `/api/dataset/reload` | Re-read the dataset without restarting |
| `POST` | `/api/analyze` | Analyze pasted text or a `dataset_id` |
| `POST` | `/api/chat/stream` | Streaming copilot reply (SSE) |

`POST /api/analyze` takes either `raw_content`, a `dataset_id`, or both.

## The golden dataset

`golden_dataset.json` holds ten labelled cases spanning malicious logs, phishing,
ransomware, social engineering, cloud threats, plus deliberate edge cases — an empty
submission, irrelevant chatter, and a wall of repeated text for stress-testing.

It is used for two things: one-click loading in the UI, and similarity matching so the
AI copilot can be grounded in a known-good labelled example.

## Security notes

- `.env` is gitignored — never commit API keys.
- This tool is defensive: it analyses text you paste and hands you commands to
  **block** attackers. Do not use it to attack anything.
- Requests are capped at 20,000 characters and at 3 IPs / 2 URLs per analysis, to stay
  inside free-tier quotas and avoid token-limit blowups on the stress-test case.