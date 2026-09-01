# 🛡️ IOC Enrichment Console

<p align="center">
  <strong>Real-time threat intelligence enrichment console for SOC analysts</strong>
</p>

<p align="center">
  VirusTotal · AbuseIPDB · ipgeolocation.io · STIX 2.1 · Real-time maps · Interactive visualizations
</p>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Live Demo](#live-demo)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [Author](#author)
- [License](#license)

---

## 🎯 Overview

The **IOC Enrichment Console** is a full-stack threat intelligence tool designed for SOC analysts, incident responders, and IT security teams. It allows you to bulk-enrich Indicators of Compromise (IP addresses, domains, SHA256 file hashes) against multiple threat intelligence APIs — **VirusTotal**, **AbuseIPDB**, and **ipgeolocation.io** — and presents the results through an interactive, visually rich dashboard with real-time scan progress, geographic threat maps, and exportable reports.

Built with **Next.js 15 (App Router)** + **Flask**, the console streams per-IOC results via Server-Sent Events (SSE) so you see each IOC complete in real-time as the scan progresses — no more staring at a loading spinner while 50 IOCs are being queried.

### Who is this for?

- **SOC Analysts** — triage IOCs faster with visual verdicts, confidence scores, and one-click STIX export
- **Incident Responders** — identify malicious infrastructure quickly with geo-mapped threat visualization
- **IT Security Teams** — bulk-check IPs before blocking, with private-IP detection built in
- **Security Students** — learn how threat intel APIs work together with a real, production-quality tool

---

## ✨ Features

### Core Enrichment
- **3 scan modes**: Combined (VT + AbuseIPDB), VirusTotal only, AbuseIPDB only
- **3 IOC types**: IPv4 addresses, domains, SHA256 file hashes
- **Real-time SSE streaming** — watch each IOC complete live as it's scanned
- **Private/reserved IP detection** — RFC 1918, loopback, link-local, CGNAT, TEST-NET, multicast, Class E — with clear rejection messages explaining *why* the IP can't be scanned
- **Automatic verdicts**: malicious / suspicious / benign / unknown — based on VT vendor detections and AbuseIPDB confidence scores
- **Retry failed only** — re-scan just the IOCs that failed (rate-limited, auth errors) without re-running the entire batch
- **Hot-swap API keys** — paste a new key in Settings, save, and hit Retry — the backend picks up the new key instantly, no restart needed

### Visualizations (after scan completes)
- **Post-scan progress bar** — stacked verdict distribution with threat-level badge (LOW / MODERATE / HIGH)
- **Malicious vs Non-Malicious donut chart** — quick at-a-glance threat ratio
- **Verdict breakdown bar chart** — malicious / suspicious / benign / unknown counts
- **Interactive threat geographic map** — real OpenStreetMap tiles with colored dots for each IOC, pulsing rings for malicious IPs, click for popup details
- **Choropleth map** — countries shaded by threat intensity (Benign → Critical) using real GeoJSON country boundaries
- **Confidence score scatter chart** — per-IOC confidence with 75-threshold line
- **Security vendor word cloud** — VT flagging vendors sized by frequency, spiral-laid-out

### Export
- **CSV** — client-side generation with selectable columns (pick exactly which fields to include)
- **JSON** — structured export with the same column selection
- **STIX 2.1 bundle** — importable into SIEM/MISP (generated on the backend)
- **Text report** — human-readable summary report

### UX
- **Live IST clock** in the ops header (ticks every second)
- **Radar animation** during active scanning with terminal-style live log
- **Per-IOC status pills** — watch each IOC transition from "querying" to its verdict
- **API key status dots** — green dots in header show which keys are configured
- **Fully responsive** — works on mobile, tablet, and desktop
- **Dark SOC theme** — professional dark UI designed for security operations centers

---

## 🏗️ Architecture

```
┌─────────────────┐     SSE Stream      ┌──────────────────┐
│                 │  ◄──────────────────│                  │
│   Next.js 15    │     /api/*          │   Flask Backend   │
│   Frontend      │  ──────────────────►│   (Python)       │
│                 │                     │                  │
│  • React 19     │  ┌───────────────┐  │  • core.py       │
│  • App Router   │  │  Direct fetch │  │  • app.py        │
│  • TypeScript   │  │  to :5000     │  │  • config.json   │
│  • Leaflet maps │  └───────────────┘  │                  │
│  • CSS variables│                     │  External APIs:  │
│                 │                     │  • VirusTotal    │
└─────────────────┘                     │  • AbuseIPDB     │
                                        │  • ipgeolocation │
                                        │  • ip-api.com    │
                                        └──────────────────┘
```

**Frontend** (Next.js 15, React 19, TypeScript) runs on `:3000` and calls the Flask backend directly at `:5000`. Leaflet maps are loaded from CDN at runtime (no npm dependency).

**Backend** (Flask, Python) runs on `:5000` and handles all API calls to VirusTotal, AbuseIPDB, and geolocation services. API keys are stored in `config.json` on the server.

---

## 🔧 Prerequisites

- **Python 3.9+** (macOS has this via Xcode Command Line Tools)
- **Node.js 18+** (download LTS from [nodejs.org](https://nodejs.org))
- **API Keys** (free tiers available):
  - [VirusTotal API key](https://www.virustotal.com/gui/my-apikey) — required for Combined / VT-only modes
  - [AbuseIPDB API key](https://www.abuseipdb.com/account/api) — required for Combined / AbuseIPDB-only modes
  - [ipgeolocation.io key](https://ipgeolocation.io/) — optional, adds city/country + lat/lon for map

---

## 🚀 Installation

### One-command setup (recommended)

```bash
git clone https://github.com/amitambekar510/ioc-enrichment-console.git
cd ioc-enrichment-console
chmod +x start.sh
./start.sh
```

The `start.sh` script will:
1. Kill any stale processes on ports 5000 and 3000
2. Create a Python virtual environment and install Flask dependencies
3. Start the Flask backend on `http://127.0.0.1:5000`
4. Wait for Flask to be ready
5. Install npm dependencies (first run only)
6. Start the Next.js frontend on `http://localhost:3000`

Open **http://localhost:3000** in your browser. Press `Ctrl+C` to stop both servers.

### Manual setup (two terminals)

**Terminal 1 — Backend:**
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm install
npm run dev
```

---

## 📖 Usage

### 1. Configure API Keys
Click **Settings** in the header and paste your VirusTotal and AbuseIPDB API keys. The optional ipgeolocation.io key adds city/country data for the maps. Click **Save keys** — they're stored in `backend/config.json` on the server.

### 2. Paste IOCs
Enter one IOC per line in the textarea:
```
203.55.131.4
example.com
44d88612fea8a8f36de82e1278abb02f
```

### 3. Pick a Mode
- **Combined** — VirusTotal + AbuseIPDB (best coverage)
- **VirusTotal only** — IP / domain / hash
- **AbuseIPDB only** — IP only (includes free geo via ip-api.com)

### 4. Run Enrichment
Click **Run enrichment**. Watch the radar animation and live terminal log as each IOC is queried in real-time.

### 5. Review Results
After the scan completes, scroll down to see:
- Stacked progress bar with threat-level badge
- Malicious vs Non-Malicious donut chart
- Verdict breakdown bar chart
- Interactive threat map with pulsing dots
- Choropleth map with country threat intensity
- Confidence score scatter chart
- Security vendor word cloud

### 6. Export
- **CSV / JSON** — select columns via checkboxes, then download
- **STIX 2.1** — for SIEM/MISP import (links in the results table)
- **Text report** — human-readable summary

### 7. Retry Failed IOCs
If some IOCs failed due to rate limits or auth errors, the **Retry failed only** button appears. Update your API key in Settings if needed, save, then click Retry — the backend picks up the new key automatically.

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/keys` | Get saved API keys |
| `POST` | `/api/keys` | Save API keys to `config.json` |
| `GET` | `/api/time` | Get server time (IST) |
| `POST` | `/api/check-ip` | Check if an IP is private/reserved |
| `POST` | `/api/analyze` | Batch analyze IOCs (blocks until done) |
| `POST` | `/api/analyze/stream` | **SSE** — stream per-IOC results in real-time |
| `POST` | `/api/reports` | Rebuild CSV/text/STIX from existing results |
| `GET` | `/api/download/<filename>` | Download a generated report |

### SSE Event Types (`/api/analyze/stream`)

| Event | Payload | Description |
|-------|---------|-------------|
| `start` | `{ total, warnings, mode, generated_at }` | Scan begins |
| `progress` | `{ index, total, ioc, ioc_type, status }` | Before each IOC is queried |
| `result` | `{ index, total, finding }` | After each IOC completes |
| `complete` | `{ downloads, summary, total, generated_at }` | All done, reports generated |

---

## 📁 Project Structure

```
ioc-enrichment-console/
├── start.sh                       # One-command startup script
├── README.md
│
├── backend/                       # Flask backend (Python)
│   ├── app.py                     # REST + SSE endpoints, CORS
│   ├── core.py                    # Enrichment logic (VT/AbuseIPDB/geo, verdicts, reports)
│   ├── config.json                # Saved API keys (created on first save)
│   ├── requirements.txt           # flask, requests
│   ├── static/                    # Original Flask UI (backward compat)
│   └── output/                    # Generated CSV / text / STIX reports
│
└── frontend/                     # Next.js frontend (TypeScript)
    ├── next.config.js             # Next.js config
    ├── package.json               # Dependencies (next, react, leaflet)
    ├── .env.local                 # Backend URL config
    └── src/
        ├── app/
        │   ├── globals.css        # Full dark SOC theme + Leaflet dark filter
        │   ├── layout.tsx         # Root layout + SEO metadata
        │   └── page.tsx          # Main page (state, SSE, component orchestration)
        ├── components/
        │   ├── OpsHeader.tsx       # Top bar: SOC mark, key status dots, clock
        │   ├── SettingsPanel.tsx   # API key entry + save + hot-swap
        │   ├── ScanPanel.tsx       # Mode selector + IOC textarea + run options
        │   ├── ScanProgress.tsx    # Radar animation + progress bar + terminal log
        │   ├── PostScanProgress.tsx# Stacked verdict bar + threat-level badge
        │   ├── SummaryChips.tsx    # Verdict count chips
        │   ├── ResultsTable.tsx    # Sortable results table + download links
        │   ├── ChartsPanel.tsx     # Composes all chart components
        │   ├── MaliciousPieChart.tsx  # Malicious vs non-malicious donut
        │   ├── VerdictBarChart.tsx    # Horizontal verdict bars
        │   ├── ThreatMap.tsx         # Leaflet map with pulsing IP dots
        │   ├── ThreatChoropleth.tsx  # Leaflet + GeoJSON country threat shading
        │   ├── VendorWordCloud.tsx   # Spiral-laid vendor name cloud
        │   └── ExportPanel.tsx       # CSV/JSON export with column selection
        ├── hooks/
        │   └── useISTClock.ts      # Live IST clock (ticks every second)
        └── lib/
            ├── types.ts            # TypeScript types + export column defs
            ├── api.ts              # API client (fetch + SSE streaming)
            └── export.ts           # Client-side CSV/JSON generation
```

---

## 📸 Screenshots

| Scan Progress | Results Dashboard |
|:---:|:---:|
| Radar animation + live terminal log during scanning | Maps, charts, and word cloud after scan |

| Threat Map | Choropleth |
|:---:|:---:|
| Interactive map with pulsing malicious dots | Countries shaded by threat intensity |

---

## 🔒 Security Notes

- API keys are stored in `backend/config.json` in plain text on the server. **Do not commit this file to git.** It's in `.gitignore`.
- The Flask backend runs on `127.0.0.1` only — not exposed to the network.
- All API calls go through the Flask backend — your keys never leave the server.
- For production deployment, use a reverse proxy (nginx/caddy) and HTTPS.

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15, React 19, TypeScript |
| Backend | Flask (Python 3.9+) |
| Maps | Leaflet + OpenStreetMap |
| Charts | Custom SVG (donut, bar, scatter, word cloud) |
| Streaming | Server-Sent Events (SSE) |
| Export | Client-side Blob (CSV/JSON), server-side (STIX 2.1, text) |
| Fonts | Space Grotesk, Inter, JetBrains Mono |

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 👨‍💻 Author

**Amit Ambekar**

- 🔗 GitHub: [https://github.com/amitambekar510](https://github.com/amitambekar510)
- 💼 LinkedIn: [Amit Ambekar](https://www.linkedin.com/in/amit-ambekar)

*SOC Analyst · Threat Intelligence · Incident Response*

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

## ⭐ Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for their threat intelligence API
- [AbuseIPDB](https://www.abuseipdb.com/) for IP reputation data
- [ipgeolocation.io](https://ipgeolocation.io/) for IP geolocation
- [ip-api.com](https://ip-api.com/) for free geolocation fallback
- [Leaflet](https://leafletjs.com/) for the mapping library
- [OpenStreetMap](https://www.openstreetmap.org/) for map tiles
- [Natural Earth](https://www.naturalearthdata.com/) for country GeoJSON data

---

<p align="center">
  If this project helped you, please ⭐ star the repo!
</p>
