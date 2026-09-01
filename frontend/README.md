# IOC Enrichment Console — Next.js Frontend

Production-ready Next.js (App Router) conversion of the original Flask single-page UI.
Preserves the exact dark SOC theme, layout, and functionality while adding:

- Real-time per-IOC scan progress (SSE streaming)
- Live IST clock in the ops header
- Verdict distribution donut chart
- Confidence score scatter chart
- World map with geo-located IP dots (color-coded by verdict)
- CSV/JSON export with column selection
- Private/reserved IP detection with clear rejection messages
- Fully responsive (mobile / tablet / desktop)
- SEO metadata via Next.js Metadata API

## Setup

```bash
# 1. Start the Flask backend first
cd ../backend
source venv/bin/activate
python app.py   # runs on :5000

# 2. In another terminal, start Next.js
cd ../frontend
npm install
npm run dev     # runs on :3000
```

Open `http://localhost:3000`. The Next.js dev server proxies `/api/*` to Flask.

## Project Structure

```
frontend/
├── next.config.js          # Rewrites /api/* → Flask backend
├── package.json
├── tsconfig.json
├── public/                 # Static assets (images, icons)
└── src/
    ├── app/
    │   ├── globals.css     # Exact dark SOC theme (ported from original <style>)
    │   ├── layout.tsx      # Root layout + SEO metadata + font loading
    │   └── page.tsx        # Main page (state management, SSE orchestration)
    ├── components/
    │   ├── OpsHeader.tsx       # Top bar: SOC mark, key status dots, clock, settings toggle
    │   ├── SettingsPanel.tsx   # API key entry (VT, AbuseIPDB, ipgeolocation.io)
    │   ├── ScanPanel.tsx       # Mode selector, IOC textarea, run options
    │   ├── ScanProgress.tsx    # Radar animation, progress bar, terminal log, IOC pills
    │   ├── SummaryChips.tsx    # Verdict count chips (malicious/suspicious/benign/unknown)
    │   ├── ResultsTable.tsx    # Results table with verdict badges + download links
    │   ├── ChartsPanel.tsx     # Donut chart + confidence scatter + world map
    │   └── ExportPanel.tsx     # CSV/JSON export with column selection checkboxes
    ├── hooks/
    │   └── useISTClock.ts      # IST clock hook (ticks locally, no backend call)
    └── lib/
        ├── types.ts        # TypeScript types + export column definitions
        ├── api.ts          # API client (fetch, SSE streaming, keys, downloads)
        └── export.ts       # Client-side CSV/JSON generation with column selection
```

## Key Architecture Decisions

1. **Flask backend kept** — all VirusTotal/AbuseIPDB/geolocation calls stay server-side.
   Next.js proxies `/api/*` to Flask via `next.config.js` rewrites.

2. **SSE streaming** — new `/api/analyze/stream` endpoint sends `start`, `progress`,
   `result`, and `complete` events so the frontend updates per-IOC in real-time.

3. **Client-side export** — CSV/JSON with column selection is generated in the browser
   via `Blob` + `URL.createObjectURL`, avoiding extra backend round-trips. The
   backend's CSV/text/STIX reports are still available via download links.

4. **Clock** — ticks locally using the browser's time converted to IST (UTC+5:30).
   No backend call needed; resyncs implicitly each tick.

5. **Private IP detection** — handled server-side in `core.py`'s `is_private_ip()`,
   which checks RFC 1918, loopback, link-local, CGNAT, TEST-NET, multicast, and
   Class E ranges. Returns a structured reason string the frontend displays.
