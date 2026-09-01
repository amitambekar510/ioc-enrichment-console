#!/usr/bin/env python3
"""
app.py - Local browser GUI for the IOC Enrichment toolkit.

This is the updated backend that serves both the original REST endpoints
AND a new Server-Sent Events (SSE) streaming endpoint for real-time
per-IOC progress during scans.

Run:
    pip install -r requirements.txt
    python app.py
Then open:
    http://127.0.0.1:5000  (original Flask UI)
    http://localhost:3000    (Next.js frontend — proxies /api to this server)

The Next.js frontend talks to this backend via /api/* routes.
Configure the proxy in next.config.js to point at this server.

API keys are entered in the Settings panel in the browser and are saved to
config.json on this machine so they stay filled in next time you open the
page. They are only sent from your browser to this local server, and from
this local server out to VirusTotal / AbuseIPDB / ipgeolocation.io.
"""

import csv
import io
import json
import time
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, Response, stream_with_context

import core

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.json"
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

app = Flask(__name__, static_folder="static", static_url_path="")

DEFAULT_CONFIG = {
    "vt_api_key": "",
    "abuseipdb_api_key": "",
    "ipgeo_api_key": "",
}


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text())
            return {**DEFAULT_CONFIG, **cfg}
        except json.JSONDecodeError:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    merged = {**load_config(), **cfg}
    CONFIG_PATH.write_text(json.dumps(merged, indent=2))


# --------------------------------------------------------------------------
# CORS — allow the Next.js dev server (localhost:3000) to call this API
# --------------------------------------------------------------------------

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


# --------------------------------------------------------------------------
# Static frontend (original Flask UI — kept for backward compat)
# --------------------------------------------------------------------------

@app.route("/")
def index():
    return app.send_static_file("index.html")


# --------------------------------------------------------------------------
# API: keys
# --------------------------------------------------------------------------

@app.route("/api/keys", methods=["GET"])
def get_keys():
    """Return currently saved keys so the browser panel can pre-fill them."""
    return jsonify(load_config())


@app.route("/api/keys", methods=["POST"])
def set_keys():
    """Overwrite saved keys with whatever the browser panel submits."""
    body = request.get_json(force=True, silent=True) or {}
    update = {
        "vt_api_key": body.get("vt_api_key", ""),
        "abuseipdb_api_key": body.get("abuseipdb_api_key", ""),
        "ipgeo_api_key": body.get("ipgeo_api_key", ""),
    }
    save_config(update)
    return jsonify({"status": "saved", "keys": load_config()})


# --------------------------------------------------------------------------
# API: server time (IST)
# --------------------------------------------------------------------------

@app.route("/api/time", methods=["GET"])
def server_time():
    """Return current server time in IST ISO format."""
    return jsonify({
        "ist": core.format_ist(),
        "epoch": int(time.time()),
        "timezone": "Asia/Kolkata",
    })


# --------------------------------------------------------------------------
# API: private IP check
# --------------------------------------------------------------------------

@app.route("/api/check-ip", methods=["POST"])
def check_ip():
    """Check if a single IP is private/reserved. Returns structured result."""
    body = request.get_json(force=True, silent=True) or {}
    ip = body.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "No IP provided"}), 400
    is_priv, reason = core.is_private_ip(ip)
    return jsonify({
        "ip": ip,
        "is_private": is_priv,
        "reason": reason,
    })


# --------------------------------------------------------------------------
# API: analyze (original — batch, blocks until all done)
# --------------------------------------------------------------------------

@app.route("/api/analyze", methods=["POST"])
def analyze():
    body = request.get_json(force=True, silent=True) or {}
    mode = body.get("mode", "combined")
    if mode not in core.MODES:
        return jsonify({"error": f"invalid mode '{mode}'"}), 400

    raw_text = body.get("iocs", "")
    skip_private = bool(body.get("skip_private", True))
    max_age_days = int(body.get("max_age_days", 90))
    delay = float(body.get("delay", 1.5))

    cfg = load_config()
    vt_key = cfg.get("vt_api_key") or None
    abuse_key = cfg.get("abuseipdb_api_key") or None
    geo_key = cfg.get("ipgeo_api_key") or None

    if mode in ("combined", "vt_only") and not vt_key:
        return jsonify({"error": "VirusTotal API key is not set. Add it in Settings first."}), 400
    if mode in ("combined", "abuseipdb_only") and not abuse_key:
        return jsonify({"error": "AbuseIPDB API key is not set. Add it in Settings first."}), 400

    parsed = core.parse_iocs(raw_text, skip_private, mode)
    warnings = [w for (_, t, w) in parsed if w]
    to_analyze = [(ioc, t) for (ioc, t, w) in parsed if w is None]

    if not to_analyze:
        return jsonify({"error": "No valid IOCs to analyze.", "warnings": warnings}), 400

    findings = []
    for idx, (ioc, ioc_type) in enumerate(to_analyze, start=1):
        finding = core.analyze_ioc(ioc, ioc_type, mode, vt_key, abuse_key, geo_key, max_age_days)
        findings.append(finding)
        if idx < len(to_analyze):
            time.sleep(delay)

    timestamp = core.format_ist(fmt="%Y%m%dT%H%M%S")
    prefix = {"combined": "combined_report", "vt_only": "vt_report", "abuseipdb_only": "abuseipdb_report"}[mode]

    # CSV
    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    for row in core.build_csv_rows(findings):
        writer.writerow(row)
    csv_name = f"{prefix}_{timestamp}.csv"
    (OUTPUT_DIR / csv_name).write_text(csv_buf.getvalue())

    # Text
    txt_name = f"{prefix}_{timestamp}.txt"
    (OUTPUT_DIR / txt_name).write_text(core.build_text_report(findings))

    # STIX
    stix_name = f"{prefix}_{timestamp}.stix2.json"
    (OUTPUT_DIR / stix_name).write_text(json.dumps(core.build_stix_bundle(findings), indent=2))

    return jsonify({
        "mode": mode,
        "generated_at": core.format_ist(),
        "warnings": warnings,
        "results": [f.to_dict() for f in findings],
        "downloads": {
            "csv": csv_name,
            "txt": txt_name,
            "stix": stix_name,
        },
    })


# --------------------------------------------------------------------------
# API: analyze/stream — NEW SSE endpoint for real-time per-IOC progress
# --------------------------------------------------------------------------

@app.route("/api/analyze/stream", methods=["POST"])
def analyze_stream():
    """Stream per-IOC results as Server-Sent Events. The frontend uses
    EventSource (or fetch + ReadableStream) to consume these events and
    update the UI incrementally as each IOC completes.

    SSE event types:
      - "start":    { total, warnings } — scan begins
      - "progress": { index, total, ioc, ioc_type, status } — before each IOC
      - "result":   { index, total, finding } — after each IOC completes
      - "complete": { downloads, summary } — all done, reports generated
      - "error":    { message } — fatal error
    """
    body = request.get_json(force=True, silent=True) or {}
    mode = body.get("mode", "combined")
    if mode not in core.MODES:
        return jsonify({"error": f"invalid mode '{mode}'"}), 400

    raw_text = body.get("iocs", "")
    skip_private = bool(body.get("skip_private", True))
    max_age_days = int(body.get("max_age_days", 90))
    delay = float(body.get("delay", 1.5))

    parsed = core.parse_iocs(raw_text, skip_private, mode)
    warnings = [w for (_, t, w) in parsed if w]
    to_analyze = [(ioc, t) for (ioc, t, w) in parsed if w is None]

    if not to_analyze:
        return jsonify({"error": "No valid IOCs to analyze.", "warnings": warnings}), 400

    # Validate keys exist before starting the stream.
    # Keys are re-read INSIDE generate() so that if the user saves
    # new keys in Settings and hits Retry, the new keys are picked up.
    cfg_check = load_config()
    if mode in ("combined", "vt_only") and not (cfg_check.get("vt_api_key") or ""):
        return jsonify({"error": "VirusTotal API key is not set. Add it in Settings first."}), 400
    if mode in ("combined", "abuseipdb_only") and not (cfg_check.get("abuseipdb_api_key") or ""):
        return jsonify({"error": "AbuseIPDB API key is not set. Add it in Settings first."}), 400

    def generate():
        # RELOAD config inside the generator so Retry picks up newly saved keys.
        cfg = load_config()
        vt_key = cfg.get("vt_api_key") or None
        abuse_key = cfg.get("abuseipdb_api_key") or None
        geo_key = cfg.get("ipgeo_api_key") or None

        # --- start event ---
        start_data = {
            "total": len(to_analyze),
            "warnings": warnings,
            "mode": mode,
            "generated_at": core.format_ist(),
        }
        yield f"event: start\ndata: {json.dumps(start_data)}\n\n"

        findings = []

        for idx, (ioc, ioc_type) in enumerate(to_analyze, start=1):
            # --- progress event (before querying) ---
            progress_data = {
                "index": idx,
                "total": len(to_analyze),
                "ioc": ioc,
                "ioc_type": ioc_type,
                "status": "querying",
            }
            yield f"event: progress\ndata: {json.dumps(progress_data)}\n\n"

            finding = core.analyze_ioc(ioc, ioc_type, mode, vt_key, abuse_key, geo_key, max_age_days)
            findings.append(finding)

            # --- result event (after querying) ---
            result_data = {
                "index": idx,
                "total": len(to_analyze),
                "finding": finding.to_dict(),
            }
            yield f"event: result\ndata: {json.dumps(result_data)}\n\n"

            if idx < len(to_analyze):
                time.sleep(delay)

        # --- generate downloadable reports ---
        timestamp = core.format_ist(fmt="%Y%m%dT%H%M%S")
        prefix = {"combined": "combined_report", "vt_only": "vt_report", "abuseipdb_only": "abuseipdb_report"}[mode]

        csv_buf = io.StringIO()
        writer = csv.writer(csv_buf)
        for row in core.build_csv_rows(findings):
            writer.writerow(row)
        csv_name = f"{prefix}_{timestamp}.csv"
        (OUTPUT_DIR / csv_name).write_text(csv_buf.getvalue())

        txt_name = f"{prefix}_{timestamp}.txt"
        (OUTPUT_DIR / txt_name).write_text(core.build_text_report(findings))

        stix_name = f"{prefix}_{timestamp}.stix2.json"
        (OUTPUT_DIR / stix_name).write_text(json.dumps(core.build_stix_bundle(findings), indent=2))

        # Summary counts
        counts = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0}
        for f in findings:
            counts[f.verdict] += 1

        complete_data = {
            "downloads": {
                "csv": csv_name,
                "txt": txt_name,
                "stix": stix_name,
            },
            "summary": counts,
            "total": len(findings),
            "generated_at": core.format_ist(),
        }
        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# --------------------------------------------------------------------------
# API: rebuild reports (from an already-computed result set)
# --------------------------------------------------------------------------

@app.route("/api/reports", methods=["POST"])
def rebuild_reports():
    """Rebuild CSV/text/STIX files from an already-computed result set (no new
    network calls) - used after a 'retry failed only' merge on the frontend so
    the downloadable reports reflect the corrected, merged data."""
    body = request.get_json(force=True, silent=True) or {}
    mode = body.get("mode", "combined")
    result_dicts = body.get("results", [])
    if not result_dicts:
        return jsonify({"error": "No results provided."}), 400

    findings = [core.IOCFinding.from_dict(d) for d in result_dicts]

    timestamp = core.format_ist(fmt="%Y%m%dT%H%M%S")
    prefix = {"combined": "combined_report", "vt_only": "vt_report", "abuseipdb_only": "abuseipdb_report"}.get(mode, "ioc_report")

    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    for row in core.build_csv_rows(findings):
        writer.writerow(row)
    csv_name = f"{prefix}_{timestamp}.csv"
    (OUTPUT_DIR / csv_name).write_text(csv_buf.getvalue())

    txt_name = f"{prefix}_{timestamp}.txt"
    (OUTPUT_DIR / txt_name).write_text(core.build_text_report(findings))

    stix_name = f"{prefix}_{timestamp}.stix2.json"
    (OUTPUT_DIR / stix_name).write_text(json.dumps(core.build_stix_bundle(findings), indent=2))

    return jsonify({
        "downloads": {"csv": csv_name, "txt": txt_name, "stix": stix_name},
    })


@app.route("/api/download/<path:filename>")
def download(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
