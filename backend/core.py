"""
core.py - Shared IOC enrichment logic for the browser GUI.

Adapted from the three original standalone scripts:
  - ABUSEIPDB/abuseipdb_analyzer.py
  - VIRUSTOTAL/virustotal.py
  - VIRUS TOTAL WITH ABUSEIPDB/ioc_ip_analyzer.py

Supports three modes:
  - "combined"     : VirusTotal + AbuseIPDB (+ optional ipgeolocation.io)  [ip/domain/hash]
  - "vt_only"       : VirusTotal only (+ optional ipgeolocation.io)        [ip/domain/hash]
  - "abuseipdb_only": AbuseIPDB only (+ free ip-api.com geolocation)       [ip only]
"""

import dataclasses
import ipaddress
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

import requests

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{ioc}"
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{ioc}"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
IPGEO_URL = "https://api.ipgeolocation.io/ipgeo"
IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,as,isp,org,query"

IST_OFFSET = timedelta(hours=5, minutes=30)

MODES = ("combined", "vt_only", "abuseipdb_only")

# Private / reserved IP ranges (RFC 1918, loopback, link-local, CGNAT, etc.)
PRIVATE_RANGES_DESC = {
    "10.0.0.0/8": "Class A private (RFC 1918) — internal network",
    "172.16.0.0/12": "Class B private (RFC 1918) — internal network",
    "192.168.0.0/16": "Class C private (RFC 1918) — home/office LAN",
    "127.0.0.0/8": "Loopback (localhost) — not routable on the internet",
    "169.254.0.0/16": "Link-local (APIPA) — auto-config, not internet-routable",
    "100.64.0.0/10": "CGNAT (RFC 6598) — carrier-grade NAT, not publicly reachable",
    "0.0.0.0/8": "This network (RFC 1122) — not usable on the public internet",
    "192.0.2.0/24": "TEST-NET-1 (RFC 5737) — documentation/example only",
    "198.51.100.0/24": "TEST-NET-2 (RFC 5737) — documentation/example only",
    "203.0.113.0/24": "TEST-NET-3 (RFC 5737) — documentation/example only",
    "224.0.0.0/4": "Multicast (RFC 5771) — not a source/dest for regular traffic",
    "240.0.0.0/4": "Reserved for future use (Class E) — not routable",
}


def now_ist() -> datetime:
    return datetime.now(timezone.utc).astimezone(timezone(IST_OFFSET))


def format_ist(dt: Optional[datetime] = None, fmt: str = "%Y-%m-%d %H:%M IST") -> str:
    if dt is None:
        dt = now_ist()
    return dt.strftime(fmt)


def is_private_ip(ip_str: str) -> tuple[bool, Optional[str]]:
    """Check if IP is private/reserved. Returns (is_private, reason_with_range)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, None

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        # Find which range it falls in for a descriptive message
        for cidr, desc in PRIVATE_RANGES_DESC.items():
            try:
                if addr in ipaddress.ip_network(cidr):
                    return True, f"Private/reserved IP ({ip_str} ∈ {cidr}): {desc}. Cannot scan — not reachable from the public internet."
            except ValueError:
                continue
        return True, f"Private/reserved IP ({ip_str}): not reachable on the public internet. Cannot scan."

    # Check bogon ranges that Python's is_private doesn't always catch
    for cidr in ("100.64.0.0/10", "0.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24",
                 "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"):
        try:
            if addr in ipaddress.ip_network(cidr):
                desc = PRIVATE_RANGES_DESC.get(cidr, "bogon/reserved range")
                return True, f"Reserved IP ({ip_str} ∈ {cidr}): {desc}. Cannot scan."
        except ValueError:
            continue

    return False, None


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class IOCFinding:
    ioc: str
    ioc_type: str  # 'ip', 'domain', 'hash'

    # VirusTotal
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    vt_reputation: Optional[int] = None
    vt_last_analysis_date: Optional[str] = None
    vt_asn: Optional[int] = None
    vt_flagging_vendors: list = field(default_factory=list)
    vt_error: Optional[str] = None
    vt_error_type: Optional[str] = None

    # AbuseIPDB (IP only)
    abuse_confidence_score: Optional[int] = None
    abuse_total_reports: Optional[int] = None
    abuse_country: Optional[str] = None
    abuse_isp: Optional[str] = None
    abuse_usage_type: Optional[str] = None
    abuse_is_tor: Optional[bool] = None
    abuse_last_reported: Optional[str] = None
    abuse_error: Optional[str] = None
    abuse_error_type: Optional[str] = None

    # Geo (IP only)
    geo_city: Optional[str] = None
    geo_country: Optional[str] = None
    geo_asn: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    geo_error: Optional[str] = None
    geo_error_type: Optional[str] = None

    @property
    def community_score(self) -> Optional[int]:
        if self.vt_malicious is None and self.vt_suspicious is None:
            return None
        return (self.vt_malicious or 0) + (self.vt_suspicious or 0)

    @property
    def location(self) -> str:
        if not self.geo_city and not self.geo_country:
            return "N/A"
        return f"{self.geo_city or 'N/A'}, {self.geo_country or 'N/A'}"

    @property
    def verdict(self) -> str:
        vt_hit = (self.vt_malicious or 0) > 0
        vt_susp = (self.vt_suspicious or 0) > 0
        abuse_hit = (self.abuse_confidence_score or 0) >= 75
        abuse_susp = 25 <= (self.abuse_confidence_score or 0) < 75

        if vt_hit or abuse_hit:
            return "malicious"
        if vt_susp or abuse_susp:
            return "suspicious"
        has_any_error = self.vt_error or self.abuse_error
        has_any_data = (
            self.vt_malicious is not None or self.abuse_confidence_score is not None
        )
        if has_any_error and not has_any_data:
            return "unknown"
        return "benign"

    @property
    def confidence(self) -> int:
        return max(self.abuse_confidence_score or 0, (self.vt_malicious or 0) * 10)

    @property
    def is_retryable(self) -> bool:
        """True if any source failed - a good candidate for the 'retry failed only' action."""
        return bool(self.vt_error) or bool(self.abuse_error)

    @classmethod
    def from_dict(cls, d: dict) -> "IOCFinding":
        """Reconstruct a finding from a to_dict() payload (e.g. after a retry merge),
        ignoring computed/derived keys that aren't real dataclass fields."""
        valid = {f.name for f in dataclasses.fields(cls)}
        kwargs = {k: v for k, v in d.items() if k in valid}
        return cls(**kwargs)

    def to_dict(self) -> dict:
        d = {
            "ioc": self.ioc,
            "ioc_type": self.ioc_type,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "location": self.location,
            "community_score": self.community_score,
            "vt_malicious": self.vt_malicious,
            "vt_suspicious": self.vt_suspicious,
            "vt_harmless": self.vt_harmless,
            "vt_reputation": self.vt_reputation,
            "vt_last_analysis_date": self.vt_last_analysis_date,
            "vt_asn": self.vt_asn,
            "vt_flagging_vendors": self.vt_flagging_vendors,
            "vt_error": self.vt_error,
            "vt_error_type": self.vt_error_type,
            "abuse_confidence_score": self.abuse_confidence_score,
            "abuse_total_reports": self.abuse_total_reports,
            "abuse_country": self.abuse_country,
            "abuse_isp": self.abuse_isp,
            "abuse_usage_type": self.abuse_usage_type,
            "abuse_is_tor": self.abuse_is_tor,
            "abuse_last_reported": self.abuse_last_reported,
            "abuse_error": self.abuse_error,
            "abuse_error_type": self.abuse_error_type,
            "geo_city": self.geo_city,
            "geo_country": self.geo_country,
            "geo_asn": self.geo_asn,
            "geo_lat": self.geo_lat,
            "geo_lon": self.geo_lon,
            "geo_error": self.geo_error,
            "geo_error_type": self.geo_error_type,
            "is_retryable": self.is_retryable,
        }
        return d


# --------------------------------------------------------------------------
# IOC type detection
# --------------------------------------------------------------------------

def detect_ioc_type(value: str) -> Optional[str]:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "hash"

    if re.fullmatch(r"[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+", value):
        return "domain"

    return None


def parse_iocs(raw_text: str, skip_private: bool, mode: str):
    """Parse newline-separated IOC text into a list of (ioc, type, warning) tuples.
    warning is None unless the line was skipped/invalid, in which case ioc/type
    are the original line and a reason string respectively.
    """
    results = []
    seen = set()
    for lineno, raw in enumerate(raw_text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        ioc_type = detect_ioc_type(line)
        if not ioc_type:
            results.append((line, None, f"Line {lineno}: not a valid IP, domain, or SHA256 hash"))
            continue

        if mode == "abuseipdb_only" and ioc_type != "ip":
            results.append((line, None, f"Line {lineno}: AbuseIPDB-only mode supports IPs only, skipping '{line}'"))
            continue

        if ioc_type == "ip":
            is_priv, reason = is_private_ip(line)
            if is_priv and skip_private:
                results.append((line, None, f"⚠ PRIVATE IP — {reason}"))
                continue

        if line not in seen:
            seen.add(line)
            results.append((line, ioc_type, None))

    return results


# --------------------------------------------------------------------------
# API calls
# --------------------------------------------------------------------------

def _get_with_retry(url, headers=None, params=None, max_retries=2, timeout=10):
    """Returns a dict: {"resp": Response|None, "rate_limited": bool, "network_error": bool}.
    rate_limited is True if every retry attempt was exhausted because of repeated 429s
    (as opposed to connection failures or other errors), so callers can tell a caller
    "you're being rate limited" apart from "something else is wrong"."""
    backoff = 2
    saw_429 = False
    saw_network_error = False
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        except requests.RequestException:
            saw_network_error = True
            time.sleep(backoff)
            backoff *= 2
            continue

        if resp.status_code == 429:
            saw_429 = True
            saw_network_error = False  # this attempt did reach the server
            time.sleep(backoff)
            backoff *= 2
            continue

        return {"resp": resp, "rate_limited": False, "network_error": False}

    return {"resp": None, "rate_limited": saw_429, "network_error": saw_network_error}


def _classify_failure(outcome: dict, service_name: str) -> tuple:
    """Turn a _get_with_retry() outcome (or a returned non-200 response) into
    (error_type, message). error_type is one of:
    "auth", "rate_limit", "not_found", "network", "other"."""
    resp = outcome.get("resp")

    if resp is None:
        if outcome.get("rate_limited"):
            return "rate_limit", (
                f"{service_name} rate limit reached after retries - wait a bit, "
                f"or increase the delay between requests, then retry this IOC"
            )
        if outcome.get("network_error"):
            return "network", f"{service_name} request failed - network/connection error after retries"
        return "other", f"{service_name} request failed after retries"

    if resp.status_code in (401, 403):
        return "auth", f"{service_name} rejected the API key (HTTP {resp.status_code}) - check Settings"
    if resp.status_code == 404:
        return "not_found", f"not found in {service_name}"
    if resp.status_code == 429:
        return "rate_limit", f"{service_name} rate limit reached (HTTP 429)"
    return "other", f"{service_name} error HTTP {resp.status_code}: {resp.text[:200]}"


def query_virustotal(ioc: str, ioc_type: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    if ioc_type == "ip":
        url = VT_IP_URL.format(ioc=ioc)
    elif ioc_type == "domain":
        url = VT_DOMAIN_URL.format(ioc=ioc)
    elif ioc_type == "hash":
        url = VT_FILE_URL.format(ioc=ioc)
    else:
        return {"vt_error": "unknown IOC type", "vt_error_type": "other"}

    outcome = _get_with_retry(url, headers=headers)
    resp = outcome["resp"]

    if resp is None or resp.status_code != 200:
        error_type, message = _classify_failure(outcome, "VirusTotal")
        return {"vt_error": message, "vt_error_type": error_type}

    try:
        data = resp.json()["data"]["attributes"]
    except (KeyError, ValueError) as e:
        return {"vt_error": f"unexpected response shape: {e}", "vt_error_type": "other"}

    stats = data.get("last_analysis_stats", {})
    results = data.get("last_analysis_results", {})
    flagging_vendors = [
        vendor for vendor, verdict in results.items()
        if verdict.get("category") in ("malicious", "suspicious")
    ]

    last_analysis_date = data.get("last_analysis_date")
    if last_analysis_date:
        try:
            dt = datetime.fromtimestamp(last_analysis_date, tz=timezone.utc).astimezone(timezone(IST_OFFSET))
            last_analysis_date = dt.strftime("%Y-%m-%d %H:%M IST")
        except (OSError, OverflowError, ValueError):
            last_analysis_date = str(last_analysis_date)

    asn = data.get("asn") if ioc_type == "ip" else None

    return {
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
        "vt_reputation": data.get("reputation"),
        "vt_last_analysis_date": last_analysis_date,
        "vt_asn": asn,
        "vt_flagging_vendors": flagging_vendors,
    }


def query_abuseipdb(ip: str, api_key: str, max_age_days: int) -> dict:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""}
    outcome = _get_with_retry(ABUSEIPDB_URL, headers=headers, params=params)
    resp = outcome["resp"]

    if resp is None or resp.status_code != 200:
        error_type, message = _classify_failure(outcome, "AbuseIPDB")
        return {"abuse_error": message, "abuse_error_type": error_type}

    try:
        data = resp.json()["data"]
    except (KeyError, ValueError) as e:
        return {"abuse_error": f"unexpected response shape: {e}", "abuse_error_type": "other"}

    return {
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "abuse_total_reports": data.get("totalReports"),
        "abuse_country": data.get("countryName") or data.get("countryCode"),
        "abuse_isp": data.get("isp"),
        "abuse_usage_type": data.get("usageType"),
        "abuse_is_tor": data.get("isTor"),
        "abuse_last_reported": data.get("lastReportedAt"),
    }


def query_geolocation(ip: str, api_key: str) -> dict:
    """ipgeolocation.io - used in combined/vt_only modes when a geo key is configured."""
    params = {"apiKey": api_key, "ip": ip}
    outcome = _get_with_retry(IPGEO_URL, params=params, max_retries=2)
    resp = outcome["resp"]
    if resp is None or resp.status_code != 200:
        error_type, message = _classify_failure(outcome, "ipgeolocation.io")
        return {"geo_error": message, "geo_error_type": error_type}
    try:
        data = resp.json()
    except ValueError as e:
        return {"geo_error": f"unexpected response shape: {e}", "geo_error_type": "other"}
    geo_data = {
        "geo_city": data.get("city") or None,
        "geo_country": data.get("country_name") or None,
    }
    # Capture lat/lon for map visualization
    try:
        geo_data["geo_lat"] = float(data.get("latitude")) if data.get("latitude") else None
    except (TypeError, ValueError):
        pass
    try:
        geo_data["geo_lon"] = float(data.get("longitude")) if data.get("longitude") else None
    except (TypeError, ValueError):
        pass
    return geo_data


def query_ipapi(ip: str) -> dict:
    """Free ip-api.com lookup - used in abuseipdb_only mode (no key required)."""
    url = IPAPI_URL.format(ip=ip)
    outcome = _get_with_retry(url, max_retries=2, timeout=10)
    resp = outcome["resp"]

    if resp is None or resp.status_code != 200:
        error_type, message = _classify_failure(outcome, "ip-api.com")
        return {"geo_error": message, "geo_error_type": error_type}

    try:
        data = resp.json()
    except ValueError:
        return {"geo_error": "invalid JSON", "geo_error_type": "other"}

    if data.get("status") != "success":
        return {"geo_error": data.get("message", "ip-api lookup failed"), "geo_error_type": "other"}

    geo_data = {
        "geo_city": data.get("city"),
        "geo_country": data.get("country"),
        "geo_asn": data.get("as"),
    }
    # Capture lat/lon for map visualization
    try:
        geo_data["geo_lat"] = float(data.get("lat")) if data.get("lat") else None
    except (TypeError, ValueError):
        pass
    try:
        geo_data["geo_lon"] = float(data.get("lon")) if data.get("lon") else None
    except (TypeError, ValueError):
        pass
    return geo_data


def analyze_ioc(
    ioc: str,
    ioc_type: str,
    mode: str,
    vt_key: Optional[str],
    abuse_key: Optional[str],
    geo_key: Optional[str],
    max_age_days: int,
) -> IOCFinding:
    finding = IOCFinding(ioc=ioc, ioc_type=ioc_type)

    if mode in ("combined", "vt_only") and vt_key:
        vt_data = query_virustotal(ioc, ioc_type, vt_key)
        for k, v in vt_data.items():
            setattr(finding, k, v)
        if ioc_type == "ip" and geo_key:
            geo_data = query_geolocation(ioc, geo_key)
            for k, v in geo_data.items():
                setattr(finding, k, v)

    if mode in ("combined", "abuseipdb_only") and ioc_type == "ip" and abuse_key:
        abuse_data = query_abuseipdb(ioc, abuse_key, max_age_days)
        for k, v in abuse_data.items():
            setattr(finding, k, v)

        # Free geolocation fallback (abuseipdb_only mode, or combined mode w/o geo key)
        if not finding.geo_city and not finding.geo_country:
            geo_data = query_ipapi(ioc)
            for k, v in geo_data.items():
                setattr(finding, k, v)

    return finding


# --------------------------------------------------------------------------
# STIX 2.1 output
# --------------------------------------------------------------------------

def to_stix_indicator(finding: IOCFinding) -> dict:
    now = format_ist(fmt="%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+05:30"
    verdict = finding.verdict
    ioc = finding.ioc
    ioc_type = finding.ioc_type

    indicator_type_map = {
        "malicious": "malicious-activity",
        "suspicious": "anomalous-activity",
        "benign": "benign",
        "unknown": "unknown",
    }

    if ioc_type == "ip":
        pattern = f"[ipv4-addr:value = '{ioc}']"
    elif ioc_type == "domain":
        pattern = f"[domain-name:value = '{ioc}']"
    elif ioc_type == "hash":
        pattern = f"[file:hashes.'SHA-256' = '{ioc}']"
    else:
        pattern = f"[x-custom:value = '{ioc}']"

    desc_lines = [f"Automated enrichment for {ioc_type.upper()} {ioc}."]
    if finding.vt_malicious is not None or finding.vt_error:
        if finding.vt_error:
            desc_lines.append(f"VirusTotal: {finding.vt_error}")
        else:
            desc_lines.append(
                f"VirusTotal: {finding.vt_malicious} malicious / {finding.vt_suspicious} "
                f"suspicious vendor detections."
            )
            if finding.vt_flagging_vendors:
                desc_lines.append("Flagging vendors: " + ", ".join(finding.vt_flagging_vendors[:10]))

    if finding.abuse_confidence_score is not None or finding.abuse_error:
        if finding.abuse_error:
            desc_lines.append(f"AbuseIPDB: {finding.abuse_error}")
        else:
            desc_lines.append(
                f"AbuseIPDB: confidence score {finding.abuse_confidence_score}/100 "
                f"from {finding.abuse_total_reports} report(s)."
            )
    if finding.geo_city or finding.geo_country:
        desc_lines.append(f"Location: {finding.location}.")

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": f"{verdict.capitalize()} {ioc_type.upper()}: {ioc}",
        "description": " ".join(desc_lines),
        "indicator_types": [indicator_type_map.get(verdict, "unknown")],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": now,
        "confidence": finding.confidence,
        "labels": [verdict, ioc_type],
        "external_references": [
            {
                "source_name": "VirusTotal",
                "url": f"https://www.virustotal.com/gui/{'ip-address' if ioc_type=='ip' else ioc_type}/{ioc}",
            },
        ],
        "x_ioc_type": ioc_type,
        "x_virustotal_malicious": finding.vt_malicious,
        "x_virustotal_suspicious": finding.vt_suspicious,
        "x_virustotal_community_score": finding.community_score,
        "x_virustotal_flagging_vendors": finding.vt_flagging_vendors,
        "x_virustotal_asn": finding.vt_asn,
        "x_abuseipdb_confidence_score": finding.abuse_confidence_score,
        "x_abuseipdb_total_reports": finding.abuse_total_reports,
        "x_abuseipdb_is_tor": finding.abuse_is_tor,
        "x_geolocation_city": finding.geo_city,
        "x_geolocation_country": finding.geo_country,
    }
    return indicator


def build_stix_bundle(findings) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [to_stix_indicator(f) for f in findings],
    }


# --------------------------------------------------------------------------
# CSV + text report builders (return strings, GUI writes them to disk)
# --------------------------------------------------------------------------

def build_csv_rows(findings):
    fields = [
        "ioc", "ioc_type", "verdict", "confidence", "location",
        "vt_asn", "vt_malicious", "vt_suspicious", "vt_harmless", "vt_reputation",
        "community_score", "vt_last_analysis_date", "vt_error", "vt_error_type",
        "abuse_confidence_score", "abuse_total_reports", "abuse_country",
        "abuse_isp", "abuse_usage_type", "abuse_is_tor", "abuse_last_reported",
        "abuse_error_type", "geo_error", "geo_lat", "geo_lon",
    ]
    rows = [fields]
    for finding in findings:
        d = finding.to_dict()
        row = []
        for f in fields:
            val = d.get(f)
            if isinstance(val, list):
                val = ";".join(val)
            row.append(val if val is not None else "")
        rows.append(row)
    return rows


def build_text_report(findings) -> str:
    lines = []
    now = format_ist()
    lines.append("=" * 70)
    lines.append("IOC ENRICHMENT REPORT")
    lines.append(f"Generated: {now}")
    lines.append(f"Total IOCs analyzed: {len(findings)}")

    type_counts = {"ip": 0, "domain": 0, "hash": 0}
    verdict_counts = {"malicious": 0, "suspicious": 0, "benign": 0, "unknown": 0}
    for f in findings:
        type_counts[f.ioc_type] = type_counts.get(f.ioc_type, 0) + 1
        verdict_counts[f.verdict] += 1
    lines.append(
        f"IPs: {type_counts.get('ip',0)} | Domains: {type_counts.get('domain',0)} | Hashes: {type_counts.get('hash',0)}"
    )
    lines.append(
        f"Malicious: {verdict_counts['malicious']} | Suspicious: {verdict_counts['suspicious']} | "
        f"Benign: {verdict_counts['benign']} | Unknown: {verdict_counts['unknown']}"
    )
    lines.append("=" * 70)

    order = {"malicious": 0, "suspicious": 1, "unknown": 2, "benign": 3}
    for f in sorted(findings, key=lambda x: (order[x.verdict], x.ioc_type)):
        lines.append("")
        lines.append(f"{f.ioc_type.upper()}: {f.ioc}  [{f.verdict.upper()}]  confidence={f.confidence}")
        if f.ioc_type == "ip":
            lines.append(f"Location: {f.location}")
            if f.vt_asn:
                lines.append(f"ASN: {f.vt_asn}")
        lines.append("-" * 70)
        if f.vt_malicious is not None or f.vt_error:
            if f.vt_error:
                tag = f"[{f.vt_error_type}] " if f.vt_error_type else ""
                lines.append(f"  VirusTotal   : ERROR {tag}- {f.vt_error}")
            else:
                lines.append(
                    f"  VirusTotal   : community_score={f.community_score} "
                    f"(malicious={f.vt_malicious} suspicious={f.vt_suspicious} harmless={f.vt_harmless})"
                )
                if f.vt_flagging_vendors:
                    lines.append(f"                 Flagged by: {', '.join(f.vt_flagging_vendors[:8])}")
        if f.abuse_confidence_score is not None or f.abuse_error:
            if f.abuse_error:
                tag = f"[{f.abuse_error_type}] " if f.abuse_error_type else ""
                lines.append(f"  AbuseIPDB    : ERROR {tag}- {f.abuse_error}")
            else:
                lines.append(
                    f"  AbuseIPDB    : confidence={f.abuse_confidence_score}/100 reports={f.abuse_total_reports}"
                )
                lines.append(
                    f"                 ISP={f.abuse_isp}  Country={f.abuse_country}  Tor={f.abuse_is_tor}"
                )

    return "\n".join(lines)
