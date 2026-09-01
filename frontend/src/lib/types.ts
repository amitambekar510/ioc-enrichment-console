// Types shared across the IOC Enrichment Console frontend

export type ScanMode = 'combined' | 'vt_only' | 'abuseipdb_only';
export type Verdict = 'malicious' | 'suspicious' | 'benign' | 'unknown';
export type IOCType = 'ip' | 'domain' | 'hash';
export type ErrorType = 'auth' | 'rate_limit' | 'not_found' | 'network' | 'other' | null;

export interface IOCFinding {
  ioc: string;
  ioc_type: IOCType;
  verdict: Verdict;
  confidence: number;
  location: string;
  community_score: number | null;
  vt_malicious: number | null;
  vt_suspicious: number | null;
  vt_harmless: number | null;
  vt_reputation: number | null;
  vt_last_analysis_date: string | null;
  vt_asn: number | null;
  vt_flagging_vendors: string[];
  vt_error: string | null;
  vt_error_type: ErrorType;
  abuse_confidence_score: number | null;
  abuse_total_reports: number | null;
  abuse_country: string | null;
  abuse_isp: string | null;
  abuse_usage_type: string | null;
  abuse_is_tor: boolean | null;
  abuse_last_reported: string | null;
  abuse_error: string | null;
  abuse_error_type: ErrorType;
  geo_city: string | null;
  geo_country: string | null;
  geo_asn: string | null;
  geo_lat: number | null;
  geo_lon: number | null;
  geo_error: string | null;
  geo_error_type: ErrorType;
  is_retryable: boolean;
}

export interface ApiKeys {
  vt_api_key: string;
  abuseipdb_api_key: string;
  ipgeo_api_key: string;
}

export interface Downloads {
  csv: string;
  txt: string;
  stix: string;
}

export interface ScanSummary {
  malicious: number;
  suspicious: number;
  benign: number;
  unknown: number;
}

// SSE event payloads
export interface StartEvent {
  total: number;
  warnings: string[];
  mode: ScanMode;
  generated_at: string;
}

export interface ProgressEvent {
  index: number;
  total: number;
  ioc: string;
  ioc_type: IOCType;
  status: 'querying';
}

export interface ResultEvent {
  index: number;
  total: number;
  finding: IOCFinding;
}

export interface CompleteEvent {
  downloads: Downloads;
  summary: ScanSummary;
  total: number;
  generated_at: string;
}

export interface PrivateIpCheck {
  ip: string;
  is_private: boolean;
  reason: string | null;
}

// Column definitions for export selection
export const EXPORT_COLUMNS: { key: keyof IOCFinding; label: string }[] = [
  { key: 'ioc', label: 'IOC' },
  { key: 'ioc_type', label: 'Type' },
  { key: 'verdict', label: 'Verdict' },
  { key: 'confidence', label: 'Confidence' },
  { key: 'location', label: 'Location' },
  { key: 'vt_malicious', label: 'VT Malicious' },
  { key: 'vt_suspicious', label: 'VT Suspicious' },
  { key: 'vt_harmless', label: 'VT Harmless' },
  { key: 'vt_reputation', label: 'VT Reputation' },
  { key: 'community_score', label: 'Community Score' },
  { key: 'vt_asn', label: 'ASN' },
  { key: 'vt_last_analysis_date', label: 'VT Last Analysis' },
  { key: 'vt_flagging_vendors', label: 'Flagging Vendors' },
  { key: 'vt_error', label: 'VT Error' },
  { key: 'abuse_confidence_score', label: 'AbuseIPDB Confidence' },
  { key: 'abuse_total_reports', label: 'AbuseIPDB Reports' },
  { key: 'abuse_country', label: 'AbuseIPDB Country' },
  { key: 'abuse_isp', label: 'ISP' },
  { key: 'abuse_is_tor', label: 'Is Tor' },
  { key: 'geo_city', label: 'City' },
  { key: 'geo_country', label: 'Country' },
  { key: 'geo_lat', label: 'Latitude' },
  { key: 'geo_lon', label: 'Longitude' },
];
