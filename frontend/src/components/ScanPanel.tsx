'use client';

import type { ScanMode } from '@/lib/types';

interface ScanPanelProps {
  mode: ScanMode;
  onModeChange: (mode: ScanMode) => void;
  iocs: string;
  onIocsChange: (v: string) => void;
  skipPrivate: boolean;
  onSkipPrivateChange: (v: boolean) => void;
  maxAge: number;
  onMaxAgeChange: (v: number) => void;
  delay: number;
  onDelayChange: (v: number) => void;
  onRun: () => void;
  isScanning: boolean;
  warnings: string[];
  error: string | null;
}

const MODES: { value: ScanMode; label: string; sub: string }[] = [
  { value: 'combined', label: 'Combined', sub: 'VirusTotal + AbuseIPDB' },
  { value: 'vt_only', label: 'VirusTotal only', sub: 'IP / domain / hash' },
  { value: 'abuseipdb_only', label: 'AbuseIPDB only', sub: 'IP only' },
];

export function ScanPanel({
  mode,
  onModeChange,
  iocs,
  onIocsChange,
  skipPrivate,
  onSkipPrivateChange,
  maxAge,
  onMaxAgeChange,
  delay,
  onDelayChange,
  onRun,
  isScanning,
  warnings,
  error,
}: ScanPanelProps) {
  return (
    <section className="panel">
      <h2>Run enrichment</h2>
      <p className="hint">
        Pick a mode, paste IOCs (one per line), run. Private/reserved IPs are automatically
        detected and flagged — they cannot be scanned because they are not reachable from the
        public internet.
      </p>

      <div className="mode-row">
        {MODES.map((m) => (
          <div
            key={m.value}
            className={`mode-btn ${mode === m.value ? 'active' : ''}`}
            onClick={() => onModeChange(m.value)}
          >
            {m.label}
            <small>{m.sub}</small>
          </div>
        ))}
      </div>

      <textarea
        value={iocs}
        onChange={(e) => onIocsChange(e.target.value)}
        placeholder={'8.8.8.8\nexample.com\n44d88612fea8a8f36de82e1278abb02f...'}
      />

      <div className="run-row">
        <label className="opt">
          <input
            type="checkbox"
            checked={skipPrivate}
            onChange={(e) => onSkipPrivateChange(e.target.checked)}
          />
          Skip private/reserved IPs
        </label>
        <label className="opt">
          Max age (days){' '}
          <input
            type="text"
            value={maxAge}
            onChange={(e) => onMaxAgeChange(parseInt(e.target.value || '90', 10))}
          />
        </label>
        <label className="opt">
          Delay/req (s){' '}
          <input
            type="text"
            value={delay}
            onChange={(e) => onDelayChange(parseFloat(e.target.value || '1.5'))}
          />
        </label>
        <div className="spacer"></div>
        <button className="primary" onClick={onRun} disabled={isScanning}>
          {isScanning ? 'Scanning…' : 'Run enrichment'}
        </button>
      </div>

      {warnings.length > 0 && (
        <div className="warnings">
          {warnings.map((w, i) => (
            <div key={i}>⚠ {w}</div>
          ))}
        </div>
      )}

      {error && <div className="error-banner">{error}</div>}
    </section>
  );
}
