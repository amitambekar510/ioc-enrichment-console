'use client';

import type { IOCFinding } from '@/lib/types';

interface ScanProgressProps {
  total: number;
  current: number;
  currentIoc: string | null;
  results: IOCFinding[];
  logLines: { ts: string; ioc: string; status: string; verdict?: string }[];
}

export function ScanProgress({ total, current, currentIoc, results, logLines }: ScanProgressProps) {
  const percent = total > 0 ? Math.round((current / total) * 100) : 0;

  return (
    <div className="scan-progress">
      <div className="progress-header">
        <span className="progress-label">
          {current < total ? 'Scanning IOCs…' : 'Scan complete'}
        </span>
        <span className="progress-count">
          {current} / {total} IOCs ({percent}%)
        </span>
      </div>

      <div className="progress-bar-container">
        <div className="progress-bar-fill" style={{ width: `${percent}%` }}></div>
      </div>

      <div className="radar-container">
        <div className="radar">
          <div className="radar-sweep"></div>
          <div className="radar-center"></div>
        </div>

        <div className="scan-log">
          {logLines.length === 0 && <div className="log-line">Waiting for first result…</div>}
          {logLines.map((line, i) => (
            <div key={i} className={`log-line ${line.status}`}>
              <span className="ts">[{line.ts}]</span>
              {line.ioc} →{' '}
              {line.status === 'querying' ? 'querying…' : line.verdict || line.status}
            </div>
          ))}
        </div>
      </div>

      <div className="ioc-status-list">
        {results.map((r, i) => (
          <span key={i} className={`ioc-pill ${r.verdict}`}>
            {r.ioc}
          </span>
        ))}
        {currentIoc && (
          <span className="ioc-pill querying">{currentIoc}</span>
        )}
      </div>
    </div>
  );
}
