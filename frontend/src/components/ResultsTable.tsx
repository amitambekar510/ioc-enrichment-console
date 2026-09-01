'use client';

import type { IOCFinding, Downloads } from '@/lib/types';
import { downloadUrl } from '@/lib/api';
import { SummaryChips } from './SummaryChips';

interface ResultsTableProps {
  results: IOCFinding[];
  downloads: Downloads;
  onRetry: () => void;
  isRetrying: boolean;
}

const ERROR_LABELS: Record<string, string> = {
  auth: 'key issue',
  rate_limit: 'rate limited',
  network: 'network',
  not_found: 'not found',
  other: 'error',
};

function ErrCell({ msg, type }: { msg: string | null; type: string | null }) {
  if (!msg) return null;
  const badge = type ? (
    <span className={`err-type ${type}`}>{ERROR_LABELS[type] || type}</span>
  ) : null;
  return (
    <>
      {badge}
      <span className="err-msg">{msg}</span>
    </>
  );
}

export function ResultsTable({ results, downloads, onRetry, isRetrying }: ResultsTableProps) {
  const retryableCount = results.filter((r) => r.is_retryable).length;
  const order: Record<string, number> = { malicious: 0, suspicious: 1, unknown: 2, benign: 3 };
  const sorted = [...results].sort((a, b) => order[a.verdict] - order[b.verdict]);

  return (
    <section className="panel">
      <div className="results-head">
        <SummaryChips results={results} />

        <div className="downloads">
          {retryableCount > 0 && (
            <button
              className={`retry-btn show`}
              onClick={onRetry}
              disabled={isRetrying}
            >
              {isRetrying ? 'Retrying…' : `Retry failed only (${retryableCount})`}
            </button>
          )}
          {downloads.csv && (
            <a href={downloadUrl(downloads.csv)} download>
              CSV
            </a>
          )}
          {downloads.txt && (
            <a href={downloadUrl(downloads.txt)} download>
              Text
            </a>
          )}
          {downloads.stix && (
            <a href={downloadUrl(downloads.stix)} download>
              STIX 2.1
            </a>
          )}
        </div>
      </div>

      {results.length === 0 ? (
        <div className="empty-state">No results.</div>
      ) : (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>IOC</th>
                <th>Verdict</th>
                <th>Confidence</th>
                <th>VirusTotal</th>
                <th>AbuseIPDB</th>
                <th>Location</th>
                <th>Flagged by</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((r, i) => {
                const vtErr = r.vt_error ? (
                  <ErrCell msg={r.vt_error} type={r.vt_error_type} />
                ) : null;
                const abuseErr = r.abuse_error ? (
                  <ErrCell msg={r.abuse_error} type={r.abuse_error_type} />
                ) : null;

                return (
                  <tr key={i}>
                    <td>
                      <span className="ioc-cell">{r.ioc}</span>
                      <span className="type-tag">{r.ioc_type}</span>
                    </td>
                    <td>
                      <span className={`verdict-badge ${r.verdict}`}>{r.verdict}</span>
                    </td>
                    <td>{r.confidence}</td>
                    <td>
                      {vtErr ||
                        (r.vt_malicious != null
                          ? `${r.vt_malicious}m / ${r.vt_suspicious}s / ${r.vt_harmless}h`
                          : '—')}
                    </td>
                    <td>
                      {abuseErr ||
                        (r.abuse_confidence_score != null
                          ? `${r.abuse_confidence_score}/100 (${r.abuse_total_reports} rpts)`
                          : '—')}
                    </td>
                    <td>{r.location || 'N/A'}</td>
                    <td>
                      <span
                        className="vendors"
                        title={(r.vt_flagging_vendors || []).join(', ')}
                      >
                        {(r.vt_flagging_vendors || []).slice(0, 3).join(', ') || '—'}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
