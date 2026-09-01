'use client';

import { useMemo } from 'react';
import type { IOCFinding } from '@/lib/types';

interface PostScanProgressProps {
  results: IOCFinding[];
  scanTime: string;
}

export function PostScanProgress({ results, scanTime }: PostScanProgressProps) {
  const { stats, threatPct } = useMemo(() => {
    const mal = results.filter((r) => r.verdict === 'malicious').length;
    const susp = results.filter((r) => r.verdict === 'suspicious').length;
    const benign = results.filter((r) => r.verdict === 'benign').length;
    const unk = results.filter((r) => r.verdict === 'unknown').length;
    const total = results.length || 1;
    const threat = Math.round(((mal + susp) / total) * 100);
    return {
      stats: { mal, susp, benign, unk },
      threatPct: threat,
    };
  }, [results]);

  const total = results.length || 1;
  const segments = [
    { label: 'Malicious', count: stats.mal, color: '#FF4D6A', pct: (stats.mal / total) * 100 },
    { label: 'Suspicious', count: stats.susp, color: '#FFB238', pct: (stats.susp / total) * 100 },
    { label: 'Unknown', count: stats.unk, color: '#6E80A6', pct: (stats.unk / total) * 100 },
    { label: 'Benign', count: stats.benign, color: '#2FE08A', pct: (stats.benign / total) * 100 },
  ];

  return (
    <div className="scan-progress" style={{ padding: '20px 22px' }}>
      <div className="progress-header">
        <span className="progress-label">Scan Complete — Threat Assessment</span>
        <span className="progress-count">{results.length} IOCs scanned · {scanTime}</span>
      </div>

      {/* Stacked bar showing verdict distribution */}
      <div style={{ display: 'flex', width: '100%', height: '22px', borderRadius: '4px', overflow: 'hidden', marginBottom: '10px', border: '1px solid #1A2740' }}>
        {segments.map((s) => (
          <div
            key={s.label}
            style={{
              width: `${s.pct}%`,
              background: s.color,
              opacity: s.count > 0 ? 0.85 : 0.15,
              transition: 'width 0.6s ease',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontFamily: 'JetBrains Mono',
              fontSize: '9px',
              fontWeight: '700',
              color: '#060B14',
              overflow: 'hidden',
            }}
          >
            {s.pct > 8 ? s.count : ''}
          </div>
        ))}
      </div>

      {/* Threat level indicator */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '8px' }}>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {segments.map((s) => (
            <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'JetBrains Mono', fontSize: '10px' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '2px', background: s.color, display: 'inline-block' }}></span>
              <span style={{ color: '#64789E' }}>{s.label}:</span>
              <span style={{ color: '#DCE6F5', fontWeight: '600' }}>{s.count}</span>
            </div>
          ))}
        </div>
        <div style={{
          fontFamily: 'JetBrains Mono',
          fontSize: '11px',
          fontWeight: '700',
          padding: '3px 10px',
          borderRadius: '10px',
          background: threatPct >= 50 ? '#3A0F1A' : threatPct >= 25 ? '#3A2A0A' : '#0E3324',
          color: threatPct >= 50 ? '#FF4D6A' : threatPct >= 25 ? '#FFB238' : '#2FE08A',
          border: `1px solid ${threatPct >= 50 ? '#FF4D6A' : threatPct >= 25 ? '#FFB238' : '#2FE08A'}`,
        }}>
          {threatPct >= 50 ? '🔴 HIGH THREAT' : threatPct >= 25 ? '🟡 MODERATE' : '🟢 LOW THREAT'} — {threatPct}%
        </div>
      </div>
    </div>
  );
}
