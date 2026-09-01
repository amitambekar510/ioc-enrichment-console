'use client';

import { useMemo, useState } from 'react';
import type { IOCFinding, Verdict } from '@/lib/types';
import { MaliciousPieChart } from './MaliciousPieChart';
import { VerdictBarChart } from './VerdictBarChart';
import { VendorWordCloud } from './VendorWordCloud';
import { ThreatMap } from './ThreatMap';
import { ThreatChoropleth } from './ThreatChoropleth';

interface ChartsPanelProps {
  results: IOCFinding[];
}

const VERDICT_COLORS: Record<Verdict, string> = {
  malicious: '#FF4D6A',
  suspicious: '#FFB238',
  benign: '#2FE08A',
  unknown: '#6E80A6',
};

export function ChartsPanel({ results }: ChartsPanelProps) {
  return (
    <div className="charts-grid">
      <MaliciousPieChart results={results} />
      <VerdictBarChart results={results} />
      <ThreatMap results={results} />
      <ThreatChoropleth results={results} />

      {/* Confidence Scatter */}
      <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
        <h3 className="chart-title">Confidence Scores per IOC</h3>
        <svg width="100%" height="160" viewBox="0 0 760 160">
          {[0, 25, 50, 75, 100].map((p) => {
            const y = 130 - (p / 100) * 110;
            return (
              <g key={p}>
                <line x1="50" y1={y} x2="750" y2={y} stroke="#1A2740" strokeWidth="0.5" />
                <text x="42" y={y + 3} textAnchor="end" fill="#3D4E6E" fontSize="8" fontFamily="JetBrains Mono">{p}</text>
              </g>
            );
          })}
          <line x1="50" y1="47" x2="750" y2="47" stroke="#FF4D6A" strokeWidth="0.5" strokeDasharray="4 4" opacity="0.3" />
          {results.map((r, i) => {
            const x = 60 + (i / Math.max(results.length - 1, 1)) * 680;
            const y = 130 - (r.confidence / 100) * 110;
            return (
              <g key={i}>
                <circle cx={x} cy={y} r="4" fill={VERDICT_COLORS[r.verdict]} opacity="0.8">
                  <title>{r.ioc} — confidence {r.confidence} [{r.verdict}]</title>
                </circle>
                <text x={x} y={y - 8} textAnchor="middle" fill="#3D4E6E" fontSize="6" fontFamily="JetBrains Mono">
                  {r.ioc.length > 12 ? r.ioc.slice(0, 10) + '..' : r.ioc}
                </text>
              </g>
            );
          })}
          <line x1="50" y1="130" x2="750" y2="130" stroke="#26385A" strokeWidth="1" />
        </svg>
      </div>

      <VendorWordCloud results={results} />
    </div>
  );
}
