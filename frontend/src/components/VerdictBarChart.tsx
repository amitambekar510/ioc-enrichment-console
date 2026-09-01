'use client';

import { useMemo } from 'react';
import type { IOCFinding, Verdict } from '@/lib/types';

interface VerdictBarChartProps {
  results: IOCFinding[];
}

const VERDICT_COLORS: Record<Verdict, string> = {
  malicious: '#FF4D6A',
  suspicious: '#FFB238',
  benign: '#2FE08A',
  unknown: '#6E80A6',
};

const VERDICT_ORDER: Verdict[] = ['malicious', 'suspicious', 'benign', 'unknown'];

export function VerdictBarChart({ results }: VerdictBarChartProps) {
  const counts = useMemo(() => {
    const c: Record<Verdict, number> = { malicious: 0, suspicious: 0, benign: 0, unknown: 0 };
    results.forEach((r) => c[r.verdict]++);
    return c;
  }, [results]);

  const maxVal = Math.max(...VERDICT_ORDER.map((v) => counts[v]), 1);
  const chartW = 360;
  const chartH = 130;
  const barH = 20;
  const gap = 14;
  const labelW = 80;
  const startX = labelW;

  return (
    <div className="chart-card">
      <h3 className="chart-title">Verdict Breakdown</h3>
      <svg width="100%" height={chartH} viewBox={`0 0 ${chartW} ${chartH}`}>
        {/* Background grid */}
        {[0.25, 0.5, 0.75, 1].map((f) => {
          const x = startX + f * (chartW - labelW - 30);
          return (
            <g key={f}>
              <line x1={x} y1="5" x2={x} y2={chartH - 15} stroke="#1A2740" strokeWidth="0.5" />
              <text x={x} y={chartH - 4} textAnchor="middle" fill="#3D4E6E" fontSize="7" fontFamily="JetBrains Mono">
                {Math.round(f * maxVal)}
              </text>
            </g>
          );
        })}

        {VERDICT_ORDER.map((v, i) => {
          const val = counts[v];
          const barW = (val / maxVal) * (chartW - labelW - 30);
          const y = i * (barH + gap) + 6;
          return (
            <g key={v}>
              {/* Label */}
              <text x={labelW - 6} y={y + barH / 2 + 3} textAnchor="end" fill="#64789E" fontSize="9" fontFamily="JetBrains Mono">
                {v.toUpperCase()}
              </text>
              {/* Bar background */}
              <rect x={startX} y={y} width={chartW - labelW - 30} height={barH} fill="#08111E" rx="2" />
              {/* Bar fill with animation */}
              <rect x={startX} y={y} width={barW} height={barH} fill={VERDICT_COLORS[v]} rx="2" opacity="0.85"
                style={{ transition: 'width 0.6s ease' }}
              />
              {/* Count label at end of bar */}
              <text x={startX + barW + 4} y={y + barH / 2 + 3} fill="#DCE6F5" fontSize="9" fontFamily="JetBrains Mono" fontWeight="600">
                {val}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
