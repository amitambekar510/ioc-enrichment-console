'use client';

import { useMemo } from 'react';
import type { IOCFinding } from '@/lib/types';

interface MaliciousPieChartProps {
  results: IOCFinding[];
}

export function MaliciousPieChart({ results }: MaliciousPieChartProps) {
  const { malicious, nonMalicious } = useMemo(() => {
    let mal = 0;
    let nonMal = 0;
    results.forEach((r) => {
      if (r.verdict === 'malicious') mal++;
      else nonMal++;
    });
    return { malicious: mal, nonMalicious: nonMal };
  }, [results]);

  const total = results.length || 1;
  const malFraction = malicious / total;
  const nonMalFraction = nonMalicious / total;

  const radius = 50;
  const circumference = 2 * Math.PI * radius;

  return (
    <div className="chart-card">
      <h3 className="chart-title">Malicious vs Non-Malicious</h3>
      <div className="donut-container">
        <svg className="donut-svg" width="140" height="140" viewBox="0 0 140 140">
          <circle cx="70" cy="70" r={radius} fill="none" stroke="#1A2740" strokeWidth="14" />
          {/* Non-malicious arc (green) */}
          <circle
            cx="70" cy="70" r={radius} fill="none"
            stroke="#2FE08A" strokeWidth="14"
            strokeDasharray={`${nonMalFraction * circumference} ${circumference}`}
            strokeDashoffset={-malFraction * circumference}
            transform="rotate(-90 70 70)"
            style={{ transition: 'stroke-dasharray 0.6s ease' }}
          />
          {/* Malicious arc (red) */}
          <circle
            cx="70" cy="70" r={radius} fill="none"
            stroke="#FF4D6A" strokeWidth="14"
            strokeDasharray={`${malFraction * circumference} ${circumference}`}
            strokeDashoffset="0"
            transform="rotate(-90 70 70)"
            style={{ transition: 'stroke-dasharray 0.6s ease' }}
          />
          <text x="70" y="66" textAnchor="middle" fill="#FF4D6A" fontSize="26" fontFamily="JetBrains Mono" fontWeight="700">
            {malicious}
          </text>
          <text x="70" y="82" textAnchor="middle" fill="#64789E" fontSize="9" fontFamily="JetBrains Mono">
            MALICIOUS
          </text>
        </svg>
        <div className="donut-legend">
          <div className="legend-item">
            <span className="legend-color" style={{ background: '#FF4D6A' }}></span>
            Malicious: {malicious} ({Math.round(malFraction * 100)}%)
          </div>
          <div className="legend-item">
            <span className="legend-color" style={{ background: '#2FE08A' }}></span>
            Non-Malicious: {nonMalicious} ({Math.round(nonMalFraction * 100)}%)
          </div>
        </div>
      </div>
    </div>
  );
}
