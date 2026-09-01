'use client';

import type { IOCFinding, Verdict } from '@/lib/types';

interface SummaryChipsProps {
  results: IOCFinding[];
}

export function SummaryChips({ results }: SummaryChipsProps) {
  const counts: Record<Verdict, number> = {
    malicious: 0,
    suspicious: 0,
    benign: 0,
    unknown: 0,
  };
  results.forEach((r) => counts[r.verdict]++);

  const chips: { key: string; label: string; value: number }[] = [
    { key: 'mal', label: 'MALICIOUS', value: counts.malicious },
    { key: 'susp', label: 'SUSPICIOUS', value: counts.suspicious },
    { key: 'benign', label: 'BENIGN', value: counts.benign },
    { key: 'unk', label: 'UNKNOWN', value: counts.unknown },
  ];

  return (
    <div className="summary-chips">
      {chips.map((c) => (
        <div key={c.key} className={`chip ${c.key}`}>
          <span className="chip-num">{c.value}</span>
          <span className="chip-label">{c.label}</span>
        </div>
      ))}
    </div>
  );
}
