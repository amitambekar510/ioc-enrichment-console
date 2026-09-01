'use client';

import { useState } from 'react';
import type { IOCFinding } from '@/lib/types';
import { EXPORT_COLUMNS } from '@/lib/types';
import { exportResults } from '@/lib/export';

interface ExportPanelProps {
  results: IOCFinding[];
}

const DEFAULT_COLUMNS = new Set([
  'ioc',
  'ioc_type',
  'verdict',
  'confidence',
  'location',
  'vt_malicious',
  'vt_suspicious',
  'vt_harmless',
  'abuse_confidence_score',
  'abuse_total_reports',
]);

export function ExportPanel({ results }: ExportPanelProps) {
  const [selected, setSelected] = useState<Set<string>>(new Set(DEFAULT_COLUMNS));

  const toggleColumn = (key: string) => {
    const next = new Set(selected);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setSelected(next);
  };

  const selectAll = () => setSelected(new Set(EXPORT_COLUMNS.map((c) => c.key)));
  const selectNone = () => setSelected(new Set());

  return (
    <section className="export-panel">
      <h2>Export Results (CSV / JSON)</h2>
      <p className="hint">
        Select which columns to include, then download as CSV or JSON. The backend-generated
        CSV, text report, and STIX 2.1 bundle are also available above the results table.
      </p>

      <div className="export-columns">
        <button className="ghost" onClick={selectAll} style={{ fontSize: '11px', padding: '4px 8px' }}>
          Select all
        </button>
        <button className="ghost" onClick={selectNone} style={{ fontSize: '11px', padding: '4px 8px' }}>
          Clear
        </button>
        {EXPORT_COLUMNS.map((col) => (
          <label key={col.key} className="column-checkbox">
            <input
              type="checkbox"
              checked={selected.has(col.key)}
              onChange={() => toggleColumn(col.key)}
            />
            {col.label}
          </label>
        ))}
      </div>

      <div className="export-buttons">
        <button className="primary" onClick={() => exportResults(results, 'csv', selected)}>
          Download CSV
        </button>
        <button className="primary" onClick={() => exportResults(results, 'json', selected)}>
          Download JSON
        </button>
      </div>
    </section>
  );
}
