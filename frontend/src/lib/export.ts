// Client-side export utilities — generate CSV/JSON from results with column selection.
// This lets users pick which columns to include before downloading, without
// needing another backend round-trip.

import type { IOCFinding } from './types';
import { EXPORT_COLUMNS } from './types';

export type ExportFormat = 'csv' | 'json';

export function exportResults(
  results: IOCFinding[],
  format: ExportFormat,
  selectedColumns: Set<string>
): void {
  const cols = EXPORT_COLUMNS.filter((c) => selectedColumns.has(c.key));

  if (format === 'json') {
    const data = results.map((r) => {
      const obj: Record<string, unknown> = {};
      for (const col of cols) {
        let val: unknown = r[col.key];
        if (Array.isArray(val)) val = val.join('; ');
        obj[col.label] = val;
      }
      return obj;
    });
    downloadFile(
      JSON.stringify(data, null, 2),
      'ioc_report.json',
      'application/json'
    );
    return;
  }

  // CSV
  const header = cols.map((c) => `"${c.label}"`).join(',');
  const rows = results.map((r) => {
    return cols
      .map((c) => {
        let val = r[c.key];
        if (Array.isArray(val)) val = val.join('; ');
        if (val == null) val = '';
        const s = String(val);
        // Escape quotes and wrap if needed
        if (s.includes(',') || s.includes('"') || s.includes('\n')) {
          return `"${s.replace(/"/g, '""')}"`;
        }
        return s;
      })
      .join(',');
  });

  const csv = [header, ...rows].join('\n');
  downloadFile(csv, 'ioc_report.csv', 'text/csv');
}

function downloadFile(content: string, filename: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
