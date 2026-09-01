// API client for the IOC Enrichment Console backend (Flask)
// Calls the Flask backend directly (not through Next.js rewrites).
// Set NEXT_PUBLIC_BACKEND_URL in .env.local, or it defaults to localhost:5000.

import type {
  ApiKeys,
  IOCFinding,
  ScanMode,
  PrivateIpCheck,
  StartEvent,
  ProgressEvent,
  ResultEvent,
  CompleteEvent,
  Downloads,
} from './types';

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://127.0.0.1:5000';
const API_BASE = `${BACKEND_URL}/api`;

export async function getKeys(): Promise<ApiKeys> {
  const res = await fetch(`${API_BASE}/keys`);
  if (!res.ok) throw new Error('Failed to fetch API keys');
  return res.json();
}

export async function saveKeys(keys: ApiKeys): Promise<{ status: string; keys: ApiKeys }> {
  const res = await fetch(`${API_BASE}/keys`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(keys),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    throw new Error(data.error || `Failed to save API keys (HTTP ${res.status})`);
  }
  return res.json();
}

export async function checkIp(ip: string): Promise<PrivateIpCheck> {
  const res = await fetch(`${API_BASE}/check-ip`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  });
  if (!res.ok) throw new Error('Failed to check IP');
  return res.json();
}

export async function analyzeBatch(
  iocs: string,
  mode: ScanMode,
  options: { skip_private: boolean; max_age_days: number; delay: number }
): Promise<{ results: IOCFinding[]; warnings: string[]; downloads: Downloads }> {
  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode, iocs, ...options }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Analysis failed');
  return data;
}

/**
 * Stream per-IOC results via SSE. Uses fetch + ReadableStream instead of
 * EventSource because EventSource only supports GET, and we need POST.
 */
export async function streamAnalyze(
  iocs: string,
  mode: ScanMode,
  options: { skip_private: boolean; max_age_days: number; delay: number },
  callbacks: {
    onStart: (e: StartEvent) => void;
    onProgress: (e: ProgressEvent) => void;
    onResult: (e: ResultEvent) => void;
    onComplete: (e: CompleteEvent) => void;
    onError: (msg: string) => void;
  }
): Promise<void> {
  try {
    const res = await fetch(`${API_BASE}/analyze/stream`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'text/event-stream',
      },
      body: JSON.stringify({ mode, iocs, ...options }),
    });

    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      callbacks.onError(data.error || `HTTP ${res.status}`);
      return;
    }

    const reader = res.body?.getReader();
    if (!reader) {
      callbacks.onError('No response body');
      return;
    }

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      // SSE events are separated by double newlines
      const parts = buffer.split('\n\n');
      buffer = parts.pop() || '';

      for (const part of parts) {
        const lines = part.split('\n');
        let event = 'message';
        let data = '';

        for (const line of lines) {
          if (line.startsWith('event:')) {
            event = line.slice(6).trim();
          } else if (line.startsWith('data:')) {
            data += line.slice(5).trim();
          }
        }

        if (!data) continue;

        try {
          const parsed = JSON.parse(data);
          switch (event) {
            case 'start':
              callbacks.onStart(parsed);
              break;
            case 'progress':
              callbacks.onProgress(parsed);
              break;
            case 'result':
              callbacks.onResult(parsed);
              break;
            case 'complete':
              callbacks.onComplete(parsed);
              return;
          }
        } catch {
          // ignore JSON parse errors for partial chunks
        }
      }
    }
  } catch (e) {
    callbacks.onError(e instanceof Error ? e.message : 'Stream failed');
  }
}

export async function rebuildReports(
  mode: ScanMode,
  results: IOCFinding[]
): Promise<{ downloads: Downloads }> {
  const res = await fetch(`${API_BASE}/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode, results }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to rebuild reports');
  return data;
}

export function downloadUrl(filename: string): string {
  return `${API_BASE}/download/${filename}`;
}
