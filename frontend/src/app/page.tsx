'use client';

import { useState, useCallback, useRef } from 'react';
import { OpsHeader } from '@/components/OpsHeader';
import { SettingsPanel } from '@/components/SettingsPanel';
import { ScanPanel } from '@/components/ScanPanel';
import { ScanProgress } from '@/components/ScanProgress';
import { PostScanProgress } from '@/components/PostScanProgress';
import { ResultsTable } from '@/components/ResultsTable';
import { ChartsPanel } from '@/components/ChartsPanel';
import { ExportPanel } from '@/components/ExportPanel';
import { streamAnalyze, rebuildReports, getKeys } from '@/lib/api';
import type { ScanMode, IOCFinding, ApiKeys, Downloads } from '@/lib/types';

interface LogLine {
  ts: string;
  ioc: string;
  status: string;
  verdict?: string;
}

export default function Home() {
  const [keys, setKeys] = useState<ApiKeys>({ vt_api_key: '', abuseipdb_api_key: '', ipgeo_api_key: '' });
  const [settingsVisible, setSettingsVisible] = useState(true);
  const [mode, setMode] = useState<ScanMode>('combined');
  const [iocs, setIocs] = useState('203.55.131.4\n195.96.139.151\n108.165.121.243');
  const [skipPrivate, setSkipPrivate] = useState(true);
  const [maxAge, setMaxAge] = useState(90);
  const [delay, setDelay] = useState(1.5);

  const [isScanning, setIsScanning] = useState(false);
  const [scanTotal, setScanTotal] = useState(0);
  const [scanCurrent, setScanCurrent] = useState(0);
  const [currentIoc, setCurrentIoc] = useState<string | null>(null);
  const [progressResults, setProgressResults] = useState<IOCFinding[]>([]);
  const [logLines, setLogLines] = useState<LogLine[]>([]);

  const [results, setResults] = useState<IOCFinding[]>([]);
  const [downloads, setDownloads] = useState<Downloads>({} as Downloads);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [isRetrying, setIsRetrying] = useState(false);
  const [scanTime, setScanTime] = useState('');
  const resultsRef = useRef<IOCFinding[]>([]);

  const handleKeysLoaded = useCallback((k: ApiKeys) => setKeys(k), []);
  const handleKeysSaved = useCallback((k: ApiKeys) => setKeys(k), []);

  const handleRun = async () => {
    setIsScanning(true);
    setError(null);
    setWarnings([]);
    setResults([]);
    setDownloads({} as Downloads);
    setProgressResults([]);
    setLogLines([]);
    setScanCurrent(0);
    setCurrentIoc(null);

    await streamAnalyze(
      iocs,
      mode,
      { skip_private: skipPrivate, max_age_days: maxAge, delay },
      {
        onStart: (e) => {
          setScanTotal(e.total);
          if (e.warnings?.length) setWarnings(e.warnings);
        },
        onProgress: (e) => {
          setScanCurrent(e.index);
          setCurrentIoc(e.ioc);
          const ts = new Date().toLocaleTimeString('en-GB');
          setLogLines((prev) => [...prev, { ts, ioc: e.ioc, status: 'querying' }]);
        },
        onResult: (e) => {
          setProgressResults((prev) => [...prev, e.finding]);
          setCurrentIoc(null);
          setLogLines((prev) => {
            const updated = [...prev];
            const last = updated[updated.length - 1];
            if (last && last.ioc === e.finding.ioc && last.status === 'querying') {
              updated[updated.length - 1] = {
                ...last,
                status: e.finding.verdict,
                verdict: e.finding.verdict,
              };
            }
            return updated;
          });
        },
        onComplete: (e) => {
          setDownloads(e.downloads);
          setResults(resultsRef.current);
          setScanTime(e.generated_at || new Date().toLocaleString('en-GB'));
          setIsScanning(false);
        },
        onError: (msg) => {
          setError(msg);
          setIsScanning(false);
        },
      }
    );
  };

  if (isScanning) {
    resultsRef.current = progressResults;
  }

  const handleRetry = async () => {
    const failed = results.filter((r) => r.is_retryable);
    if (!failed.length) return;

    setIsRetrying(true);
    setError(null);

    try {
      try {
        const freshKeys = await getKeys();
        setKeys(freshKeys);
      } catch {}

      const failedIocs = failed.map((r) => r.ioc).join('\n');

      await streamAnalyze(
        failedIocs,
        mode,
        { skip_private: skipPrivate, max_age_days: maxAge, delay },
        {
          onStart: () => {},
          onProgress: () => {},
          onResult: (e) => {
            setResults((prev) => {
              const byIoc = new Map(prev.map((r) => [r.ioc, r]));
              byIoc.set(e.finding.ioc, e.finding);
              return Array.from(byIoc.values());
            });
          },
          onComplete: async (e) => {
            try {
              const rep = await rebuildReports(mode, results);
              setDownloads((prev) => ({ ...prev, ...rep.downloads }));
            } catch {}
          },
          onError: (msg) => setError(msg),
        }
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Retry failed');
    } finally {
      setIsRetrying(false);
    }
  };

  const finalResults = isScanning ? progressResults : results;
  const showCharts = !isScanning && finalResults.length > 0;

  return (
    <>
      <OpsHeader
        vtKeySet={!!(keys.vt_api_key && keys.vt_api_key.trim())}
        abuseKeySet={!!(keys.abuseipdb_api_key && keys.abuseipdb_api_key.trim())}
        onToggleSettings={() => setSettingsVisible(!settingsVisible)}
        settingsVisible={settingsVisible}
      />

      <main>
        {settingsVisible && (
          <SettingsPanel onKeysLoaded={handleKeysLoaded} onKeysSaved={handleKeysSaved} />
        )}

        <ScanPanel
          mode={mode}
          onModeChange={setMode}
          iocs={iocs}
          onIocsChange={setIocs}
          skipPrivate={skipPrivate}
          onSkipPrivateChange={setSkipPrivate}
          maxAge={maxAge}
          onMaxAgeChange={setMaxAge}
          delay={delay}
          onDelayChange={setDelay}
          onRun={handleRun}
          isScanning={isScanning}
          warnings={warnings}
          error={error}
        />

        {isScanning && (
          <ScanProgress
            total={scanTotal}
            current={scanCurrent}
            currentIoc={currentIoc}
            results={progressResults}
            logLines={logLines}
          />
        )}

        {showCharts && (
          <>
            <PostScanProgress results={finalResults} scanTime={scanTime} />
            <ChartsPanel results={finalResults} />
            <ExportPanel results={finalResults} />
          </>
        )}

        {!isScanning && (results.length > 0 || downloads.csv) && (
          <ResultsTable
            results={results}
            downloads={downloads}
            onRetry={handleRetry}
            isRetrying={isRetrying}
          />
        )}
      </main>
    </>
  );
}
