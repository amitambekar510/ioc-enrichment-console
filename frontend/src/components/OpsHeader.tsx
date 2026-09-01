'use client';

import { useISTClock } from '@/hooks/useISTClock';

interface OpsHeaderProps {
  vtKeySet: boolean;
  abuseKeySet: boolean;
  onToggleSettings: () => void;
  settingsVisible: boolean;
}

export function OpsHeader({ vtKeySet, abuseKeySet, onToggleSettings, settingsVisible }: OpsHeaderProps) {
  const clock = useISTClock();

  return (
    <header className="ops-bar">
      <div className="ops-left">
        <span className="ops-mark">SOC</span>
        <div className="ops-title">
          <h1>IOC Enrichment Console</h1>
          <span className="ops-sub">threat intel · reputation monitoring</span>
        </div>
      </div>
      <div className="ops-status">
        <div className="status-item">
          <span className={`status-dot ${vtKeySet ? 'on' : ''}`}></span>
          VT
        </div>
        <div className="status-item">
          <span className={`status-dot ${abuseKeySet ? 'on' : ''}`}></span>
          ABUSEIPDB
        </div>
        <div className="status-item live">
          <span className="pulse-dot"></span>
          LIVE
        </div>
        <div className="status-clock">{clock}</div>
        <button className="ghost" onClick={onToggleSettings}>
          {settingsVisible ? 'Hide Settings' : 'Settings'}
        </button>
      </div>
    </header>
  );
}
