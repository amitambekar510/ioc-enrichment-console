'use client';

import { useState, useEffect } from 'react';
import { getKeys, saveKeys } from '@/lib/api';
import type { ApiKeys } from '@/lib/types';

interface SettingsPanelProps {
  onKeysLoaded: (keys: ApiKeys) => void;
  onKeysSaved: (keys: ApiKeys) => void;
}

export function SettingsPanel({ onKeysLoaded, onKeysSaved }: SettingsPanelProps) {
  const [vtKey, setVtKey] = useState('');
  const [abuseKey, setAbuseKey] = useState('');
  const [geoKey, setGeoKey] = useState('');
  const [showVt, setShowVt] = useState(false);
  const [showAbuse, setShowAbuse] = useState(false);
  const [showGeo, setShowGeo] = useState(false);
  const [saveStatus, setSaveStatus] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getKeys()
      .then((data) => {
        setVtKey(data.vt_api_key || '');
        setAbuseKey(data.abuseipdb_api_key || '');
        setGeoKey(data.ipgeo_api_key || '');
        onKeysLoaded(data);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [onKeysLoaded]);

  const handleSave = async () => {
    const keys: ApiKeys = {
      vt_api_key: vtKey.trim(),
      abuseipdb_api_key: abuseKey.trim(),
      ipgeo_api_key: geoKey.trim(),
    };
    try {
      const data = await saveKeys(keys);
      // Notify parent that keys were saved — this updates the header
      // status dots AND ensures Retry will use the new keys.
      onKeysSaved(data.keys);
      onKeysLoaded(data.keys);
      setSaveStatus(true);
      setTimeout(() => setSaveStatus(false), 1600);
    } catch {
      // silently fail — user can retry
    }
  };

  if (loading) return null;

  return (
    <section className="panel">
      <h2>API Keys</h2>
      <p className="hint">
        Saved to <code>config.json</code> on the backend server and pre-filled here until you
        change them. If an API key is expired or rate-limited, paste a new key here and click
        <strong> Save keys</strong> — then hit <strong>Retry failed only</strong> to re-scan
        with the updated key. The backend picks up the new key automatically.
      </p>
      <div className="settings-grid">
        <div className="field">
          <label>
            VirusTotal API key <span className="req">*</span>
          </label>
          <div className="key-row">
            <input
              type={showVt ? 'text' : 'password'}
              value={vtKey}
              onChange={(e) => setVtKey(e.target.value)}
              placeholder="Paste key"
            />
            <button className="toggle-vis" onClick={() => setShowVt(!showVt)}>
              {showVt ? 'hide' : 'show'}
            </button>
          </div>
        </div>
        <div className="field">
          <label>
            AbuseIPDB API key <span className="req">*</span>
          </label>
          <div className="key-row">
            <input
              type={showAbuse ? 'text' : 'password'}
              value={abuseKey}
              onChange={(e) => setAbuseKey(e.target.value)}
              placeholder="Paste key"
            />
            <button className="toggle-vis" onClick={() => setShowAbuse(!showAbuse)}>
              {showAbuse ? 'hide' : 'show'}
            </button>
          </div>
        </div>
        <div className="field">
          <label>ipgeolocation.io key (optional)</label>
          <div className="key-row">
            <input
              type={showGeo ? 'text' : 'password'}
              value={geoKey}
              onChange={(e) => setGeoKey(e.target.value)}
              placeholder="Paste key"
            />
            <button className="toggle-vis" onClick={() => setShowGeo(!showGeo)}>
              {showGeo ? 'hide' : 'show'}
            </button>
          </div>
        </div>
      </div>
      <div className="settings-footer">
        <button className="primary" onClick={handleSave}>
          Save keys
        </button>
        <span className={`save-status ${saveStatus ? 'show' : ''}`}>Saved</span>
      </div>
    </section>
  );
}
