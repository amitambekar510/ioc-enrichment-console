'use client';

import { useEffect, useRef, useMemo } from 'react';
import type { IOCFinding } from '@/lib/types';

interface ThreatChoroplethProps {
  results: IOCFinding[];
}

function getThreatColor(malicious: number, total: number): string {
  if (total === 0) return 'transparent';
  if (malicious >= 8) return '#FF4D6A';
  if (malicious >= 5) return '#CC3D55';
  if (malicious >= 3) return '#992D3B';
  if (malicious >= 2) return '#661E22';
  if (malicious >= 1) return '#3A0F1A';
  return '#0E3324';
}

function loadLeaflet(): Promise<any> {
  return new Promise((resolve, reject) => {
    if ((window as any).L) {
      resolve((window as any).L);
      return;
    }
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
    document.head.appendChild(link);
    const script = document.createElement('script');
    script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
    script.onload = () => resolve((window as any).L);
    script.onerror = () => reject(new Error('Failed to load Leaflet'));
    document.head.appendChild(script);
  });
}

let geoJsonCache: any = null;
async function loadWorldGeoJSON(): Promise<any> {
  if (geoJsonCache) return geoJsonCache;
  const res = await fetch('https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson');
  geoJsonCache = await res.json();
  return geoJsonCache;
}

const TILE_URL = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
const TILE_OPTS = { attribution: '', maxZoom: 18 };

export function ThreatChoropleth({ results }: ThreatChoroplethProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<any>(null);
  const geoJsonLayerRef = useRef<any>(null);

  const countryData = useMemo(() => {
    const m = new Map<string, { total: number; malicious: number; suspicious: number; ips: string[] }>();
    results.forEach((r) => {
      const country = r.geo_country;
      if (!country) return;
      const key = country.toLowerCase();
      const existing = m.get(key) || { total: 0, malicious: 0, suspicious: 0, ips: [] };
      existing.total++;
      if (r.verdict === 'malicious') existing.malicious++;
      if (r.verdict === 'suspicious') existing.suspicious++;
      existing.ips.push(r.ioc);
      m.set(key, existing);
    });
    return m;
  }, [results]);

  const locatedCount = Array.from(countryData.values()).reduce((s, d) => s + d.total, 0);

  useEffect(() => {
    if (!containerRef.current || locatedCount === 0) return;

    let cancelled = false;

    Promise.all([loadLeaflet(), loadWorldGeoJSON()]).then(([L, worldData]) => {
      if (cancelled || !containerRef.current) return;

      if (!mapRef.current) {
        mapRef.current = L.map(containerRef.current, {
          zoomControl: false,
          scrollWheelZoom: false,
          dragging: false,
          doubleClickZoom: false,
          boxZoom: false,
          keyboard: false,
          touchZoom: false,
          attributionControl: false,
        }).setView([20, 0], 1.5);

        const tileLayer = L.tileLayer(TILE_URL, TILE_OPTS);
        tileLayer.addTo(mapRef.current);
        (mapRef.current as any)._tileLayer = tileLayer;
      }

      if (geoJsonLayerRef.current) {
        mapRef.current.removeLayer(geoJsonLayerRef.current);
      }

      function styleFeature(feature: any) {
        const countryName = (feature.properties.NAME || feature.properties.name || '').toLowerCase();
        const data = countryData.get(countryName);
        const fillColor = data ? getThreatColor(data.malicious, data.total) : 'transparent';
        return {
          fillColor,
          fillOpacity: data ? 0.7 : 0,
          color: '#1A2740',
          weight: 0.5,
        };
      }

      geoJsonLayerRef.current = L.geoJson(worldData, {
        style: styleFeature,
        onEachFeature: (feature: any, layer: any) => {
          const countryName = (feature.properties.NAME || feature.properties.name || '').toLowerCase();
          const data = countryData.get(countryName);
          if (data) {
            layer.bindPopup(
              `<div style="font-family: monospace; font-size: 12px;">
                <strong>${feature.properties.NAME || feature.properties.name}</strong><br>
                <span style="color: #FF4D6A;">Malicious: ${data.malicious}</span><br>
                <span style="color: #FFB238;">Suspicious: ${data.suspicious}</span><br>
                Total IOCs: ${data.total}<br>
                <span style="color: #64789E;">${data.ips.join(', ')}</span>
              </div>`
            );
            layer.on('mouseover', () => {
              layer.setStyle({ weight: 2, color: '#33E8C7' });
            });
            layer.on('mouseout', () => {
              layer.setStyle({ weight: 0.5, color: '#1A2740' });
            });
          }
        },
      }).addTo(mapRef.current);

      setTimeout(() => {
        if (mapRef.current) {
          mapRef.current.invalidateSize();
        }
      }, 200);
    }).catch(() => {});

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [locatedCount, countryData]);

  useEffect(() => {
    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, []);

  if (locatedCount === 0) {
    return (
      <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
        <h3 className="chart-title">Choropleth — Threat Intensity by Country</h3>
        <div style={{ textAlign: 'center', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '12px', padding: '40px 0' }}>
          No country data available.
        </div>
      </div>
    );
  }

  return (
    <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
      <h3 className="chart-title">
        Choropleth — Threat Intensity by Country
        <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginLeft: '8px' }}>
          ({locatedCount} IPs across {countryData.size} countries — hover/click countries)
        </span>
      </h3>
      <div
        ref={containerRef}
        className="leaflet-dark-container"
        style={{
          width: '100%',
          height: '380px',
          borderRadius: '6px',
          overflow: 'hidden',
          border: '1px solid var(--line)',
          background: '#060B14',
          zIndex: 0,
        }}
      />
      <div style={{ display: 'flex', gap: '10px', marginTop: '8px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--text-dim)' }}>
          <span style={{ width: '12px', height: '12px', borderRadius: '2px', background: '#0E3324', display: 'inline-block', border: '1px solid var(--line)' }}></span>
          Benign
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--text-dim)' }}>
          <span style={{ width: '12px', height: '12px', borderRadius: '2px', background: '#3A0F1A', display: 'inline-block', border: '1px solid var(--line)' }}></span>
          Low (1+)
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--text-dim)' }}>
          <span style={{ width: '12px', height: '12px', borderRadius: '2px', background: '#661E22', display: 'inline-block', border: '1px solid var(--line)' }}></span>
          Medium (2+)
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--text-dim)' }}>
          <span style={{ width: '12px', height: '12px', borderRadius: '2px', background: '#992D3B', display: 'inline-block', border: '1px solid var(--line)' }}></span>
          High (3+)
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--text-dim)' }}>
          <span style={{ width: '12px', height: '12px', borderRadius: '2px', background: '#CC3D55', display: 'inline-block', border: '1px solid var(--line)' }}></span>
          Severe (5+)
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--text-dim)' }}>
          <span style={{ width: '12px', height: '12px', borderRadius: '2px', background: '#FF4D6A', display: 'inline-block', border: '1px solid var(--line)' }}></span>
          Critical (8+)
        </div>
      </div>
    </div>
  );
}
