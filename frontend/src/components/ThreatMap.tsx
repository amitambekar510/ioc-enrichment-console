'use client';

import { useEffect, useRef } from 'react';
import type { IOCFinding, Verdict } from '@/lib/types';

interface ThreatMapProps {
  results: IOCFinding[];
}

const VERDICT_COLORS: Record<Verdict, string> = {
  malicious: '#FF4D6A',
  suspicious: '#FFB238',
  benign: '#2FE08A',
  unknown: '#6E80A6',
};

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

// OpenStreetMap standard tiles — free, no API key, always reliable
const TILE_URL = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
const TILE_OPTS = {
  attribution: '',
  maxZoom: 18,
};

export function ThreatMap({ results }: ThreatMapProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const mapRef = useRef<any>(null);
  const markersRef = useRef<any[]>([]);

  const geoPoints = results.filter(
    (r) => r.geo_lat != null && r.geo_lon != null
  );

  useEffect(() => {
    if (!containerRef.current || geoPoints.length === 0) return;

    let cancelled = false;

    loadLeaflet().then((L) => {
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
        }).setView([20, 0], 2);

        const tileLayer = L.tileLayer(TILE_URL, TILE_OPTS);
        tileLayer.addTo(mapRef.current);
        (mapRef.current as any)._tileLayer = tileLayer;
      }

      // Clear old markers
      markersRef.current.forEach((m) => {
        if (m._interval) clearInterval(m._interval);
        mapRef.current.removeLayer(m);
      });
      markersRef.current = [];

      // Add markers
      geoPoints.forEach((r) => {
        const color = VERDICT_COLORS[r.verdict];
        const marker = L.circleMarker([r.geo_lat!, r.geo_lon!], {
          radius: 7,
          fillColor: color,
          color: '#060B14',
          weight: 2,
          opacity: 1,
          fillOpacity: 0.85,
        }).addTo(mapRef.current);

        marker.bindPopup(
          `<div style="font-family: monospace; font-size: 12px;">
            <strong style="color: ${color};">${r.ioc}</strong><br>
            <span style="color: #64789E;">${r.verdict.toUpperCase()}</span><br>
            ${r.geo_city || 'Unknown'}, ${r.geo_country || 'Unknown'}<br>
            <span style="color: #64789E;">Confidence: ${r.confidence}</span><br>
            <span style="color: #64789E;">Lat: ${r.geo_lat?.toFixed(2)}, Lon: ${r.geo_lon?.toFixed(2)}</span>
          </div>`
        );

        if (r.verdict === 'malicious') {
          const pulseMarker = L.circleMarker([r.geo_lat!, r.geo_lon!], {
            radius: 7,
            fillColor: color,
            color: color,
            weight: 1,
            opacity: 0.4,
            fillOpacity: 0,
          }).addTo(mapRef.current);
          markersRef.current.push(pulseMarker);

          let growing = true;
          const interval = setInterval(() => {
            let rad = pulseMarker.getRadius();
            if (growing) {
              rad += 0.5;
              if (rad > 18) growing = false;
            } else {
              rad -= 0.5;
              if (rad < 7) {
                growing = true;
                rad = 7;
              }
            }
            pulseMarker.setRadius(rad);
            pulseMarker.setStyle({ opacity: 0.4 * (1 - (rad - 7) / 11) });
          }, 50);
          (pulseMarker as any)._interval = interval;
        }

        markersRef.current.push(marker);
      });

      // Fit bounds
      if (geoPoints.length > 0) {
        const bounds = L.latLngBounds(
          geoPoints.map((r) => [r.geo_lat!, r.geo_lon!])
        );
        mapRef.current.fitBounds(bounds, { padding: [50, 50], maxZoom: 4 });
      }

      // Force tile render — must run after the container is visible
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
  }, [geoPoints.length]);

  useEffect(() => {
    return () => {
      markersRef.current.forEach((m) => {
        if (m._interval) clearInterval(m._interval);
      });
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, []);

  if (geoPoints.length === 0) {
    return (
      <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
        <h3 className="chart-title">Threat Geographic Map</h3>
        <div style={{ textAlign: 'center', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: '12px', padding: '40px 0' }}>
          No geolocation data available.
        </div>
      </div>
    );
  }

  return (
    <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
      <h3 className="chart-title">
        Threat Geographic Map
        <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', marginLeft: '8px' }}>
          ({geoPoints.length} of {results.length} IPs located — click dots for details)
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
      <div style={{ display: 'flex', gap: '12px', marginTop: '8px', flexWrap: 'wrap' }}>
        {(Object.keys(VERDICT_COLORS) as Verdict[]).map((v) => (
          <div key={v} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-dim)' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: VERDICT_COLORS[v], display: 'inline-block' }}></span>
            {v}
          </div>
        ))}
      </div>
    </div>
  );
}
