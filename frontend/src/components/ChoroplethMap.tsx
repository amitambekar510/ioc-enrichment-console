'use client';

import { useMemo, useState } from 'react';
import type { IOCFinding, Verdict } from '@/lib/types';

interface ChoroplethMapProps {
  results: IOCFinding[];
}

// Threat level colors (darker = more malicious IOCs)
const THREAT_COLORS = [
  { threshold: 0, color: '#0C1626', label: 'No data' },
  { threshold: 1, color: '#1A3A2E', label: 'Benign (1+)' },
  { threshold: 2, color: '#3A4A0A', label: 'Low threat (2+)' },
  { threshold: 3, color: '#6E4A0A', label: 'Medium (3+)' },
  { threshold: 5, color: '#8A4A1A', label: 'High (5+)' },
  { threshold: 8, color: '#FF4D6A', label: 'Critical (8+)' },
];

function getThreatColor(maliciousCount: number, totalCount: number): string {
  if (totalCount === 0) return THREAT_COLORS[0].color;
  if (maliciousCount >= 8) return THREAT_COLORS[5].color;
  if (maliciousCount >= 5) return THREAT_COLORS[4].color;
  if (maliciousCount >= 3) return THREAT_COLORS[3].color;
  if (maliciousCount >= 2) return THREAT_COLORS[2].color;
  if (maliciousCount >= 1) return THREAT_COLORS[1].color;
  return '#0E3324'; // benign-only
}

// Simplified continent region paths for choropleth coloring.
// Each region is a country/area drawn as an SVG path in the 800x400 viewBox.
// These are approximate shapes for visual representation, not survey-grade.
const REGIONS: { name: string; path: string; lat: number; lon: number }[] = [
  { name: 'USA', lat: 39, lon: -98, path: 'M 95 80 L 155 72 L 185 78 L 200 90 L 195 105 L 180 115 L 165 125 L 145 135 L 125 138 L 110 130 L 98 115 L 92 95 Z' },
  { name: 'Canada', lat: 56, lon: -106, path: 'M 80 50 L 160 45 L 200 50 L 210 60 L 200 70 L 180 75 L 150 72 L 120 68 L 85 62 Z' },
  { name: 'Brazil', lat: -10, lon: -55, path: 'M 180 190 L 215 185 L 240 195 L 245 215 L 240 240 L 225 260 L 210 255 L 195 235 L 185 210 Z' },
  { name: 'UK', lat: 54, lon: -2, path: 'M 348 75 L 360 70 L 363 82 L 355 92 L 346 88 Z' },
  { name: 'Germany', lat: 51, lon: 10, path: 'M 385 72 L 398 68 L 405 78 L 400 88 L 388 85 L 383 78 Z' },
  { name: 'France', lat: 46, lon: 2, path: 'M 372 82 L 385 78 L 390 88 L 385 98 L 375 95 L 368 90 Z' },
  { name: 'Russia', lat: 61, lon: 90, path: 'M 410 52 L 530 48 L 620 52 L 670 58 L 680 68 L 660 75 L 620 72 L 560 70 L 490 68 L 420 65 L 408 58 Z' },
  { name: 'China', lat: 35, lon: 105, path: 'M 570 78 L 620 75 L 645 82 L 650 95 L 635 105 L 610 108 L 585 105 L 572 95 L 568 85 Z' },
  { name: 'India', lat: 21, lon: 79, path: 'M 540 120 L 555 118 L 565 135 L 562 155 L 550 165 L 538 158 L 533 140 Z' },
  { name: 'Japan', lat: 36, lon: 138, path: 'M 690 82 L 700 78 L 708 88 L 703 102 L 693 98 Z' },
  { name: 'Australia', lat: -25, lon: 134, path: 'M 620 245 L 660 240 L 690 250 L 700 268 L 690 288 L 665 298 L 635 293 L 618 278 L 612 260 Z' },
  { name: 'South Africa', lat: -29, lon: 24, path: 'M 420 245 L 445 242 L 460 250 L 465 265 L 455 278 L 440 280 L 425 270 L 418 258 Z' },
  { name: 'Egypt', lat: 27, lon: 30, path: 'M 422 128 L 438 125 L 448 135 L 444 148 L 432 150 L 422 140 Z' },
  { name: 'Nigeria', lat: 9, lon: 8, path: 'M 395 155 L 408 152 L 415 162 L 412 175 L 400 178 L 390 168 Z' },
  { name: 'Saudi Arabia', lat: 24, lon: 45, path: 'M 445 130 L 465 128 L 478 135 L 482 148 L 472 160 L 458 158 L 448 148 Z' },
  { name: 'Iran', lat: 32, lon: 53, path: 'M 478 105 L 498 102 L 512 108 L 515 120 L 505 128 L 488 125 L 478 118 Z' },
  { name: 'Turkey', lat: 39, lon: 35, path: 'M 425 95 L 448 92 L 462 98 L 465 108 L 452 112 L 438 110 L 425 105 Z' },
  { name: 'Mexico', lat: 23, lon: -102, path: 'M 105 115 L 130 112 L 145 118 L 140 130 L 125 135 L 110 132 L 100 125 Z' },
  { name: 'Argentina', lat: -38, lon: -64, path: 'M 195 245 L 215 242 L 225 255 L 220 275 L 210 290 L 198 285 L 192 268 Z' },
  { name: 'Indonesia', lat: -2, lon: 118, path: 'M 610 168 L 635 165 L 655 172 L 650 182 L 630 185 L 612 180 Z' },
  { name: 'South Korea', lat: 37, lon: 128, path: 'M 660 85 L 672 82 L 678 92 L 672 102 L 662 98 Z' },
  { name: 'Spain', lat: 40, lon: -4, path: 'M 358 88 L 372 85 L 378 95 L 372 102 L 360 100 L 355 93 Z' },
  { name: 'Italy', lat: 42, lon: 12, path: 'M 398 88 L 408 85 L 415 92 L 418 102 L 412 110 L 402 105 L 395 97 Z' },
  { name: 'Netherlands', lat: 52, lon: 5, path: 'M 378 72 L 386 70 L 390 76 L 386 82 L 378 80 Z' },
  { name: 'Singapore', lat: 1, lon: 104, path: 'M 635 158 L 642 156 L 645 162 L 640 166 L 635 163 Z' },
];

export function ChoroplethMap({ results }: ChoroplethMapProps) {
  const [hovered, setHovered] = useState<string | null>(null);

  // Aggregate by country
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

  // Map country names to region shapes
  const coloredRegions = REGIONS.map((region) => {
    const data = countryData.get(region.name.toLowerCase());
    return {
      ...region,
      data,
      color: data ? getThreatColor(data.malicious, data.total) : THREAT_COLORS[0].color,
    };
  });

  const locatedCount = Array.from(countryData.values()).reduce((s, d) => s + d.total, 0);

  return (
    <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
      <h3 className="chart-title">
        Choropleth — Threat Intensity by Country
        <span style={{ fontSize: '11px', color: '#64789E', fontFamily: 'JetBrains Mono', marginLeft: '8px' }}>
          ({locatedCount} IPs across {countryData.size} countries)
        </span>
      </h3>

      {locatedCount === 0 ? (
        <div style={{ textAlign: 'center', color: '#64789E', fontFamily: 'JetBrains Mono', fontSize: '12px', padding: '40px 0' }}>
          No country data available. Countries will be colored here when geo data is returned for scanned IPs.
        </div>
      ) : (
        <>
          <svg viewBox="0 0 800 400" style={{ width: '100%', maxHeight: '400px' }}>
            {/* Ocean */}
            <rect x="0" y="0" width="800" height="400" fill="#08111E" rx="6" />

            {/* Grid */}
            {Array.from({ length: 8 }, (_, i) => (i + 1) * 50).map((y) => (
              <line key={`h${y}`} x1="0" y1={y} x2="800" y2={y} stroke="#0C1626" strokeWidth="0.5" />
            ))}
            {Array.from({ length: 16 }, (_, i) => (i + 1) * 50).map((x) => (
              <line key={`v${x}`} x1={x} y1="0" x2={x} y2="400" stroke="#0C1626" strokeWidth="0.5" />
            ))}

            {/* Country regions */}
            {coloredRegions.map((r, i) => (
              <path
                key={i}
                d={r.path}
                fill={r.color}
                stroke="#1A2740"
                strokeWidth="0.6"
                style={{
                  cursor: r.data ? 'pointer' : 'default',
                  opacity: hovered && hovered !== r.name ? 0.3 : 1,
                  transition: 'opacity 0.2s',
                }}
                onMouseEnter={() => r.data && setHovered(r.name)}
                onMouseLeave={() => setHovered(null)}
              >
                {r.data && (
                  <title>
                    {r.name}: {r.data.total} IOC(s) — {r.data.malicious} malicious, {r.data.suspicious} suspicious
                  </title>
                )}
              </path>
            ))}

            {/* Hover tooltip */}
            {hovered && (() => {
              const region = coloredRegions.find((r) => r.name === hovered);
              if (!region || !region.data) return null;
              const { x, y } = { x: ((region.lon + 180) / 360) * 800, y: ((90 - region.lat) / 180) * 400 };
              const tx = Math.min(x + 8, 640);
              return (
                <g style={{ pointerEvents: 'none' }}>
                  <rect x={tx} y={y - 28} width="150" height="42" rx="3" fill="#0B1524" stroke="#26385A" strokeWidth="0.5" opacity="0.95" />
                  <text x={tx + 6} y={y - 14} fill="#DCE6F5" fontSize="10" fontFamily="JetBrains Mono" fontWeight="600">
                    {region.name}
                  </text>
                  <text x={tx + 6} y={y - 2} fill="#FF4D6A" fontSize="8" fontFamily="JetBrains Mono">
                    {region.data.malicious} malicious
                  </text>
                  <text x={tx + 6} y={y + 8} fill="#64789E" fontSize="8" fontFamily="JetBrains Mono">
                    {region.data.total} total IOC(s)
                  </text>
                </g>
              );
            })()}
          </svg>

          {/* Legend */}
          <div style={{ display: 'flex', gap: '10px', marginTop: '8px', flexWrap: 'wrap' }}>
            {THREAT_COLORS.map((t, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '4px', fontFamily: 'JetBrains Mono', fontSize: '9px', color: '#64789E' }}>
                <span style={{ width: '12px', height: '12px', borderRadius: '2px', background: t.color, display: 'inline-block', border: '1px solid #1A2740' }}></span>
                {t.label}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
