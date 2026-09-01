'use client';

import { useMemo, useState, useRef, useEffect } from 'react';
import type { IOCFinding } from '@/lib/types';

interface VendorWordCloudProps {
  results: IOCFinding[];
}

interface WordItem {
  text: string;
  count: number;
  x: number;
  y: number;
  width: number;
  height: number;
  fontSize: number;
  color: string;
  angle: number;
}

const COLORS = ['#FF4D6A', '#FFB238', '#33E8C7', '#2FE08A', '#6E80A6', '#DCE6F5', '#5CF0D4'];

function spiralLayout(
  words: { text: string; count: number }[],
  width: number,
  height: number
): WordItem[] {
  const placed: WordItem[] = [];
  const centerX = width / 2;
  const centerY = height / 2;
  const maxCount = Math.max(...words.map((w) => w.count), 1);

  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    // Font size: scale between 11 and 38 based on frequency
    const ratio = word.count / maxCount;
    const fontSize = Math.round(11 + ratio * 27);
    const estWidth = word.text.length * fontSize * 0.62;
    const estHeight = fontSize * 1.2;

    // Spiral search for a non-colliding position
    let placed_ok = false;
    let x = centerX;
    let y = centerY;
    let angle = 0;
    let radius = 0;
    const angleStep = 0.35;
    const radiusStep = 0.6;

    for (let attempt = 0; attempt < 600; attempt++) {
      x = centerX + radius * Math.cos(angle);
      y = centerY + radius * Math.sin(angle);

      // Alternate between horizontal and vertical for variety
      const useAngle = i % 3 === 2 ? 90 : 0;
      const w = useAngle === 0 ? estWidth : estHeight;
      const h = useAngle === 0 ? estHeight : estWidth;

      // Check bounds
      if (x - w / 2 < 4 || x + w / 2 > width - 4 || y - h / 2 < 4 || y + h / 2 > height - 4) {
        angle += angleStep;
        radius += radiusStep;
        continue;
      }

      // Check collision with placed words
      let collides = false;
      for (const p of placed) {
        const pw = p.angle === 0 ? p.width : p.height;
        const ph = p.angle === 0 ? p.height : p.width;
        if (
          Math.abs(x - p.x) < (w + pw) / 2 + 4 &&
          Math.abs(y - p.y) < (h + ph) / 2 + 4
        ) {
          collides = true;
          break;
        }
      }

      if (!collides) {
        placed.push({
          text: word.text,
          count: word.count,
          x,
          y,
          width: estWidth,
          height: estHeight,
          fontSize,
          color: COLORS[i % COLORS.length],
          angle: useAngle,
        });
        placed_ok = true;
        break;
      }

      angle += angleStep;
      radius += radiusStep;
    }

    if (!placed_ok) {
      // Force-place even if overlapping (for dense clouds)
      placed.push({
        text: word.text,
        count: word.count,
        x: centerX + (Math.random() - 0.5) * width * 0.7,
        y: centerY + (Math.random() - 0.5) * height * 0.7,
        width: estWidth,
        height: estHeight,
        fontSize,
        color: COLORS[i % COLORS.length],
        angle: 0,
      });
    }
  }

  return placed;
}

export function VendorWordCloud({ results }: VendorWordCloudProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [dims, setDims] = useState({ w: 500, h: 280 });
  const [hovered, setHovered] = useState<string | null>(null);

  useEffect(() => {
    if (containerRef.current) {
      const rect = containerRef.current.getBoundingClientRect();
      setDims({ w: Math.max(rect.width, 300), h: 280 });
    }
  }, []);

  // Aggregate vendor counts
  const vendorCounts = useMemo(() => {
    const m = new Map<string, number>();
    results.forEach((r) => {
      (r.vt_flagging_vendors || []).forEach((v) => {
        m.set(v, (m.get(v) || 0) + 1);
      });
    });
    // Sort by count desc, take top 40
    return Array.from(m.entries())
      .map(([text, count]) => ({ text, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 40);
  }, [results]);

  const layout = useMemo(() => spiralLayout(vendorCounts, dims.w, dims.h), [vendorCounts, dims]);

  if (vendorCounts.length === 0) {
    return (
      <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
        <h3 className="chart-title">Security Vendor Word Cloud</h3>
        <div style={{ textAlign: 'center', color: '#64789E', fontFamily: 'JetBrains Mono', fontSize: '12px', padding: '40px 0' }}>
          No vendor data available. Vendors appear here when VirusTotal flags an IOC as malicious or suspicious.
        </div>
      </div>
    );
  }

  return (
    <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
      <h3 className="chart-title">
        Security Vendor Word Cloud
        <span style={{ fontSize: '11px', color: '#64789E', fontFamily: 'JetBrains Mono', marginLeft: '8px' }}>
          ({vendorCounts.length} vendors — size = frequency)
        </span>
      </h3>
      <div ref={containerRef} style={{ position: 'relative', width: '100%', height: dims.h, overflow: 'hidden' }}>
        <svg width="100%" height={dims.h} viewBox={`0 0 ${dims.w} ${dims.h}`}>
          {layout.map((w, i) => (
            <text
              key={i}
              x={w.x}
              y={w.y}
              textAnchor="middle"
              dominantBaseline="middle"
              fill={hovered === w.text ? '#FFFFFF' : w.color}
              fontSize={w.fontSize}
              fontFamily="JetBrains Mono"
              fontWeight={w.count > 2 ? '700' : '500'}
              transform={w.angle === 90 ? `rotate(90 ${w.x} ${w.y})` : undefined}
              style={{
                cursor: 'pointer',
                opacity: hovered && hovered !== w.text ? 0.3 : 1,
                transition: 'opacity 0.2s, fill 0.2s',
              }}
              onMouseEnter={() => setHovered(w.text)}
              onMouseLeave={() => setHovered(null)}
            >
              <title>{w.text} — flagged {w.count} IOC(s)</title>
              {w.text}
            </text>
          ))}
        </svg>
      </div>
    </div>
  );
}
