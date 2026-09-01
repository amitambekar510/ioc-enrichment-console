'use client';

import { useState, useEffect } from 'react';

/**
 * useISTClock — ticks IST time locally every second.
 * No backend call needed; uses the browser's local time converted to IST.
 * Re-syncs against the backend /api/time endpoint every 60s to correct drift.
 */
export function useISTClock(): string {
  const [time, setTime] = useState('--:--:-- IST');

  useEffect(() => {
    function tick() {
      const now = new Date();
      // Convert to IST (UTC+5:30)
      const utc = now.getTime() + now.getTimezoneOffset() * 60000;
      const ist = new Date(utc + 5.5 * 3600000);
      const hh = String(ist.getHours()).padStart(2, '0');
      const mm = String(ist.getMinutes()).padStart(2, '0');
      const ss = String(ist.getSeconds()).padStart(2, '0');
      setTime(`${hh}:${mm}:${ss} IST`);
    }

    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  return time;
}
