import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'IOC Enrichment Console — Threat Intel & Reputation Monitoring',
  description:
    'Real-time IOC enrichment console for SOC analysts. Query VirusTotal, AbuseIPDB, and geolocation APIs for IP addresses, domains, and file hashes. Export results as CSV, JSON, or STIX 2.1 bundles.',
  keywords: [
    'IOC enrichment',
    'threat intelligence',
    'VirusTotal',
    'AbuseIPDB',
    'SOC',
    'cybersecurity',
    'STIX',
    'indicator of compromise',
    'IP reputation',
    'malware analysis',
  ],
  authors: [{ name: 'IOC Enrichment Console' }],
  robots: { index: false, follow: false },
  openGraph: {
    title: 'IOC Enrichment Console',
    description: 'Real-time IOC enrichment for SOC analysts — VirusTotal + AbuseIPDB + geolocation.',
    type: 'website',
    locale: 'en_US',
  },
};

export const viewport = {
  width: 'device-width',
  initialScale: 1.0,
  themeColor: '#060B14',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
