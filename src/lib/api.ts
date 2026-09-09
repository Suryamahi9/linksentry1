// Same-origin proxy path — Next.js rewrites /api/* to the backend (see next.config.js)
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "/api";

export interface ScanSignal {
  signal: string;
  triggered: boolean;
  weight: number;
  explanation: string;
}

export interface PagePreview {
  domain: string;
  title: string;
  description: string | null;
  siteName: string | null;
  https: boolean;
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  score: number;
  verdict: "safe" | "suspicious" | "malicious";
  signals: ScanSignal[];
  scannedAt: string;
  providersSkipped?: string[];
  pagePreview?: PagePreview | null;
}

export interface ScanError {
  error: string;
}

export async function scanUrl(url: string): Promise<ScanResult> {
  const response = await fetch(`${API_BASE}/v1/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || `Scan failed with status ${response.status}`);
  }

  return data as ScanResult;
}

export function isValidUrl(str: string): boolean {
  try {
    const url = new URL(str);
    return ["http:", "https:"].includes(url.protocol);
  } catch {
    return false;
  }
}

export function formatDomain(urlStr: string): string {
  try {
    const url = new URL(urlStr);
    return url.hostname;
  } catch {
    return urlStr;
  }
}
