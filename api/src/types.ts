export interface ScanSignal {
  signal: string;
  triggered: boolean;
  weight: number;
  explanation: string;
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

export interface PagePreview {
  domain: string;
  title: string;
  description: string | null;
  siteName: string | null;
  https: boolean;
}

export interface ScannerModule {
  name: string;
  scan(url: string, finalUrl: string, html?: string): Promise<ScanSignal>;
}

export type Verdict = "safe" | "suspicious" | "malicious";

export interface ScanRequest {
  url: string;
}
