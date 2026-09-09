import type { ScanSignal } from "../types.js";
import { googleSafeBrowsingProvider } from "./google-safebrowsing.js";
import { virusTotalProvider } from "./virustotal.js";
import { phishTankProvider } from "./phishtank.js";
import { urlhausProvider } from "./urlhaus.js";
import type { ThreatProvider } from "./types.js";
import { getDomain } from "./domain.js";

// Provider-triggered signals carry high weight — they're strong evidence.
const PROVIDER_WEIGHTS: Record<string, number> = {
  "google-safebrowsing": 90,
  virustotal: 85,
  phishtank: 80,
  urlhaus: 80,
};

const ALL_PROVIDERS: ThreatProvider[] = [
  googleSafeBrowsingProvider,
  virusTotalProvider,
  phishTankProvider,
  urlhausProvider,
];

export interface ProvidersRun {
  signals: ScanSignal[];
  providersSkipped: string[];
}

export async function runAllProviders(finalUrl: string): Promise<ProvidersRun> {
  const signals: ScanSignal[] = [];
  const providersSkipped: string[] = [];

  let domain: string;
  try {
    domain = getDomain(finalUrl);
  } catch {
    domain = "";
  }

  for (const provider of ALL_PROVIDERS) {
    if (!provider.isConfigured()) {
      providersSkipped.push(provider.name);
      continue;
    }

    try {
      const res = await provider.check({ url: finalUrl, domain });
      signals.push({
        signal: provider.name,
        triggered: res.triggered,
        weight: res.triggered ? PROVIDER_WEIGHTS[provider.name] ?? 80 : 0,
        explanation: res.explanation,
      });
    } catch (err: any) {
      // A provider that fails at runtime is not a hard failure — surface it as
      // a neutral, non-triggering signal so the scan still returns.
      signals.push({
        signal: provider.name,
        triggered: false,
        weight: 0,
        explanation: `${provider.name} check unavailable: ${err.message || "unknown error"}`,
      });
    }
  }

  return { signals, providersSkipped };
}