import type { ThreatProvider, ProviderContext, ProviderResult } from "./types.js";
import { cacheGet, cacheSet } from "../utils/cache.js";

const API_KEY = process.env.VIRUSTOTAL_API_KEY || "";
const CACHE_TTL = 3600; // 1 hour
const CACHE_PREFIX = "provider:vt:";

export const virusTotalProvider: ThreatProvider = {
  name: "virustotal",

  isConfigured() {
    return API_KEY.length > 0;
  },

  async check(ctx: ProviderContext): Promise<ProviderResult> {
    const cacheKey = `${CACHE_PREFIX}${ctx.domain}`;
    const cached = await cacheGet(cacheKey);
    if (cached) {
      return JSON.parse(cached) as ProviderResult;
    }

    const response = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ctx.domain)}`,
      {
        headers: { "x-apikey": API_KEY },
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!response.ok) {
      throw new Error(`VirusTotal returned HTTP ${response.status}`);
    }

    const data = (await response.json()) as {
      data?: {
        attributes?: {
          last_analysis_stats?: {
            malicious?: number;
            suspicious?: number;
            undetected?: number;
            harmless?: number;
            timeout?: number;
          };
          reputation?: number;
        };
      };
    };

    const stats = data.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    const result: ProviderResult =
      malicious > 0
        ? {
            triggered: true,
            source: "virustotal",
            explanation: `VirusTotal: ${malicious} vendor(s) flagged this domain as malicious (${suspicious} suspicious).`,
          }
        : {
            triggered: false,
            source: "virustotal",
            explanation: `VirusTotal: no malicious vendor detections (${malicious} malicious, ${suspicious} suspicious).`,
          };

    await cacheSet(cacheKey, JSON.stringify(result), CACHE_TTL);
    return result;
  },
};