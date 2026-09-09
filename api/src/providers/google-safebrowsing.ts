import type { ThreatProvider, ProviderContext, ProviderResult } from "./types.js";
import { cacheGet, cacheSet } from "../utils/cache.js";

const API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY || "";
const CACHE_TTL = 3600; // 1 hour
const CACHE_PREFIX = "provider:gbs:";

export const googleSafeBrowsingProvider: ThreatProvider = {
  name: "google-safebrowsing",

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
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "linksentry", clientVersion: "0.1.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: ctx.url }],
          },
        }),
        signal: AbortSignal.timeout(5000),
      }
    );

    if (!response.ok) {
      throw new Error(`Google Safe Browsing returned HTTP ${response.status}`);
    }

    const data = (await response.json()) as { matches?: { threatType: string }[] };
    const matches = data.matches || [];

    const result: ProviderResult =
      matches.length > 0
        ? {
            triggered: true,
            source: "google-safebrowsing",
            explanation: `Listed by Google Safe Browsing for: ${matches.map((m) => m.threatType).join(", ")}.`,
          }
        : {
            triggered: false,
            source: "google-safebrowsing",
            explanation: "Not listed in Google Safe Browsing.",
          };

    await cacheSet(cacheKey, JSON.stringify(result), CACHE_TTL);
    return result;
  },
};