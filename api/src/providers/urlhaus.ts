import type { ThreatProvider, ProviderContext, ProviderResult } from "./types.js";
import { cacheGet, cacheSet } from "../utils/cache.js";

const CACHE_TTL = 3600; // 1 hour
const CACHE_PREFIX = "provider:urlhaus:";

export const urlhausProvider: ThreatProvider = {
  name: "urlhaus",

  // Public API — no key required.
  isConfigured() {
    return true;
  },

  async check(ctx: ProviderContext): Promise<ProviderResult> {
    const cacheKey = `${CACHE_PREFIX}${ctx.domain}`;
    const cached = await cacheGet(cacheKey);
    if (cached) {
      return JSON.parse(cached) as ProviderResult;
    }

    const response = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ host: ctx.domain }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) {
      throw new Error(`URLhaus returned HTTP ${response.status}`);
    }

    const data = (await response.json()) as {
      query_status?: string;
      url_count?: number;
      urls?: { url?: string; threat?: string }[];
    };

    let result: ProviderResult;
    if (data.query_status === "ok" && (data.urls?.length || 0) > 0) {
      const threats = [
        ...new Set((data.urls || []).map((u) => u.threat).filter(Boolean)),
      ];
      result = {
        triggered: true,
        source: "urlhaus",
        explanation: `Host is listed on URLhaus (${data.urls?.length} malicious URL(s)${
          threats.length ? `; threats: ${threats.join(", ")}` : ""
        }).`,
      };
    } else {
      result = {
        triggered: false,
        source: "urlhaus",
        explanation: "Not listed on URLhaus.",
      };
    }

    await cacheSet(cacheKey, JSON.stringify(result), CACHE_TTL);
    return result;
  },
};