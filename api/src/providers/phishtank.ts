import type { ThreatProvider, ProviderContext, ProviderResult } from "./types.js";
import { cacheGet, cacheSet } from "../utils/cache.js";

const API_KEY = process.env.PHISHTANK_API_KEY || "";
const FEED_TTL = 1200; // refresh feed every 20 min
const CACHE_PREFIX = "provider:phishtank:";
const FEED_CACHE_KEY = `${CACHE_PREFIX}feed`;

// In-memory host list with expiry (keeps per-request cost near zero and
// survives Redis being unavailable).
let memHosts: Set<string> | null = null;
let memExpiresAt = 0;

function normalizeHost(host: string): string {
  return host
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/:.*$/, "")
    .replace(/\.$/, "");
}

async function loadHosts(): Promise<Set<string>> {
  const now = Date.now();
  if (memHosts && now < memExpiresAt) return memHosts;

  const cached = await cacheGet(FEED_CACHE_KEY);
  if (cached) {
    const hosts = new Set<string>(JSON.parse(cached) as string[]);
    memHosts = hosts;
    memExpiresAt = now + FEED_TTL * 1000;
    return hosts;
  }

  // Build the feed URL. With a key, use the authenticated feed; otherwise try
  // the public anonymous feed.
  const base = API_KEY
    ? `https://data.phishtank.com/data/${encodeURIComponent(API_KEY)}/online-valid.json`
    : "https://data.phishtank.com/data/online-valid.json";

  const response = await fetch(base, {
    headers: { "User-Agent": "LinkSentry/1.0 (URL Scanner)" },
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) {
    if (response.status === 429) {
      // Rate-limited: hold a short-lived negative so we stop hammering the
      // feed between scans instead of retrying every request.
      await cacheSet(FEED_CACHE_KEY, JSON.stringify([]), 120);
      const empty = new Set<string>();
      memHosts = empty;
      memExpiresAt = now + 120 * 1000;
      return empty;
    }
    throw new Error(`PhishTank feed returned HTTP ${response.status}`);
  }

  const entries = (await response.json()) as { url?: string }[];
  const hosts = new Set<string>();
  for (const entry of entries) {
    if (!entry.url) continue;
    try {
      hosts.add(normalizeHost(new URL(entry.url).hostname));
    } catch {
      // skip malformed feed entries
    }
  }

  await cacheSet(FEED_CACHE_KEY, JSON.stringify([...hosts]), FEED_TTL);
  memHosts = hosts;
  memExpiresAt = now + FEED_TTL * 1000;
  return hosts;
}

export const phishTankProvider: ThreatProvider = {
  name: "phishtank",

  // Works with or without an API key (public feed).
  isConfigured() {
    return true;
  },

  async check(ctx: ProviderContext): Promise<ProviderResult> {
    try {
      const hosts = await loadHosts();
      const target = normalizeHost(ctx.domain);

      if (hosts.has(target)) {
        return {
          triggered: true,
          source: "phishtank",
          explanation: `Domain ${ctx.domain} is listed in the PhishTank community phishing feed.`,
        };
      }

      return {
        triggered: false,
        source: "phishtank",
        explanation: "Not found in the PhishTank community feed.",
      };
    } catch (err: any) {
      return {
        triggered: false,
        source: "phishtank",
        explanation: `PhishTank feed unavailable: ${err.message}.`,
      };
    }
  },
};