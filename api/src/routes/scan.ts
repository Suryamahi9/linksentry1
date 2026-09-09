import type { FastifyInstance } from "fastify";
import { validateUrl, safeFetch } from "../utils/ssrf.js";
import { runAllScanners } from "../scanners/index.js";
import { runAllProviders } from "../providers/index.js";
import { communityBlocklistSignal } from "../scanners/community-blocklist.js";
import { calculateScore, scoreToVerdict } from "../utils/score.js";
import { extractPreview } from "../utils/metadata.js";
import { prisma } from "../lib/prisma.js";
import type { PagePreview } from "../types.js";
import { checkRateLimit, extractBearerToken, resolveApiKey } from "../utils/auth.js";

export async function scanRoutes(app: FastifyInstance) {
  app.post<{
    Body: { url: string };
  }>("/v1/scan", async (request, reply) => {
    const { url } = request.body || {};

    if (!url || typeof url !== "string") {
      return reply.status(400).send({
        error: "Missing or invalid 'url' field in request body",
      });
    }

    // Validate URL format
    let parsedUrl;
    try {
      parsedUrl = validateUrl(url.trim());
    } catch (err: any) {
      return reply.status(400).send({
        error: err.message || "Invalid URL",
      });
    }

    const originalUrl = parsedUrl.toString();
    let finalUrl = originalUrl;
    let pagePreview: PagePreview | null = null;

    let blockedReason: string | null = null;
    try {
      // Fetch the URL with SSRF protections
      const fetchResult = await safeFetch(originalUrl);
      finalUrl = fetchResult.finalUrl;
      // Extract a bounded, sanitized text-only preview (never renders page content)
      pagePreview = await extractPreview(fetchResult.response, finalUrl);
    } catch (err: any) {
      if (err && typeof err.message === "string" && err.message.startsWith("SSRF blocked")) {
        blockedReason = err.message;
      } else {
        // Other fetch failures (timeout, DNS, network) — scan what we can
        finalUrl = originalUrl;
      }
    }

    // If SSRF blocked the fetch, surface it as a hard rejection
    if (blockedReason) {
      return reply.status(400).send({
        error: blockedReason,
        url: originalUrl,
      });
    }

    // Rate limiting — per API key if Bearer present, else per IP
    const bearer = extractBearerToken((request.headers as any).authorization);
    let rateLimitKey: string | null = null;
    let rateLimit: number;
    let rateWindow: number;
    if (bearer) {
      const record = await resolveApiKey(bearer);
      if (!record) return reply.status(401).send({ error: "Invalid API key" });
      // @ts-ignore — attach for downstream
      (request as any).apiKey = record;
      rateLimitKey = `rl:key:${record.id}`;
      rateLimit = 100;
      rateWindow = 60;
    } else {
      const ip = request.ip || "unknown";
      rateLimitKey = `rl:ip:${ip}`;
      // Look up user role if X-User-Id forwarded (higher limit for authed users)
      const maybeUserId = (request.headers as any)["x-user-id"];
      if (maybeUserId) {
        rateLimit = 100;
        rateWindow = 60;
      } else {
        rateLimit = 20;
        rateWindow = 3600;
      }
    }
    if (rateLimitKey) {
      const { allowed, remaining } = await checkRateLimit(rateLimitKey, rateLimit, rateWindow);
      reply.header("X-RateLimit-Remaining", String(remaining));
      if (!allowed) return reply.status(429).send({ error: "Rate limit exceeded" });
    }

    // Run heuristic scanners + threat-intel providers + community blocklist in parallel
    const [signals, providerRun, blocklistSignal] = await Promise.all([
      runAllScanners(originalUrl, finalUrl),
      runAllProviders(finalUrl),
      communityBlocklistSignal(finalUrl),
    ]);

    const allSignals = [...signals, ...providerRun.signals, blocklistSignal];

    // Calculate risk score
    const score = calculateScore(allSignals);
    const verdict = scoreToVerdict(score);

    // Record analytics event (best-effort)
    try {
      await prisma.scanEvent.create({
        data: { domain: new URL(finalUrl).hostname, verdict, score },
      });
    } catch {}

    return {
      url: originalUrl,
      finalUrl,
      score,
      verdict,
      signals: allSignals,
      scannedAt: new Date().toISOString(),
      providersSkipped: providerRun.providersSkipped,
      pagePreview,
    };
  });
}