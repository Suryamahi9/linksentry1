import Fastify from "fastify";
import cors from "@fastify/cors";
import multipart from "@fastify/multipart";
import { scanRoutes } from "./routes/scan.js";
import { bulkRoutes } from "./routes/bulk.js";
import { communityRoutes } from "./routes/community.js";
import { apiKeyRoutes } from "./routes/keys.js";
import { adminRoutes } from "./routes/admin.js";
import { initCache, getBullRedis } from "./utils/cache.js";

console.log("[boot] index.ts loaded — initializing cache");

// Initialize optional Redis cache (graceful if Redis is absent)
await initCache();
console.log("[boot] cache init complete");

const app = Fastify({
  logger: {
    level: "info",
  },
});

// Enable CORS for the frontend. CORS_ORIGIN is a comma-separated allow-list.
const corsOrigins = (process.env.CORS_ORIGIN || "http://localhost:3000,http://localhost:8000")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

await app.register(cors, {
  origin: corsOrigins.length > 0 ? corsOrigins : true,
  methods: ["POST", "GET", "DELETE", "OPTIONS"],
});

await app.register(multipart, { limits: { fileSize: 2 * 1024 * 1024 } });

// Register routes
await app.register(scanRoutes);
await app.register(bulkRoutes);
await app.register(communityRoutes);
await app.register(apiKeyRoutes);
await app.register(adminRoutes);

// Health check
app.get("/health", async () => ({ status: "ok" }));

// Start bulk worker (needs the scan function)
try {
  const { startBulkWorker } = await import("./queue/bulk.js");
  const { runAllScanners } = await import("./scanners/index.js");
  const { runAllProviders } = await import("./providers/index.js");
  const { communityBlocklistSignal } = await import("./scanners/community-blocklist.js");
  const { calculateScore, scoreToVerdict } = await import("./utils/score.js");
  const { validateUrl, safeFetch } = await import("./utils/ssrf.js");
  const { extractPreview } = await import("./utils/metadata.js");

  async function scanOne(url: string) {
    let parsed: URL;
    try {
      parsed = validateUrl(url);
    } catch (e: any) {
      throw new Error(e.message);
    }
    const original = parsed.toString();
    let finalUrl = original;
    try {
      const r = await safeFetch(original);
      finalUrl = r.finalUrl;
    } catch (e: any) {
      if (e.message?.startsWith("SSRF blocked")) throw e;
    }
    const [signals, providerRun, blocklistSignal] = await Promise.all([
      runAllScanners(original, finalUrl),
      runAllProviders(finalUrl),
      communityBlocklistSignal(finalUrl),
    ]);
    const all = [...signals, ...providerRun.signals, blocklistSignal];
    const score = calculateScore(all);
    const verdict = scoreToVerdict(score);
    return {
      url: original,
      finalUrl,
      score,
      verdict,
      signals: all,
      scannedAt: new Date().toISOString(),
      providersSkipped: providerRun.providersSkipped,
      pagePreview: null,
    } as any;
  }

  startBulkWorker(scanOne);
} catch (err: any) {
  console.log("[queue] Bulk worker not started:", err.message);
}

// Start server
// Vercel Fluid Compute injects PORT for the internal server socket — honor it
// so the runtime can route requests to this process. API_PORT/3001 are fallbacks
// for local development.
const PORT = parseInt(process.env.PORT || process.env.API_PORT || "3001", 10);
const HOST = process.env.API_HOST || "0.0.0.0";

console.log(`[boot] starting fastify on ${HOST}:${PORT}`);

try {
  await app.listen({ port: PORT, host: HOST });
  console.log(`LinkSentry API running on http://${HOST}:${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
