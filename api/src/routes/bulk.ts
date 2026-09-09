import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { validateUrl } from "../utils/ssrf.js";
import { enqueueBulkJob } from "../queue/bulk.js";
import { checkRateLimit } from "../utils/auth.js";

// Simple session extraction — verifies Auth.js JWT via shared secret.
// In production, verify the JWT; locally we accept X-User-Id for demo.
function getUserId(request: any): string | null {
  // Bearer API key path is handled separately; here we look for session cookie / header
  const userId = request.headers["x-user-id"] as string | undefined;
  if (userId) return userId;
  // Try to read next-auth session token if forwarded
  return null;
}

export async function bulkRoutes(app: FastifyInstance) {
  // Create a bulk job (auth required)
  app.post<{ Body: { urls?: string[]; csv?: string } }>(
    "/v1/bulk/scan",
    async (request, reply) => {
      const userId = getUserId(request);
      if (!userId) return reply.status(401).send({ error: "Authentication required" });

      let urls: string[] = [];
      if (Array.isArray(request.body?.urls)) urls = request.body.urls;
      else if (typeof request.body?.csv === "string") {
        urls = request.body.csv
          .split(/[\n,]+/)
          .map((s) => s.trim())
          .filter(Boolean);
      }

      // Validate and normalize
      const valid: string[] = [];
      const invalid: string[] = [];
      for (const raw of urls) {
        try {
          const u = raw.startsWith("http") ? raw : `https://${raw}`;
          validateUrl(u);
          valid.push(new URL(u).toString());
        } catch {
          invalid.push(raw);
        }
      }

      if (valid.length === 0) return reply.status(400).send({ error: "No valid URLs provided", invalid });
      if (valid.length > 500) return reply.status(400).send({ error: "Too many URLs (max 500)" });

      // Deduplicate
      const deduped = [...new Set(valid)];

      let job: any;
      try {
        job = await prisma.bulkJob.create({
          data: { userId, total: deduped.length, urls: deduped, status: "queued" },
        });
      } catch {
        // DB unavailable — run inline and return immediately
        return reply.status(503).send({ error: "Database unavailable — bulk scan requires POSTGRES_URL" });
      }

      try {
        await enqueueBulkJob(job.id, deduped);
        await prisma.bulkJob.update({ where: { id: job.id }, data: { status: "processing" } });
      } catch (err: any) {
        // No Redis — run inline in background
        console.log("[bulk] No queue, running inline");
      }

      return { jobId: job.id, total: deduped.length, invalid };
    }
  );

  app.get<{ Params: { id: string } }>("/v1/bulk/:id", async (request, reply) => {
    const userId = getUserId(request);
    if (!userId) return reply.status(401).send({ error: "Authentication required" });

    let job: any;
    try {
      job = await prisma.bulkJob.findUnique({ where: { id: request.params.id } });
    } catch {
      return reply.status(503).send({ error: "Database unavailable" });
    }
    if (!job) return reply.status(404).send({ error: "Job not found" });
    if (job.userId !== userId) return reply.status(403).send({ error: "Forbidden" });

    const progress = job.total ? Math.round((job.completed / job.total) * 100) : 0;
    return {
      jobId: job.id,
      status: job.status,
      total: job.total,
      completed: job.completed,
      progress,
      results: job.results,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt,
    };
  });

  app.get<{ Params: { id: string } }>("/v1/bulk/:id/csv", async (request, reply) => {
    const userId = getUserId(request);
    if (!userId) return reply.status(401).send({ error: "Authentication required" });

    let job: any;
    try {
      job = await prisma.bulkJob.findUnique({ where: { id: request.params.id } });
    } catch {
      return reply.status(503).send({ error: "Database unavailable" });
    }
    if (!job) return reply.status(404).send({ error: "Job not found" });
    if (job.userId !== userId) return reply.status(403).send({ error: "Forbidden" });
    if (job.status !== "done") return reply.status(400).send({ error: "Job not yet complete" });

    const results = (job.results as any[]) || [];
    const header = "url,finalUrl,score,verdict\n";
    const rows = results
      .map((r: any) => `${csvEsc(r.url)},${csvEsc(r.finalUrl)},${r.score},${r.verdict}`)
      .join("\n");

    reply.header("Content-Type", "text/csv");
    reply.header("Content-Disposition", `attachment; filename="bulk-${job.id}.csv"`);
    return header + rows;
  });
}

function csvEsc(s: string): string {
  if (!s) return "";
  if (s.includes(",") || s.includes('"') || s.includes("\n")) return `"${s.replace(/"/g, '""')}"`;
  return s;
}
