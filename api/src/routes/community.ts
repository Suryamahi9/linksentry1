import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { validateUrl } from "../utils/ssrf.js";

const BLOCKLIST_THRESHOLD = 5;

export async function communityRoutes(app: FastifyInstance) {
  function getUserId(request: any): string | null {
    return (request.headers["x-user-id"] as string | undefined) || null;
  }

  // Submit a report (auth required)
  app.post<{
    Body: { url: string; category: string; reason?: string };
  }>("/v1/report", async (request, reply) => {
    const userId = getUserId(request);
    if (!userId) return reply.status(401).send({ error: "Authentication required" });

    const { url, category, reason } = request.body || {};
    const allowed = ["phishing", "malware", "scam", "spam-ad", "other"];
    if (!url || typeof url !== "string") return reply.status(400).send({ error: "url is required" });
    if (!allowed.includes(category)) return reply.status(400).send({ error: `category must be one of: ${allowed.join(", ")}` });

    let parsed: URL;
    try {
      parsed = validateUrl(url.trim());
    } catch (e: any) {
      return reply.status(400).send({ error: e.message || "Invalid URL" });
    }

    const domain = parsed.hostname.replace(/^www\./, "").toLowerCase();

    try {
      const report = await prisma.report.create({
        data: {
          url: parsed.toString(),
          domain,
          category,
          reason: reason?.slice(0, 1000) || null,
          reporterId: userId,
        },
      });
      return { reportId: report.id, status: report.status };
    } catch {
      return reply.status(503).send({ error: "Database unavailable — reporting requires POSTGRES_URL" });
    }
  });

  // Upvote a report (auth required, one vote per user per report)
  app.post<{ Params: { id: string } }>("/v1/report/:id/vote", async (request, reply) => {
    const userId = getUserId(request);
    if (!userId) return reply.status(401).send({ error: "Authentication required" });

    const reportId = request.params.id;
    try {
      const report = await prisma.report.findUnique({ where: { id: reportId } });
      if (!report) return reply.status(404).send({ error: "Report not found" });

      await prisma.reportVote.create({ data: { reportId, userId } });

      const voteCount = await prisma.reportVote.count({ where: { reportId } });

      if (voteCount >= BLOCKLIST_THRESHOLD && report.status !== "blocklisted") {
        await prisma.$transaction([
          prisma.report.update({ where: { id: reportId }, data: { status: "blocklisted" } }),
          prisma.communityBlocklist.upsert({
            where: { domain: report.domain },
            update: { votes: voteCount },
            create: { domain: report.domain, sourceUrl: report.url, votes: voteCount },
          }),
        ]);
      }

      return { votes: voteCount, blocklisted: voteCount >= BLOCKLIST_THRESHOLD };
    } catch (err: any) {
      if (err.code === "P2002") return reply.status(409).send({ error: "Already voted" });
      return reply.status(503).send({ error: "Database unavailable" });
    }
  });

  // Public transparency feed — paginated, no PII
  app.get<{ Querystring: { page?: string; limit?: string } }>(
    "/v1/transparency",
    async (request) => {
      const page = Math.max(1, parseInt(request.query.page || "1", 10) || 1);
      const limit = Math.min(50, Math.max(1, parseInt(request.query.limit || "20", 10) || 20));
      try {
        const [items, total] = await Promise.all([
          prisma.communityBlocklist.findMany({
            orderBy: { addedAt: "desc" },
            skip: (page - 1) * limit,
            take: limit,
            select: { domain: true, addedAt: true, votes: true },
          }),
          prisma.communityBlocklist.count(),
        ]);
        return { items, total, page, limit };
      } catch {
        return { items: [], total: 0, page, limit };
      }
    }
  );

  // Check if a domain is blocklisted (used by the scan signal)
  app.get<{ Params: { domain: string } }>("/v1/blocklist/:domain", async (request, reply) => {
    try {
      const entry = await prisma.communityBlocklist.findUnique({
        where: { domain: request.params.domain.toLowerCase() },
      });
      if (!entry) return reply.status(404).send({ blocklisted: false });
      return { blocklisted: true, domain: entry.domain, votes: entry.votes, addedAt: entry.addedAt };
    } catch {
      return { blocklisted: false };
    }
  });
}
