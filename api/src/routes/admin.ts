import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";

function getUserId(request: any): string | null {
  return (request.headers["x-user-id"] as string | undefined) || null;
}

async function requireAdmin(request: any, reply: any): Promise<boolean> {
  const userId = getUserId(request);
  if (!userId) {
    reply.status(401).send({ error: "Authentication required" });
    return false;
  }
  try {
    const user = await prisma.user.findUnique({ where: { id: userId }, select: { role: true } });
    if (!user || user.role !== "admin") {
      reply.status(403).send({ error: "Admin access required" });
      return false;
    }
  } catch {
    reply.status(503).send({ error: "Database unavailable" });
    return false;
  }
  return true;
}

export async function adminRoutes(app: FastifyInstance) {
  app.get("/v1/admin/reports", async (request, reply) => {
    if (!(await requireAdmin(request, reply))) return;
    const url = new URL(request.url, "http://localhost");
    const status = url.searchParams.get("status") || "open";
    try {
      const reports = await prisma.report.findMany({
        where: { status },
        orderBy: { createdAt: "desc" },
        take: 50,
        include: { votes: true },
      });
      return { reports };
    } catch {
      return reply.status(503).send({ error: "Database unavailable" });
    }
  });

  // Manual domain override (allow or block)
  app.post<{
    Body: { domain: string; action: "allow" | "block"; reason?: string };
  }>("/v1/admin/override", async (request, reply) => {
    const userId = getUserId(request)!;
    if (!(await requireAdmin(request, reply))) return;

    const { domain, action, reason } = request.body || {};
    if (!domain || !["allow", "block"].includes(action))
      return reply.status(400).send({ error: "domain and action (allow|block) are required" });

    const normalized = domain.toLowerCase().replace(/^www\./, "").trim();

    try {
      await prisma.domainOverride.upsert({
        where: { domain: normalized },
        update: { action, reason: reason?.slice(0, 1000) || null },
        create: { domain: normalized, action, reason: reason?.slice(0, 1000) || null, createdBy: userId },
      });
      await prisma.auditLog.create({
        data: { actorId: userId, action: `override:${action}`, target: normalized, detail: reason || null },
      });
      return { domain: normalized, action };
    } catch {
      return reply.status(503).send({ error: "Database unavailable" });
    }
  });

  app.delete<{ Params: { domain: string } }>("/v1/admin/override/:domain", async (request, reply) => {
    const userId = getUserId(request)!;
    if (!(await requireAdmin(request, reply))) return;

    const domain = request.params.domain.toLowerCase().replace(/^www\./, "").trim();
    try {
      await prisma.domainOverride.delete({ where: { domain } });
      await prisma.auditLog.create({
        data: { actorId: userId, action: "override:remove", target: domain },
      });
      return { removed: true };
    } catch {
      return reply.status(404).send({ error: "Override not found" });
    }
  });

  app.get("/v1/admin/audit", async (request, reply) => {
    if (!(await requireAdmin(request, reply))) return;
    try {
      const logs = await prisma.auditLog.findMany({ orderBy: { createdAt: "desc" }, take: 50 });
      return { logs };
    } catch {
      return reply.status(503).send({ error: "Database unavailable" });
    }
  });

  app.get("/v1/admin/stats", async (request, reply) => {
    if (!(await requireAdmin(request, reply))) return;
    try {
      const [totalScans, verdictCounts, recentScans, blocklisted] = await Promise.all([
        prisma.scanEvent.count(),
        prisma.scanEvent.groupBy({ by: ["verdict"], _count: true }),
        prisma.scanEvent.findMany({ orderBy: { createdAt: "desc" }, take: 7, select: { createdAt: true, verdict: true } }),
        prisma.communityBlocklist.count(),
      ]);

      // Aggregate scans/day for last 7 days
      const byDay: Record<string, number> = {};
      for (const s of recentScans) {
        const day = new Date(s.createdAt).toISOString().split("T")[0];
        byDay[day] = (byDay[day] || 0) + 1;
      }

      return {
        totalScans,
        verdictCounts: verdictCounts.map((v: any) => ({ verdict: v.verdict, count: v._count })),
        byDay,
        blocklisted,
      };
    } catch {
      return reply.status(503).send({ error: "Database unavailable" });
    }
  });
}
