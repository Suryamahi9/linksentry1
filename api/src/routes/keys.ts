import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { generateApiKey, checkRateLimit, extractBearerToken, resolveApiKey } from "../utils/auth.js";

function getUserId(request: any): string | null {
  return (request.headers["x-user-id"] as string | undefined) || null;
}

export async function apiKeyRoutes(app: FastifyInstance) {
  // Create a new API key (auth required)
  app.post<{ Body: { name?: string } }>("/v1/keys", async (request, reply) => {
    const userId = getUserId(request);
    if (!userId) return reply.status(401).send({ error: "Authentication required" });

    const name = (request.body?.name || "default").slice(0, 64);
    const { raw, hash, prefix } = generateApiKey();

    try {
      await prisma.apiKey.create({ data: { userId, name, keyHash: hash, prefix } });
    } catch {
      return reply.status(503).send({ error: "Database unavailable — API keys require POSTGRES_URL" });
    }

    // Raw key is shown only once
    return { key: raw, prefix, name };
  });

  app.get("/v1/keys", async (request, reply) => {
    const userId = getUserId(request);
    if (!userId) return reply.status(401).send({ error: "Authentication required" });

    try {
      const keys = await prisma.apiKey.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
        select: { id: true, name: true, prefix: true, createdAt: true, lastUsedAt: true, revokedAt: true },
      });
      return { keys };
    } catch {
      return reply.status(503).send({ error: "Database unavailable" });
    }
  });

  app.delete<{ Params: { id: string } }>("/v1/keys/:id", async (request, reply) => {
    const userId = getUserId(request);
    if (!userId) return reply.status(401).send({ error: "Authentication required" });

    try {
      const key = await prisma.apiKey.findUnique({ where: { id: request.params.id } });
      if (!key || key.userId !== userId) return reply.status(404).send({ error: "Key not found" });
      await prisma.apiKey.update({ where: { id: key.id }, data: { revokedAt: new Date() } });
      return { revoked: true };
    } catch {
      return reply.status(503).send({ error: "Database unavailable" });
    }
  });
}

// Fastify preHandler that enforces per-key rate limits for /v1/* routes
export async function apiKeyRateLimitPreHandler(request: any, reply: any) {
  const token = extractBearerToken(request.headers.authorization);
  if (!token) return; // unauthenticated — let IP-based limiter handle it

  const record = await resolveApiKey(token);
  if (!record) {
    return reply.status(401).send({ error: "Invalid API key" });
  }

  // Attach resolved key for downstream handlers
  request.apiKey = record;
  request.userId = record.userId;

  // Per-key rate limit: 100 req/min
  const key = `rl:key:${record.id}`;
  const { allowed, remaining } = await checkRateLimit(key, 100, 60);
  reply.header("X-RateLimit-Remaining", String(remaining));
  if (!allowed) return reply.status(429).send({ error: "Rate limit exceeded for this API key (100/min)" });
}
