import crypto from "crypto";

/**
 * Rate limiting (Redis) + API-key auth helpers.
 * Both are graceful when Redis/DB are absent.
 */
import { incrWithExpiry } from "./cache.js";
import { prisma } from "../lib/prisma.js";

export async function checkRateLimit(
  key: string,
  limit: number,
  windowSeconds: number
): Promise<{ allowed: boolean; remaining: number }> {
  const count = await incrWithExpiry(key, windowSeconds);
  // If Redis is absent, count is 0 — allow the request.
  if (count === 0) return { allowed: true, remaining: limit };
  return { allowed: count <= limit, remaining: Math.max(0, limit - count) };
}

export function hashApiKey(raw: string): string {
  return crypto.createHash("sha256").update(raw).digest("hex");
}

export function generateApiKey(): { raw: string; hash: string; prefix: string } {
  const raw = `ls_${crypto.randomBytes(24).toString("base64url")}`;
  const hash = hashApiKey(raw);
  const prefix = raw.slice(0, 8);
  return { raw, hash, prefix };
}

export async function resolveApiKey(raw: string) {
  const hash = hashApiKey(raw);
  try {
    const record = await prisma.apiKey.findUnique({ where: { keyHash: hash } });
    if (!record || record.revokedAt) return null;
    // touch lastUsedAt asynchronously
    prisma.apiKey.update({ where: { id: record.id }, data: { lastUsedAt: new Date() } }).catch(() => {});
    return record;
  } catch {
    return null;
  }
}

export function extractBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const m = header.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}
