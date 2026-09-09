import { createClient, type RedisClientType } from "redis";
import { Redis as IORedis } from "ioredis";

let client: RedisClientType | null = null;
let ioClient: InstanceType<typeof IORedis> | null = null;
let initialized = false;
let warned = false;

export function isCacheAvailable(): boolean {
  return client !== null;
}

export function getRedisClient(): RedisClientType | null {
  return client;
}

// BullMQ needs ioredis — expose a shared instance
export function getBullRedis(): InstanceType<typeof IORedis> | null {
  if (!process.env.REDIS_URL) return null;
  if (ioClient) return ioClient;
  try {
    ioClient = new IORedis(process.env.REDIS_URL, {
      maxRetriesPerRequest: null, // required by BullMQ
    });
    ioClient.on("error", (err: Error) => {
      if (!warned) {
        console.warn(`[cache] ioredis error: ${err.message}`);
        warned = true;
      }
    });
    return ioClient;
  } catch {
    return null;
  }
}

/**
 * Initialize the Redis client. If REDIS_URL is missing or Redis can't be
 * reached, caching is silently disabled — providers still work, they just
 * skip the cache. This keeps the API runnable in local/demo environments.
 */
export async function initCache(): Promise<void> {
  if (initialized) return;
  initialized = true;

  const url = process.env.REDIS_URL;
  if (!url) {
    if (!warned) {
      console.log("[cache] REDIS_URL not set — provider caching disabled");
      warned = true;
    }
    return;
  }

  try {
    client = createClient({ url });
    client.on("error", (err: Error) => {
      if (!warned) {
        console.warn(`[cache] Redis error: ${err.message}`);
        warned = true;
      }
    });
    await client.connect();
    console.log("[cache] Redis connected");
  } catch (err: any) {
    console.warn(`[cache] Redis unavailable — provider caching disabled: ${err.message}`);
    client = null;
  }
}

export async function cacheGet(key: string): Promise<string | null> {
  if (!client) return null;
  try {
    return await client.get(key);
  } catch {
    return null;
  }
}

export async function cacheSet(
  key: string,
  value: string,
  ttlSeconds: number
): Promise<void> {
  if (!client) return;
  try {
    await client.set(key, value, { EX: ttlSeconds });
  } catch {
    // cache is best-effort only
  }
}

export async function incrWithExpiry(key: string, windowSeconds: number): Promise<number> {
  if (!client) return 0;
  try {
    const count = await client.incr(key);
    if (count === 1) await client.expire(key, windowSeconds);
    return count;
  } catch {
    return 0;
  }
}
