import { Queue, Worker, type JobsOptions } from "bullmq";
import { getBullRedis } from "../utils/cache.js";
import type { ScanResult } from "../types.js";
import { prisma } from "../lib/prisma.js";

export const BULK_QUEUE_NAME = "bulk-scan";

let queue: Queue | null = null;
let worker: Worker | null = null;

function getQueue(): Queue | null {
  const conn = getBullRedis();
  if (!conn) return null;
  if (!queue) {
    queue = new Queue(BULK_QUEUE_NAME, { connection: conn });
  }
  return queue;
}

export async function enqueueBulkJob(jobId: string, urls: string[]) {
  const q = getQueue();
  if (!q) throw new Error("Queue unavailable — REDIS_URL not configured");
  await q.add(
    "scan-urls",
    { jobId, urls },
    { jobId, removeOnComplete: { age: 3600 }, removeOnFail: { age: 3600 * 24 } } satisfies JobsOptions
  );
}

export function startBulkWorker(
  scanFn: (url: string) => Promise<ScanResult>
) {
  const conn = getBullRedis();
  if (!conn) {
    console.log("[queue] REDIS_URL not set — bulk jobs will run inline");
    return;
  }
  worker = new Worker(
    BULK_QUEUE_NAME,
    async (job) => {
      const { jobId, urls } = job.data as { jobId: string; urls: string[] };
      const results: ScanResult[] = [];
      for (let i = 0; i < urls.length; i++) {
        try {
          const r = await scanFn(urls[i]);
          results.push(r);
        } catch (err: any) {
          results.push({
            url: urls[i],
            finalUrl: urls[i],
            score: 0,
            verdict: "suspicious",
            signals: [
              { signal: "scan-error", triggered: true, weight: 0, explanation: err.message || "Scan failed" },
            ],
            scannedAt: new Date().toISOString(),
          } as unknown as ScanResult);
        }
        // Update progress in DB
        try {
          await prisma.bulkJob.update({
            where: { id: jobId },
            data: { completed: i + 1, results: results as any },
          });
        } catch {}
        await job.updateProgress(Math.round(((i + 1) / urls.length) * 100));
      }
      try {
        await prisma.bulkJob.update({
          where: { id: jobId },
          data: { status: "done", completed: urls.length, results: results as any },
        });
      } catch {}
      // Also record ScanEvents for analytics
      try {
        await prisma.scanEvent.createMany({
          data: results.map((r) => ({
            domain: new URL(r.finalUrl).hostname,
            verdict: r.verdict,
            score: r.score,
          })),
        });
      } catch {}
      return results;
    },
    { connection: conn, concurrency: 3 }
  );

  worker.on("failed", async (job, err) => {
    const jobId = (job?.data as any)?.jobId;
    if (jobId) {
      try {
        await prisma.bulkJob.update({ where: { id: jobId }, data: { status: "failed" } });
      } catch {}
    }
    console.error(`[queue] job ${job?.id} failed:`, err.message);
  });

  console.log("[queue] Bulk worker started");
}

export async function getQueueCounts() {
  const q = getQueue();
  if (!q) return null;
  return q.getJobCounts();
}
