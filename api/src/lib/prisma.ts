import { PrismaClient } from "@prisma/client";

// Prisma is optional for the API — scans work with no Postgres. When the
// generated client hasn't been generated (or POSTGRES_URL is missing) the
// constructor throws; guard it so the API still boots and DB features degrade
// gracefully. The static import stays: it resolves to a stub that only throws
// on construction.

const globalForPrisma = globalThis as unknown as { prisma?: any };

export const prisma: any = (() => {
  if (!process.env.POSTGRES_URL) return null;
  try {
    return (
      globalForPrisma.prisma ??
      new PrismaClient({
        log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
      })
    );
  } catch {
    return null;
  }
})();

if (process.env.NODE_ENV !== "production" && prisma) {
  globalForPrisma.prisma = prisma;
}

export async function isDbAvailable(): Promise<boolean> {
  if (!prisma) return false;
  try {
    await prisma.$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}