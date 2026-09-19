// Prisma is optional for the API — scans work with no Postgres. This module
// never hard-imports @prisma/client so the process still boots when the
// generated client hasn't been generated (or POSTGRES_URL is missing);
// DB features degrade gracefully instead of killing the API.

const globalForPrisma = globalThis as unknown as { prisma?: any };

let prisma: any = null;

if (process.env.POSTGRES_URL) {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { PrismaClient } = require("@prisma/client");
    prisma =
      globalForPrisma.prisma ??
      new PrismaClient({
        log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
      });
    if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;
  } catch {
    // Prisma client not generated — DB features will gracefully degrade
    prisma = null;
  }
}

export { prisma };

export async function isDbAvailable(): Promise<boolean> {
  if (!prisma) return false;
  try {
    await prisma.$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}