// Prisma is optional for the web app — auth works without DB via JWT.
// This module never hard-imports @prisma/client so typecheck passes even
// when the generated client hasn't been generated (schema lives in api/prisma).

let prisma: any = null;

try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { PrismaClient } = require("@prisma/client");
  const globalForPrisma = globalThis as unknown as { prisma?: any };
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

export { prisma };
