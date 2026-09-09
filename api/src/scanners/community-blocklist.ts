import type { ScanSignal } from "../types.js";
import { prisma } from "../lib/prisma.js";

export async function communityBlocklistSignal(finalUrl: string): Promise<ScanSignal> {
  try {
    const domain = new URL(finalUrl).hostname.replace(/^www\./, "").toLowerCase();

    // Check explicit override first
    try {
      const override = await prisma.domainOverride.findUnique({ where: { domain } });
      if (override) {
        const isBlock = override.action === "block";
        return {
          signal: "community-blocklist",
          triggered: isBlock,
          weight: isBlock ? 95 : 0,
          explanation: isBlock
            ? `Domain is manually blocklisted by admins: ${override.reason || "no reason given"}.`
            : `Domain has an admin allow-override: ${override.reason || ""}`.trim(),
        };
      }
    } catch {}

    const entry = await prisma.communityBlocklist.findUnique({ where: { domain } });
    if (entry) {
      return {
        signal: "community-blocklist",
        triggered: true,
        weight: 90,
        explanation: `Domain is on the community blocklist (${entry.votes} reports, added ${new Date(entry.addedAt).toISOString().split("T")[0]}).`,
      };
    }
    return {
      signal: "community-blocklist",
      triggered: false,
      weight: 0,
      explanation: "Domain is not on the community blocklist.",
    };
  } catch {
    return {
      signal: "community-blocklist",
      triggered: false,
      weight: 0,
      explanation: "Community blocklist check unavailable.",
    };
  }
}
