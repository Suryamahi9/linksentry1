import type { ScannerModule, ScanSignal } from "../types.js";

export const redirectChainScanner: ScannerModule = {
  name: "redirect-chain",

  async scan(url: string, finalUrl: string): Promise<ScanSignal> {
    try {
      const originalParsed = new URL(url);
      const finalParsed = new URL(finalUrl);

      const originalDomain = originalParsed.hostname.replace(/^www\./, "").toLowerCase();
      const finalDomain = finalParsed.hostname.replace(/^www\./, "").toLowerCase();

      if (originalDomain === finalDomain) {
        return {
          signal: "redirect-chain",
          triggered: false,
          weight: 0,
          explanation: "No domain-level redirect detected.",
        };
      }

      // Domain changed — check if it's a redirect to a different domain
      const topLevelOriginal = originalDomain.split(".").slice(-2).join(".");
      const topLevelFinal = finalDomain.split(".").slice(-2).join(".");

      if (topLevelOriginal !== topLevelFinal) {
        // Completely different domain
        return {
          signal: "redirect-chain",
          triggered: true,
          weight: 55,
          explanation: `URL redirects from ${originalDomain} to a completely different domain: ${finalDomain}. Cross-domain redirects are a common phishing technique.`,
        };
      }

      // Same parent domain but different subdomain
      return {
        signal: "redirect-chain",
        triggered: true,
        weight: 20,
        explanation: `URL redirects from ${originalDomain} to ${finalDomain}. While on the same parent domain, this may indicate a tracking redirect.`,
      };
    } catch {
      return {
        signal: "redirect-chain",
        triggered: false,
        weight: 0,
        explanation: "Unable to analyze redirect chain.",
      };
    }
  },
};
