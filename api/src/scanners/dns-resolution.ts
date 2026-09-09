import type { ScannerModule, ScanSignal } from "../types.js";
import dns from "dns/promises";

export const dnsResolutionScanner: ScannerModule = {
  name: "dns-resolution",

  async scan(_url: string, finalUrl: string): Promise<ScanSignal> {
    try {
      const parsed = new URL(finalUrl);
      const hostname = parsed.hostname.replace(/^\[|\]$/g, "");

      // IP literals don't need DNS resolution
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":")) {
        return {
          signal: "dns-resolution",
          triggered: false,
          weight: 0,
          explanation: "URL uses an IP address literal, no DNS resolution required.",
        };
      }

      await dns.lookup(hostname);
      return {
        signal: "dns-resolution",
        triggered: false,
        weight: 0,
        explanation: `Domain ${hostname} resolves correctly.`,
      };
    } catch {
      return {
        signal: "dns-resolution",
        triggered: true,
        weight: 50,
        explanation:
          "Domain does not resolve to any server. The site may be dead, the domain misspelled, or DNS not yet propagated.",
      };
    }
  },
};