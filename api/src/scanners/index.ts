import type { ScannerModule, ScanSignal } from "../types.js";
import { homoglyphScanner } from "./homoglyph.js";
import { ipLiteralScanner } from "./ip-literal.js";
import { urlShortenerScanner } from "./url-shortener.js";
import { domainAgeScanner } from "./domain-age.js";
import { sslCheckScanner } from "./ssl-check.js";
import { redirectChainScanner } from "./redirect-chain.js";
import { dnsResolutionScanner } from "./dns-resolution.js";
import { heuristicRulesScanner } from "./rules-150.js";

export const scanners: ScannerModule[] = [
  homoglyphScanner,
  ipLiteralScanner,
  urlShortenerScanner,
  domainAgeScanner,
  sslCheckScanner,
  redirectChainScanner,
  dnsResolutionScanner,
  heuristicRulesScanner,
];

export async function runAllScanners(
  url: string,
  finalUrl: string
): Promise<ScanSignal[]> {
  const results = await Promise.allSettled(
    scanners.map((scanner) => scanner.scan(url, finalUrl))
  );

  return results.map((result, index) => {
    if (result.status === "fulfilled") {
      return result.value;
    }

    return {
      signal: scanners[index].name,
      triggered: false,
      weight: 0,
      explanation: `Scanner failed: ${result.reason?.message || "unknown error"}`,
    };
  });
}
