import type { ScannerModule, ScanSignal } from "../types.js";

const IP_LITERAL_REGEX =
  /^https?:\/\/(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::\d+)?(?:\/.*)?$/;
const IPV6_REGEX = /^https?:\/\/\[[\da-fA-F:]+\](?::\d+)?(?:\/.*)?$/;

export const ipLiteralScanner: ScannerModule = {
  name: "ip-literal",

  async scan(url: string, _finalUrl: string): Promise<ScanSignal> {
    try {
      const isIPv4 = IP_LITERAL_REGEX.test(url);
      const isIPv6 = IPV6_REGEX.test(url);

      if (isIPv4 || isIPv6) {
        return {
          signal: "ip-literal",
          triggered: true,
          weight: 60,
          explanation: `URL uses an IP address literal (${isIPv6 ? "IPv6" : "IPv4"}) instead of a domain name. This is common in phishing URLs.`,
        };
      }

      return {
        signal: "ip-literal",
        triggered: false,
        weight: 0,
        explanation: "URL uses a domain name, not an IP literal.",
      };
    } catch {
      return {
        signal: "ip-literal",
        triggered: false,
        weight: 0,
        explanation: "Unable to check for IP literal in URL.",
      };
    }
  },
};
