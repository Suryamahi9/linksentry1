import type { ScannerModule, ScanSignal } from "../types.js";

const KNOWN_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "is.gd",
  "buff.ly",
  "ow.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at",
  "rb.gy",
  "bl.ink",
  "lnkd.in",
  "tiny.cc",
  "clk.sh",
  "cut.ly",
  "shorturl.do",
  "v.gd",
  "qr.ae",
]);

export const urlShortenerScanner: ScannerModule = {
  name: "url-shortener",

  async scan(url: string, _finalUrl: string): Promise<ScanSignal> {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();

      const isShortener = KNOWN_SHORTENERS.has(hostname);

      if (isShortener) {
        // If finalUrl differs from original, we followed the redirect
        const finalParsed = new URL(_finalUrl);
        const finalHostname = finalParsed.hostname.toLowerCase();
        const wasFollowed = hostname !== finalHostname;

        if (wasFollowed) {
          return {
            signal: "url-shortener",
            triggered: true,
            weight: 20,
            explanation: `URL uses shortener ${hostname} which redirects to ${finalHostname}. The final destination was scored instead.`,
          };
        }

        return {
          signal: "url-shortener",
          triggered: true,
          weight: 20,
          explanation: `URL uses known shortener ${hostname}. Shortened URLs obscure the real destination and are commonly used in phishing.`,
        };
      }

      return {
        signal: "url-shortener",
        triggered: false,
        weight: 0,
        explanation: "URL does not use a known URL shortener.",
      };
    } catch {
      return {
        signal: "url-shortener",
        triggered: false,
        weight: 0,
        explanation: "Unable to check for URL shortener.",
      };
    }
  },
};
