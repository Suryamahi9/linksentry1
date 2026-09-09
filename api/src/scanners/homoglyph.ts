import type { ScannerModule, ScanSignal } from "../types.js";

// Homoglyph characters that look similar to ASCII
const HOMOGLYPHS: Record<string, string[]> = {
  a: ["а", "ạ", "à", "á", "â", "ã", "ä", "å", "α", "ａ"],
  c: ["с", "ç", "ć", "č", "ｃ"],
  e: ["е", "ё", "ε", "ｅ"],
  o: ["о", "ο", "ò", "ó", "ô", "õ", "ö", "ø", "ｏ"],
  p: ["р", "ρ", "ｐ"],
  x: ["х", "χ", "ｘ"],
  y: ["у", "ý", "ｙ"],
};

const KNOWN_BRANDS = [
  "google",
  "facebook",
  "apple",
  "microsoft",
  "amazon",
  "paypal",
  "netflix",
  "instagram",
  "twitter",
  "linkedin",
  "github",
  "dropbox",
  "bank",
  "chase",
  "wellsfargo",
  "wells",
  "citibank",
  "hsbc",
];

export const homoglyphScanner: ScannerModule = {
  name: "homoglyph-check",

  async scan(url: string, _finalUrl: string): Promise<ScanSignal> {
    try {
      const parsed = new URL(url);
      const domain = parsed.hostname;

      // Check for punycode / internationalized domain (non-ASCII encoded as xn--)
      const isPunycode = domain.startsWith("xn--");

      // Check for non-ASCII characters directly in the hostname
      const hasNonAscii = /[^\x00-\x7F]/.test(domain);

      // Check for homoglyph substitutions in known brands
      let homoglyphDetected = false;
      let matchedBrand = "";

      for (const brand of KNOWN_BRANDS) {
        const brandChars = brand.split("");
        let mismatches = 0;
        let matchCount = 0;

        for (const char of brandChars) {
          if (domain.includes(char)) {
            matchCount++;
          } else {
            const glyphs = HOMOGLYPHS[char] || [];
            const hasGlyph = glyphs.some((g) => domain.includes(g));
            if (hasGlyph) {
              matchCount++;
              mismatches++;
            }
          }
        }

        if (
          matchCount >= brandChars.length * 0.7 &&
          mismatches > 0 &&
          domain.length < brand.length + 10
        ) {
          homoglyphDetected = true;
          matchedBrand = brand;
          break;
        }
      }

      const hasExcessiveSpecials = /[-_]{3,}/.test(domain);
      const isSuspiciouslyLong = domain.length > 50;

      const triggered =
        homoglyphDetected || isPunycode || hasNonAscii || hasExcessiveSpecials || isSuspiciouslyLong;

      let explanation = "Domain appears to use standard ASCII characters.";
      if (homoglyphDetected) {
        explanation = `Domain contains homoglyph characters that mimic "${matchedBrand}" — possible typosquatting.`;
      } else if (isPunycode) {
        explanation =
          "Domain uses punycode (internationalized domain name). This can be used for homograph attacks.";
      } else if (hasNonAscii) {
        explanation =
          "Domain contains non-ASCII characters, which may indicate an internationalized domain used for spoofing.";
      } else if (hasExcessiveSpecials) {
        explanation =
          "Domain contains excessive hyphens/underscores, which is atypical for legitimate sites.";
      } else if (isSuspiciouslyLong) {
        explanation = "Domain is unusually long (>50 chars), which can be used to obscure the real destination.";
      }

      return {
        signal: "homoglyph",
        triggered,
        weight: homoglyphDetected ? 70 : isPunycode ? 30 : hasNonAscii ? 25 : 15,
        explanation,
      };
    } catch {
      return {
        signal: "homoglyph",
        triggered: false,
        weight: 0,
        explanation: "Unable to parse domain for homoglyph analysis.",
      };
    }
  },
};
