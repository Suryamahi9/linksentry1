import dns from "dns";
import { URL } from "url";

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/,
  /^fd00:/,
  /^fe80:/i,
  /^localhost$/i,
];

const LOOPBACK = /^127\./;
const LINK_LOCAL = /^169\.254\./;

const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 5000;

function isIpLiteral(host: string): boolean {
  // Strip brackets for IPv6
  const h = host.replace(/^\[|\]$/g, "");
  // IPv4
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h)) {
    const parts = h.split(".").map(Number);
    if (parts.every((p) => p >= 0 && p <= 255)) return true;
  }
  // IPv6 (contains colons)
  if (h.includes(":")) return true;
  return false;
}

export async function resolveAndValidateHost(hostname: string): Promise<string> {
  // If the host is an IP literal, validate it directly (no DNS needed)
  if (isIpLiteral(hostname)) {
    // IPv6 literals come bracketed; strip them
    const ip = hostname.replace(/^\[|\]$/g, "");
    validateIp(ip);
    return ip;
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("DNS resolution timed out"));
    }, 3000);

    dns.resolve4(hostname, (err, addresses) => {
      clearTimeout(timeout);
      if (err) {
        // Try IPv6
        dns.resolve6(hostname, (err6, addresses6) => {
          if (err6) {
            reject(new Error(`DNS resolution failed for ${hostname}: ${err.message}`));
          } else if (addresses6.length > 0) {
            validateIp(addresses6[0]);
            resolve(addresses6[0]);
          }
        });
      } else if (addresses.length > 0) {
        validateIp(addresses[0]);
        resolve(addresses[0]);
      }
    });
  });
}

function validateIp(ip: string): void {
  for (const range of PRIVATE_RANGES) {
    if (range.test(ip)) {
      throw new Error(
        `SSRF blocked: ${ip} is in a private/loopback/link-local range`
      );
    }
  }
}

export function validateUrl(urlStr: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(urlStr);
  } catch {
    throw new Error("Invalid URL format");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(
      `Unsupported protocol: ${parsed.protocol}. Only http: and https: are allowed`
    );
  }

  return parsed;
}

export async function safeFetch(
  urlStr: string,
  options: {
    maxRedirects?: number;
    timeoutMs?: number;
    method?: string;
  } = {}
): Promise<{ response: Response; redirectChain: string[]; finalUrl: string }> {
  const {
    maxRedirects = MAX_REDIRECTS,
    timeoutMs = FETCH_TIMEOUT_MS,
    method = "GET",
  } = options;

  let currentUrl = urlStr;
  const redirectChain: string[] = [urlStr];
  let redirectCount = 0;

  while (true) {
    const parsed = new URL(currentUrl);

    // Validate hostname before each fetch
    await resolveAndValidateHost(parsed.hostname);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(currentUrl, {
        method: redirectCount === 0 ? method : "GET",
        signal: controller.signal,
        headers: {
          "User-Agent": "LinkSentry/1.0 (URL Scanner)",
          Accept: "text/html,*/*",
        },
        redirect: "manual", // We handle redirects manually to validate each hop
      });

      clearTimeout(timeoutId);

      // Check if this is a redirect
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location) {
          throw new Error("Redirect with no Location header");
        }

        redirectCount++;
        if (redirectCount > maxRedirects) {
          throw new Error(
            `Too many redirects (exceeded ${maxRedirects}): ${redirectChain.join(" -> ")}`
          );
        }

        // Resolve relative redirects
        const nextUrl = new URL(location, currentUrl).toString();
        redirectChain.push(nextUrl);

        // Check for domain mismatch (redirect to different domain)
        const nextParsed = new URL(nextUrl);
        if (nextParsed.hostname !== parsed.hostname) {
          // This is a cross-domain redirect — we still follow it but flag it
        }

        currentUrl = nextUrl;
        continue;
      }

      return {
        response,
        redirectChain,
        finalUrl: currentUrl,
      };
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === "AbortError") {
        throw new Error(`Fetch timed out after ${timeoutMs}ms: ${currentUrl}`);
      }
      throw err;
    }
  }
}

export function getRedirectDomains(redirectChain: string[]): string[] {
  return redirectChain.map((url) => new URL(url).hostname);
}
