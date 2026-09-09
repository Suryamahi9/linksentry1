import type { ScannerModule, ScanSignal } from "../types.js";
import tls from "tls";

export const sslCheckScanner: ScannerModule = {
  name: "ssl-check",

  async scan(_url: string, finalUrl: string): Promise<ScanSignal> {
    try {
      const parsed = new URL(finalUrl);

      if (parsed.protocol !== "https:") {
        return {
          signal: "ssl-check",
          triggered: true,
          weight: 20,
          explanation:
            "URL does not use HTTPS. Data sent to this URL is transmitted unencrypted.",
        };
      }

      const hostname = parsed.hostname;
      const port = parseInt(parsed.port || "443", 10);

      const cert = await new Promise<any>((resolve, reject) => {
        const socket = tls.connect(
          {
            host: hostname,
            port,
            servername: hostname,
            rejectUnauthorized: false,
            timeout: 5000,
          },
          () => {
            const c = socket.getPeerCertificate();
            socket.end();
            resolve(c);
          }
        );

        socket.on("error", (err) => {
          socket.destroy();
          reject(err);
        });

        socket.on("timeout", () => {
          socket.destroy();
          reject(new Error("TLS handshake timeout"));
        });
      });

      if (!cert || !cert.subject) {
        return {
          signal: "ssl-check",
          triggered: false,
          weight: 0,
          explanation:
            "TLS connection established but no certificate details were returned.",
        };
      }

      const issues: string[] = [];

      const isSelfSigned =
        cert.issuer?.CN === cert.subject?.CN &&
        cert.issuer?.O === cert.subject?.O;

      if (isSelfSigned) {
        issues.push("self-signed");
      }

      const validTo = new Date(cert.valid_to);
      if (validTo < new Date()) {
        issues.push("expired");
      }

      const domainMatch = checkDomainMatch(cert, hostname);
      if (!domainMatch) {
        issues.push("domain mismatch");
      }

      if (issues.length > 0) {
        return {
          signal: "ssl-check",
          triggered: true,
          weight: issues.includes("expired") ? 75 : 65,
          explanation: `SSL certificate issues: ${issues.join(", ")}. The certificate is not trustworthy, which can indicate the site is not properly secured or is impersonating another domain.`,
        };
      }

      return {
        signal: "ssl-check",
        triggered: false,
        weight: 0,
        explanation: `SSL certificate is valid and issued by ${cert.issuer?.CN || "unknown CA"}.`,
      };
    } catch (err: any) {
      // Connection failures (DNS error, timeout, refused) are NOT certificate
      // problems — report neutral so a dead/hostile network doesn't produce a
      // false "broken certificate" finding.
      return {
        signal: "ssl-check",
        triggered: false,
        weight: 0,
        explanation:
          "SSL check could not establish a connection (DNS, timeout, or network error). No certificate finding.",
      };
    }
  },
};

function checkDomainMatch(cert: any, hostname: string): boolean {
  const san = cert.subjectaltname || "";
  const sanDomains = san
    .split(",")
    .map((s: string) => s.trim().replace("DNS:", ""))
    .filter(Boolean);

  for (const domain of sanDomains) {
    if (domain === hostname) return true;
    if (domain.startsWith("*.")) {
      const wildcard = domain.slice(2);
      if (hostname.endsWith(wildcard)) return true;
    }
  }

  if (cert.subject?.CN === hostname) return true;

  return false;
}