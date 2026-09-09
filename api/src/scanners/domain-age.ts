import type { ScannerModule, ScanSignal } from "../types.js";

// RDAP bootstrap URL for TLD lookup
const RDAP_BOOTSTRAP_URL = "https://rdap.org/domain/";

// WHOIS-style lookup using RDAP (more reliable than raw WHOIS parsing)
async function getDomainCreationDate(domain: string): Promise<Date | null> {
  try {
    // Use rdap.org which is a public RDAP endpoint
    const response = await fetch(`${RDAP_BOOTSTRAP_URL}${domain}`, {
      headers: {
        Accept: "application/json",
        "User-Agent": "LinkSentry/1.0",
      },
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return null;

    const data = (await response.json()) as any;

    // RDAP events include "registration" which is the creation date
    const events = data.events || [];
    const registrationEvent = events.find(
      (e: any) => e.eventAction === "registration"
    );

    if (registrationEvent?.eventDate) {
      return new Date(registrationEvent.eventDate);
    }

    return null;
  } catch {
    return null;
  }
}

const DOMAIN_AGE_THRESHOLD_DAYS = 30;

export const domainAgeScanner: ScannerModule = {
  name: "domain-age",

  async scan(url: string, _finalUrl: string): Promise<ScanSignal> {
    try {
      const parsed = new URL(_finalUrl);
      const domain = parsed.hostname.replace(/^www\./, "");

      const creationDate = await getDomainCreationDate(domain);

      if (!creationDate) {
        return {
          signal: "domain-age",
          triggered: false,
          weight: 0,
          explanation:
            "Domain age lookup was unavailable. This is inconclusive — the registrar or registry may not expose creation dates via RDAP.",
        };
      }

      const now = new Date();
      const ageDays = Math.floor(
        (now.getTime() - creationDate.getTime()) / (1000 * 60 * 60 * 24)
      );

      if (ageDays < DOMAIN_AGE_THRESHOLD_DAYS) {
        return {
          signal: "domain-age",
          triggered: true,
          weight: 55,
          explanation: `Domain is only ${ageDays} day(s) old (registered ${creationDate.toISOString().split("T")[0]}). Recently registered domains are commonly used in phishing campaigns.`,
        };
      }

      if (ageDays < 90) {
        return {
          signal: "domain-age",
          triggered: true,
          weight: 20,
          explanation: `Domain is ${ageDays} days old (registered ${creationDate.toISOString().split("T")[0]}). Relatively new domain.`,
        };
      }

      return {
        signal: "domain-age",
        triggered: false,
        weight: 0,
        explanation: `Domain is ${ageDays} days old (registered ${creationDate.toISOString().split("T")[0]}).`,
      };
    } catch {
      return {
        signal: "domain-age",
        triggered: false,
        weight: 0,
        explanation: "Unable to perform domain age lookup.",
      };
    }
  },
};
