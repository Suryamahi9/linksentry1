export function getDomain(url: string): string {
  const parsed = new URL(url);
  return parsed.hostname.replace(/^www\./, "").replace(/^\[|\]$/g, "").toLowerCase();
}

export function normalizeHost(host: string): string {
  return host
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/:.*$/, "")
    .replace(/\.$/, "");
}