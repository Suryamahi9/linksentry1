import type { PagePreview } from "../types.js";

const MAX_BYTES = 65536;

// Strip anything that looks like markup, collapse whitespace, cap length.
// Output is plain text only — fetched bytes are treated as untrusted data
// and never parsed as HTML/DOM.
function clean(raw: string | null | undefined, maxLen: number): string | null {
  if (!raw) return null;
  const stripped = raw
    .replace(/<\/?[^>]+>/g, " ")
    .replace(/[\r\n\t]+/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
  if (!stripped) return null;
  return stripped.slice(0, maxLen);
}

function attr(
  html: string,
  tag: RegExp,
  attrName: string
): string | null {
  const m = html.match(tag);
  if (!m) return null;
  const attrMatch = m[0].match(
    new RegExp(`${attrName}\\s*=\\s*["']([^"']*)["']`, "i")
  );
  return attrMatch ? attrMatch[1] : null;
}

function parse(html: string, finalUrl: string): PagePreview {
  const parsed = new URL(finalUrl);
  const domain = parsed.hostname;

  const titleTag = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const ogTitle = attr(html, /<meta[^>]+property=["']og:title["'][^>]*>/i, "content");
  const ogSite = attr(html, /<meta[^>]+property=["']og:site_name["'][^>]*>/i, "content");
  const metaDesc = attr(html, /<meta[^>]+name=["']description["'][^>]*>/i, "content");
  const ogDesc = attr(html, /<meta[^>]+property=["']og:description["'][^>]*>/i, "content");

  const title = clean(titleTag?.[1] ?? ogTitle, 120) || domain;
  const description = clean(metaDesc ?? ogDesc, 220);
  const siteName = clean(ogSite, 60);

  return {
    domain,
    title,
    description,
    siteName,
    https: parsed.protocol === "https:",
  };
}

/**
 * Request a bounded prefix of the final response, and only if it's HTML,
 * extract safe plain-text metadata for the preview card. Never renders or
 * executes any of the fetched bytes.
 */
export async function extractPreview(
  response: Response,
  finalUrl: string
): Promise<PagePreview | null> {
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("html")) return null;
  if (!response.ok) return null;

  try {
    // We only read the first response — the body is never written to disk,
    // rendered, or re-emitted except as sanitized text fields.
    const reader = response.body?.getReader();
    if (!reader) return null;

    let buf = "";
    let total = 0;
    const decoder = new TextDecoder();
    try {
      while (total < MAX_BYTES) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        total += value.byteLength;
      }
    } finally {
      reader.releaseLock();
    }

    // Terminate the underlying connection so we don't keep downloading.
    await response.body?.cancel().catch(() => {});

    // Require a real <html> (or at least <title>) to avoid false positives
    // on binary-ish bodies mislabeled as HTML.
    if (!/(<html|<title|<!doctype\s+html)/i.test(buf)) return null;

    return parse(buf, finalUrl);
  } catch {
    return null;
  }
}