import type { ScannerModule, ScanSignal } from "../types.js";

// Each rule is a lightweight synchronous check. Heavy async checks (WHOIS, SSL, DNS) live in their own scanners.
// This engine covers 150 heuristic rules for URL/DOMAIN/CONTENT/BRAND/TECHNICAL pattern detection.

type Rule = {
  id: string;
  weight: number;
  check: (url: URL, raw: string, domain: string) => { triggered: boolean; explanation: string };
};

const INDIAN_BRANDS = [
  "sbi", "hdfc", "icici", "axisbank", "kotak", "pnb", "bob", "canarabank", "unionbank",
  "phonepe", "paytm", "googlepay", "gpay", "bhim", "upi",
  "irctc", "aadhaar", "uidai", "pan", "incometax",
  "flipkart", "amazon", "myntra", "meesho",
];

const GLOBAL_BRANDS = [
  "google", "facebook", "apple", "microsoft", "amazon", "paypal", "netflix", "instagram",
  "twitter", "linkedin", "github", "dropbox", "whatsapp", "telegram",
];

const SUSPICIOUS_TLDS = new Set([".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".date", ".loan", ".win", ".bid", ".click", ".country", ".stream"]);
const PHISH_KEYWORDS = ["login", "verify", "secure", "account", "update", "confirm", "signin", "banking", "kyc", "otp", "urgent", "suspended", "limited", "unlock", "authenticate", "validate", "webscr", "ebayisapi"];
const URGENCY_WORDS = ["urgent", "immediate", "suspended", "blocked", "limited", "expire", "alert", "warning", "attention", "action required"];
const FINANCIAL_WORDS = ["payment", "invoice", "refund", "transfer", "wallet", "balance", "transaction", "kyc", "aadhaar", "pan", "upi"];

function hasKeyword(haystack: string, words: string[]): string | null {
  const low = haystack.toLowerCase();
  for (const w of words) if (low.includes(w)) return w;
  return null;
}

function entropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let e = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

const RULES: Rule[] = [
  // ── 1-30: URL STRUCTURE ────────────────────────────────────────────────
  { id: "url-too-long", weight: 15, check: (u, raw) => ({ triggered: raw.length > 200, explanation: raw.length > 200 ? `URL is unusually long (${raw.length} chars), often used to hide the real destination.` : "URL length is normal." }) },
  { id: "url-very-long", weight: 25, check: (u, raw) => ({ triggered: raw.length > 400, explanation: raw.length > 400 ? "URL exceeds 400 characters — highly suspicious." : "URL not excessively long." }) },
  { id: "contains-at-symbol", weight: 40, check: (u, raw) => ({ triggered: raw.includes("@"), explanation: raw.includes("@") ? "URL contains '@', which can obscure the real host (e.g. http://legit@evil.com)." : "No '@' obfuscation." }) },
  { id: "multiple-at-symbols", weight: 55, check: (u, raw) => ({ triggered: (raw.match(/@/g) || []).length > 1, explanation: "Multiple '@' symbols — strong obfuscation signal." }) },
  { id: "userinfo-in-url", weight: 60, check: (u) => ({ triggered: Boolean(u.username || u.password), explanation: u.username ? "URL contains userinfo (user:pass@host) — classic phishing trick." : "No userinfo in URL." }) },
  { id: "double-slash-in-path", weight: 20, check: (u, raw) => ({ triggered: u.pathname.includes("//"), explanation: u.pathname.includes("//") ? "Double slash in path — possible path confusion." : "No double slash." }) },
  { id: "percent-encoding-heavy", weight: 25, check: (u, raw) => ({ triggered: (raw.match(/%[0-9a-fA-F]{2}/g) || []).length >= 4, explanation: "Heavy percent-encoding (≥4 sequences) — used to hide keywords." }) },
  { id: "hex-encoded-url", weight: 30, check: (u, raw) => ({ triggered: /%0[0-8a-d]/i.test(raw), explanation: /%0[0-8a-d]/i.test(raw) ? "Suspicious hex encoding (%00, %0a etc) — evasion attempt." : "No suspicious hex encoding." }) },
  { id: "port-specified", weight: 20, check: (u) => ({ triggered: Boolean(u.port), explanation: u.port ? `Non-default port :${u.port} — uncommon for public sites.` : "No custom port." }) },
  { id: "nonstandard-https-port", weight: 15, check: (u) => ({ triggered: u.protocol === "https:" && u.port !== "" && u.port !== "443", explanation: u.protocol === "https:" && u.port !== "" && u.port !== "443" ? "HTTPS on non-standard port." : "Standard HTTPS port." }) },
  { id: "fragment-contains-url", weight: 25, check: (u) => ({ triggered: u.hash.includes("http"), explanation: u.hash.includes("http") ? "Fragment contains a URL — possible open redirect." : "No URL in fragment." }) },
  { id: "query-contains-url", weight: 25, check: (u) => ({ triggered: u.search.toLowerCase().includes("http"), explanation: u.search.toLowerCase().includes("http") ? "Query string contains a URL — possible open redirect." : "No URL in query." }) },
  { id: "excessive-query-params", weight: 15, check: (u) => ({ triggered: [...u.searchParams.keys()].length >= 6, explanation: [...u.searchParams.keys()].length >= 6 ? "Excessive query parameters (≥6) — tracking or injection." : "Query param count normal." }) },
  { id: "whitespace-encoded", weight: 20, check: (u, raw) => ({ triggered: raw.includes("%20") && raw.split("%20").length > 3, explanation: raw.includes("%20") && raw.split("%20").length > 3 ? "Multiple encoded spaces — obfuscation." : "No whitespace obfuscation." }) },
  { id: "path-depth-excessive", weight: 15, check: (u) => ({ triggered: u.pathname.split("/").filter(Boolean).length >= 6, explanation: u.pathname.split("/").filter(Boolean).length >= 6 ? "Deep path (≥6 segments) — mimics legit hierarchy." : "Path depth normal." }) },
  { id: "data-uri-scheme", weight: 80, check: (u, raw) => ({ triggered: raw.toLowerCase().startsWith("data:"), explanation: raw.toLowerCase().startsWith("data:") ? "data: URI — can embed malicious payloads." : "Not a data URI." }) },
  { id: "javascript-scheme", weight: 90, check: (u, raw) => ({ triggered: raw.toLowerCase().startsWith("javascript:"), explanation: raw.toLowerCase().startsWith("javascript:") ? "javascript: URI — XSS vector." : "Not javascript: URI." }) },
  { id: "base64-like-substring", weight: 20, check: (u, raw) => ({ triggered: /[A-Za-z0-9+/]{40,}={0,2}/.test(raw), explanation: /[A-Za-z0-9+/]{40,}={0,2}/.test(raw) ? "Long base64-like substring — possible encoded payload." : "No base64-like blob." }) },
  { id: "excessive-numeric-ratio", weight: 15, check: (u, raw) => ({ triggered: (raw.replace(/\D/g, "").length / raw.length) > 0.3, explanation: (raw.replace(/\D/g, "").length / raw.length) > 0.3 ? "High digit ratio (>30%) — random-looking URL." : "Digit ratio normal." }) },
  { id: "underscore-in-url", weight: 10, check: (u, raw) => ({ triggered: raw.includes("_") && (raw.match(/_/g) || []).length >= 3, explanation: raw.includes("_") && (raw.match(/_/g) || []).length >= 3 ? "Multiple underscores — uncommon in legit URLs." : "No excessive underscores." }) },
  { id: "excessive-dots", weight: 15, check: (u, raw) => ({ triggered: (raw.match(/\./g) || []).length >= 6, explanation: (raw.match(/\./g) || []).length >= 6 ? "Excessive dots (≥6) — subdomain stuffing." : "Dot count normal." }) },
  { id: "dash-in-url-heavy", weight: 10, check: (u, raw) => ({ triggered: (raw.match(/-/g) || []).length >= 5, explanation: (raw.match(/-/g) || []).length >= 5 ? "Many hyphens (≥5) — typosquatting pattern." : "Hyphen count normal." }) },
  { id: "mixed-case-url", weight: 10, check: (u, raw) => ({ triggered: /[A-Z]/.test(raw) && /[a-z]/.test(raw) && raw.length > 40, explanation: /[A-Z]/.test(raw) && /[a-z]/.test(raw) && raw.length > 40 ? "Mixed case in long URL — evasion attempt." : "Case pattern normal." }) },
  { id: "url-shortener-param", weight: 15, check: (u) => ({ triggered: u.search.toLowerCase().includes("url=") || u.search.toLowerCase().includes("redirect"), explanation: u.search.toLowerCase().includes("url=") ? "Query contains url=/redirect — open redirect risk." : "No redirect param." }) },
  { id: "suspicious-file-extension", weight: 30, check: (u) => ({ triggered: /\.(exe|scr|dll|bat|cmd|js|vbs|ps1)$/i.test(u.pathname), explanation: /\.(exe|scr|dll|bat|cmd|js|vbs|ps1)$/i.test(u.pathname) ? "URL ends with executable extension — malware risk." : "No executable extension." }) },
  { id: "login-keyword-in-path", weight: 20, check: (u) => ({ triggered: hasKeyword(u.pathname + u.search, ["login", "signin"]) !== null, explanation: hasKeyword(u.pathname + u.search, ["login", "signin"]) ? "Login keyword in path — phishing lure." : "No login keyword." }) },
  { id: "secure-keyword-decoy", weight: 20, check: (u) => ({ triggered: hasKeyword(u.hostname + u.pathname, ["secure", "safety", "protected"]) !== null, explanation: hasKeyword(u.hostname + u.pathname, ["secure", "safety", "protected"]) ? "Decoy 'secure' keyword — false trust signal." : "No secure decoy." }) },
  { id: "verify-keyword", weight: 20, check: (u) => ({ triggered: hasKeyword(u.pathname + u.search + u.hostname, ["verify", "validation", "authenticate"]) !== null, explanation: hasKeyword(u.pathname + u.search + u.hostname, ["verify", "validation", "authenticate"]) ? "Verification keyword — common phishing bait." : "No verify keyword." }) },
  { id: "update-keyword", weight: 15, check: (u) => ({ triggered: hasKeyword(u.pathname + u.search + u.hostname, ["update", "upgrade"]) !== null, explanation: hasKeyword(u.pathname + u.search + u.hostname, ["update", "upgrade"]) ? "Update keyword — urgency bait." : "No update keyword." }) },
  { id: "account-keyword", weight: 15, check: (u) => ({ triggered: hasKeyword(u.pathname + u.search + u.hostname, ["account", "profile"]) !== null, explanation: hasKeyword(u.pathname + u.search + u.hostname, ["account", "profile"]) ? "Account keyword in URL." : "No account keyword." }) },

  // ── 31-60: DOMAIN & TLD ────────────────────────────────────────────────
  { id: "suspicious-tld", weight: 35, check: (u, raw, domain) => { const tld = "." + domain.split(".").pop()!; return { triggered: SUSPICIOUS_TLDS.has(tld), explanation: SUSPICIOUS_TLDS.has(tld) ? `Suspicious TLD ${tld} — abused for phishing.` : `TLD ${tld} not in high-risk list.` }; } },
  { id: "domain-too-long", weight: 15, check: (u, raw, domain) => ({ triggered: domain.length > 30, explanation: domain.length > 30 ? `Domain very long (${domain.length} chars).` : "Domain length normal." }) },
  { id: "domain-very-short", weight: 10, check: (u, raw, domain) => ({ triggered: domain.split(".")[0].length <= 2 && domain.length > 5, explanation: domain.split(".")[0].length <= 2 ? "Ultra-short label — possible random domain." : "Domain label not suspiciously short." }) },
  { id: "domain-entropy-high", weight: 25, check: (u, raw, domain) => { const label = domain.split(".")[0]; const e = entropy(label); return { triggered: e > 3.5 && label.length > 8, explanation: e > 3.5 && label.length > 8 ? `High entropy (${e.toFixed(1)}) — random-looking domain.` : "Domain entropy normal." }; } },
  { id: "domain-digit-heavy", weight: 15, check: (u, raw, domain) => { const label = domain.split(".")[0]; return { triggered: (label.replace(/\D/g, "").length / label.length) > 0.4, explanation: (label.replace(/\D/g, "").length / label.length) > 0.4 ? "Domain label digit-heavy (>40%)." : "Digit ratio in domain normal." }; } },
  { id: "excessive-subdomain-depth", weight: 25, check: (u, raw, domain) => ({ triggered: domain.split(".").length >= 5, explanation: domain.split(".").length >= 5 ? "Excessive subdomain depth (≥5 labels) — hiding real host." : "Subdomain depth normal." }) },
  { id: "www-multiple", weight: 10, check: (u, raw, domain) => ({ triggered: (domain.match(/www\./g) || []).length > 1, explanation: (domain.match(/www\./g) || []).length > 1 ? "Multiple www. — obfuscation." : "Single www." }) },
  { id: "hyphen-heavy-domain", weight: 20, check: (u, raw, domain) => ({ triggered: (domain.match(/-/g) || []).length >= 3, explanation: (domain.match(/-/g) || []).length >= 3 ? "Domain has ≥3 hyphens — typosquatting." : "Hyphens normal." }) },
  { id: "consecutive-hyphens", weight: 25, check: (u, raw, domain) => ({ triggered: domain.includes("--"), explanation: domain.includes("--") ? "Consecutive hyphens — punycode or obfuscation." : "No consecutive hyphens." }) },
  { id: "starts-ends-with-hyphen", weight: 20, check: (u, raw, domain) => { const label = domain.split(".")[0]; return { triggered: label.startsWith("-") || label.endsWith("-"), explanation: label.startsWith("-") || label.endsWith("-") ? "Label starts/ends with hyphen — invalid-looking." : "Hyphen placement normal." }; } },
  { id: "numeric-tld", weight: 30, check: (u, raw, domain) => ({ triggered: /\.\d+$/.test(domain), explanation: /\.\d+$/.test(domain) ? "Numeric TLD — highly suspicious." : "TLD not numeric." }) },
  { id: "single-char-subdomain", weight: 15, check: (u, raw, domain) => ({ triggered: domain.split(".").some((p) => p.length === 1 && p !== "w"), explanation: domain.split(".").some((p) => p.length === 1 && p !== "w") ? "Single-char subdomain label — random." : "No single-char subdomain." }) },
  { id: "brand-subdomain-trick", weight: 35, check: (u, raw, domain) => { const low = domain.toLowerCase(); const hit = [...GLOBAL_BRANDS, ...INDIAN_BRANDS].find((b) => low.includes(b) && !low.startsWith(b + ".") && !low.startsWith(b + "-") && low !== b && low.split(".").slice(-2).join(".") !== b + ".com"); return { triggered: Boolean(hit), explanation: hit ? `Brand '${hit}' appears as subdomain of unrelated domain — impersonation.` : "No brand-in-subdomain trick." }; } },
  { id: "tld-is-brand", weight: 40, check: (u, raw, domain) => { const parts = domain.toLowerCase().split("."); const tldBrand = parts[parts.length - 1]; return { triggered: [...GLOBAL_BRANDS, ...INDIAN_BRANDS].includes(tldBrand), explanation: [...GLOBAL_BRANDS, ...INDIAN_BRANDS].includes(tldBrand) ? `TLD is a brand name '${tldBrand}' — spoofing.` : "TLD not a brand." }; } },
  { id: "duplicated-domain-words", weight: 15, check: (u, raw, domain) => { const parts = domain.toLowerCase().split("."); return { triggered: new Set(parts).size !== parts.length, explanation: new Set(parts).size !== parts.length ? "Repeated label in domain — stuffing." : "No repeated labels." }; } },
  { id: "longest-label-over-20", weight: 15, check: (u, raw, domain) => ({ triggered: Math.max(...domain.split(".").map((p) => p.length)) > 20, explanation: Math.max(...domain.split(".").map((p) => p.length)) > 20 ? "A domain label exceeds 20 chars — obfuscation." : "Label lengths normal." }) },
  { id: "xn-prefix-anywhere", weight: 30, check: (u, raw, domain) => ({ triggered: domain.includes("xn--"), explanation: domain.includes("xn--") ? "Punycode segment — homograph risk." : "No punycode." }) },
  { id: "unicode-in-domain", weight: 30, check: (u, raw, domain) => ({ triggered: /[^\x00-\x7F]/.test(domain), explanation: /[^\x00-\x7F]/.test(domain) ? "Non-ASCII in domain — homograph risk." : "Domain is ASCII." }) },
  { id: "mixed-script-domain", weight: 40, check: (u, raw, domain) => ({ triggered: /[a-z]/.test(domain) && /[\u0400-\u04FF]/.test(domain), explanation: /[a-z]/.test(domain) && /[\u0400-\u04FF]/.test(domain) ? "Mixed Latin + Cyrillic — homograph attack." : "No mixed scripts." }) },
  { id: "dga-like-consonant-run", weight: 20, check: (u, raw, domain) => { const label = domain.split(".")[0].toLowerCase(); return { triggered: /[bcdfghjklmnpqrstvwxyz]{5,}/.test(label), explanation: /[bcdfghjklmnpqrstvwxyz]{5,}/.test(label) ? "Long consonant run — DGA-like." : "No DGA consonant run." }; } },
  { id: "repeated-char-run", weight: 15, check: (u, raw, domain) => ({ triggered: /(.)\1{3,}/.test(domain), explanation: /(.)\1{3,}/.test(domain) ? "Repeated character run (≥4) — random domain." : "No repeated run." }) },
  { id: "indian-tld-mismatch", weight: 20, check: (u, raw, domain) => { const low = domain.toLowerCase(); const isIndian = INDIAN_BRANDS.some((b) => low.includes(b)); const tld = low.split(".").pop(); return { triggered: isIndian && tld !== "in" && tld !== "co" && !low.endsWith(".co.in") && !low.endsWith(".com"), explanation: isIndian && tld !== "in" && tld !== "co" && !low.endsWith(".co.in") && !low.endsWith(".com") ? "Indian brand on unexpected TLD." : "TLD/brand alignment normal." }; } },
  { id: "new-tld-high-risk", weight: 20, check: (u, raw, domain) => { const tld = "." + domain.split(".").pop()!.toLowerCase(); return { triggered: [".online", ".site", ".website", ".space", ".tech"].includes(tld) && domain.split(".")[0].length > 15, explanation: [".online", ".site", ".website", ".space", ".tech"].includes(tld) && domain.split(".")[0].length > 15 ? `New gTLD ${tld} with long label.` : "New gTLD not suspicious." }; } },
  { id: "domain-looks-like-ip", weight: 25, check: (u, raw, domain) => ({ triggered: /^\d+-\d+-\d+-\d+$/.test(domain.split(".")[0]), explanation: /^\d+-\d+-\d+-\d+$/.test(domain.split(".")[0]) ? "Label looks like an IP (dash-separated)." : "No IP-like label." }) },
  { id: "subdomain-is-ip-dotted", weight: 30, check: (u, raw, domain) => ({ triggered: /^\d+\.\d+\.\d+\.\d+$/.test(domain), explanation: /^\d+\.\d+\.\d+\.\d+$/.test(domain) ? "Domain is a dotted IP, not a name." : "Not an IP." }) },

  // ── 61-90: PHISHING CONTENT & INDIAN THREAT SIGNALS ─────────────────────
  { id: "phish-keyword-login", weight: 20, check: (u, raw) => { const low = raw.toLowerCase(); return { triggered: low.includes("login") || low.includes("signin"), explanation: low.includes("login") || low.includes("signin") ? "Login/signin keyword — phishing lure." : "No login keyword." }; } },
  { id: "phish-keyword-kyc", weight: 35, check: (u, raw) => ({ triggered: raw.toLowerCase().includes("kyc"), explanation: raw.toLowerCase().includes("kyc") ? "KYC keyword — Indian KYC scam pattern." : "No KYC keyword." }) },
  { id: "phish-keyword-otp", weight: 30, check: (u, raw) => ({ triggered: raw.toLowerCase().includes("otp"), explanation: raw.toLowerCase().includes("otp") ? "OTP keyword — credential theft." : "No OTP keyword." }) },
  { id: "phish-keyword-aadhaar", weight: 35, check: (u, raw) => ({ triggered: /aadhaar|aadhar|uidai/i.test(raw), explanation: /aadhaar|aadhar|uidai/i.test(raw) ? "Aadhaar/UIDAI keyword — identity harvest." : "No Aadhaar keyword." }) },
  { id: "phish-keyword-pan", weight: 30, check: (u, raw) => ({ triggered: /\bpan\b/i.test(raw) && /pan.*(update|verify|link)/i.test(raw), explanation: /\bpan\b/i.test(raw) && /pan.*(update|verify|link)/i.test(raw) ? "PAN update lure." : "No PAN lure." }) },
  { id: "phish-keyword-upi", weight: 35, check: (u, raw) => ({ triggered: /\bupi\b/i.test(raw) || /phonepe|paytm|gpay|bhim/i.test(raw), explanation: /\bupi\b/i.test(raw) || /phonepe|paytm|gpay|bhim/i.test(raw) ? "UPI/payment app keyword in URL — impersonation." : "No UPI keyword." }) },
  { id: "phish-keyword-irctc", weight: 30, check: (u, raw) => ({ triggered: /irctc/i.test(raw), explanation: /irctc/i.test(raw) ? "IRCTC keyword — fake booking scam." : "No IRCTC keyword." }) },
  { id: "phish-keyword-whatsapp-job", weight: 25, check: (u, raw) => ({ triggered: /whatsapp.*(job|earn|offer)|job.*whatsapp/i.test(raw), explanation: /whatsapp.*(job|earn|offer)|job.*whatsapp/i.test(raw) ? "WhatsApp job lure pattern." : "No job lure." }) },
  { id: "phish-keyword-bank-urgency", weight: 30, check: (u, raw) => ({ triggered: /sbi|hdfc|icici|axis/i.test(raw) && hasKeyword(raw, URGENCY_WORDS) !== null, explanation: /sbi|hdfc|icici|axis/i.test(raw) && hasKeyword(raw, URGENCY_WORDS) !== null ? "Bank name + urgency word — classic scam." : "No bank+urgency combo." }) },
  { id: "urgency-words", weight: 15, check: (u, raw) => { const hit = hasKeyword(raw, URGENCY_WORDS); return { triggered: hit !== null, explanation: hit ? `Urgency word '${hit}' — pressure tactic.` : "No urgency words." }; } },
  { id: "financial-words", weight: 15, check: (u, raw) => { const hit = hasKeyword(raw, FINANCIAL_WORDS); return { triggered: hit !== null, explanation: hit ? `Financial keyword '${hit}'.` : "No financial keywords." }; } },
  { id: "refund-prize-lure", weight: 25, check: (u, raw) => ({ triggered: /refund|prize|winner|lottery|reward|cashback/i.test(raw), explanation: /refund|prize|winner|lottery|reward|cashback/i.test(raw) ? "Refund/prize lure." : "No prize lure." }) },
  { id: "free-gift-lure", weight: 15, check: (u, raw) => ({ triggered: /free.*gift|gift.*free|congratulations/i.test(raw), explanation: /free.*gift|gift.*free|congratulations/i.test(raw) ? "Free gift lure." : "No gift lure." }) },
  { id: "suspended-blocked-lure", weight: 25, check: (u, raw) => ({ triggered: /suspended|blocked|restricted|locked/i.test(raw), explanation: /suspended|blocked|restricted|locked/i.test(raw) ? "Account suspended lure." : "No suspended lure." }) },
  { id: "click-here-pattern", weight: 15, check: (u) => ({ triggered: u.search.toLowerCase().includes("click") || u.pathname.toLowerCase().includes("click"), explanation: u.search.toLowerCase().includes("click") || u.pathname.toLowerCase().includes("click") ? "Click-bait path." : "No click-bait." }) },
  { id: "infected-virus-scare", weight: 20, check: (u, raw) => ({ triggered: /infected|virus|malware|threat.*detected/i.test(raw), explanation: /infected|virus|malware|threat.*detected/i.test(raw) ? "Virus scare keyword." : "No scare keyword." }) },
  { id: "gov-spoof-in", weight: 30, check: (u, raw) => ({ triggered: /gov\.in/i.test(raw) && !/\.gov\.in$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname), explanation: /gov\.in/i.test(raw) && !/\.gov\.in$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname) ? "Fake gov.in in URL — gov spoof." : "No gov spoof." }) },
  { id: "lottery-scam-india", weight: 20, check: (u, raw) => ({ triggered: /kbc|lottery.*india|rs.*crore/i.test(raw), explanation: /kbc|lottery.*india|rs.*crore/i.test(raw) ? "Indian lottery scam pattern." : "No lottery scam." }) },
  { id: "electricity-bill-scam", weight: 20, check: (u, raw) => ({ triggered: /electricity.*(bill|disconnect)|power.*cut/i.test(raw), explanation: /electricity.*(bill|disconnect)|power.*cut/i.test(raw) ? "Electricity bill scam pattern." : "No bill scam." }) },
  { id: "courier-scam", weight: 15, check: (u, raw) => ({ triggered: /courier|delivery.*(failed|pending)|customs.*fee/i.test(raw), explanation: /courier|delivery.*(failed|pending)|customs.*fee/i.test(raw) ? "Courier/delivery scam pattern." : "No courier scam." }) },
  { id: "brand-in-path-19", weight: 30, check: (u, raw) => { const low = (u.pathname + u.search).toLowerCase(); const hit = [...GLOBAL_BRANDS, ...INDIAN_BRANDS].find((b) => low.includes(b)); return { triggered: Boolean(hit), explanation: hit ? `Brand '${hit}' in path/query — impersonation.` : "No brand in path." }; } },
  { id: "brand-typosquat-fuzzy", weight: 35, check: (u, raw, domain) => { const label = domain.split(".")[0].toLowerCase(); const hit = [...GLOBAL_BRANDS, ...INDIAN_BRANDS].find((b) => { if (b.length < 4) return false; if (label === b) return false; let d = 0; for (let i = 0; i < Math.min(label.length, b.length); i++) if (label[i] !== b[i]) d++; return d === 1 && Math.abs(label.length - b.length) <= 1; }); return { triggered: Boolean(hit), explanation: hit ? `Possible typosquat of '${hit}' (off-by-one).` : "No typosquat detected." }; } },
  { id: "multiple-brands", weight: 40, check: (u, raw) => { const low = raw.toLowerCase(); const count = [...GLOBAL_BRANDS, ...INDIAN_BRANDS].filter((b) => low.includes(b)).length; return { triggered: count >= 2, explanation: count >= 2 ? `Multiple brands (${count}) in one URL — highly suspicious.` : "Not multiple brands." }; } },
  { id: "fake-login-page-pattern", weight: 35, check: (u, raw) => ({ triggered: /login.*(php|html).*\?|signin.*\.php/i.test(raw), explanation: /login.*(php|html).*\?|signin.*\.php/i.test(raw) ? "Fake login page pattern (login.php? id).`." : "No fake login pattern." }) },
  { id: "credential-harvest-pattern", weight: 30, check: (u, raw) => ({ triggered: /password|credential|harvest/i.test(raw) && u.search.length > 10, explanation: /password|credential|harvest/i.test(raw) && u.search.length > 10 ? "Credential keyword with query — harvest attempt." : "No credential harvest pattern." }) },

  // ── 91-120: TECHNICAL & REPUTATION ─────────────────────────────────────
  { id: "ip-in-subdomain", weight: 30, check: (u, raw, domain) => ({ triggered: /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/.test(domain), explanation: /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/.test(domain) ? "IP-like numbers in subdomain (dash-separated)." : "No IP-like subdomain." }) },
  { id: "hex-subdomain", weight: 20, check: (u, raw, domain) => ({ triggered: /\b[0-9a-f]{8,}\b/i.test(domain), explanation: /\b[0-9a-f]{8,}\b/i.test(domain) ? "Hex-like subdomain (tracking/exploit)." : "No hex subdomain." }) },
  { id: "url-contains-credentials-param", weight: 25, check: (u) => ({ triggered: [...u.searchParams.keys()].some((k) => /pass|pwd|token|secret|key/i.test(k)), explanation: [...u.searchParams.keys()].some((k) => /pass|pwd|token|secret|key/i.test(k)) ? "Query param looks like credential (pass/token)." : "No credential param." }) },
  { id: "open-redirect-param", weight: 30, check: (u) => ({ triggered: [...u.searchParams.keys()].some((k) => /^(url|next|redirect|return|goto|continue|dest|destination)$/i.test(k)), explanation: [...u.searchParams.keys()].some((k) => /^(url|next|redirect|return|goto|continue|dest|destination)$/i.test(k)) ? "Open-redirect parameter (url/next/redirect)." : "No open-redirect param." }) },
  { id: "double-encoding", weight: 25, check: (u, raw) => ({ triggered: /%25[0-9a-fA-F]{2}/.test(raw), explanation: /%25[0-9a-fA-F]{2}/.test(raw) ? "Double percent-encoding — evasion." : "No double encoding." }) },
  { id: "null-byte-injection", weight: 40, check: (u, raw) => ({ triggered: raw.includes("%00"), explanation: raw.includes("%00") ? "Null byte %00 — injection attempt." : "No null byte." }) },
  { id: "crlf-injection", weight: 35, check: (u, raw) => ({ triggered: raw.includes("%0d") || raw.includes("%0a"), explanation: raw.includes("%0d") || raw.includes("%0a") ? "CRLF %0d/%0a — header injection." : "No CRLF." }) },
  { id: "xss-param-pattern", weight: 35, check: (u, raw) => ({ triggered: /<script|%3cscript|javascript:/i.test(raw), explanation: /<script|%3cscript|javascript:/i.test(raw) ? "XSS payload pattern in URL." : "No XSS pattern." }) },
  { id: "sqli-param-pattern", weight: 30, check: (u, raw) => ({ triggered: /(\%27|\')\s*(or|union|select)\s+/i.test(raw), explanation: /(\%27|\')\s*(or|union|select)\s+/i.test(raw) ? "SQLi pattern in query." : "No SQLi pattern." }) },
  { id: "path-traversal", weight: 40, check: (u, raw) => ({ triggered: raw.includes("../") || raw.includes("%2e%2e"), explanation: raw.includes("../") || raw.includes("%2e%2e") ? "Path traversal ../ — exploit." : "No traversal." }) },
  { id: "excessive-slashes", weight: 15, check: (u, raw) => ({ triggered: (raw.match(/\//g) || []).length >= 8, explanation: (raw.match(/\//g) || []).length >= 8 ? "Excessive slashes (≥8) — deep nesting." : "Slash count normal." }) },
  { id: "tiny-url-param-id", weight: 15, check: (u) => ({ triggered: u.searchParams.has("id") && (u.searchParams.get("id") || "").length >= 20, explanation: u.searchParams.has("id") && (u.searchParams.get("id") || "").length >= 20 ? "Long id= param — tracking or token exfil." : "No long id param." }) },
  { id: "tracking-utm-heavy", weight: 10, check: (u) => ({ triggered: [...u.searchParams.keys()].filter((k) => k.startsWith("utm_")).length >= 3, explanation: [...u.searchParams.keys()].filter((k) => k.startsWith("utm_")).length >= 3 ? "Many utm_ params — heavy tracking." : "UTM count normal." }) },
  { id: "private-ip-in-query", weight: 50, check: (u) => ({ triggered: /10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/.test(u.search), explanation: /10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/.test(u.search) ? "Private IP in query — SSRF probe." : "No private IP in query." }) },
  { id: "localhost-in-url", weight: 40, check: (u, raw) => ({ triggered: /localhost|127\.0\.0\.1/i.test(raw) && !raw.includes("localhost:3000") && !raw.includes("localhost:3001"), explanation: /localhost|127\.0\.0\.1/i.test(raw) && !raw.includes("localhost:3000") && !raw.includes("localhost:3001") ? "Localhost in URL — SSRF." : "No localhost trick." }) },
  { id: "cloud-metadata-ip", weight: 60, check: (u, raw) => ({ triggered: raw.includes("169.254.169.254") || raw.includes("metadata.google"), explanation: raw.includes("169.254.169.254") || raw.includes("metadata.google") ? "Cloud metadata IP — SSRF." : "No metadata IP." }) },
  { id: "aws-key-pattern", weight: 35, check: (u, raw) => ({ triggered: /AKIA[0-9A-Z]{16}/.test(raw), explanation: /AKIA[0-9A-Z]{16}/.test(raw) ? "AWS key pattern in URL — secret leak." : "No AWS key pattern." }) },
  { id: "api-key-in-query", weight: 25, check: (u) => ({ triggered: [...u.searchParams.keys()].some((k) => /api[_-]?key|apikey/i.test(k)), explanation: [...u.searchParams.keys()].some((k) => /api[_-]?key|apikey/i.test(k)) ? "api_key in query — credential exposure." : "No api_key in query." }) },
  { id: "ipfs-gateway", weight: 15, check: (u, raw, domain) => ({ triggered: domain.includes("ipfs") || raw.includes("/ipfs/"), explanation: domain.includes("ipfs") || raw.includes("/ipfs/") ? "IPFS gateway — decentralized, hard to takedown." : "Not IPFS." }) },
  { id: "ngrok-trycloudflare-tunnel", weight: 20, check: (u, raw, domain) => ({ triggered: /ngrok|trycloudflare|loca\.lt/i.test(domain), explanation: /ngrok|trycloudflare|loca\.lt/i.test(domain) ? "Tunneling domain — ephemeral phishing." : "No tunnel domain." }) },
  { id: "github-pages-spoof", weight: 15, check: (u, raw, domain) => ({ triggered: domain.endsWith("github.io") && /login|verify|secure/i.test(raw), explanation: domain.endsWith("github.io") && /login|verify|secure/i.test(raw) ? "GitHub Pages hosting phishing-like path." : "Not GitHub Pages abuse." }) },
  { id: "vercel-spoof", weight: 15, check: (u, raw, domain) => ({ triggered: domain.endsWith("vercel.app") && /sbi|hdfc|paytm|upi|login/i.test(raw), explanation: domain.endsWith("vercel.app") && /sbi|hdfc|paytm|upi|login/i.test(raw) ? "Vercel app hosting bank-like path — impersonation." : "Not Vercel abuse." }) },
  { id: "free-hosting-spoof", weight: 20, check: (u, raw, domain) => ({ triggered: /\.(tk|ml|ga|cf|gq|000webhostapp\.com|infinityfreeapp\.com)/i.test(domain) && /login|verify/i.test(raw), explanation: /\.(tk|ml|ga|cf|gq|000webhostapp\.com|infinityfreeapp\.com)/i.test(domain) && /login|verify/i.test(raw) ? "Free hosting + login path — phishing." : "No free-hosting abuse." }) },
  { id: "punycode-tld", weight: 35, check: (u, raw, domain) => ({ triggered: domain.split(".").pop()!.startsWith("xn--"), explanation: domain.split(".").pop()!.startsWith("xn--") ? "Punycode TLD — homograph." : "TLD not punycode." }) },
  { id: "idn-in-subdomain", weight: 25, check: (u, raw, domain) => ({ triggered: domain.split(".").slice(0, -2).some((p) => p.startsWith("xn--")), explanation: domain.split(".").slice(0, -2).some((p) => p.startsWith("xn--")) ? "Punycode in subdomain — homograph." : "Subdomain not punycode." }) },
  { id: "too-many-labels", weight: 10, check: (u, raw, domain) => ({ triggered: domain.split(".").length > 6, explanation: domain.split(".").length > 6 ? "Too many labels (>6) — subdomain stuffing." : "Label count normal." }) },
  { id: "random-subdomain-hash", weight: 20, check: (u, raw, domain) => ({ triggered: domain.split(".").some((p) => p.length >= 12 && /^[a-z0-9]+$/i.test(p) && entropy(p) > 3.8), explanation: domain.split(".").some((p) => p.length >= 12 && /^[a-z0-9]+$/i.test(p) && entropy(p) > 3.8) ? "Random hash-like subdomain — DGA/tracking." : "No hash subdomain." }) },

  // ── 121-150: BEHAVIORAL / COMPOSITE ──────────────────────────────────────
  { id: "no-https", weight: 20, check: (u) => ({ triggered: u.protocol === "http:", explanation: u.protocol === "http:" ? "No HTTPS — unencrypted." : "Uses HTTPS." }) },
  { id: "https-but-ip", weight: 45, check: (u) => ({ triggered: u.protocol === "https:" && /^\d+\.\d+\.\d+\.\d+$/.test(u.hostname), explanation: u.protocol === "https:" && /^\d+\.\d+\.\d+\.\d+$/.test(u.hostname) ? "HTTPS to raw IP — unusual, self-signed likely." : "No HTTPS-to-IP." }) },
  { id: "http-with-login", weight: 35, check: (u, raw) => ({ triggered: u.protocol === "http:" && /login|password|otp|kyc/i.test(raw), explanation: u.protocol === "http:" && /login|password|otp|kyc/i.test(raw) ? "Login/OTP over plain HTTP — credential theft." : "No HTTP credential risk." }) },
  { id: "multiple-phish-keywords", weight: 40, check: (u, raw) => { const low = raw.toLowerCase(); const count = PHISH_KEYWORDS.filter((k) => low.includes(k)).length; return { triggered: count >= 3, explanation: count >= 3 ? `${count} phishing keywords — strong lure.` : "Phish keyword count normal." }; } },
  { id: "brand-plus-login", weight: 45, check: (u, raw) => { const low = raw.toLowerCase(); const hasBrand = [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => low.includes(b)); return { triggered: hasBrand && /login|verify|secure|account/i.test(low), explanation: hasBrand && /login|verify|secure|account/i.test(low) ? "Brand + auth keyword — impersonation." : "No brand+auth combo." }; } },
  { id: "urgent-plus-link-param", weight: 30, check: (u, raw) => ({ triggered: hasKeyword(raw, URGENCY_WORDS) !== null && raw.toLowerCase().includes("http"), explanation: hasKeyword(raw, URGENCY_WORDS) !== null && raw.toLowerCase().includes("http") ? "Urgency + embedded URL — pressure redirect." : "No urgency+link combo." }) },
  { id: "short-domain-long-path", weight: 20, check: (u, raw, domain) => ({ triggered: domain.split(".")[0].length <= 6 && u.pathname.length > 40, explanation: domain.split(".")[0].length <= 6 && u.pathname.length > 40 ? "Short domain, very long path — hiding real path." : "Domain/path balance normal." }) },
  { id: "numeric-subdomain-plus-login", weight: 30, check: (u, raw, domain) => ({ triggered: /\d{3,}/.test(domain.split(".")[0]) && /login|verify/i.test(raw), explanation: /\d{3,}/.test(domain.split(".")[0]) && /login|verify/i.test(raw) ? "Numeric subdomain + login — phishing." : "No numeric+login combo." }) },
  { id: "tld-mismatch-india", weight: 25, check: (u, raw, domain) => { const low = domain.toLowerCase(); const indianHit = INDIAN_BRANDS.find((b) => low.includes(b)); const tld = low.split(".").pop(); return { triggered: Boolean(indianHit) && !["in", "com", "co"].includes(tld!) && !low.endsWith(".co.in"), explanation: indianHit && !["in", "com", "co"].includes(tld!) && !low.endsWith(".co.in") ? `Indian brand '${indianHit}' on .${tld} — TLD mismatch.` : "TLD matches brand region." }; } },
  { id: "homoglyph-plus-brand", weight: 50, check: (u, raw, domain) => ({ triggered: /[^\x00-\x7F]/.test(domain) && [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => domain.toLowerCase().includes(b[0])), explanation: /[^\x00-\x7F]/.test(domain) && [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => domain.toLowerCase().includes(b[0])) ? "Unicode + brand-like chars — homograph." : "No homoglyph+brand." }) },
  { id: "suspicious-tld-plus-login", weight: 35, check: (u, raw, domain) => { const tld = "." + domain.split(".").pop()!.toLowerCase(); return { triggered: SUSPICIOUS_TLDS.has(tld) && /login|verify|secure/i.test(raw), explanation: SUSPICIOUS_TLDS.has(tld) && /login|verify|secure/i.test(raw) ? `High-risk TLD ${tld} + auth path — phishing.` : "No high-risk TLD+auth." }; } },
  { id: "free-tool-plus-phish-keyword", weight: 25, check: (u, raw, domain) => ({ triggered: /000webhost|infinityfree|freehost/i.test(domain) && hasKeyword(raw, PHISH_KEYWORDS) !== null, explanation: /000webhost|infinityfree|freehost/i.test(domain) && hasKeyword(raw, PHISH_KEYWORDS) !== null ? "Free hosting + phishing keywords." : "No free-host+phish combo." }) },
  { id: "url-has-both-http-https", weight: 20, check: (u, raw) => ({ triggered: /https?:\/\/.*https?:\/\//i.test(raw), explanation: /https?:\/\/.*https?:\/\//i.test(raw) ? "URL contains two schemes — redirect wrapper." : "Single scheme." }) },
  { id: "encoded-brand-name", weight: 30, check: (u, raw) => { const decoded = (() => { try { return decodeURIComponent(raw); } catch { return raw; } })(); const enc = raw !== decoded && [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => decoded.toLowerCase().includes(b)); return { triggered: enc, explanation: enc ? "Encoded brand name — obfuscated impersonation." : "No encoded brand." }; } },
  { id: "lookalike-brand-plus-hyphen", weight: 30, check: (u, raw, domain) => { const label = domain.split(".")[0].toLowerCase(); return { triggered: [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => label.includes(b + "-") || label.includes("-" + b)), explanation: [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => label.includes(b + "-") || label.includes("-" + b)) ? "Brand + hyphen combo — lookalike." : "No brand-hyphen combo." }; } },
  { id: "apple-icloud-lure", weight: 30, check: (u, raw) => ({ triggered: /apple.*(icloud|id|verify)|icloud.*apple/i.test(raw), explanation: /apple.*(icloud|id|verify)|icloud.*apple/i.test(raw) ? "Apple/iCloud lure." : "No Apple lure." }) },
  { id: "microsoft-office-lure", weight: 30, check: (u, raw) => ({ triggered: /microsoft|office365|outlook.*verify/i.test(raw), explanation: /microsoft|office365|outlook.*verify/i.test(raw) ? "Microsoft/Office lure." : "No Microsoft lure." }) },
  { id: "paypal-lure", weight: 35, check: (u, raw) => ({ triggered: /paypal/i.test(raw) && !/paypal\.com$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname), explanation: /paypal/i.test(raw) && !/paypal\.com$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname) ? "PayPal outside paypal.com — spoof." : "No PayPal spoof." }) },
  { id: "netflix-lure", weight: 25, check: (u, raw) => ({ triggered: /netflix/i.test(raw) && !/netflix\.com$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname), explanation: /netflix/i.test(raw) && !/netflix\.com$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname) ? "Netflix outside netflix.com — spoof." : "No Netflix spoof." }) },
  { id: "amazon-lure", weight: 25, check: (u, raw) => ({ triggered: /amazon/i.test(raw) && !/amazon\.(com|in)$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname), explanation: /amazon/i.test(raw) && !/amazon\.(com|in)$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname) ? "Amazon outside amazon.com/.in — spoof." : "No Amazon spoof." }) },
  { id: "flipkart-lure", weight: 30, check: (u, raw) => ({ triggered: /flipkart/i.test(raw) && !/flipkart\.com$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname), explanation: /flipkart/i.test(raw) && !/flipkart\.com$/i.test(new URL(raw.startsWith("http") ? raw : "https://" + raw).hostname) ? "Flipkart outside flipkart.com — spoof." : "No Flipkart spoof." }) },
  { id: "url-has-ip-and-brand", weight: 50, check: (u, raw) => ({ triggered: /\d+\.\d+\.\d+\.\d+/.test(raw) && [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => raw.toLowerCase().includes(b)), explanation: /\d+\.\d+\.\d+\.\d+/.test(raw) && [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => raw.toLowerCase().includes(b)) ? "Raw IP + brand — spoof." : "No IP+brand combo." }) },
  { id: "tiny-url-plus-brand", weight: 35, check: (u, raw, domain) => { const shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly"]; return { triggered: shorteners.some((s) => domain.includes(s)) && [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => raw.toLowerCase().includes(b)), explanation: shorteners.some((s) => domain.includes(s)) && [...GLOBAL_BRANDS, ...INDIAN_BRANDS].some((b) => raw.toLowerCase().includes(b)) ? "Shortener + brand — masked phishing." : "No shortener+brand." }; } },
  { id: "data-exfil-param", weight: 30, check: (u) => ({ triggered: [...u.searchParams.keys()].some((k) => /email|phone|aadhaar|pan|account|card/i.test(k)), explanation: [...u.searchParams.keys()].some((k) => /email|phone|aadhaar|pan|account|card/i.test(k)) ? "Sensitive field name in query — data exfil." : "No sensitive field in query." }) },
  { id: "too-many-encoded-equals", weight: 15, check: (u, raw) => ({ triggered: (raw.match(/%3D/gi) || []).length >= 3, explanation: (raw.match(/%3D/gi) || []).length >= 3 ? "Many encoded '=' (%3D) — obfuscated params." : "Encoded '=' count normal." }) },
];

export const heuristicRulesScanner: ScannerModule = {
  name: "heuristic-rules",
  async scan(url: string, finalUrl: string): Promise<ScanSignal> {
    const target = finalUrl || url;
    let parsed: URL;
    try {
      parsed = new URL(target);
    } catch {
      return { signal: "heuristic-rules", triggered: false, weight: 0, explanation: "Unable to parse URL for heuristic rules." };
    }
    const raw = target;
    const domain = parsed.hostname;

    const hits: { id: string; weight: number; explanation: string }[] = [];
    for (const rule of RULES) {
      try {
        const res = rule.check(parsed, raw, domain);
        if (res.triggered) hits.push({ id: rule.id, weight: rule.weight, explanation: res.explanation });
      } catch {}
    }

    if (hits.length === 0) {
      return { signal: "heuristic-rules", triggered: false, weight: 0, explanation: "No heuristic phishing patterns detected (150 checks)." };
    }

    // Aggregate: strongest single hit determines base, plus small bonus per additional hit
    const maxWeight = Math.max(...hits.map((h) => h.weight));
    const bonus = Math.min(30, (hits.length - 1) * 4);
    const total = Math.min(95, maxWeight + bonus);
    const hitIds = hits.slice(0, 6).map((h) => h.id).join(", ");
    const more = hits.length > 6 ? ` +${hits.length - 6} more` : "";

    return {
      signal: "heuristic-rules",
      triggered: true,
      weight: total,
      explanation: `${hits.length} heuristic pattern(s) triggered [${hitIds}${more}]. Strongest: ${hits.find((h) => h.weight === maxWeight)?.explanation}`,
    };
  },
};

export const RULE_COUNT = RULES.length;
