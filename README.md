# LinkSentry

**Know what a link really is.** LinkSentry scans URLs for phishing, malware, and spam indicators and returns a fast, explainable 0–100 risk verdict.

## Stack

- **Frontend:** Next.js 15 (App Router), TypeScript, Tailwind CSS, three.js 3D hero
- **Backend:** Node.js + Fastify (TypeScript)
- **Database / Cache:** PostgreSQL via Prisma, Redis + BullMQ *(stages 3+)*
- **Auth:** Auth.js — email + OAuth *(stage 3+)*

## Project layout

```
api/        Fastify REST API (POST /v1/scan, threat-intel providers)
src/        Next.js web app (3D landing page + scanner)
```

## Run locally

```bash
# 1. API (terminal A)
cd api
npm install
npm run dev            # http://localhost:3001

# 2. Web (terminal B)
npm install
npm run dev -- -p 8000 # http://localhost:8000 (proxies /api/* to the API)
```

## Scan API

```
POST /v1/scan
{ "url": "https://example.com" }
```

Returns `{ url, finalUrl, score, verdict, signals[], scannedAt, providersSkipped, pagePreview }`.
Verdicts: `safe` (0–29) · `suspicious` (30–69) · `malicious` (70–100).

## Heuristic signals

`homoglyph-check` · `ip-literal` · `url-shortener` · `domain-age` · `ssl-check` · `redirect-chain` · `dns-resolution`

## Threat-intel providers

Google Safe Browsing, VirusTotal, PhishTank, URLhaus. Providers without a configured API key are skipped (surfaced as `providersSkipped`). Results are cached per-domain in Redis (1h).

## Safety guarantees

- SSRF protection on every fetch: private/loopback/link-local IPs rejected, redirects validated each hop, max 5 redirects, 5s timeout.
- Fetched page content is never rendered or executed — only bounded, sanitized text metadata is returned.
- Scans are not tied to identity; a "don't save this scan" toggle is planned.

## Environment variables

See [`.env.example`](.env.example) for the full list with where to get each value.