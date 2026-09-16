# AGENTS.md

LinkSentry scans URLs for phishing/malware/spam and returns an explainable 0-100 risk score. Two independent packages, each with its own `package.json` + lockfile. No root test suite, no CI, no API-side linter. Git repo: `github.com/Suryamahi9/linksentry1.git`, branch `master`.

## Layout & commands

- `src/` — Next.js 15 App Router web app (root `package.json`). Run web on port **8000**: `npm run dev -- -p 8000` (default 3000 also works but README/CORS assume 8000). Tools: `npm run typecheck`, `npm run lint` (`next lint`).
- `api/` — Fastify 5 API, TypeScript, ESM (`"type": "module"`, `module: Node16`). `cd api && npm run dev` (tsx watch, port 3001), `npm run typecheck`, `npm run build` (tsc → dist), `npm run start` (node dist/index.js).
- No test framework anywhere. Verification = `typecheck` in both packages (no ordering constraint).

## Frontend ↔ backend wiring

- Browser code always calls same-origin `/api/v1/scan` (`src/lib/api.ts`); never call the API cross-origin from the browser.
- `next.config.js` rewrites `/api/:path*` → `API_UPSTREAM` — but **only when an upstream is set** (`NODE_ENV !== "production"` falls back to `http://localhost:3001` for dev). Production without `API_UPSTREAM` serves `/api/*` directly from the Fastify function in the same deployment. Set `API_UPSTREAM` at build-time on the web project to proxy to a separately-deployed API instead.
- `CORS_ORIGIN` (comma-separated allow-list, defaults `localhost:3000,localhost:8000`) on the API only matters if a browser hits the API cross-origin directly — behind the server-side rewrite it's irrelevant.
- Env: copy `.env.example` to `api/.env`; web reads `NEXT_PUBLIC_*` at runtime, `API_UPSTREAM` at build.

## Deployment (all on Vercel, no external host)

- **Two Vercel projects from the same repo** (standard monorepo layout): web project with root directory `/` (Next.js auto-detected), API project with root directory `api` (Fastify **zero-config** — entrypoint `api/src/index.ts` keeps `fastify.listen()`, no adapter/rework needed). Vercel runs it as a Fluid-Compute function that scales to zero.
- **API project import gotcha:** set Framework Preset to **Fastify** (not "Other") and leave Build Command/Output Directory **empty**. If the preset defaults to "Other", the build fails with `No Output Directory named "public" found after the Build completed`.
- In the web project, set a **build-time** env var `API_UPSTREAM` to the API project's URL (e.g. `https://linksentry-api.vercel.app`) — the localhost default is unreachable from Vercel's runtime and `/api/*` scans will fail. The Next.js rewrite (`next.config.js`) proxies `/api/*` server-side, so **no CORS config is needed** between the two Vercel projects.
- Set API env vars in the API project only: provider API keys, optionally `POSTGRES_URL`/`REDIS_URL`, `AUTH_*`. `CORS_ORIGIN` only matters if a browser hits the API cross-origin (not the case behind the rewrite).
- **Limitations of serverless:** the BullMQ bulk worker (`queue/bulk.ts`) needs a persistent process + Redis — bulk jobs won't process on Vercel. Sequential `POST /v1/scan` works fine.

## API architecture (all in `api/src/`)

- Entry: `index.ts` — registers routes, lazy-starts the BullMQ bulk worker. `initCache()` (Redis) is **graceful**: API boots with no Redis/Postgres. Nothing database-backed is required to scan.
- **SSRF is a hard invariant**: every fetch of a user-supplied URL must go through `validateUrl()`/`safeFetch()` in `api/src/utils/ssrf.ts`. Never `fetch()` a user URL directly — new fetch code must route through these helpers.
- Scanners (`scanners/`, e.g. `homoglyph`, `domain-age`, `rules-150`) and threat-intel providers (`providers/`: Google Safe Browsing, VirusTotal, PhishTank, URLhaus) are registries — a new scanner must also be appended to the `scanners` array in `scanners/index.ts`; providers skipped without an API key are surfaced as `providersSkipped`.
- Signal type: `{ signal, triggered, weight, explanation }` (`types.ts`). Score thresholds `safe` 0-29 / `suspicious` 30-69 / `malicious` 70-100 in `utils/score.ts`.

## Gotchas

- API is ESM/Node16 (`api/tsconfig.json`): relative imports must use explicit `.js` extensions even for `.ts` files (`import "./routes/scan.js"`). Omitting the extension breaks dev and build.
- npm v10+ blocks dependency install scripts by default unless declared — `api/package.json` has an `allowScripts` block allowing Prisma's generate (and esbuild/msgpackr-extract). If install logs show `npm warn allow-scripts`, new deps with postinstall scripts need the same declaration.
- Prisma schema lives only at `api/prisma/schema.prisma` (Postgres). After edits, run `npx prisma generate` (and `npx prisma db push`/migrate) inside `api/`. The web app's `src/lib/prisma.ts` deliberately uses a runtime `require()` so the frontend typechecks without a generated client — don't hard-import `@prisma/client` in the web app.
- Auth (Auth.js v5 beta, `src/auth/config.ts`) works DB-less via JWT; `@auth/prisma-adapter` is only active when Postgres is present.
- Tailwind (v3) uses a custom dark "cyber" theme — color tokens `ink`, `phosphor`, `danger`, `amber` and mono/sans font stack in `tailwind.config.ts`; the UI does not use default palette colors.