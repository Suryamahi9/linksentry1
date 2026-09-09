/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    // On Vercel the Fastify API is deployed as a same-origin function at
    // /api/*, so /api calls are served directly — no rewrite here.
    // The rewrite only applies when an upstream is configured, i.e. local
    // development (defaults to localhost:3001). Set API_UPSTREAM (build-time
    // env) to proxy /api/* to a separately hosted API instead.
    const upstream =
      process.env.API_UPSTREAM ||
      process.env.NEXT_PUBLIC_API_URL ||
      (process.env.NODE_ENV !== "production" ? "http://localhost:3001" : "");

    if (!upstream) return [];

    return [
      {
        source: "/api/:path*",
        destination: `${upstream}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;