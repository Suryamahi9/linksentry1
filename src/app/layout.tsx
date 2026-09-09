import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "LinkSentry — URL Threat Scanner",
  description:
    "Scan URLs for spam, phishing, and malware risk. Get fast, explainable verdicts.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-ink text-white min-h-screen antialiased">
        <header className="hairline-border-bottom bg-ink/70 backdrop-blur sticky top-0 z-50">
          <div className="max-w-6xl mx-auto px-6 sm:px-8 py-3 flex items-center justify-between">
            <a href="#" className="flex items-center gap-2.5 group">
              <div className="w-2.5 h-2.5 rounded-full bg-phosphor group-hover:animate-scan-pulse" />
              <span className="font-mono text-sm tracking-wider text-phosphor uppercase">
                LinkSentry
              </span>
            </a>
            <nav className="font-mono text-xs text-gray-400 flex items-center gap-6">
              <a href="/" className="hover:text-phosphor transition-colors">
                Scan
              </a>
              <a href="/bulk" className="hover:text-phosphor transition-colors">
                Bulk
              </a>
              <a href="/transparency" className="hover:text-phosphor transition-colors">
                Transparency
              </a>
              <a href="/settings" className="hover:text-phosphor transition-colors">
                API
              </a>
              <a href="/admin" className="hover:text-phosphor transition-colors">
                Admin
              </a>
              <a
                href="/auth/signin"
                className="hairline-border rounded-sm px-2 py-1 text-phosphor/60 hover:text-phosphor"
              >
                Sign in
              </a>
            </nav>
          </div>
        </header>
        <main className="max-w-6xl mx-auto px-6 sm:px-8 py-8">{children}</main>
        <footer className="hairline-border-top mt-12">
          <div className="max-w-6xl mx-auto px-6 sm:px-8 py-6 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-phosphor" />
              <span className="font-mono text-xs text-gray-500">
                LinkSentry — signal analysis, not vibes.
              </span>
            </div>
            <span className="font-mono text-[10px] text-gray-600">
              SSRF-guarded · no fetched content is ever rendered · scans are never tied to you
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}