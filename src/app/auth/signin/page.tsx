"use client";

import { useState } from "react";

export default function SignInPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleEmailSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      const res = await fetch("/api/auth/signin/nodemailer", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ email, callbackUrl: "/" }).toString(),
      });
      if (res.ok) setSent(true);
      else setError("Failed to send magic link. Check EMAIL_SERVER config.");
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div className="max-w-md mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Sign in</h1>
        <p className="font-mono text-sm text-gray-500 mt-1">Choose a provider or use email magic link.</p>
      </div>

      <div className="hairline-border bg-ink-lighter rounded-sm p-4 space-y-3">
        <a
          href="/api/auth/signin/github"
          className="block text-center px-4 py-2 font-mono text-sm bg-white text-black rounded-sm hover:bg-gray-200"
        >
          Continue with GitHub
        </a>
        <a
          href="/api/auth/signin/google"
          className="block text-center px-4 py-2 font-mono text-sm bg-white text-black rounded-sm hover:bg-gray-200"
        >
          Continue with Google
        </a>

        <div className="flex items-center gap-2 py-2">
          <div className="flex-1 h-px bg-ink-border" />
          <span className="font-mono text-xs text-gray-600">or</span>
          <div className="flex-1 h-px bg-ink-border" />
        </div>

        <form onSubmit={handleEmailSignIn} className="space-y-2">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            required
            className="w-full bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none"
          />
          <button
            type="submit"
            className="w-full px-4 py-2 font-mono text-xs bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm hover:bg-phosphor/20"
          >
            Send magic link
          </button>
        </form>

        {sent && (
          <div className="font-mono text-xs text-phosphor">Check your email for a sign-in link.</div>
        )}
        {error && <div className="font-mono text-xs text-danger">{error}</div>}
      </div>

      <p className="font-mono text-[11px] text-gray-600">
        Demo: without OAuth/email configured, set <code>linksentry_user_id</code> in localStorage to simulate a signed-in user.
      </p>
    </div>
  );
}
