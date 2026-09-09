"use client";

import { useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "/api";

function getHeaders(): HeadersInit {
  // In production, the session cookie is forwarded server-side; for demo we
  // also support a local X-User-Id header via localStorage
  const h: Record<string, string> = { "Content-Type": "application/json" };
  try {
    const uid = localStorage.getItem("linksentry_user_id");
    if (uid) h["X-User-Id"] = uid;
  } catch {}
  return h;
}

export default function BulkPage() {
  const [input, setInput] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    let urls: string[] = [];

    if (file) {
      const text = await file.text();
      urls = text.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    } else {
      urls = input.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    }

    if (urls.length === 0) {
      setError("Paste URLs or upload a CSV first.");
      setLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API}/v1/bulk/scan`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify({ urls }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Bulk scan failed");
      setJobId(data.jobId);
      window.location.href = `/bulk/${data.jobId}`;
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (jobId) {
    return (
      <div className="font-mono text-sm text-gray-400">
        Created job {jobId} — redirecting…
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold">Bulk scan</h1>
        <p className="font-mono text-sm text-gray-500 mt-1">
          Paste a newline-separated list or upload a <code>.csv</code> of URLs. Requires sign-in.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="hairline-border bg-ink-lighter rounded-sm p-4 space-y-3">
          <label className="font-mono text-xs text-gray-400 uppercase">URLs</label>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={"https://example.com\nhttps://phishing.test\n..."}
            rows={8}
            className="w-full bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none"
          />
          <div className="flex items-center gap-2 font-mono text-xs text-gray-500">
            <span>or</span>
            <input
              type="file"
              accept=".csv,.txt"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              className="font-mono text-xs text-gray-400"
            />
            {file && <span className="text-phosphor">{file.name}</span>}
          </div>
        </div>

        {error && (
          <div className="hairline-border border-danger/30 bg-danger/5 rounded-sm px-3 py-2">
            <span className="font-mono text-xs text-danger">{error}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className="px-5 py-2.5 font-mono text-xs uppercase tracking-wider bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm hover:bg-phosphor/20 disabled:opacity-40 transition-colors"
        >
          {loading ? "Creating job…" : "Start bulk scan"}
        </button>
      </form>

      <p className="font-mono text-[11px] text-gray-600">
        Tip: set <code>POSTGRES_URL</code> + <code>REDIS_URL</code> for queued jobs. Without them, bulk scan is unavailable (single scans still work).
      </p>
    </div>
  );
}
