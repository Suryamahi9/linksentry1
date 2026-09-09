"use client";

import { useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "/api";

function getHeaders(): HeadersInit {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  try {
    const uid = localStorage.getItem("linksentry_user_id");
    if (uid) h["X-User-Id"] = uid;
  } catch {}
  return h;
}

export function ReportButton({ url }: { url: string }) {
  const [category, setCategory] = useState("phishing");
  const [reason, setReason] = useState("");
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    try {
      const res = await fetch(`${API}/v1/report`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify({ url, category, reason }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Report failed");
      setDone(true);
    } catch (err: any) {
      setError(err.message);
    }
  };

  if (done) {
    return (
      <div className="hairline-border bg-phosphor/5 rounded-sm p-3">
        <span className="font-mono text-xs text-phosphor">Report submitted. Thank you.</span>
      </div>
    );
  }

  return (
    <div className="hairline-border bg-ink-lighter rounded-sm p-4 space-y-3">
      <div className="font-mono text-xs text-gray-500 uppercase">Report this URL</div>
      <div className="flex gap-2">
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white outline-none"
        >
          <option value="phishing">phishing</option>
          <option value="malware">malware</option>
          <option value="scam">scam</option>
          <option value="spam-ad">spam-ad</option>
          <option value="other">other</option>
        </select>
        <input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason (optional)"
          className="flex-1 bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none"
        />
        <button
          onClick={submit}
          className="px-4 py-2 font-mono text-xs bg-amber/10 text-amber border border-amber/30 rounded-sm hover:bg-amber/20"
        >
          Submit
        </button>
      </div>
      {error && <div className="font-mono text-xs text-danger">{error}</div>}
    </div>
  );
}
