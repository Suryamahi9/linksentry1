"use client";

import { useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "/api";

function getHeaders(): HeadersInit {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  try {
    const uid = localStorage.getItem("linksentry_user_id");
    if (uid) h["X-User-Id"] = uid;
  } catch {}
  return h;
}

interface ApiKey {
  id: string;
  name: string;
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export default function SettingsPage() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [name, setName] = useState("");
  const [newKey, setNewKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      const res = await fetch(`${API}/v1/keys`, { headers: getHeaders() });
      const data = await res.json();
      if (res.ok) setKeys(data.keys || []);
    } catch {}
  };

  useEffect(() => {
    load();
  }, []);

  const createKey = async () => {
    setError(null);
    setNewKey(null);
    try {
      const res = await fetch(`${API}/v1/keys`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify({ name: name || "default" }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to create key");
      setNewKey(data.key);
      setName("");
      load();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const revoke = async (id: string) => {
    await fetch(`${API}/v1/keys/${id}`, { method: "DELETE", headers: getHeaders() });
    load();
  };

  return (
    <div className="space-y-6 max-w-2xl">
      <div>
        <h1 className="text-2xl font-bold">Developer API</h1>
        <p className="font-mono text-sm text-gray-500 mt-1">
          Generate API keys for <code>/v1/scan</code>. Use{" "}
          <code>Authorization: Bearer &lt;key&gt;</code>. Per-key limit: 100/min.
        </p>
      </div>

      <div className="hairline-border bg-ink-lighter rounded-sm p-4 space-y-3">
        <div className="flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Key name (e.g. my-app)"
            className="flex-1 bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none"
          />
          <button
            onClick={createKey}
            className="px-4 py-2 font-mono text-xs bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm hover:bg-phosphor/20"
          >
            Create key
          </button>
        </div>

        {newKey && (
          <div className="hairline-border border-amber/30 bg-amber/10 rounded-sm p-3">
            <div className="font-mono text-xs text-amber">Copy this key now — it will not be shown again:</div>
            <code className="font-mono text-sm text-white break-all">{newKey}</code>
          </div>
        )}

        {error && (
          <div className="font-mono text-xs text-danger">{error}</div>
        )}
      </div>

      <div className="hairline-border bg-ink-lighter rounded-sm overflow-hidden">
        <div className="px-4 py-2 hairline-border-bottom">
          <span className="font-mono text-xs text-gray-500 uppercase">Your keys</span>
        </div>
        <div className="divide-y divide-ink-border">
          {keys.length === 0 ? (
            <div className="px-4 py-6 text-center font-mono text-sm text-gray-600">No keys yet.</div>
          ) : (
            keys.map((k) => (
              <div key={k.id} className="px-4 py-3 flex items-center justify-between">
                <div>
                  <div className="font-mono text-sm text-white">
                    {k.name} <span className="text-gray-500">· {k.prefix}…</span>
                    {k.revokedAt && <span className="ml-2 text-danger text-xs">revoked</span>}
                  </div>
                  <div className="font-mono text-[11px] text-gray-500">
                    Created {new Date(k.createdAt).toLocaleDateString()}
                    {k.lastUsedAt ? ` · Last used ${new Date(k.lastUsedAt).toLocaleDateString()}` : ""}
                  </div>
                </div>
                {!k.revokedAt && (
                  <button
                    onClick={() => revoke(k.id)}
                    className="font-mono text-xs text-danger hover:text-white"
                  >
                    Revoke
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      <div className="hairline-border bg-ink-lighter rounded-sm p-4">
        <div className="font-mono text-xs text-gray-400">Example</div>
        <pre className="mt-2 bg-ink rounded-sm p-3 font-mono text-xs text-gray-300 overflow-auto">
{`curl -H "Authorization: Bearer <key>" \\
  -H "Content-Type: application/json" \\
  -d '{"url":"https://example.com"}' \\
  $API/v1/scan`}
        </pre>
      </div>
    </div>
  );
}
