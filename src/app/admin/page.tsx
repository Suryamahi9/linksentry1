"use client";

import { useEffect, useState } from "react";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

const API = process.env.NEXT_PUBLIC_API_URL || "/api";

function getHeaders(): HeadersInit {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  try {
    const uid = localStorage.getItem("linksentry_user_id");
    if (uid) h["X-User-Id"] = uid;
  } catch {}
  return h;
}

const COLORS: Record<string, string> = {
  safe: "#4FE8C4",
  suspicious: "#F5A623",
  malicious: "#E4573D",
};

export default function AdminPage() {
  const [stats, setStats] = useState<any>(null);
  const [reports, setReports] = useState<any[]>([]);
  const [overrides, setOverrides] = useState<{ domain: string; action: string; reason: string }>({
    domain: "",
    action: "block",
    reason: "",
  });
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${API}/v1/admin/stats`, { headers: getHeaders() })
      .then((r) => r.json())
      .then((d) => {
        if (d.error) setError(d.error);
        else setStats(d);
      })
      .catch((e) => setError(e.message));

    fetch(`${API}/v1/admin/reports?status=open`, { headers: getHeaders() })
      .then((r) => r.json())
      .then((d) => setReports(d.reports || []))
      .catch(() => {});
  }, []);

  const handleOverride = async () => {
    const res = await fetch(`${API}/v1/admin/override`, {
      method: "POST",
      headers: getHeaders(),
      body: JSON.stringify(overrides),
    });
    const data = await res.json();
    if (!res.ok) alert(data.error || "Failed");
    else {
      alert(`Override ${data.action} for ${data.domain}`);
      setOverrides({ domain: "", action: "block", reason: "" });
    }
  };

  return (
    <div className="space-y-8 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">Admin console</h1>
        <p className="font-mono text-sm text-gray-500 mt-1">Report queue, overrides, and analytics.</p>
      </div>

      {error && (
        <div className="hairline-border border-danger/30 bg-danger/5 rounded-sm p-3">
          <span className="font-mono text-xs text-danger">{error} — ensure your user has role=admin and POSTGRES_URL is set.</span>
        </div>
      )}

      {/* Stats */}
      {stats && (
        <div className="grid sm:grid-cols-3 gap-4">
          <div className="hairline-border bg-ink-lighter rounded-sm p-4">
            <div className="font-mono text-xs text-gray-500 uppercase">Total scans</div>
            <div className="font-mono text-2xl font-bold text-white mt-1">{stats.totalScans ?? 0}</div>
          </div>
          <div className="hairline-border bg-ink-lighter rounded-sm p-4">
            <div className="font-mono text-xs text-gray-500 uppercase">Blocklisted domains</div>
            <div className="font-mono text-2xl font-bold text-white mt-1">{stats.blocklisted ?? 0}</div>
          </div>
          <div className="hairline-border bg-ink-lighter rounded-sm p-4">
            <div className="font-mono text-xs text-gray-500 uppercase">Verdict mix</div>
            <div className="font-mono text-xs text-gray-400 mt-1">
              {(stats.verdictCounts || []).map((v: any) => `${v.verdict}: ${v.count}`).join(" · ") || "—"}
            </div>
          </div>
        </div>
      )}

      {stats?.verdictCounts && stats.verdictCounts.length > 0 && (
        <div className="grid sm:grid-cols-2 gap-4">
          <div className="hairline-border bg-ink-lighter rounded-sm p-4">
            <div className="font-mono text-xs text-gray-500 uppercase mb-3">Verdict distribution</div>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={stats.verdictCounts}
                  dataKey="count"
                  nameKey="verdict"
                  cx="50%"
                  cy="50%"
                  outerRadius={70}
                >
                  {stats.verdictCounts.map((e: any, i: number) => (
                    <Cell key={i} fill={COLORS[e.verdict] || "#888"} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="hairline-border bg-ink-lighter rounded-sm p-4">
            <div className="font-mono text-xs text-gray-500 uppercase mb-3">Scans / day (last 7)</div>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart
                data={Object.entries(stats.byDay || {}).map(([day, count]) => ({ day, count }))}
              >
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: "#6b7280" }} />
                <YAxis tick={{ fontSize: 10, fill: "#6b7280" }} />
                <Tooltip />
                <Bar dataKey="count" fill="#4FE8C4" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Report queue */}
      <div className="hairline-border bg-ink-lighter rounded-sm overflow-hidden">
        <div className="px-4 py-2 hairline-border-bottom">
          <span className="font-mono text-xs text-gray-500 uppercase">Open reports ({reports.length})</span>
        </div>
        <div className="divide-y divide-ink-border max-h-96 overflow-auto">
          {reports.length === 0 ? (
            <div className="px-4 py-6 text-center font-mono text-sm text-gray-600">No open reports.</div>
          ) : (
            reports.map((r: any) => (
              <div key={r.id} className="px-4 py-3 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-mono text-sm text-white truncate">{r.domain}</div>
                  <div className="font-mono text-xs text-gray-500">
                    {r.category} · {r.votes?.length || 0} votes · {new Date(r.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <span className="font-mono text-xs text-gray-400 shrink-0">{r.status}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Manual override */}
      <div className="hairline-border bg-ink-lighter rounded-sm p-4 space-y-3">
        <div className="font-mono text-xs text-gray-500 uppercase">Manual domain override</div>
        <div className="flex flex-wrap gap-2">
          <input
            value={overrides.domain}
            onChange={(e) => setOverrides({ ...overrides, domain: e.target.value })}
            placeholder="example.com"
            className="flex-1 min-w-40 bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none"
          />
          <select
            value={overrides.action}
            onChange={(e) => setOverrides({ ...overrides, action: e.target.value })}
            className="bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white outline-none"
          >
            <option value="block">block</option>
            <option value="allow">allow</option>
          </select>
          <input
            value={overrides.reason}
            onChange={(e) => setOverrides({ ...overrides, reason: e.target.value })}
            placeholder="Reason"
            className="flex-1 min-w-40 bg-ink hairline-border rounded-sm px-3 py-2 font-mono text-sm text-white placeholder-gray-600 outline-none"
          />
          <button
            onClick={handleOverride}
            className="px-4 py-2 font-mono text-xs bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm hover:bg-phosphor/20"
          >
            Apply
          </button>
        </div>
      </div>
    </div>
  );
}
