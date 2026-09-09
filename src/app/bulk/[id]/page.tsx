"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";

const API = process.env.NEXT_PUBLIC_API_URL || "/api";

function getHeaders(): HeadersInit {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  try {
    const uid = localStorage.getItem("linksentry_user_id");
    if (uid) h["X-User-Id"] = uid;
  } catch {}
  return h;
}

interface JobStatus {
  jobId: string;
  status: string;
  total: number;
  completed: number;
  progress: number;
  results?: any[];
}

export default function BulkStatusPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [job, setJob] = useState<JobStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let timer: ReturnType<typeof setInterval>;
    const poll = async () => {
      try {
        const res = await fetch(`${API}/v1/bulk/${id}`, { headers: getHeaders() });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to fetch job");
        setJob(data);
        if (data.status === "done" || data.status === "failed") clearInterval(timer);
      } catch (err: any) {
        setError(err.message);
        clearInterval(timer);
      }
    };
    poll();
    timer = setInterval(poll, 1500);
    return () => clearInterval(timer);
  }, [id]);

  if (error) {
    return (
      <div className="hairline-border border-danger/30 bg-danger/5 rounded-sm p-4">
        <span className="font-mono text-xs text-danger">{error}</span>
      </div>
    );
  }

  if (!job) {
    return <div className="font-mono text-sm text-gray-500">Loading job {id}…</div>;
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-xl font-bold">
          Bulk job <span className="font-mono text-phosphor">{job.jobId.slice(0, 8)}</span>
        </h1>
        <p className="font-mono text-xs text-gray-500 mt-1">
          {job.completed}/{job.total} — {job.status} ({job.progress}%)
        </p>
      </div>

      <div className="hairline-border bg-ink-lighter rounded-sm p-4">
        <div className="w-full h-2 bg-ink rounded-full overflow-hidden">
          <div
            className="h-full bg-phosphor rounded-full transition-all duration-500"
            style={{ width: `${job.progress}%` }}
          />
        </div>
        <div className="mt-2 font-mono text-xs text-gray-500">
          {job.status === "done" ? "Complete" : job.status === "failed" ? "Failed" : "Processing…"}
        </div>
      </div>

      {job.status === "done" && (
        <div className="space-y-3">
          <a
            href={`${API}/v1/bulk/${job.jobId}/csv`}
            className="inline-block px-4 py-2 font-mono text-xs bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm hover:bg-phosphor/20"
          >
            Download CSV
          </a>

          <div className="hairline-border bg-ink-lighter rounded-sm overflow-hidden">
            <div className="max-h-96 overflow-auto divide-y divide-ink-border">
              {(job.results || []).map((r: any, i: number) => (
                <div key={i} className="px-3 py-2 flex items-center gap-3 font-mono text-xs">
                  <span
                    className={`w-2 h-2 rounded-full shrink-0 ${
                      r.verdict === "safe" ? "bg-phosphor" : r.verdict === "suspicious" ? "bg-amber" : "bg-danger"
                    }`}
                  />
                  <span className="truncate flex-1 text-gray-300">{r.url}</span>
                  <span className="text-gray-500">{r.score}/100</span>
                  <span
                    className={
                      r.verdict === "safe"
                        ? "text-phosphor"
                        : r.verdict === "suspicious"
                          ? "text-amber"
                          : "text-danger"
                    }
                  >
                    {r.verdict}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
