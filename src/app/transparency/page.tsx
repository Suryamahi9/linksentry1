"use client";

import { useEffect, useState } from "react";

const API = process.env.NEXT_PUBLIC_API_URL || "/api";

interface BlockedItem {
  domain: string;
  addedAt: string;
  votes: number;
}

export default function TransparencyPage() {
  const [items, setItems] = useState<BlockedItem[]>([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const limit = 20;

  useEffect(() => {
    fetch(`${API}/v1/transparency?page=${page}&limit=${limit}`)
      .then((r) => r.json())
      .then((data) => {
        setItems(data.items || []);
        setTotal(data.total || 0);
      })
      .catch(() => {});
  }, [page]);

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Transparency</h1>
        <p className="font-mono text-sm text-gray-500 mt-1">
          Recently added community-blocklist domains. No personal data is shown.
        </p>
      </div>

      <div className="hairline-border bg-ink-lighter rounded-sm overflow-hidden">
        <div className="divide-y divide-ink-border">
          {items.length === 0 ? (
            <div className="px-4 py-8 text-center font-mono text-sm text-gray-600">
              No blocklisted domains yet.
            </div>
          ) : (
            items.map((item) => (
              <div key={item.domain} className="px-4 py-3 flex items-center justify-between">
                <span className="font-mono text-sm text-white">{item.domain}</span>
                <span className="font-mono text-xs text-gray-500">
                  {new Date(item.addedAt).toISOString().split("T")[0]} · {item.votes} reports
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 font-mono text-xs">
        <button
          disabled={page <= 1}
          onClick={() => setPage((p) => Math.max(1, p - 1))}
          className="px-3 py-1 hairline-border rounded-sm text-gray-400 disabled:opacity-30 hover:text-white"
        >
          Previous
        </button>
        <span className="text-gray-500">
          Page {page} of {totalPages} · {total} total
        </span>
        <button
          disabled={page >= totalPages}
          onClick={() => setPage((p) => p + 1)}
          className="px-3 py-1 hairline-border rounded-sm text-gray-400 disabled:opacity-30 hover:text-white"
        >
          Next
        </button>
      </div>
    </div>
  );
}
