"use client";

import { useState } from "react";
import { isValidUrl } from "@/lib/api";

interface ScanInputProps {
  onScan: (url: string) => void;
  isLoading: boolean;
}

export default function ScanInput({ onScan, isLoading }: ScanInputProps) {
  const [input, setInput] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmed = input.trim();
    if (!trimmed) {
      setError("Enter a URL to scan");
      return;
    }

    // Add protocol if missing
    let url = trimmed;
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
    }

    if (!isValidUrl(url)) {
      setError("Invalid URL format");
      return;
    }

    onScan(url);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="hairline-border bg-ink-lighter rounded-sm">
        <div className="flex items-center gap-2 px-4 py-3">
          <span className="font-mono text-phosphor text-sm select-none">$</span>
          <span className="font-mono text-gray-500 text-sm select-none hidden sm:inline">
            scan
          </span>
          <input
            type="text"
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setError(null);
            }}
            placeholder="https://example.com"
            disabled={isLoading}
            className="flex-1 bg-transparent font-mono text-sm text-white placeholder-gray-600 outline-none disabled:opacity-50"
            autoFocus
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            className="px-4 py-1.5 font-mono text-xs uppercase tracking-wider bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm hover:bg-phosphor/20 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            {isLoading ? (
              <span className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-phosphor animate-scan-pulse" />
                Scanning
              </span>
            ) : (
              "Scan"
            )}
          </button>
        </div>
      </div>
      {error && (
        <p className="mt-2 font-mono text-xs text-danger">{error}</p>
      )}
    </form>
  );
}
