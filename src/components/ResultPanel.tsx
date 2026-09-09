"use client";

import type { ScanResult } from "@/lib/api";
import { SitePreviewCard } from "@/components/SitePreviewCard";
import { ScoreCard } from "@/components/ScoreCard";
import { ReportButton } from "@/components/ReportButton";

interface ResultPanelProps {
  result: ScanResult;
}

export default function ResultPanel({ result }: ResultPanelProps) {

  return (
    <div className="w-full space-y-4">
      <ScoreCard score={result.score} verdict={result.verdict} signals={result.signals} />

      {/* URL Info */}
      <div className="hairline-border bg-ink-lighter rounded-sm p-4 space-y-2">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-gray-500 w-16 shrink-0">
              SCANNED
            </span>
            <span className="font-mono text-xs text-white truncate">
              {result.url}
            </span>
          </div>
          {result.url !== result.finalUrl && (
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs text-gray-500 w-16 shrink-0">
                FINAL
              </span>
              <span className="font-mono text-xs text-phosphor truncate">
                {result.finalUrl}
              </span>
            </div>
          )}
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-gray-500 w-16 shrink-0">
              TIME
            </span>
            <span className="font-mono text-xs text-gray-400">
              {new Date(result.scannedAt).toLocaleString()}
            </span>
          </div>
        </div>
      </div>

      {/* Site Preview — sanitized text metadata only, never the live page */}
      <SitePreviewCard result={result} />

      {/* Signals */}
      <div className="hairline-border bg-ink-lighter rounded-sm">
        <div className="px-4 py-2 hairline-border-bottom">
          <span className="font-mono text-xs text-gray-500 uppercase tracking-wider">
            Analysis Signals
          </span>
        </div>
        <div className="divide-y divide-ink-border">
          {result.signals.map((signal) => (
            <div
              key={signal.signal}
              className={`px-4 py-3 flex items-start gap-3 ${
                signal.triggered ? "bg-white/[0.02]" : ""
              }`}
            >
              {/* Status indicator */}
              <div className="mt-1 shrink-0">
                {signal.triggered ? (
                  <div
                    className={`w-2 h-2 rounded-full ${
                      signal.weight >= 60
                        ? "bg-danger"
                        : signal.weight >= 30
                          ? "bg-amber"
                          : "bg-phosphor-dim"
                    }`}
                  />
                ) : (
                  <div className="w-2 h-2 rounded-full bg-gray-700" />
                )}
              </div>

              {/* Signal info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs font-medium text-white uppercase">
                    {signal.signal}
                  </span>
                  {signal.triggered && (
                    <span
                      className={`font-mono text-[10px] px-1.5 py-0.5 rounded-sm ${
                        signal.weight >= 60
                          ? "bg-danger/20 text-danger"
                          : signal.weight >= 30
                            ? "bg-amber/20 text-amber"
                            : "bg-phosphor/20 text-phosphor-dim"
                      }`}
                    >
                      weight: {signal.weight}
                    </span>
                  )}
                </div>
                <p className="font-mono text-xs text-gray-400 leading-relaxed">
                  {signal.explanation}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Providers skipped notice */}
      {result.providersSkipped && result.providersSkipped.length > 0 && (
        <div className="hairline-border bg-ink-lighter rounded-sm px-4 py-2">
          <span className="font-mono text-[10px] text-gray-500">
            Skipped providers: {result.providersSkipped.join(", ")}
          </span>
        </div>
      )}

      <ReportButton url={result.url} />
    </div>
  );
}
