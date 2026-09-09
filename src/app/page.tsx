"use client";

import { useState } from "react";
import ScanInput from "@/components/ScanInput";
import ResultPanel from "@/components/ResultPanel";
import ScanField3D from "@/components/ScanField3D";
import { ScoreGauge } from "@/components/ScoreCard";
import { PipelineSection, SignalsSection } from "@/components/Sections";
import { VerdictLegend } from "@/components/Verdict";
import {
  LiveStatsBar,
  HowItWorksSection,
  DetectionRulesSection,
  ToolsGridSection,
  IndiaThreatsSection,
  FAQSection,
  QuizSection,
  FeedbackSection,
} from "@/components/CyberSections";
import { scanUrl, type ScanResult } from "@/lib/api";

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pingUrl, setPingUrl] = useState<string | null>(null);

  const handleScan = async (url: string) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setPingUrl(null);

    try {
      const scanResult = await scanUrl(url);
      setResult(scanResult);
      // Fire the 3D "ping" on the node nearest this scan — presentational only,
      // never blocks or gates the scan flow.
      setPingUrl(url);
    } catch (err: any) {
      setError(
        err.message || "Scan failed. Please check your connection and try again."
      );
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      {/* ============ HERO ============ */}
      <section className="relative -mx-6 sm:-mx-8 min-h-[600px] flex items-center overflow-hidden">
        {/* 3D backdrop */}
        <div className="absolute inset-0">
          <ScanField3D pingUrl={pingUrl} />
          <div className="absolute inset-0 bg-gradient-to-r from-ink via-ink/80 to-transparent" />
        </div>

        <div className="relative z-10 py-16 max-w-xl">
          <div className="flex items-center gap-2 mb-6">
            <span className="font-mono text-xs text-phosphor tracking-widest">+ THREAT SCANNER</span>
            <span className="text-gray-700">/</span>
            <span className="font-mono text-xs text-amber tracking-widest">v0.1</span>
          </div>

          <h1 className="text-4xl sm:text-5xl font-bold leading-tight tracking-tight">
            Know what a link
            <br />
            <span className="text-phosphor">really is.</span>
          </h1>

          <p className="mt-4 font-mono text-sm text-gray-400 leading-relaxed max-w-md">
            Scan any URL for phishing, malware, and spam indicators. You get a
            number, a verdict, and — always — the reason{" "}
            <span className="text-phosphor">why</span>.
          </p>

          {/* Scan input */}
          <div className="mt-8">
            <ScanInput onScan={handleScan} isLoading={isLoading} />
            {error && (
              <div className="mt-3 hairline-border border-danger/30 bg-danger/5 rounded-sm px-3 py-2">
                <span className="font-mono text-xs text-danger">{error}</span>
              </div>
            )}
          </div>

          {/* Compact live result (when idle → nothing; when loading → pipeline; when done → verdict + score) */}
          {isLoading && (
            <div className="mt-6 hairline-border bg-ink-lighter rounded-sm p-4">
              <div className="space-y-2">
                {["Fetching & following redirects", "Analyzing domain signals", "Cross-checking heuristics", "Calculating risk score"].map(
                  (step, i) => (
                    <div key={step} className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full ${i === 0 ? "bg-phosphor animate-scan-pulse" : "bg-gray-700"}`} />
                      <span className={`font-mono text-xs ${i === 0 ? "text-phosphor" : "text-gray-600"}`}>
                        {step}
                      </span>
                    </div>
                  )
                )}
              </div>
              <div className="mt-4 h-0.5 bg-ink rounded-full overflow-hidden">
                <div className="h-full w-1/3 bg-phosphor/50 rounded-full animate-scan-line" />
              </div>
            </div>
          )}

          {result && !isLoading && (
            <>
              <div className="mt-6 hairline-border bg-ink-lighter rounded-sm p-4 flex items-center gap-4">
                <ScoreGauge score={result.score} verdict={result.verdict} size={72} />
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-xs text-gray-400">Result</div>
                  <div className="font-mono text-sm font-semibold text-white truncate">
                    {result.url.replace(/^https?:\/\//, "")}
                  </div>
                  <div className="font-mono text-[10px] text-gray-500 truncate">
                    {result.finalUrl}
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <div
                    className={`font-mono text-xl font-bold ${
                      result.verdict === "safe"
                        ? "text-phosphor"
                        : result.verdict === "suspicious"
                          ? "text-amber"
                          : "text-danger"
                    }`}
                  >
                    {result.score}
                    <span className="text-[11px] font-normal text-gray-600">/100</span>
                  </div>
                  <div
                    className={`font-mono text-[10px] font-semibold ${
                      result.verdict === "safe"
                        ? "text-phosphor"
                        : result.verdict === "suspicious"
                          ? "text-amber"
                          : "text-danger"
                    }`}
                  >
                    {result.verdict.toUpperCase()}
                  </div>
                </div>
              </div>
              <button
                onClick={() =>
                  window.scrollTo({ top: document.getElementById("report")!.offsetTop - 96, behavior: "smooth" })
                }
                className="mt-2 font-mono text-xs text-phosphor hover:text-white transition-colors"
              >
                view full report ↓
              </button>
            </>
          )}
        </div>
      </section>

      {/* ============ FULL REPORT ============ */}
      {result && !isLoading && (
        <section id="report" className="my-16 scroll-mt-24">
          <ResultPanel result={result} />
        </section>
      )}

      {/* ============ LIVE STATS ============ */}
      <LiveStatsBar />

      {/* ============ SECTIONS ============ */}
      <HowItWorksSection />
      <DetectionRulesSection />
      <PipelineSection />
      <SignalsSection />

      <section className="my-24" id="verdicts">
        <div className="flex items-baseline gap-3 mb-8">
          <span className="font-mono text-xs text-phosphor/60">03</span>
          <h2 className="text-xl font-semibold">The verdict scale</h2>
          <div className="flex-1 hairline-border-top" />
        </div>
        <VerdictLegend />
      </section>

      <ToolsGridSection />
      <IndiaThreatsSection />
      <QuizSection />
      <FAQSection />
      <FeedbackSection />

      {/* ============ CTA ============ */}
      <section className="my-24 hairline-border bg-ink-lighter rounded-sm relative overflow-hidden">
        <div className="absolute -top-24 -right-24 w-72 h-72 rounded-full bg-phosphor/5 blur-3xl" />
        <div className="relative p-8 sm:p-12 grid lg:grid-cols-2 gap-8 items-center">
          <div>
            <h2 className="text-2xl font-bold">Scan your first URL.</h2>
            <p className="mt-2 font-mono text-sm text-gray-500">
              No account, no API key, no noise. Just a verdict and the evidence behind it.
            </p>
          </div>
          <div className="flex sm:justify-end">
            <button
              onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
              className="px-5 py-2.5 font-mono text-xs uppercase tracking-wider bg-phosphor/10 text-phosphor border border-phosphor/30 rounded-sm hover:bg-phosphor/20 transition-colors"
            >
              Scan now
            </button>
          </div>
        </div>
      </section>
    </>
  );
}