"use client";

import { useEffect, useRef, useState } from "react";

interface ScoreGaugeProps {
  score: number;
  verdict: "safe" | "suspicious" | "malicious";
  size?: number; // diameter in px
}

const VERDICT_META = {
  safe: { color: "#4FE8C4", label: "SAFE", sublabel: "Low risk" },
  suspicious: { color: "#F5A623", label: "SUSPICIOUS", sublabel: "Proceed with caution" },
  malicious: { color: "#E4573D", label: "MALICIOUS", sublabel: "High risk — avoid" },
} as const;

export function ScoreGauge({ score, verdict, size = 140 }: ScoreGaugeProps) {
  const [displayScore, setDisplayScore] = useState(0);
  const rafRef = useRef<number | null>(null);

  // Animated count-up
  useEffect(() => {
    const start = performance.now();
    const dur = 900;
    const from = displayScore;
    const to = score;

    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / dur);
      // easeOutCubic
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplayScore(Math.round(from + (to - from) * eased));
      if (t < 1) rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [score]);

  const meta = VERDICT_META[verdict];
  const stroke = size * 0.075;
  const r = (size - stroke) / 2;
  const circumference = 2 * Math.PI * r;
  // Clamp displayScore for the gauge so it never overdraws beyond 100
  const pct = Math.min(100, Math.max(0, displayScore)) / 100;
  const dashOffset = circumference * (1 - pct);

  return (
    <div
      className="relative flex items-center justify-center shrink-0"
      style={{ width: size, height: size }}
      role="meter"
      aria-valuenow={displayScore}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={`Score ${displayScore} of 100, ${meta.label}`}
    >
      <svg
        width={size}
        height={size}
        className="absolute inset-0 -rotate-90"
        aria-hidden="true"
      >
        {/* track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke="#1E2330"
          strokeWidth={stroke}
        />
        {/* threshold tick marks at 30 and 70 */}
        {[30, 70].map((t) => {
          const angle = (t / 100) * 360 - 90;
          const rad = (angle * Math.PI) / 180;
          const inner = r - 2;
          const outer = r + 2;
          return (
            <line
              key={t}
              x1={size / 2 + Math.cos(rad) * inner}
              y1={size / 2 + Math.sin(rad) * inner}
              x2={size / 2 + Math.cos(rad) * outer}
              y2={size / 2 + Math.sin(rad) * outer}
              stroke="#2a3040"
              strokeWidth={1.5}
              opacity={0.7}
            />
          );
        })}
        {/* progress */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={meta.color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          style={{ transition: "stroke-dashoffset 0.9s cubic-bezier(0.33, 1, 0.68, 1)" }}
        />
      </svg>

      {/* center content */}
      <div className="relative text-center">
        <div
          className="font-mono font-bold leading-none tabular-nums"
          style={{ color: meta.color, fontSize: size * 0.26 }}
        >
          {displayScore}
        </div>
        <div className="font-mono text-[10px] text-gray-500 -mt-0.5">/ 100</div>
        <div
          className="font-mono text-[10px] font-semibold tracking-wider mt-1"
          style={{ color: meta.color }}
        >
          {meta.label}
        </div>
      </div>
    </div>
  );
}

export function ScoreCard({
  score,
  verdict,
  signals,
}: {
  score: number;
  verdict: "safe" | "suspicious" | "malicious";
  signals: { signal: string; triggered: boolean; weight: number }[];
}) {
  const triggered = signals.filter((s) => s.triggered);
  const meta = VERDICT_META[verdict];

  return (
    <div className="hairline-border bg-ink-lighter rounded-sm overflow-hidden animate-score-in">
      <div className="px-4 py-2 hairline-border-bottom flex items-center justify-between">
        <span className="font-mono text-xs text-gray-500 uppercase tracking-wider">
          Score Card
        </span>
        <span className="font-mono text-[10px] text-gray-600 tabular-nums">
          {triggered.length} signal{triggered.length === 1 ? "" : "s"} triggered
        </span>
      </div>

      <div className="p-5 flex flex-col sm:flex-row gap-6 items-center sm:items-start">
        <ScoreGauge score={score} verdict={verdict} size={132} />

        <div className="flex-1 min-w-0 w-full space-y-3">
          <div>
            <div className="font-mono text-sm font-semibold" style={{ color: meta.color }}>
              {meta.label} — {meta.sublabel}
            </div>
            <p className="font-mono text-xs text-gray-500 mt-1 leading-relaxed">
              {verdict === "safe" &&
                "No meaningful risk indicators were found. The link looks safe to open, but always verify the sender."}
              {verdict === "suspicious" &&
                "One or more risk signals triggered. Review the breakdown below before you click or share."}
              {verdict === "malicious" &&
                "Strong phishing or malware indicators detected. Do not open this link or share it with others."}
            </p>
          </div>

          {/* Score breakdown */}
          <div className="space-y-1.5">
            <div className="font-mono text-[10px] text-gray-600 uppercase tracking-wider">
              Breakdown
            </div>
            {triggered.length === 0 ? (
              <div className="font-mono text-xs text-phosphor/70">
                No signals triggered — score remains 0.
              </div>
            ) : (
              triggered.map((s) => {
                const pct = Math.min(100, s.weight);
                return (
                  <div key={s.signal} className="flex items-center gap-2">
                    <span className="font-mono text-[11px] text-white uppercase w-28 truncate">
                      {s.signal}
                    </span>
                    <div className="flex-1 h-1.5 bg-ink rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${pct}%`,
                          background: s.weight >= 60 ? "#E4573D" : s.weight >= 30 ? "#F5A623" : "#4FE8C4",
                        }}
                      />
                    </div>
                    <span className="font-mono text-[10px] text-gray-500 w-8 text-right tabular-nums">
                      +{s.weight}
                    </span>
                  </div>
                );
              })
            )}
            {triggered.length > 0 && (
              <div className="flex items-center gap-2 pt-1 hairline-border-top">
                <span className="font-mono text-[11px] text-gray-400 w-28">Total</span>
                <div className="flex-1" />
                <span className="font-mono text-xs font-semibold tabular-nums" style={{ color: meta.color }}>
                  {score}/100
                </span>
              </div>
            )}
          </div>

          {/* Threshold legend */}
          <div className="flex gap-1.5 pt-2">
            {[
              { label: "0–29", color: "#4FE8C4", active: verdict === "safe" },
              { label: "30–69", color: "#F5A623", active: verdict === "suspicious" },
              { label: "70–100", color: "#E4573D", active: verdict === "malicious" },
            ].map((t) => (
              <div
                key={t.label}
                className={`flex-1 rounded-sm px-2 py-1 text-center font-mono text-[10px] border ${
                  t.active ? "font-semibold" : "opacity-40"
                }`}
                style={{
                  background: t.active ? `${t.color}18` : "transparent",
                  borderColor: t.active ? `${t.color}55` : "#1E2330",
                  color: t.active ? t.color : "#6b7280",
                }}
              >
                {t.label}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}