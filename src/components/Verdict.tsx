"use client";

const VERDICT_META = {
  safe: {
    label: "SAFE",
    color: "text-phosphor",
    border: "border-phosphor/40",
    bg: "bg-phosphor/10",
    dot: "bg-phosphor",
    range: "0 – 29",
    blurb: "No meaningful risk indicators found.",
  },
  suspicious: {
    label: "SUSPICIOUS",
    color: "text-amber",
    border: "border-amber/40",
    bg: "bg-amber/10",
    dot: "bg-amber",
    range: "30 – 69",
    blurb: "One or more risk indicators triggered. Proceed with caution.",
  },
  malicious: {
    label: "MALICIOUS",
    color: "text-danger",
    border: "border-danger/40",
    bg: "bg-danger/10",
    dot: "bg-danger",
    range: "70 – 100",
    blurb: "Strong indicators of phishing, malware, or fraud.",
  },
} as const;

export type Verdict = keyof typeof VERDICT_META;

export function VerdictBadge({
  verdict,
  size = "md",
}: {
  verdict: Verdict;
  size?: "sm" | "md";
}) {
  const m = VERDICT_META[verdict];
  return (
    <div
      className={`inline-flex items-center gap-2 rounded-sm ${m.border} ${m.bg} ${size === "md" ? "px-3 py-1" : "px-2 py-0.5"}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${m.dot} ${size === "md" ? "" : "scale-75"}`} />
      <span className={`font-mono ${size === "md" ? "text-sm" : "text-xs"} font-semibold ${m.color}`}>
        {m.label}
      </span>
    </div>
  );
}

export function VerdictLegend() {
  const order: Verdict[] = ["safe", "suspicious", "malicious"];
  return (
    <div className="grid sm:grid-cols-3 gap-3">
      {order.map((v) => {
        const m = VERDICT_META[v];
        return (
          <div
            key={v}
            className={`hairline-border ${m.bg} rounded-sm p-4`}
          >
            <div className="flex items-center justify-between mb-2">
              <VerdictBadge verdict={v} size="sm" />
              <span className="font-mono text-[10px] text-gray-500">{m.range}</span>
            </div>
            <p className="font-mono text-xs text-gray-400 leading-relaxed">{m.blurb}</p>
          </div>
        );
      })}
    </div>
  );
}