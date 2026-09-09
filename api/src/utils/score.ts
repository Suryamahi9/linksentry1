import type { ScanSignal, Verdict } from "../types.js";

const VERDICT_THRESHOLDS = {
  safe: { min: 0, max: 29 },
  suspicious: { min: 30, max: 69 },
  malicious: { min: 70, max: 100 },
} as const;

export function calculateScore(signals: ScanSignal[]): number {
  const triggered = signals.filter((s) => s.triggered);
  if (triggered.length === 0) return 0;

  // Additive risk model: each triggered signal contributes its weight
  // (0-100). The total is capped at 100. Weights are calibrated so a
  // single high-severity signal is enough to reach "malicious" while a
  // few low-severity signals only reach "suspicious".
  const total = triggered.reduce((sum, s) => sum + s.weight, 0);
  return Math.min(100, total);
}

export function scoreToVerdict(score: number): Verdict {
  if (score <= VERDICT_THRESHOLDS.safe.max) return "safe";
  if (score <= VERDICT_THRESHOLDS.suspicious.max) return "suspicious";
  return "malicious";
}
