import type { Finding } from "./types";

export type SevLevel = "critical" | "high" | "medium" | "low" | "none";

const IMPACT: Record<string, SevLevel> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  ERROR: "high",
  WARNING: "medium",
  INFO: "low",
  INFORMATIONAL: "low",
};

/** Resolve a display severity for a finding.
 * Prefers codeassure's assessed severity (when the verdict is a real positive),
 * else falls back to the scanner's impact / rule severity. */
export function resolveSeverity(f: Finding): SevLevel {
  const v = f.verification;
  if (v?.severity && v.verdict === "true_positive" && v.is_security_vulnerability) {
    return v.severity;
  }
  const impact =
    (f.extra?.metadata as { impact?: string } | undefined)?.impact ||
    f.extra?.severity ||
    "";
  return IMPACT[impact.toUpperCase()] ?? "none";
}

export const SEV_STYLE: Record<SevLevel, { bg: string; text: string; border: string; dot: string }> = {
  critical: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30", dot: "bg-red-500" },
  high: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30", dot: "bg-orange-500" },
  medium: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30", dot: "bg-amber-500" },
  low: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30", dot: "bg-blue-500" },
  none: { bg: "bg-zinc-500/10", text: "text-zinc-400", border: "border-zinc-500/20", dot: "bg-zinc-500" },
};

const RANK: Record<SevLevel, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
export function sevRank(s: SevLevel): number {
  return RANK[s];
}
