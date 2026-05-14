"use client";

import { motion } from "motion/react";

const colors = {
  true_positive: {
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    text: "text-red-400",
    dot: "bg-red-500",
  },
  false_positive: {
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/30",
    text: "text-emerald-400",
    dot: "bg-emerald-500",
  },
  uncertain: {
    bg: "bg-amber-500/10",
    border: "border-amber-500/30",
    text: "text-amber-400",
    dot: "bg-amber-500",
  },
};

const labels = {
  true_positive: "True Positive",
  false_positive: "False Positive",
  uncertain: "Uncertain",
};

export function VerdictBadge({
  verdict,
}: {
  verdict: "true_positive" | "false_positive" | "uncertain";
}) {
  const c = colors[verdict];
  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.8 }}
      animate={{ opacity: 1, scale: 1 }}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium border ${c.bg} ${c.border} ${c.text}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot}`} />
      {labels[verdict]}
    </motion.span>
  );
}

export function ConfidenceBadge({
  confidence,
}: {
  confidence: "high" | "medium" | "low";
}) {
  const c = {
    high: "text-zinc-300",
    medium: "text-zinc-400",
    low: "text-zinc-500",
  };
  return (
    <span className={`text-xs ${c[confidence]}`}>
      {confidence} confidence
    </span>
  );
}

export function SecurityBadge({ isSecurity }: { isSecurity: boolean }) {
  if (isSecurity) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-red-500/10 text-red-400 border border-red-500/20">
        Security
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
      Best Practice
    </span>
  );
}
