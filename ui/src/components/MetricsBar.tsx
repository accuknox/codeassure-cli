"use client";

import { motion } from "motion/react";
import type { Finding } from "@/lib/types";

interface Metrics {
  total: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  uncertain: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
}

function computeEffective(f: Finding): string {
  const v = f.verification;
  if (v.verdict === "true_positive" && !v.is_security_vulnerability) {
    return "false_positive";
  }
  return v.verdict;
}

export function computeMetrics(findings: Finding[]): Metrics {
  let tp = 0, fp = 0, tn = 0, fn = 0, uncertain = 0;

  for (const f of findings) {
    const eff = computeEffective(f);
    if (eff === "uncertain") {
      uncertain++;
    } else if (eff === "true_positive") {
      tp++;
    } else {
      // false_positive
      fp++;
    }
  }

  // Without GT we just show distribution, not accuracy
  const total = findings.length;
  const decided = tp + fp;

  return {
    total,
    tp,
    fp: 0,
    tn: 0,
    fn: 0,
    uncertain,
    accuracy: 0,
    precision: decided ? (tp / decided) * 100 : 0,
    recall: 0,
    f1: 0,
  };
}

function StatCard({
  label,
  value,
  color,
  delay,
}: {
  label: string;
  value: string | number;
  color: string;
  delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay }}
      className="flex flex-col items-center gap-1 px-4 py-3 rounded-lg bg-zinc-900 border border-zinc-800"
    >
      <span className={`text-2xl font-bold font-mono ${color}`}>{value}</span>
      <span className="text-xs text-zinc-500">{label}</span>
    </motion.div>
  );
}

export function MetricsBar({ findings }: { findings: Finding[] }) {
  const tp = findings.filter(
    (f) => computeEffective(f) === "true_positive"
  ).length;
  const fpCount = findings.filter(
    (f) => computeEffective(f) === "false_positive"
  ).length;
  const unc = findings.filter(
    (f) => f.verification.verdict === "uncertain"
  ).length;

  const security = findings.filter(
    (f) => f.verification.is_security_vulnerability && f.verification.verdict === "true_positive"
  ).length;

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
      <StatCard label="Total Findings" value={findings.length} color="text-zinc-200" delay={0} />
      <StatCard label="True Positives" value={tp} color="text-red-400" delay={0.05} />
      <StatCard label="False Positives" value={fpCount} color="text-emerald-400" delay={0.1} />
      <StatCard label="Security Issues" value={security} color="text-orange-400" delay={0.15} />
      <StatCard label="Uncertain" value={unc} color="text-amber-400" delay={0.2} />
    </div>
  );
}
