"use client";

import Link from "next/link";
import { motion } from "motion/react";
import { VerdictBadge, ConfidenceBadge, SecurityBadge } from "./VerdictBadge";
import type { Finding } from "@/lib/types";

function shortCheckId(checkId: string): string {
  return checkId.split(".").pop() || checkId;
}

export function FindingCard({
  finding,
  index,
  delay = 0,
}: {
  finding: Finding;
  index: number;
  delay?: number;
}) {
  const v = finding.verification;
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay }}
    >
      <Link href={`/findings/${index}`}>
        <div className="group border border-zinc-800 rounded-xl p-4 hover:border-zinc-600 hover:bg-zinc-900/50 transition-all cursor-pointer">
          <div className="flex items-start justify-between gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-mono font-medium text-zinc-200 truncate">
                  {shortCheckId(finding.check_id)}
                </span>
                <SecurityBadge isSecurity={v.is_security_vulnerability} />
              </div>
              <p className="text-xs text-zinc-500 font-mono truncate">
                {finding.path}:{finding.start.line}
              </p>
              <p className="text-xs text-zinc-400 mt-1.5 line-clamp-2">
                {v.reason}
              </p>
            </div>
            <div className="flex flex-col items-end gap-1.5 shrink-0">
              <VerdictBadge verdict={v.verdict} />
              <ConfidenceBadge confidence={v.confidence} />
            </div>
          </div>
        </div>
      </Link>
    </motion.div>
  );
}
