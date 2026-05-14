"use client";

import { use, useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "motion/react";
import { FindingGraph } from "@/components/FindingGraph";
import { VerdictBadge, ConfidenceBadge, SecurityBadge } from "@/components/VerdictBadge";
import type { Finding } from "@/lib/types";

function shortCheckId(checkId: string): string {
  return checkId.split(".").pop() || checkId;
}

export default function FindingDetail({
  params,
}: {
  params: Promise<{ index: string }>;
}) {
  const { index: indexStr } = use(params);
  const index = parseInt(indexStr, 10);
  const router = useRouter();
  const [finding, setFinding] = useState<Finding | null>(null);

  useEffect(() => {
    // Read from sessionStorage (set by the list page)
    const stored = sessionStorage.getItem("codeassure-results");
    if (stored) {
      try {
        const data = JSON.parse(stored);
        if (data?.results?.[index]) {
          setFinding(data.results[index]);
        }
      } catch {}
    }
  }, [index]);

  if (!finding) {
    return (
      <main className="max-w-5xl mx-auto px-6 py-10">
        <p className="text-zinc-500">
          No data loaded.{" "}
          <button
            onClick={() => router.push("/")}
            className="text-zinc-300 underline"
          >
            Go back and upload a file.
          </button>
        </p>
      </main>
    );
  }

  const v = finding.verification;

  return (
    <main className="max-w-5xl mx-auto px-6 py-10">
      <button
        onClick={() => router.back()}
        className="text-xs text-zinc-500 hover:text-zinc-300 mb-6 flex items-center gap-1 transition-colors"
      >
        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
        </svg>
        Back to findings
      </button>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {/* Header */}
        <div className="flex items-start justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold font-mono">
              {shortCheckId(finding.check_id)}
            </h1>
            <p className="text-sm text-zinc-500 font-mono mt-1">
              {finding.path}:{finding.start.line}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <SecurityBadge isSecurity={v.is_security_vulnerability} />
            <VerdictBadge verdict={v.verdict} />
          </div>
        </div>

        {/* Graph */}
        {v.graph && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="mb-6"
          >
            <FindingGraph graph={v.graph} />
          </motion.div>
        )}

        {/* Details grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Reason */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
            className="border border-zinc-800 rounded-xl p-4"
          >
            <h2 className="text-xs font-medium text-zinc-500 mb-2 uppercase tracking-wider">
              Verdict Reason
            </h2>
            <p className="text-sm text-zinc-300 leading-relaxed">{v.reason}</p>
            <div className="mt-3">
              <ConfidenceBadge confidence={v.confidence} />
            </div>
          </motion.div>

          {/* Scanner Claim */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.25 }}
            className="border border-zinc-800 rounded-xl p-4"
          >
            <h2 className="text-xs font-medium text-zinc-500 mb-2 uppercase tracking-wider">
              Scanner Claim
            </h2>
            <p className="text-sm text-zinc-300 leading-relaxed">
              {finding.extra.message}
            </p>
            {finding.extra.severity && (
              <span className="inline-block mt-2 text-xs text-zinc-500 px-2 py-0.5 border border-zinc-800 rounded">
                {finding.extra.severity}
              </span>
            )}
          </motion.div>

          {/* Evidence */}
          {v.evidence.length > 0 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3 }}
              className="border border-zinc-800 rounded-xl p-4"
            >
              <h2 className="text-xs font-medium text-zinc-500 mb-2 uppercase tracking-wider">
                Evidence Locations
              </h2>
              <div className="space-y-1">
                {v.evidence.map((e, i) => (
                  <p key={i} className="text-sm font-mono text-zinc-400">
                    {e.location}
                  </p>
                ))}
              </div>
            </motion.div>
          )}

          {/* Flagged Code */}
          {finding.extra.lines && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.35 }}
              className="border border-zinc-800 rounded-xl p-4"
            >
              <h2 className="text-xs font-medium text-zinc-500 mb-2 uppercase tracking-wider">
                Flagged Code
              </h2>
              <pre className="text-xs font-mono text-zinc-300 bg-zinc-900 p-3 rounded-lg overflow-x-auto">
                {finding.extra.lines}
              </pre>
            </motion.div>
          )}

          {/* Fix Suggestion */}
          {finding.extra.fix && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4 }}
              className="border border-zinc-800 rounded-xl p-4 md:col-span-2"
            >
              <h2 className="text-xs font-medium text-zinc-500 mb-2 uppercase tracking-wider">
                Suggested Fix
              </h2>
              <pre className="text-xs font-mono text-emerald-400 bg-zinc-900 p-3 rounded-lg overflow-x-auto">
                {finding.extra.fix}
              </pre>
            </motion.div>
          )}
        </div>
      </motion.div>
    </main>
  );
}
