"use client";

import { use, useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion } from "motion/react";
import { FindingGraph } from "@/components/FindingGraph";
import { ContextFlowGraph } from "@/components/ContextFlowGraph";
import { VerdictBadge, ConfidenceBadge, SecurityBadge, SeverityBadge } from "@/components/VerdictBadge";
import { resolveSeverity } from "@/lib/severity";
import type { Finding } from "@/lib/types";

function shortCheckId(checkId: string): string {
  return checkId.split(".").pop() || checkId;
}

const TABS = ["Overview", "Risk Analysis", "Remediation", "Code flow"] as const;
type Tab = (typeof TABS)[number];

function Card({ title, children, className = "" }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={`border border-zinc-800 rounded-xl p-4 ${className}`}>
      <h2 className="text-xs font-medium text-zinc-500 mb-2 uppercase tracking-wider">{title}</h2>
      {children}
    </div>
  );
}

export default function FindingDetail({ params }: { params: Promise<{ index: string }> }) {
  const { index: indexStr } = use(params);
  const index = parseInt(indexStr, 10);
  const router = useRouter();
  const [finding, setFinding] = useState<Finding | null>(null);
  const [tab, setTab] = useState<Tab>("Overview");

  useEffect(() => {
    const stored = sessionStorage.getItem("codeassure-results");
    if (stored) {
      try {
        const data = JSON.parse(stored);
        if (data?.results?.[index]) setFinding(data.results[index]);
      } catch {}
    }
  }, [index]);

  if (!finding) {
    return (
      <main className="max-w-5xl mx-auto px-6 py-10">
        <p className="text-zinc-500">
          No data loaded.{" "}
          <button onClick={() => router.push("/")} className="text-zinc-300 underline">
            Go back and upload a file.
          </button>
        </p>
      </main>
    );
  }

  // Tolerate raw context-graph output (no codeassure verification yet).
  const v = finding.verification ?? {
    verdict: "uncertain" as const,
    is_security_vulnerability: false,
    confidence: "low" as const,
    reason: "No AI verdict yet — run codeassure to verify and color this finding.",
    evidence: [],
  };
  const cg = finding.context_graph;
  const rem = v.remediation;

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

      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
        {/* Header */}
        <div className="flex items-start justify-between gap-4 mb-5">
          <div>
            <h1 className="text-xl font-bold font-mono">{shortCheckId(finding.check_id)}</h1>
            <p className="text-sm text-zinc-500 font-mono mt-1">
              {finding.path}:{finding.start.line}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <SeverityBadge level={resolveSeverity(finding)} />
            <SecurityBadge isSecurity={v.is_security_vulnerability} />
            <VerdictBadge verdict={v.verdict} />
          </div>
        </div>

        {/* Tab bar */}
        <div className="flex items-center gap-1 border-b border-zinc-800 mb-6">
          {TABS.map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-3 py-2 text-sm font-medium -mb-px border-b-2 transition-colors ${
                tab === t
                  ? "border-blue-500 text-zinc-100"
                  : "border-transparent text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {tab === "Overview" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card title="Verdict Reason">
              <p className="text-sm text-zinc-300 leading-relaxed">{v.reason}</p>
              <div className="mt-3"><ConfidenceBadge confidence={v.confidence} /></div>
            </Card>
            {v.rationale && (
              <Card title="Rationale">
                <p className="text-sm text-zinc-300 leading-relaxed">{v.rationale}</p>
              </Card>
            )}
            {v.business_logic && (
              <Card title="Business Logic" className="md:col-span-2">
                <p className="text-sm text-zinc-300 leading-relaxed">{v.business_logic}</p>
              </Card>
            )}
            <Card title="Scanner Claim">
              <p className="text-sm text-zinc-300 leading-relaxed">{finding.extra.message}</p>
              {finding.extra.severity && (
                <span className="inline-block mt-2 text-xs text-zinc-500 px-2 py-0.5 border border-zinc-800 rounded">
                  {finding.extra.severity}
                </span>
              )}
            </Card>
            {finding.extra.lines && (
              <Card title="Flagged Code">
                <pre className="text-xs font-mono text-zinc-300 bg-zinc-900 p-3 rounded-lg overflow-x-auto">
                  {finding.extra.lines}
                </pre>
              </Card>
            )}
          </div>
        )}

        {tab === "Risk Analysis" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card title="Explanation" className="md:col-span-2">
              <p className="text-sm text-zinc-300 leading-relaxed">
                {v.explanation || v.reason}
              </p>
            </Card>
            {cg && (
              <Card title="Data Flow (deterministic)" className="md:col-span-2">
                <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm">
                  <span className="text-zinc-500">Engine</span>
                  <span className="text-zinc-300 font-mono">{cg.engine}</span>
                  <span className="text-zinc-500">Sink</span>
                  <span className="text-zinc-300 font-mono truncate">
                    {cg.sink.file}:{cg.sink.line}
                  </span>
                  <span className="text-zinc-500">Paths to sink</span>
                  <span className="text-zinc-300">{cg.paths.length}</span>
                  <span className="text-zinc-500">Reachability</span>
                  <span className="text-zinc-300">
                    {cg.paths.some((p) => p.reachability === "reachable")
                      ? "reachable"
                      : cg.paths[0]?.reachability ?? "—"}
                  </span>
                  <span className="text-zinc-500">Protection on path</span>
                  <span className="text-zinc-300">
                    {cg.paths.some((p) => p.protection?.has_sanitizer)
                      ? "sanitizer present"
                      : cg.paths.some((p) => p.protection?.has_guard)
                        ? "guard present"
                        : "none detected"}
                  </span>
                </div>
                {(() => {
                  const entries = Array.from(
                    new Set(cg.paths.map((p) => p.entry_point).filter(Boolean))
                  ).slice(0, 6);
                  return entries.length ? (
                    <div className="mt-3">
                      <div className="text-xs text-zinc-500 mb-1">Entry points</div>
                      <div className="space-y-0.5">
                        {entries.map((e) => (
                          <div key={e} className="text-xs font-mono text-zinc-400">{e}</div>
                        ))}
                      </div>
                    </div>
                  ) : null;
                })()}
              </Card>
            )}
            <Card title="Severity">
              <p className="text-sm text-zinc-300 uppercase">{v.severity || "—"}</p>
            </Card>
            <Card title="Confidence">
              <ConfidenceBadge confidence={v.confidence} />
            </Card>
            {finding.extra.metadata?.cwe?.length ? (
              <Card title="CWE" className="md:col-span-2">
                <div className="flex flex-wrap gap-2">
                  {finding.extra.metadata.cwe.map((c) => (
                    <span key={c} className="text-xs font-mono text-zinc-400 px-2 py-0.5 border border-zinc-800 rounded">
                      {c}
                    </span>
                  ))}
                </div>
              </Card>
            ) : null}
            {v.evidence.length > 0 && (
              <Card title="Evidence Locations" className="md:col-span-2">
                <div className="space-y-1">
                  {v.evidence.map((e, i) => (
                    <p key={i} className="text-sm font-mono text-zinc-400">{e.location}</p>
                  ))}
                </div>
              </Card>
            )}
          </div>
        )}

        {tab === "Remediation" && (
          <div className="grid grid-cols-1 gap-4">
            {rem ? (
              <>
                <Card title="Fix">
                  <p className="text-sm text-zinc-300 leading-relaxed">{rem.summary}</p>
                  {rem.preserves_logic === false && (
                    <p className="mt-2 text-xs text-amber-400">
                      ⚠ This change may alter behavior — review before applying.
                    </p>
                  )}
                </Card>
                {rem.code_patch && (
                  <Card title="Copy-paste Patch">
                    <pre className="text-xs font-mono text-emerald-400 bg-zinc-900 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap">
                      {rem.code_patch}
                    </pre>
                  </Card>
                )}
                {rem.notes && (
                  <Card title="Notes">
                    <p className="text-sm text-zinc-400 leading-relaxed">{rem.notes}</p>
                  </Card>
                )}
              </>
            ) : finding.extra.fix ? (
              <Card title="Suggested Fix (scanner)">
                <pre className="text-xs font-mono text-emerald-400 bg-zinc-900 p-3 rounded-lg overflow-x-auto">
                  {finding.extra.fix}
                </pre>
              </Card>
            ) : (
              <p className="text-sm text-zinc-500">No remediation available for this finding.</p>
            )}
          </div>
        )}

        {tab === "Code flow" && (
          <div>
            {cg ? (
              <>
                <p className="text-xs text-zinc-500 mb-2">
                  {cg.engine === "joern"
                    ? "Deterministic source→sink flow (Joern CPG)."
                    : `Context graph (${cg.engine}).`}{" "}
                  Click any node to see its code.
                </p>
                <ContextFlowGraph graph={cg} />
              </>
            ) : v.graph ? (
              <FindingGraph graph={v.graph} />
            ) : (
              <p className="text-sm text-zinc-500">
                No context graph available. Run context-graph-cli to generate the source→sink flow.
              </p>
            )}
          </div>
        )}
      </motion.div>
    </main>
  );
}
