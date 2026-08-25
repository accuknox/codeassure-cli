"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { motion } from "motion/react";
import type { Finding, ScanResults } from "@/lib/types";
import { resolveSeverity, sevRank, type SevLevel } from "@/lib/severity";
import { SeverityBadge } from "@/components/VerdictBadge";

function shortCheckId(checkId: string): string {
  return checkId.split(".").pop() || checkId;
}

const SEV_ORDER: SevLevel[] = ["critical", "high", "medium", "low", "none"];

export function FindingsList({
  data,
  onOpenMap,
}: {
  data: ScanResults;
  onOpenMap?: () => void;
}) {
  const router = useRouter();
  const [q, setQ] = useState("");
  const [sevFilter, setSevFilter] = useState<SevLevel | "all">("all");

  const rows = useMemo(() => {
    return data.results
      .map((f, index) => ({ f, index, sev: resolveSeverity(f) }))
      .filter((r) => (sevFilter === "all" ? true : r.sev === sevFilter))
      .filter((r) =>
        q
          ? (r.f.check_id + " " + r.f.path).toLowerCase().includes(q.toLowerCase())
          : true
      )
      .sort((a, b) => sevRank(b.sev) - sevRank(a.sev));
  }, [data, q, sevFilter]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of data.results) {
      const s = resolveSeverity(f);
      c[s] = (c[s] || 0) + 1;
    }
    return c;
  }, [data]);

  return (
    <main className="w-full px-6 py-8">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full" style={{ background: "#1578F7" }} />
          <h1 className="text-lg font-bold">CodeAssure</h1>
          <span className="text-sm text-zinc-500">
            {data.results.length} findings
          </span>
        </div>
        {onOpenMap && (
          <button
            onClick={onOpenMap}
            className="text-xs text-zinc-500 hover:text-zinc-300 border border-zinc-800 rounded-md px-2.5 py-1"
          >
            Codebase map →
          </button>
        )}
      </div>

      {/* Severity filter pills */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <button
          onClick={() => setSevFilter("all")}
          className={`text-xs px-2.5 py-1 rounded-full border ${
            sevFilter === "all"
              ? "bg-zinc-800 border-zinc-700 text-zinc-100"
              : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
          }`}
        >
          all {data.results.length}
        </button>
        {SEV_ORDER.filter((s) => counts[s]).map((s) => (
          <button
            key={s}
            onClick={() => setSevFilter(s)}
            className={`text-xs px-2.5 py-1 rounded-full border ${
              sevFilter === s
                ? "bg-zinc-800 border-zinc-700 text-zinc-100"
                : "border-zinc-800 text-zinc-500 hover:text-zinc-300"
            }`}
          >
            {s} {counts[s]}
          </button>
        ))}
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="filter by rule or path…"
          className="ml-auto text-xs bg-zinc-900 border border-zinc-800 rounded-md px-2.5 py-1 text-zinc-300 w-56 outline-none focus:border-zinc-600"
        />
      </div>

      {/* Rows */}
      <div className="border border-zinc-800 rounded-xl divide-y divide-zinc-800/70 overflow-hidden">
        {rows.map(({ f, index, sev }) => (
          <FindingRow key={index} f={f} index={index} sev={sev} router={router} />
        ))}
        {rows.length === 0 && (
          <div className="px-4 py-8 text-center text-sm text-zinc-500">
            No findings match.
          </div>
        )}
      </div>
    </main>
  );
}

function FindingRow({
  f,
  index,
  sev,
  router,
}: {
  f: Finding;
  index: number;
  sev: SevLevel;
  router: ReturnType<typeof useRouter>;
}) {
  const cg = f.context_graph;
  const paths = cg?.paths?.length ?? 0;
  const engine = cg?.engine;
  const verdict = f.verification?.verdict;

  return (
    <motion.button
      onClick={() => router.push(`/findings/${index}`)}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="w-full flex items-center gap-3 px-4 py-3 hover:bg-zinc-900/60 text-left transition-colors"
    >
      <div className="w-20 shrink-0">
        <SeverityBadge level={sev} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-sm text-zinc-200 truncate">
          {shortCheckId(f.check_id)}
        </div>
        <div className="font-mono text-xs text-zinc-500 truncate">
          {f.path}:{f.start.line}
        </div>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {engine && (
          <span
            className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
              engine === "joern"
                ? "border-emerald-700 text-emerald-400"
                : "border-zinc-700 text-zinc-500"
            }`}
            title="context-graph engine"
          >
            {engine}
          </span>
        )}
        {paths > 0 && (
          <span className="text-[10px] font-mono text-zinc-500">{paths} path</span>
        )}
        {verdict && verdict !== "uncertain" && (
          <span
            className={`text-[10px] px-1.5 py-0.5 rounded ${
              verdict === "true_positive"
                ? "bg-red-500/10 text-red-400"
                : "bg-emerald-500/10 text-emerald-400"
            }`}
          >
            {verdict === "true_positive" ? "TP" : "FP"}
          </span>
        )}
        <span className="text-zinc-600">›</span>
      </div>
    </motion.button>
  );
}
