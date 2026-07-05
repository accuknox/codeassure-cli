"use client";

import { useState } from "react";
import { motion } from "motion/react";
import { FileUpload } from "@/components/FileUpload";
import { ForceGraph } from "@/components/ForceGraph";
import { FindingsList } from "@/components/FindingsList";
import type { ScanResults } from "@/lib/types";

export default function Home() {
  const [data, setData] = useState<ScanResults | null>(null);
  const [view, setView] = useState<"list" | "map">("list");

  function handleLoad(raw: unknown) {
    const d = raw as ScanResults;
    if (d?.results) {
      setData(d);
      // Per-finding detail route reads from sessionStorage.
      try {
        sessionStorage.setItem("codeassure-results", JSON.stringify(d));
      } catch {}
    }
  }

  if (data) {
    // Findings-first: one row per finding → its own context graph.
    if (view === "map") {
      return (
        <div className="relative">
          <button
            onClick={() => setView("list")}
            className="absolute top-4 left-4 z-10 text-xs text-zinc-600 hover:text-zinc-900 bg-white/80 border border-zinc-200 rounded-md px-2.5 py-1"
          >
            ← Findings
          </button>
          <ForceGraph data={data} />
        </div>
      );
    }
    return <FindingsList data={data} onOpenMap={() => setView("map")} />;
  }

  return (
    <div className="flex flex-col items-center justify-center h-screen px-6 bg-white">
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="text-center mb-8"
      >
        <div className="flex items-center justify-center gap-2 mb-2">
          <div className="w-3 h-3 rounded-full" style={{ background: "#1578F7" }} />
          <h1 className="text-2xl font-bold tracking-tight" style={{ color: "#212121" }}>
            CodeAssure
          </h1>
        </div>
        <p className="text-sm" style={{ color: "#94a3b8" }}>
          Visual SAST Finding Verification
        </p>
      </motion.div>
      <div className="w-full max-w-lg">
        <FileUpload onLoad={handleLoad} />
      </div>
    </div>
  );
}
