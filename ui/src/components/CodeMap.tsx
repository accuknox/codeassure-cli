"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeMouseHandler,
  Panel,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { motion, AnimatePresence } from "motion/react";
import {
  layoutCodebase,
  type CodebaseNodeData,
  type FindingRef,
} from "@/lib/elk-layout";
import { buildFindingFlowNodes } from "@/lib/graph-builder";
import { brand, severity as sevColors } from "@/lib/theme";
import type { Finding } from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Finding Detail Panel                                                */
/* ------------------------------------------------------------------ */

function FindingPanel({
  finding,
  fileFindings,
  selected,
  onSelect,
  onClose,
  onViewFlow,
}: {
  finding: Finding;
  fileFindings: FindingRef[];
  selected: number;
  onSelect: (idx: number) => void;
  onClose: () => void;
  onViewFlow: () => void;
}) {
  const v = finding.verification;
  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="absolute right-4 top-4 bottom-4 w-96 bg-[#0a0a18]/95 backdrop-blur-xl border border-[#1a1a2e] rounded-2xl z-50 shadow-2xl overflow-hidden flex flex-col"
    >
      {/* Header */}
      <div className="p-4 border-b border-[#1a1a2e] flex justify-between items-start">
        <div>
          <p className="text-[10px] uppercase tracking-widest text-[#1578F7] font-semibold mb-1">
            {finding.path}
          </p>
          <p className="text-sm font-mono font-bold text-white">
            {fileFindings.length} finding{fileFindings.length > 1 ? "s" : ""} in this file
          </p>
        </div>
        <button
          onClick={onClose}
          className="w-7 h-7 rounded-lg border border-[#2a2a3e] flex items-center justify-center text-zinc-500 hover:text-white hover:border-zinc-500 transition-all text-sm"
        >
          ×
        </button>
      </div>

      {/* Finding tabs */}
      {fileFindings.length > 1 && (
        <div className="flex gap-1 px-4 py-2 border-b border-[#1a1a2e] overflow-x-auto">
          {fileFindings.map((f, i) => (
            <button
              key={f.index}
              onClick={() => onSelect(f.index)}
              className={`shrink-0 px-2.5 py-1 text-[10px] rounded-md border transition-all font-mono ${
                f.index === selected
                  ? "border-[#1578F7] bg-[#1578F7]/10 text-[#1578F7]"
                  : "border-[#1a1a2e] text-zinc-500 hover:border-zinc-600"
              }`}
            >
              L{f.line} {f.shortCheck}
            </button>
          ))}
        </div>
      )}

      {/* Detail */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Badges */}
        <div className="flex gap-2 flex-wrap">
          <span
            className={`text-[10px] px-2 py-0.5 rounded-md border font-medium ${
              v.verdict === "true_positive"
                ? "bg-[#E80E30]/10 border-[#E80E30]/30 text-[#E80E30]"
                : v.verdict === "false_positive"
                  ? "bg-[#14A24A]/10 border-[#14A24A]/30 text-[#14A24A]"
                  : "bg-amber-500/10 border-amber-500/30 text-amber-400"
            }`}
          >
            {v.verdict.replace("_", " ").toUpperCase()}
          </span>
          <span
            className={`text-[10px] px-2 py-0.5 rounded-md border ${
              v.is_security_vulnerability
                ? "bg-[#E80E30]/10 border-[#E80E30]/20 text-[#E80E30]/80"
                : "bg-zinc-500/10 border-zinc-500/20 text-zinc-400"
            }`}
          >
            {v.is_security_vulnerability ? "SECURITY" : "BEST PRACTICE"}
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded-md border border-[#1a1a2e] text-zinc-500">
            {v.confidence}
          </span>
        </div>

        {/* Reason */}
        <div>
          <p className="text-[10px] uppercase tracking-widest text-zinc-600 mb-1">
            Verdict Reason
          </p>
          <p className="text-xs text-zinc-300 leading-relaxed">{v.reason}</p>
        </div>

        {/* Scanner claim */}
        <div>
          <p className="text-[10px] uppercase tracking-widest text-zinc-600 mb-1">
            Scanner Claim
          </p>
          <p className="text-xs text-zinc-400 leading-relaxed">
            {finding.extra.message}
          </p>
        </div>

        {/* Flagged code */}
        {finding.extra.lines && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-zinc-600 mb-1">
              Flagged Code
            </p>
            <pre className="text-[10px] font-mono text-zinc-300 bg-[#050510] p-3 rounded-lg border border-[#1a1a2e] overflow-x-auto whitespace-pre-wrap">
              {finding.extra.lines}
            </pre>
          </div>
        )}

        {/* Evidence */}
        {v.evidence.length > 0 && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-zinc-600 mb-1">
              Evidence
            </p>
            <div className="space-y-0.5">
              {v.evidence.map((e, i) => (
                <p key={i} className="text-[10px] font-mono text-[#1578F7]">
                  {e.location}
                </p>
              ))}
            </div>
          </div>
        )}

        {/* Fix */}
        {finding.extra.fix && (
          <div>
            <p className="text-[10px] uppercase tracking-widest text-zinc-600 mb-1">
              Suggested Fix
            </p>
            <pre className="text-[10px] font-mono text-[#14A24A] bg-[#050510] p-3 rounded-lg border border-[#14A24A]/20 overflow-x-auto whitespace-pre-wrap">
              {finding.extra.fix}
            </pre>
          </div>
        )}
      </div>

      {/* Flow button */}
      {v.graph && v.graph.nodes.length > 1 && (
        <div className="p-4 border-t border-[#1a1a2e]">
          <button
            onClick={onViewFlow}
            className="w-full text-xs py-2.5 rounded-lg bg-[#1040C5]/10 border border-[#1040C5]/30 text-[#1578F7] hover:bg-[#1040C5]/20 transition-all font-medium"
          >
            View vulnerability flow →
          </button>
        </div>
      )}
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/* Flow View (vulnerability path visualization)                        */
/* ------------------------------------------------------------------ */

function FlowView({
  finding,
  onBack,
}: {
  finding: Finding;
  onBack: () => void;
}) {
  const graph = finding.verification.graph!;
  const { nodes: flowNodes, edges: flowEdges } = useMemo(
    () => buildFindingFlowNodes(finding, graph),
    [finding, graph]
  );

  const [nodes, , onNodesChange] = useNodesState(flowNodes);
  const [edges, , onEdgesChange] = useEdgesState(flowEdges);

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="w-full h-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        fitViewOptions={{ padding: 0.4 }}
        proOptions={{ hideAttribution: true }}
        colorMode="dark"
      >
        <Background color="#0a0a18" gap={20} />
        <Controls showInteractive={false} />
        <Panel position="top-left">
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-3"
          >
            <button
              onClick={onBack}
              className="text-xs px-3 py-1.5 rounded-lg bg-[#0a0a18] border border-[#1a1a2e] text-zinc-300 hover:border-[#1578F7] transition-all"
            >
              ← Back to map
            </button>
            <span className="text-xs text-zinc-500 font-mono">{graph.summary}</span>
          </motion.div>
        </Panel>
      </ReactFlow>
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/* Main CodeMap                                                        */
/* ------------------------------------------------------------------ */

export function CodeMap({ results }: { results: Finding[] }) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<CodebaseNodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [loading, setLoading] = useState(true);

  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [selectedIdx, setSelectedIdx] = useState<number>(0);
  const [flowFinding, setFlowFinding] = useState<Finding | null>(null);

  // Run ELK layout
  useEffect(() => {
    setLoading(true);
    layoutCodebase(results).then(({ nodes: n, edges: e }) => {
      setNodes(n);
      setEdges(e);
      setLoading(false);
    });
  }, [results, setNodes, setEdges]);

  const selectedNode = useMemo(
    () => nodes.find((n) => n.id === selectedFile),
    [nodes, selectedFile]
  );

  const handleNodeClick: NodeMouseHandler<Node<CodebaseNodeData>> = useCallback(
    (_, node) => {
      const data = node.data;
      if (data.nodeKind !== "file" || data.findings.length === 0) return;

      setSelectedFile(data.filePath);
      setSelectedIdx(data.findings[0].index);

      // Highlight this node
      setNodes((nds) =>
        nds.map((n) => ({
          ...n,
          style: {
            ...n.style,
            boxShadow:
              n.id === node.id
                ? `0 0 40px ${brand.red}66, 0 0 80px ${brand.red}33`
                : (n.style?.boxShadow as string) || "none",
          },
        }))
      );
    },
    [setNodes]
  );

  // Flow view
  if (flowFinding) {
    return (
      <div className="w-full h-screen bg-[#050510]">
        <FlowView finding={flowFinding} onBack={() => setFlowFinding(null)} />
      </div>
    );
  }

  // Stats
  const totalFiles = new Set(results.map((r) => r.path)).size;
  const securityCount = results.filter(
    (f) => f.verification.verdict === "true_positive" && f.verification.is_security_vulnerability
  ).length;

  return (
    <div className="w-full h-screen relative bg-[#050510]">
      {loading ? (
        <div className="flex items-center justify-center h-full">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-sm text-zinc-500"
          >
            Building codebase graph...
          </motion.div>
        </div>
      ) : (
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          proOptions={{ hideAttribution: true }}
          colorMode="dark"
          minZoom={0.05}
          maxZoom={4}
        >
          <Background color="#0c0c1a" gap={30} size={1} />
          <Controls showInteractive={false} />
          <MiniMap
            nodeColor={(n) => {
              const d = n.data as CodebaseNodeData;
              if (!d?.severity || d.severity === "none") return "#1a1a2e";
              return sevColors[d.severity].border;
            }}
            maskColor="rgba(5,5,16,0.85)"
            style={{ background: "#050510", borderRadius: 12, border: "1px solid #1a1a2e" }}
          />

          {/* Header */}
          <Panel position="top-left">
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="bg-[#0a0a18]/90 backdrop-blur-xl border border-[#1a1a2e] rounded-xl px-4 py-3"
            >
              <h1 className="text-base font-bold text-white tracking-tight">
                CodeAssure
              </h1>
              <p className="text-[10px] text-zinc-500 mt-0.5">
                {results.length} findings · {totalFiles} files · {securityCount} security issues
              </p>
            </motion.div>
          </Panel>

          {/* Legend */}
          <Panel position="bottom-left">
            <div className="bg-[#0a0a18]/90 backdrop-blur border border-[#1a1a2e] rounded-xl px-3 py-2 flex items-center gap-3">
              {(["critical", "high", "medium", "low"] as const).map((s) => (
                <span key={s} className="flex items-center gap-1.5 text-[9px] text-zinc-500">
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ background: sevColors[s].border }}
                  />
                  {s}
                </span>
              ))}
              <span className="flex items-center gap-1.5 text-[9px] text-zinc-500">
                <span className="w-2 h-2 rounded-full bg-zinc-700" />
                clear
              </span>
            </div>
          </Panel>
        </ReactFlow>
      )}

      {/* Detail panel */}
      <AnimatePresence>
        {selectedNode && selectedNode.data.findings.length > 0 && (
          <FindingPanel
            finding={results[selectedIdx]}
            fileFindings={selectedNode.data.findings}
            selected={selectedIdx}
            onSelect={setSelectedIdx}
            onClose={() => {
              setSelectedFile(null);
              // Reset glow
              layoutCodebase(results).then(({ nodes: n }) => setNodes(n));
            }}
            onViewFlow={() => setFlowFinding(results[selectedIdx])}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
