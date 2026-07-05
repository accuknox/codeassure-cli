"use client";

import { useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  MarkerType,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { motion } from "motion/react";
import type { ContextGraph, CtxColor, CtxNode, CtxEdge } from "@/lib/types";

// Palette (AccuKnox brand). Used when codeassure has colored the graph.
const COLOR: Record<CtxColor, { bg: string; border: string; text: string }> = {
  red: { bg: "#E80E30", border: "#991b1b", text: "#fff" },
  orange: { bg: "#E86A3E", border: "#9a3412", text: "#fff" },
  green: { bg: "#14A24A", border: "#0f7a37", text: "#fff" },
  blue: { bg: "#1578F7", border: "#1040C5", text: "#fff" },
  gray: { bg: "#9ca3af", border: "#6b7280", text: "#1f2937" },
};

// Role → color: source=blue, sink=red, intermediate=orange, protection=green.
// Used for plain (uncolored) graphs; codeassure overrides per node when it runs.
const KIND_COLOR: Record<string, CtxColor> = {
  source: "blue",
  route: "blue",
  sink: "red",
  sanitizer: "green",
  guard: "green",
  intermediate: "orange",
  transform: "orange",
};

function nodeColor(n: CtxNode, colored: boolean): CtxColor {
  if (n.color) return n.color;
  // Colored graph (codeassure ran): an uncolored node is neutral, NOT a kind color —
  // kind colors reuse the semantic palette and would read as false "safe/protected".
  return colored ? "gray" : KIND_COLOR[n.kind] ?? "orange";
}

const LEGEND_SEMANTIC: { c: CtxColor; label: string }[] = [
  { c: "blue", label: "source" },
  { c: "orange", label: "intermediate" },
  { c: "red", label: "sink / exploitable" },
  { c: "green", label: "protected / safe" },
  { c: "gray", label: "deadcode / unreachable" },
];
const LEGEND_STRUCTURAL: { c: CtxColor; label: string }[] = [
  { c: "blue", label: "source" },
  { c: "orange", label: "intermediate" },
  { c: "red", label: "sink" },
];

/** Layered left→right layout: column = deepest position across paths (source→sink). */
function layout(nodes: CtxNode[], paths: { nodes: string[] }[]): Record<string, { x: number; y: number }> {
  const col: Record<string, number> = {};
  for (const p of paths) {
    p.nodes.forEach((id, i) => {
      col[id] = Math.max(col[id] ?? 0, i);
    });
  }
  // Nodes not on any path (isolated) → column 0.
  for (const n of nodes) if (col[n.id] === undefined) col[n.id] = 0;

  // Pin the sink to the RIGHTMOST column — flow reads source (left) → sink (right).
  const maxCol = Math.max(0, ...Object.values(col));
  for (const n of nodes) if (n.kind === "sink") col[n.id] = maxCol;

  const byCol: Record<number, string[]> = {};
  for (const [id, c] of Object.entries(col)) (byCol[c] ??= []).push(id);

  const pos: Record<string, { x: number; y: number }> = {};
  const COL_W = 320;
  const ROW_H = 130;
  for (const [c, ids] of Object.entries(byCol)) {
    ids.forEach((id, i) => {
      pos[id] = { x: Number(c) * COL_W, y: i * ROW_H - ((ids.length - 1) * ROW_H) / 2 };
    });
  }
  return pos;
}

function buildNodes(cgNodes: CtxNode[], paths: { nodes: string[] }[], colored: boolean): Node[] {
  const pos = layout(cgNodes, paths);
  return cgNodes.map((n) => {
    const c = COLOR[nodeColor(n, colored)];
    const title = n.function || n.label;
    const sub = `${n.file}:${n.line}`;
    return {
      id: n.id,
      position: pos[n.id] ?? { x: 0, y: 0 },
      data: { label: n.status ? `${title}\n${sub}\n[${n.status}]` : `${title}\n${sub}`, ctx: n },
      style: {
        background: c.bg,
        border: `2px solid ${c.border}`,
        color: c.text,
        borderRadius: 12,
        padding: "10px 14px",
        fontSize: 11,
        fontFamily: "'Geist Mono', monospace",
        maxWidth: 260,
        whiteSpace: "pre-wrap" as const,
        boxShadow: `0 0 18px ${c.bg}44`,
      },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    };
  });
}

function buildEdges(cgEdges: CtxEdge[]): Edge[] {
  return cgEdges.map((e) => {
    const stroke = e.color ? COLOR[e.color].bg : "#6b7280";
    return {
      id: e.id,
      source: e.from,
      target: e.to,
      label: e.label,
      animated: e.color === "red",
      style: { stroke, strokeWidth: 2.5 },
      labelStyle: { fill: "#9ca3af", fontSize: 10 },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
    };
  });
}

type View = "summary" | "complete";

export function ContextFlowGraph({ graph }: { graph: ContextGraph }) {
  const [view, setView] = useState<View>("summary");
  const [selected, setSelected] = useState<CtxNode | null>(null);

  const { cgNodes, cgEdges, cgPaths } = useMemo(() => {
    const wanted = graph.views?.[view];
    const nodeIds = new Set(wanted?.node_ids ?? graph.nodes.map((n) => n.id));
    const pathIds = new Set(wanted?.path_ids ?? graph.paths.map((p) => p.id));
    const cgNodes = graph.nodes.filter((n) => nodeIds.has(n.id));
    const cgPaths = graph.paths.filter((p) => pathIds.has(p.id));
    const cgEdges = graph.edges.filter(
      (e) => nodeIds.has(e.from) && nodeIds.has(e.to)
    );
    return { cgNodes, cgEdges, cgPaths };
  }, [graph, view]);

  // "colored" = codeassure has classified this graph (semantic colors present).
  const colored =
    graph.nodes.some((n) => n.color) || graph.paths.some((p) => p.color);

  const [nodes, setNodes, onNodesChange] = useNodesState(buildNodes(cgNodes, cgPaths, colored));
  const [edges, setEdges, onEdgesChange] = useEdgesState(buildEdges(cgEdges));

  useEffect(() => {
    setNodes(buildNodes(cgNodes, cgPaths, colored));
    setEdges(buildEdges(cgEdges));
  }, [cgNodes, cgEdges, cgPaths, colored, setNodes, setEdges]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="w-full h-[440px] rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden"
    >
      <div className="px-4 py-2 border-b border-zinc-800 flex items-center justify-between">
        <div className="flex items-center gap-1">
          {(["summary", "complete"] as View[]).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`text-xs px-2.5 py-1 rounded-md font-medium transition-colors ${
                view === v
                  ? "bg-zinc-800 text-zinc-100"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {v === "summary" ? "Summary Context Graph" : "Complete Context Graph"}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            {(colored ? LEGEND_SEMANTIC : LEGEND_STRUCTURAL).map((l) => (
              <span key={l.label} className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full" style={{ background: COLOR[l.c].bg }} />
                <span className="text-[10px] text-zinc-500">{l.label}</span>
              </span>
            ))}
          </div>
          <span className="text-[10px] text-zinc-600 font-mono">
            {graph.engine}
            {graph.stats?.degraded ? " · degraded" : ""} · {cgPaths.length}p
          </span>
        </div>
      </div>
      <div className="relative w-full h-[calc(100%-41px)]">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={(_, node) => setSelected((node.data as { ctx?: CtxNode }).ctx ?? null)}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          proOptions={{ hideAttribution: true }}
          colorMode="dark"
          minZoom={0.2}
          maxZoom={2}
        >
          <Background color="#27272a" gap={20} />
          <Controls showInteractive={false} className="!bg-zinc-900 !border-zinc-700 !rounded-lg" />
        </ReactFlow>

        {selected && (
          <div className="absolute top-0 right-0 h-full w-[46%] max-w-[520px] bg-zinc-900/97 border-l border-zinc-700 overflow-auto backdrop-blur-sm">
            <div className="sticky top-0 bg-zinc-900 border-b border-zinc-800 px-3 py-2 flex items-center justify-between">
              <div className="min-w-0">
                <div className="text-xs font-mono text-zinc-200 truncate">
                  {selected.qualified_name || selected.function || selected.label}
                </div>
                <div className="text-[10px] font-mono text-zinc-500 truncate">
                  {selected.file}:{selected.line} · {selected.kind}
                  {selected.status ? ` · ${selected.status}` : ""}
                </div>
              </div>
              <button
                onClick={() => setSelected(null)}
                className="text-zinc-500 hover:text-zinc-200 text-sm px-1"
              >
                ✕
              </button>
            </div>
            {selected.signature && (
              <div className="px-3 pt-2 text-[11px] font-mono text-zinc-400">
                {selected.signature}
              </div>
            )}
            <pre className="px-3 py-2 text-[11px] leading-relaxed font-mono text-zinc-300 whitespace-pre-wrap break-words">
              {selected.code || "// no source extracted for this node"}
            </pre>
          </div>
        )}
      </div>
    </motion.div>
  );
}
