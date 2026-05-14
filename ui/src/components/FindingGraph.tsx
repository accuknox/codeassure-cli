"use client";

import { useCallback, useEffect, useMemo } from "react";
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
import type { FindingGraph, GraphNode, GraphEdge } from "@/lib/types";

const nodeColors: Record<string, { bg: string; border: string; text: string }> = {
  source: { bg: "#0ea5e9", border: "#0369a1", text: "#fff" },
  sink: { bg: "#ef4444", border: "#991b1b", text: "#fff" },
  flagged: { bg: "#f97316", border: "#9a3412", text: "#fff" },
  missing: { bg: "#fca5a5", border: "#dc2626", text: "#1f2937" },
  evidence: { bg: "#374151", border: "#6b7280", text: "#d1d5db" },
  info: { bg: "#7dd3fc", border: "#0284c7", text: "#1f2937" },
  issue: { bg: "#fde68a", border: "#d97706", text: "#1f2937" },
};

function toReactFlowNodes(graphNodes: GraphNode[]): Node[] {
  const spacing = 200;
  return graphNodes.map((n, i) => {
    const colors = nodeColors[n.type] || nodeColors.evidence;
    const label = n.location ? `${n.label}\n${n.location}` : n.label;
    return {
      id: n.id,
      position: { x: 100, y: i * spacing },
      data: { label },
      style: {
        background: colors.bg,
        border: `2px solid ${colors.border}`,
        color: colors.text,
        borderRadius: 12,
        padding: "12px 16px",
        fontSize: 12,
        fontFamily: "monospace",
        maxWidth: 300,
        whiteSpace: "pre-wrap" as const,
        boxShadow: `0 0 20px ${colors.bg}33`,
      },
      sourcePosition: Position.Bottom,
      targetPosition: Position.Top,
    };
  });
}

function toReactFlowEdges(graphEdges: GraphEdge[]): Edge[] {
  return graphEdges.map((e, i) => ({
    id: `e${i}`,
    source: e.from,
    target: e.to,
    label: e.label,
    animated: true,
    style: { stroke: "#6b7280", strokeWidth: 2 },
    labelStyle: { fill: "#9ca3af", fontSize: 11 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#6b7280" },
  }));
}

export function FindingGraph({ graph }: { graph: FindingGraph }) {
  const initialNodes = useMemo(() => toReactFlowNodes(graph.nodes), [graph.nodes]);
  const initialEdges = useMemo(() => toReactFlowEdges(graph.edges), [graph.edges]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useEffect(() => {
    setNodes(toReactFlowNodes(graph.nodes));
    setEdges(toReactFlowEdges(graph.edges));
  }, [graph, setNodes, setEdges]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="w-full h-[400px] rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden"
    >
      <div className="px-4 py-2 border-b border-zinc-800 flex items-center gap-2">
        <span className="text-xs text-zinc-500 font-mono">{graph.summary}</span>
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        fitViewOptions={{ padding: 0.3 }}
        proOptions={{ hideAttribution: true }}
        colorMode="dark"
        minZoom={0.3}
        maxZoom={2}
      >
        <Background color="#27272a" gap={20} />
        <Controls
          showInteractive={false}
          className="!bg-zinc-900 !border-zinc-700 !rounded-lg"
        />
      </ReactFlow>
    </motion.div>
  );
}
