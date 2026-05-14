/**
 * Builds a codebase-level graph from scan results.
 *
 * Nodes = files (grouped by directory)
 * Edges = findings connecting code locations
 * Finding markers overlaid on file nodes
 */

import type { Finding, FindingGraph } from "./types";
import type { Node, Edge } from "@xyflow/react";

export interface CodeNode extends Record<string, unknown> {
  label: string;
  filePath: string;
  findings: FindingSummary[];
  severity: "critical" | "high" | "medium" | "low" | "none";
  directory: string;
}

export interface FindingSummary {
  index: number;
  checkId: string;
  shortCheck: string;
  line: number;
  verdict: string;
  isSecurity: boolean;
  reason: string;
  graph?: FindingGraph;
}

function shortCheck(checkId: string): string {
  return checkId.split(".").pop() || checkId;
}

function fileName(path: string): string {
  return path.split("/").pop() || path;
}

function dirName(path: string): string {
  const parts = path.split("/");
  return parts.length > 1 ? parts.slice(0, -1).join("/") : ".";
}

function fileSeverity(findings: FindingSummary[]): CodeNode["severity"] {
  const securityTPs = findings.filter(
    (f) => f.verdict === "true_positive" && f.isSecurity
  );
  if (securityTPs.length >= 5) return "critical";
  if (securityTPs.length >= 2) return "high";
  if (securityTPs.length >= 1) return "medium";
  if (findings.some((f) => f.verdict === "true_positive")) return "low";
  return "none";
}

const severityColors: Record<string, { bg: string; border: string; glow: string }> = {
  critical: { bg: "#1a0505", border: "#ef4444", glow: "0 0 30px #ef444466" },
  high: { bg: "#1a0a05", border: "#f97316", glow: "0 0 20px #f9731644" },
  medium: { bg: "#1a1505", border: "#eab308", glow: "0 0 15px #eab30833" },
  low: { bg: "#0a0a12", border: "#6366f1", glow: "0 0 10px #6366f122" },
  none: { bg: "#0a0a0f", border: "#3f3f46", glow: "none" },
};

export function buildCodebaseGraph(
  results: Finding[]
): { nodes: Node<CodeNode>[]; edges: Edge[] } {
  // Group findings by file
  const byFile = new Map<string, FindingSummary[]>();

  results.forEach((f, i) => {
    const path = f.path;
    if (!byFile.has(path)) byFile.set(path, []);
    byFile.get(path)!.push({
      index: i,
      checkId: f.check_id,
      shortCheck: shortCheck(f.check_id),
      line: f.start.line,
      verdict: f.verification.verdict,
      isSecurity: f.verification.is_security_vulnerability,
      reason: f.verification.reason,
      graph: f.verification.graph,
    });
  });

  // Group files by directory for layout
  const byDir = new Map<string, string[]>();
  for (const path of byFile.keys()) {
    const dir = dirName(path);
    if (!byDir.has(dir)) byDir.set(dir, []);
    byDir.get(dir)!.push(path);
  }

  const nodes: Node<CodeNode>[] = [];
  const edges: Edge[] = [];

  // Layout: directories as columns, files as rows within each column
  const dirList = Array.from(byDir.keys()).sort();
  const COL_WIDTH = 320;
  const ROW_HEIGHT = 100;
  const DIR_GAP = 60;

  let colX = 0;

  for (const dir of dirList) {
    const files = byDir.get(dir)!;

    // Sort files: most findings first
    files.sort(
      (a, b) => (byFile.get(b)?.length || 0) - (byFile.get(a)?.length || 0)
    );

    files.forEach((filePath, fileIdx) => {
      const findings = byFile.get(filePath)!;
      const sev = fileSeverity(findings);
      const colors = severityColors[sev];

      const tpCount = findings.filter((f) => f.verdict === "true_positive" && f.isSecurity).length;
      const fpCount = findings.filter(
        (f) => f.verdict === "false_positive" || (f.verdict === "true_positive" && !f.isSecurity)
      ).length;

      let badge = "";
      if (tpCount > 0) badge += `⚠ ${tpCount} security`;
      if (fpCount > 0) badge += `${badge ? " · " : ""}✓ ${fpCount} dismissed`;

      nodes.push({
        id: filePath,
        position: { x: colX, y: fileIdx * ROW_HEIGHT },
        type: "default",
        data: {
          label: `${fileName(filePath)}\n${badge || "no issues"}`,
          filePath,
          findings,
          severity: sev,
          directory: dir,
        },
        style: {
          background: colors.bg,
          border: `2px solid ${colors.border}`,
          borderRadius: 12,
          padding: "14px 18px",
          fontSize: 12,
          fontFamily: "'Geist Mono', monospace",
          color: "#e4e4e7",
          minWidth: 240,
          whiteSpace: "pre-wrap" as const,
          boxShadow: colors.glow,
          transition: "all 0.3s ease",
        },
      });
    });

    colX += COL_WIDTH + DIR_GAP;
  }

  // Create edges between files in the same directory that share check types
  // (visual clustering — shows related vulnerability patterns)
  for (const files of byDir.values()) {
    for (let i = 0; i < files.length; i++) {
      for (let j = i + 1; j < files.length; j++) {
        const aFindings = byFile.get(files[i])!;
        const bFindings = byFile.get(files[j])!;

        const aChecks = new Set(aFindings.map((f) => f.shortCheck));
        const bChecks = new Set(bFindings.map((f) => f.shortCheck));
        const shared = [...aChecks].filter((c) => bChecks.has(c));

        if (shared.length > 0) {
          edges.push({
            id: `${files[i]}-${files[j]}`,
            source: files[i],
            target: files[j],
            label: shared.length === 1 ? shared[0] : `${shared.length} shared`,
            animated: false,
            style: { stroke: "#3f3f46", strokeWidth: 1, opacity: 0.4 },
            labelStyle: { fill: "#52525b", fontSize: 9 },
          });
        }
      }
    }
  }

  return { nodes, edges };
}

/**
 * Build a detail-level flow graph for a specific finding.
 * This shows the actual vulnerability flow — source → code → sink.
 */
export function buildFindingFlowNodes(
  finding: Finding,
  graph: FindingGraph
): { nodes: Node[]; edges: Edge[] } {
  const nodeColors: Record<string, { bg: string; border: string }> = {
    source: { bg: "#0c4a6e", border: "#0ea5e9" },
    sink: { bg: "#7f1d1d", border: "#ef4444" },
    flagged: { bg: "#7c2d12", border: "#f97316" },
    missing: { bg: "#451a03", border: "#f59e0b" },
    evidence: { bg: "#1c1917", border: "#57534e" },
    info: { bg: "#0c4a6e", border: "#7dd3fc" },
    issue: { bg: "#422006", border: "#f59e0b" },
  };

  const SPACING_Y = 140;

  const nodes: Node[] = graph.nodes.map((n, i) => {
    const colors = nodeColors[n.type] || nodeColors.evidence;
    return {
      id: n.id,
      position: { x: 150, y: i * SPACING_Y },
      data: {
        label: n.location ? `${n.label}\n📍 ${n.location}` : n.label,
      },
      style: {
        background: colors.bg,
        border: `2px solid ${colors.border}`,
        borderRadius: 12,
        padding: "14px 18px",
        fontSize: 12,
        fontFamily: "'Geist Mono', monospace",
        color: "#e4e4e7",
        maxWidth: 320,
        whiteSpace: "pre-wrap" as const,
        boxShadow: `0 0 25px ${colors.border}44`,
      },
    };
  });

  const edges: Edge[] = graph.edges.map((e, i) => ({
    id: `flow-${i}`,
    source: e.from,
    target: e.to,
    label: e.label,
    animated: true,
    style: { stroke: "#ef4444", strokeWidth: 2.5 },
    labelStyle: { fill: "#fca5a5", fontSize: 11, fontWeight: 600 },
    markerEnd: { type: "arrowclosed" as const, color: "#ef4444" },
  }));

  return { nodes, edges };
}
