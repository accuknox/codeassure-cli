/**
 * Codebase layout engine — builds a hierarchical graph from findings.
 *
 * Uses a simple tree layout (no ELK dependency) that reliably handles
 * any codebase structure. Directories as group nodes, files inside them.
 */

import type { Node, Edge } from "@xyflow/react";
import type { Finding } from "./types";
import { getFileColor, severity as sevColors, brand } from "./theme";

export interface CodebaseNodeData extends Record<string, unknown> {
  label: string;
  nodeKind: "root" | "directory" | "file";
  filePath: string;
  findingCount: number;
  securityCount: number;
  fpCount: number;
  severity: keyof typeof sevColors;
  findings: FindingRef[];
  extension: string;
}

export interface FindingRef {
  index: number;
  shortCheck: string;
  line: number;
  verdict: string;
  isSecurity: boolean;
  reason: string;
}

function shortCheck(id: string): string {
  return id.split(".").pop() || id;
}

function ext(path: string): string {
  if (path.toLowerCase().includes("dockerfile")) return "Dockerfile";
  return path.split(".").pop() || "";
}

function computeSeverity(findings: FindingRef[]): CodebaseNodeData["severity"] {
  const sec = findings.filter((f) => f.verdict === "true_positive" && f.isSecurity);
  if (sec.length >= 5) return "critical";
  if (sec.length >= 2) return "high";
  if (sec.length >= 1) return "medium";
  if (findings.some((f) => f.verdict === "true_positive")) return "low";
  return "none";
}

interface TreeNode {
  id: string;
  name: string;
  kind: "root" | "directory" | "file";
  children: Map<string, TreeNode>;
  findings: FindingRef[];
}

function buildTree(results: Finding[]): TreeNode {
  const root: TreeNode = {
    id: "ROOT",
    name: "codebase",
    kind: "root",
    children: new Map(),
    findings: [],
  };

  for (let i = 0; i < results.length; i++) {
    const f = results[i];
    const parts = f.path.split("/");
    let current = root;

    for (let d = 0; d < parts.length - 1; d++) {
      const dirName = parts[d];
      const dirId = parts.slice(0, d + 1).join("/");
      if (!current.children.has(dirName)) {
        current.children.set(dirName, {
          id: dirId,
          name: dirName,
          kind: "directory",
          children: new Map(),
          findings: [],
        });
      }
      current = current.children.get(dirName)!;
    }

    const fileName = parts[parts.length - 1];
    if (!current.children.has(fileName)) {
      current.children.set(fileName, {
        id: f.path,
        name: fileName,
        kind: "file",
        children: new Map(),
        findings: [],
      });
    }

    current.children.get(fileName)!.findings.push({
      index: i,
      shortCheck: shortCheck(f.check_id),
      line: f.start.line,
      verdict: f.verification.verdict,
      isSecurity: f.verification.is_security_vulnerability,
      reason: f.verification.reason,
    });
  }

  return root;
}

// Layout constants
const FILE_W = 220;
const FILE_H = 44;
const FILE_GAP = 8;
const DIR_PAD_TOP = 36;
const DIR_PAD_X = 16;
const DIR_PAD_BOTTOM = 16;
const DIR_GAP = 24;

interface LayoutResult {
  nodes: Node<CodebaseNodeData>[];
  edges: Edge[];
  width: number;
  height: number;
}

function layoutTree(
  tree: TreeNode,
  x: number,
  y: number,
  parentId?: string,
): LayoutResult {
  const nodes: Node<CodebaseNodeData>[] = [];
  const edges: Edge[] = [];

  if (tree.kind === "file") {
    const findings = tree.findings;
    const sev = computeSeverity(findings);
    const colors = sevColors[sev];
    const fileClr = getFileColor(tree.id);

    const secCount = findings.filter((f) => f.verdict === "true_positive" && f.isSecurity).length;
    const fpCount = findings.filter(
      (f) => f.verdict === "false_positive" || (f.verdict === "true_positive" && !f.isSecurity)
    ).length;

    let badge = "";
    if (secCount > 0) badge += `⚠ ${secCount}`;
    if (fpCount > 0) badge += `${badge ? " · " : ""}✓ ${fpCount}`;
    const label = badge ? `${tree.name}  ${badge}` : tree.name;

    nodes.push({
      id: tree.id,
      position: { x, y },
      data: {
        label,
        nodeKind: "file",
        filePath: tree.id,
        findingCount: findings.length,
        securityCount: secCount,
        fpCount,
        severity: sev,
        findings,
        extension: ext(tree.id),
      },
      parentId,
      style: {
        background: findings.length > 0 ? colors.bg : "#0c0c14",
        border: `1.5px solid ${findings.length > 0 ? colors.border : "#1a1a2e"}`,
        borderLeft: `3px solid ${fileClr}`,
        borderRadius: 8,
        padding: "8px 14px",
        fontSize: 11,
        fontFamily: "'Geist Mono', monospace",
        color: findings.length > 0 ? colors.text : "#52525b",
        width: FILE_W,
        height: FILE_H,
        boxShadow: findings.length > 0 ? colors.glow : "none",
        cursor: findings.length > 0 ? "pointer" : "default",
      },
    });

    return { nodes, edges, width: FILE_W, height: FILE_H };
  }

  // Directory: layout children vertically
  const children = Array.from(tree.children.values());

  // Sort: files with findings first (by severity), then dirs, then files without findings
  children.sort((a, b) => {
    const aScore = a.kind === "file"
      ? (a.findings.some((f) => f.isSecurity && f.verdict === "true_positive") ? 0 : a.findings.length > 0 ? 1 : 3)
      : 2;
    const bScore = b.kind === "file"
      ? (b.findings.some((f) => f.isSecurity && f.verdict === "true_positive") ? 0 : b.findings.length > 0 ? 1 : 3)
      : 2;
    return aScore - bScore;
  });

  // For root level: layout directories side by side (columns)
  if (tree.kind === "root") {
    let colX = 0;
    for (const child of children) {
      const sub = layoutTree(child, colX, 0);
      nodes.push(...sub.nodes);
      edges.push(...sub.edges);
      colX += sub.width + DIR_GAP;
    }
    return { nodes, edges, width: colX, height: 0 };
  }

  // Directory: vertical stack of children inside a group node
  let innerY = DIR_PAD_TOP;
  let maxChildW = FILE_W;

  const childResults: { result: LayoutResult; child: TreeNode }[] = [];
  for (const child of children) {
    const sub = layoutTree(child, DIR_PAD_X, innerY, tree.id);
    childResults.push({ result: sub, child });
    innerY += sub.height + FILE_GAP;
    maxChildW = Math.max(maxChildW, sub.width);
  }

  const groupW = maxChildW + DIR_PAD_X * 2;
  const groupH = innerY + DIR_PAD_BOTTOM;

  // Count total findings in this directory (recursive)
  let dirFindings = 0;
  let dirSecurity = 0;
  for (const { result } of childResults) {
    for (const n of result.nodes) {
      const d = n.data as CodebaseNodeData;
      if (d.nodeKind === "file") {
        dirFindings += d.findingCount;
        dirSecurity += d.securityCount;
      }
    }
  }

  // Directory group node
  nodes.push({
    id: tree.id,
    position: { x, y },
    data: {
      label: dirSecurity > 0 ? `${tree.name}/  ⚠ ${dirSecurity}` : `${tree.name}/`,
      nodeKind: "directory",
      filePath: tree.id,
      findingCount: dirFindings,
      securityCount: dirSecurity,
      fpCount: 0,
      severity: dirSecurity >= 5 ? "critical" : dirSecurity >= 2 ? "high" : dirSecurity >= 1 ? "medium" : "none",
      findings: [],
      extension: "",
    },
    type: "group",
    parentId,
    style: {
      background: `${brand.bgDark}88`,
      border: `1px solid ${dirSecurity > 0 ? `${brand.blue}44` : "#1a1a2e"}`,
      borderRadius: 12,
      padding: 0,
      width: groupW,
      height: groupH,
      fontSize: 12,
      fontFamily: "'Geist Mono', monospace",
      fontWeight: 600,
      color: dirSecurity > 0 ? brand.blue : "#52525b",
    },
  });

  // Add child nodes
  for (const { result } of childResults) {
    nodes.push(...result.nodes);
    edges.push(...result.edges);
  }

  return { nodes, edges, width: groupW, height: groupH };
}

export async function layoutCodebase(
  results: Finding[]
): Promise<{ nodes: Node<CodebaseNodeData>[]; edges: Edge[] }> {
  const tree = buildTree(results);
  const { nodes, edges } = layoutTree(tree, 0, 0);
  return { nodes, edges };
}
