"use client";

import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import { motion, AnimatePresence } from "motion/react";
import { brand, severity as sevColors, getFileColor } from "@/lib/theme";
import type { Finding, ScanResults } from "@/lib/types";

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  name: string;
  kind: "file" | "dir";
  path: string;
  size: number;
  extension: string;
  parentId: string;
  findings: FindingRef[];
  severity: "critical" | "high" | "medium" | "low" | "none";
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
}

interface FindingRef {
  index: number;
  shortCheck: string;
  line: number;
  isBug: boolean;
  severity: "critical" | "high" | "medium" | "low";
  reason: string;
  confidence: string;
}

/* ------------------------------------------------------------------ */
/* Data builder                                                        */
/* ------------------------------------------------------------------ */

function shortCheck(id: string): string {
  return id.split(".").pop() || id;
}

function ext(path: string): string {
  if (path.toLowerCase().includes("dockerfile")) return "Dockerfile";
  return path.split(".").pop() || "";
}

/** Compute effective verdict: TP + not_sec → FP (dismissed) */
function isBug(f: Finding): boolean {
  const v = f.verification;
  if (v.verdict === "true_positive" && v.is_security_vulnerability) return true;
  return false;
}

/** Map scanner severity to display severity */
function toSeverity(scannerSev: string): "critical" | "high" | "medium" | "low" {
  const s = scannerSev.toUpperCase();
  if (s === "ERROR") return "critical";
  if (s === "WARNING") return "high";
  return "medium";
}

function computeNodeSeverity(findings: FindingRef[]): GraphNode["severity"] {
  const bugs = findings.filter((f) => f.isBug);
  if (bugs.length === 0) return "none";
  // Use the worst LLM-assigned severity in this file
  if (bugs.some((f) => f.severity === "critical")) return "critical";
  if (bugs.some((f) => f.severity === "high")) return "high";
  if (bugs.some((f) => f.severity === "medium")) return "medium";
  return "low";
}

function buildGraphData(data: ScanResults): { nodes: GraphNode[]; links: GraphLink[] } {
  const tree = data.codebase_tree || [];
  const results = data.results;

  // Only include confirmed bugs (effective TP) on the graph
  const findingsByPath = new Map<string, FindingRef[]>();
  results.forEach((f, i) => {
    if (!isBug(f)) return;
    if (!findingsByPath.has(f.path)) findingsByPath.set(f.path, []);
    findingsByPath.get(f.path)!.push({
      index: i,
      shortCheck: shortCheck(f.check_id),
      line: f.start.line,
      isBug: true,
      severity: f.verification.severity || "medium",
      reason: f.verification.reason,
      confidence: f.verification.confidence,
    });
  });

  const nodes: GraphNode[] = [];
  const links: GraphLink[] = [];
  const nodeIds = new Set<string>();

  nodes.push({
    id: "ROOT", name: "codebase", kind: "dir", path: "", size: 0,
    extension: "", parentId: "", findings: [], severity: "none",
  });
  nodeIds.add("ROOT");

  const entries = tree.length > 0
    ? tree
    : results.map((f) => ({ path: f.path, type: "file" as const, size: 0 }));

  for (const entry of entries) {
    const parts = entry.path.split("/");

    // Ensure parent dirs
    for (let i = 0; i < parts.length - 1; i++) {
      const dirPath = parts.slice(0, i + 1).join("/");
      if (!nodeIds.has(dirPath)) {
        const parent = i > 0 ? parts.slice(0, i).join("/") : "ROOT";
        nodes.push({
          id: dirPath, name: parts[i], kind: "dir", path: dirPath, size: 0,
          extension: "", parentId: parent, findings: [], severity: "none",
        });
        nodeIds.add(dirPath);
        links.push({ source: parent, target: dirPath });
      }
    }

    if (!nodeIds.has(entry.path)) {
      const parentPath = parts.length > 1 ? parts.slice(0, -1).join("/") : "ROOT";
      const findings = findingsByPath.get(entry.path) || [];
      nodes.push({
        id: entry.path,
        name: parts[parts.length - 1],
        kind: entry.type === "dir" ? "dir" : "file",
        path: entry.path,
        size: entry.size,
        extension: ext(entry.path),
        parentId: parentPath,
        findings,
        severity: computeNodeSeverity(findings),
      });
      nodeIds.add(entry.path);
      links.push({ source: parentPath, target: entry.path });
    }
  }

  // Also add finding-only paths not in tree
  if (tree.length > 0) {
    for (const f of results) {
      if (!nodeIds.has(f.path)) {
        const parts = f.path.split("/");
        for (let i = 0; i < parts.length; i++) {
          const p = parts.slice(0, i + 1).join("/");
          if (!nodeIds.has(p)) {
            const parent = i > 0 ? parts.slice(0, i).join("/") : "ROOT";
            const isFile = i === parts.length - 1;
            const findings = isFile ? (findingsByPath.get(f.path) || []) : [];
            nodes.push({
              id: p, name: parts[i], kind: isFile ? "file" : "dir", path: p,
              size: 0, extension: isFile ? ext(p) : "", parentId: parent,
              findings, severity: computeNodeSeverity(findings),
            });
            nodeIds.add(p);
            links.push({ source: parent, target: p });
          }
        }
      }
    }
  }

  return { nodes, links };
}

/* ------------------------------------------------------------------ */
/* Finding Panel (light theme)                                         */
/* ------------------------------------------------------------------ */

function severityLabel(sev: string): { label: string; shade: string } {
  if (sev === "critical") return { label: "Critical", shade: "#1a1a1a" };
  if (sev === "high") return { label: "High", shade: "#444444" };
  if (sev === "medium") return { label: "Medium", shade: "#777777" };
  return { label: "Low", shade: "#aaaaaa" };
}

function FindingPanel({
  node, results, selectedIdx, onSelectIdx, onClose,
}: {
  node: GraphNode; results: Finding[]; selectedIdx: number;
  onSelectIdx: (i: number) => void; onClose: () => void;
}) {
  const finding = results[selectedIdx];
  if (!finding) return null;
  const v = finding.verification;
  const sev = severityLabel(v.severity || "medium");
  const bugCount = node.findings.length;

  // File-level worst severity for the header
  const worstSev = node.findings.some((f) => f.severity === "critical")
    ? severityLabel("critical")
    : node.findings.some((f) => f.severity === "high")
      ? severityLabel("high")
      : node.findings.some((f) => f.severity === "medium")
        ? severityLabel("medium")
        : severityLabel("low");

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="absolute right-4 top-4 bottom-4 w-[380px] z-50 overflow-hidden flex flex-col rounded-2xl"
      style={{
        background: brand.white,
        border: `1px solid ${brand.border}`,
        boxShadow: "0 32px 68px rgba(0,0,0,0.12), 0 8px 20px rgba(0,0,0,0.06)",
      }}
    >
      {/* Header */}
      <div className="p-4 flex justify-between items-start" style={{ borderBottom: `1px solid ${brand.border}` }}>
        <div>
          <div className="flex items-center gap-2">
            <p style={{ color: brand.blue, fontSize: 10, letterSpacing: 2, fontWeight: 600, textTransform: "uppercase" }}>
              {node.path}
            </p>
            <span
              className="text-[9px] px-1.5 py-0.5 rounded font-semibold"
              style={{ background: `${worstSev.shade}10`, color: worstSev.shade }}
            >
              {worstSev.label}
            </span>
          </div>
          <p className="text-sm font-semibold mt-1" style={{ color: brand.text }}>
            {bugCount} issue{bugCount > 1 ? "s" : ""} detected
          </p>
        </div>
        <button
          onClick={onClose}
          className="w-7 h-7 rounded-lg flex items-center justify-center text-sm hover:bg-gray-100 transition-all"
          style={{ border: `1px solid ${brand.border}`, color: "#999" }}
        >
          ×
        </button>
      </div>

      {/* Tabs */}
      {bugCount > 1 && (
        <div className="flex gap-1 px-4 py-2 overflow-x-auto" style={{ borderBottom: `1px solid ${brand.border}` }}>
          {node.findings.map((f) => {
            const fSev = severityLabel(f.severity);
            const isActive = f.index === selectedIdx;
            return (
              <button
                key={f.index}
                onClick={() => onSelectIdx(f.index)}
                className="shrink-0 px-2.5 py-1 text-[10px] rounded-md font-mono transition-all flex items-center gap-1.5"
                style={{
                  border: `1px solid ${isActive ? fSev.shade : brand.border}`,
                  background: isActive ? `${fSev.shade}08` : brand.white,
                  color: isActive ? fSev.shade : "#888",
                }}
              >
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: fSev.shade }} />
                L{f.line} {f.shortCheck}
              </button>
            );
          })}
        </div>
      )}

      {/* Detail */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Severity + line */}
        <div className="flex gap-2 items-center">
          <span
            className="text-[10px] px-2.5 py-1 rounded-full font-semibold"
            style={{ background: `${sev.shade}12`, color: sev.shade, border: `1px solid ${sev.shade}22` }}
          >
            {sev.label}
          </span>
          <span className="text-[10px] font-mono" style={{ color: "#94a3b8" }}>
            Line {finding.start.line}
          </span>
          <span className="text-[10px]" style={{ color: "#94a3b8" }}>·</span>
          <span className="text-[10px]" style={{ color: "#94a3b8" }}>
            {v.confidence} confidence
          </span>
        </div>

        {/* What was found */}
        <div>
          <p style={{ fontSize: 10, letterSpacing: 1.5, color: "#94a3b8", marginBottom: 6, fontWeight: 600 }}>ISSUE</p>
          <p className="text-[13px] leading-relaxed" style={{ color: brand.text }}>{v.reason}</p>
        </div>

        {/* Description from scanner */}
        <div>
          <p style={{ fontSize: 10, letterSpacing: 1.5, color: "#94a3b8", marginBottom: 6, fontWeight: 600 }}>DESCRIPTION</p>
          <p className="text-[13px] leading-relaxed" style={{ color: brand.textMuted }}>{finding.extra.message}</p>
        </div>

        {/* Affected code */}
        {finding.extra.lines && (
          <div>
            <p style={{ fontSize: 10, letterSpacing: 1.5, color: "#94a3b8", marginBottom: 6, fontWeight: 600 }}>AFFECTED CODE</p>
            <pre
              className="text-[11px] font-mono p-3 rounded-lg overflow-x-auto whitespace-pre-wrap"
              style={{ background: "#f8fafc", border: `1px solid ${brand.border}`, color: brand.text }}
            >
              {finding.extra.lines}
            </pre>
          </div>
        )}

        {/* Related locations */}
        {v.evidence.length > 0 && (
          <div>
            <p style={{ fontSize: 10, letterSpacing: 1.5, color: "#94a3b8", marginBottom: 6, fontWeight: 600 }}>RELATED LOCATIONS</p>
            {v.evidence.map((e, i) => (
              <p key={i} className="text-[11px] font-mono" style={{ color: brand.blue }}>{e.location}</p>
            ))}
          </div>
        )}

        {/* Remediation */}
        {finding.extra.fix && (
          <div>
            <p style={{ fontSize: 10, letterSpacing: 1.5, color: "#94a3b8", marginBottom: 6, fontWeight: 600 }}>REMEDIATION</p>
            <pre
              className="text-[11px] font-mono p-3 rounded-lg overflow-x-auto whitespace-pre-wrap"
              style={{ background: "#f0fdf4", border: `1px solid ${brand.green}22`, color: brand.green }}
            >
              {finding.extra.fix}
            </pre>
          </div>
        )}
      </div>
    </motion.div>
  );
}

/* ------------------------------------------------------------------ */
/* Force Graph                                                         */
/* ------------------------------------------------------------------ */

export function ForceGraph({ data }: { data: ScanResults }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const graphDataRef = useRef<ReturnType<typeof buildGraphData> | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedIdx, setSelectedIdx] = useState(0);

  // Build graph data once and cache it
  if (!graphDataRef.current) {
    graphDataRef.current = buildGraphData(data);
  }
  const { nodes, links } = graphDataRef.current;

  useEffect(() => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = window.innerWidth;
    const height = window.innerHeight;
    svg.attr("viewBox", [-width / 2, -height / 2, width, height].join(" "));

    const g = svg.append("g");

    // Zoom
    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.1, 5])
        .on("zoom", (e) => g.attr("transform", e.transform))
    );

    // Simulation — stops after settling
    const n = nodes.length;
    const charge = n > 300 ? -40 : n > 100 ? -60 : -80;
    const dist = n > 300 ? 22 : n > 100 ? 30 : 40;

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink<GraphNode, GraphLink>(links).id((d) => d.id).distance(dist))
      .force("charge", d3.forceManyBody().strength(charge))
      .force("center", d3.forceCenter(0, 0).strength(0.04))
      .force("collision", d3.forceCollide().radius((d: any) => radius(d) + 2))
      .force("x", d3.forceX(0).strength(0.015))
      .force("y", d3.forceY(0).strength(0.015))
      .alphaDecay(0.03);

    // Links — visible connections
    const link = g.append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", "#c0c8d4")
      .attr("stroke-width", 1)
      .attr("opacity", 0.6);

    // Nodes
    const node = g.append("g")
      .selectAll<SVGCircleElement, GraphNode>("circle")
      .data(nodes)
      .join("circle")
      .attr("r", radius)
      .attr("fill", fill)
      .attr("stroke", stroke)
      .attr("stroke-width", (d) => d.id === "ROOT" ? 3 : d.findings.length > 0 ? 2 : 0.5)
      .attr("opacity", (d) => {
        if (d.id === "ROOT") return 1;
        if (d.findings.length > 0) return 1;
        if (d.kind === "dir") return 0.6;
        return 0.35;
      })
      .style("cursor", (d) => d.findings.length > 0 ? "pointer" : "default");

    // Labels — directories and files with issues
    const label = g.append("g")
      .selectAll<SVGTextElement, GraphNode>("text")
      .data(nodes.filter((d) => d.id === "ROOT" || d.kind === "dir" || d.findings.length > 0))
      .join("text")
      .text((d) => {
        if (d.id === "ROOT") return "codebase";
        if (d.kind === "dir") return d.name + "/";
        const issueCount = d.findings.length;
        return issueCount > 1 ? `${d.name} (${issueCount})` : d.name;
      })
      .attr("font-size", (d) => d.id === "ROOT" ? 13 : d.kind === "dir" ? 10 : 9)
      .attr("font-family", "system-ui, -apple-system, sans-serif")
      .attr("font-weight", (d) => (d.id === "ROOT" || d.kind === "dir") ? 600 : 400)
      .attr("fill", (d) => {
        if (d.id === "ROOT") return brand.text;
        if (d.kind === "dir") return "#94a3b8";
        if (d.severity === "critical") return "#1a1a1a";
        if (d.severity === "high") return "#333";
        if (d.severity === "medium") return "#555";
        return "#888";
      })
      .attr("text-anchor", "middle")
      .attr("dy", (d) => -radius(d) - 5)
      .attr("pointer-events", "none");

    // Issue count badges (clickable)
    const badge = g.append("g")
      .selectAll<SVGGElement, GraphNode>("g")
      .data(nodes.filter((d) => d.findings.length > 0))
      .join("g")
      .style("cursor", "pointer")
      .on("click", (event, d) => {
        event.stopPropagation();
        node.attr("stroke-width", (n) =>
          n.id === d.id ? 3 : n.id === "ROOT" ? 3 : n.findings.length > 0 ? 2 : 0.5
        );
        setSelectedNode(d);
        setSelectedIdx(d.findings[0].index);
      });

    badge.append("circle")
      .attr("r", (d) => d.findings.length > 9 ? 9 : 7)
      .attr("fill", (d) => {
        if (d.severity === "critical") return "#1a1a1a";
        if (d.severity === "high") return "#444";
        if (d.severity === "medium") return "#777";
        return "#aaa";
      })
      .attr("stroke", brand.white)
      .attr("stroke-width", 2);

    badge.append("text")
      .text((d) => d.findings.length.toString())
      .attr("font-size", 8)
      .attr("font-family", "system-ui")
      .attr("font-weight", 700)
      .attr("fill", brand.white)
      .attr("text-anchor", "middle")
      .attr("dy", 3);

    // Hover
    node
      .on("mouseover", function (_, d) {
        d3.select(this).transition().duration(150)
          .attr("r", radius(d) * 1.4).attr("opacity", 1);
      })
      .on("mouseout", function (_, d) {
        d3.select(this).transition().duration(150)
          .attr("r", radius(d))
          .attr("opacity", d.findings.length > 0 ? 1 : d.kind === "dir" ? 0.5 : 0.3);
      });

    // Click — select node without re-rendering graph
    node.on("click", (event, d) => {
      event.stopPropagation();
      if (d.findings.length > 0) {
        // Highlight clicked node
        node.attr("stroke-width", (n) =>
          n.id === d.id ? 3 : n.id === "ROOT" ? 3 : n.findings.length > 0 ? 2 : 0.5
        );
        setSelectedNode(d);
        setSelectedIdx(d.findings[0].index);
      }
    });

    // Click background to deselect
    svg.on("click", () => {
      node.attr("stroke-width", (n) =>
        n.id === "ROOT" ? 3 : n.findings.length > 0 ? 2 : 0.5
      );
      setSelectedNode(null);
    });

    // Drag
    node.call(
      d3.drag<SVGCircleElement, GraphNode>()
        .on("start", (e, d) => {
          if (!e.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on("end", (e, d) => {
          if (!e.active) simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        })
    );

    // Tick
    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x).attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x).attr("y2", (d: any) => d.target.y);
      node.attr("cx", (d) => d.x!).attr("cy", (d) => d.y!);
      label.attr("x", (d) => d.x!).attr("y", (d) => d.y!);
      badge.attr("transform", (d) => `translate(${d.x! + radius(d) - 2},${d.y! - radius(d) + 2})`);
    });

    // Once simulation settles, freeze positions so graph never moves again
    simulation.on("end", () => {
      nodes.forEach((d) => { d.fx = d.x; d.fy = d.y; });
    });

    return () => { simulation.stop(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data]);

  // Stats — only confirmed bugs
  const bugResults = data.results.filter(isBug);
  const bugCount = bugResults.length;
  const criticalCount = bugResults.filter((f) => f.extra.severity.toUpperCase() === "ERROR").length;
  const highCount = bugResults.filter((f) => f.extra.severity.toUpperCase() === "WARNING").length;

  return (
    <div className="w-full h-screen relative" style={{ background: brand.bgSoft }}>
      <svg ref={svgRef} className="w-full h-full" />

      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="absolute left-4 top-4 px-5 py-3 rounded-xl"
        style={{ background: brand.white, border: `1px solid ${brand.border}`, boxShadow: "0 2px 8px rgba(0,0,0,0.06)" }}
      >
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full" style={{ background: brand.blue }} />
          <h1 className="text-sm font-bold" style={{ color: brand.text }}>CodeAssure</h1>
        </div>
        <p className="text-[10px] mt-1" style={{ color: "#94a3b8" }}>
          {bugCount} issues · {criticalCount > 0 ? `${criticalCount} critical · ` : ""}{highCount > 0 ? `${highCount} high · ` : ""}{new Set(bugResults.map((r) => r.path)).size} files affected
        </p>
      </motion.div>

      {/* Legend */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="absolute left-4 bottom-4 px-4 py-2.5 rounded-xl flex items-center gap-4"
        style={{ background: brand.white, border: `1px solid ${brand.border}`, boxShadow: "0 2px 8px rgba(0,0,0,0.06)" }}
      >
        {[
          { label: "Critical", color: "#1a1a1a" },
          { label: "High", color: "#444444" },
          { label: "Moderate", color: "#777777" },
          { label: "Low", color: "#aaaaaa" },
          { label: "Clean", color: "#e8ecf0" },
        ].map(({ label, color }) => (
          <span key={label} className="flex items-center gap-1.5 text-[10px] font-medium" style={{ color: "#94a3b8" }}>
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />
            {label}
          </span>
        ))}
      </motion.div>

      {/* Panel */}
      <AnimatePresence>
        {selectedNode && selectedNode.findings.length > 0 && (
          <FindingPanel
            node={selectedNode}
            results={data.results}
            selectedIdx={selectedIdx}
            onSelectIdx={setSelectedIdx}
            onClose={() => setSelectedNode(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function radius(d: GraphNode): number {
  if (d.id === "ROOT") return 24;
  if (d.kind === "dir") return 6;
  if (d.findings.length > 0) {
    // Scale by issue count — minimum 8 so it's always clickable
    return Math.max(8, Math.min(18, 7 + d.findings.length * 1.5));
  }
  return Math.max(2, Math.min(5, 1 + Math.log(d.size + 1) * 0.5));
}

function fill(d: GraphNode): string {
  if (d.id === "ROOT") return brand.blue;
  if (d.kind === "dir") return "#e2e8f0";
  // Grey intensity: more issues = darker grey
  if (d.severity === "critical") return "#1a1a1a";  // darkest
  if (d.severity === "high") return "#444444";
  if (d.severity === "medium") return "#777777";
  if (d.severity === "low") return "#aaaaaa";
  return "#e8ecf0";  // clean files: very light
}

function stroke(d: GraphNode): string {
  if (d.id === "ROOT") return brand.blue;  // same as fill, no visible border
  if (d.findings.length > 0) {
    // Grey stroke matching fill intensity
    if (d.severity === "critical") return "#000000";
    if (d.severity === "high") return "#333333";
    if (d.severity === "medium") return "#666666";
    return "#999999";
  }
  if (d.kind === "dir") return "#cbd5e1";
  return "#d0d8e0";
}
