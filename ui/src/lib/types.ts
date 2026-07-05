export interface GraphNode {
  id: string;
  label: string;
  type: "source" | "sink" | "flagged" | "missing" | "evidence" | "info" | "issue";
  location?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  label?: string;
}

export interface FindingGraph {
  summary: string;
  mermaid: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Remediation {
  summary: string;
  code_patch?: string;
  preserves_logic?: boolean;
  notes?: string;
}

export interface Verification {
  verdict: "true_positive" | "false_positive" | "uncertain";
  is_security_vulnerability: boolean;
  severity?: "critical" | "high" | "medium" | "low";
  confidence: "high" | "medium" | "low";
  reason: string;
  evidence: { location: string }[];
  graph?: FindingGraph;
  // Enrichment pass (codeassure)
  rationale?: string;
  business_logic?: string;
  explanation?: string;
  remediation?: Remediation;
}

// ---- Deterministic context graph (context-graph-cli, colored by codeassure) ----
export type CtxColor = "red" | "orange" | "green" | "blue" | "gray";

export interface CtxNode {
  id: string;
  kind: "source" | "sink" | "intermediate" | "transform" | "route" | "sanitizer" | "guard";
  role?: string;
  label: string;
  file: string;
  line: number;
  end_line?: number;
  function?: string;
  qualified_name?: string;
  containing_class?: string | null;
  signature?: string;
  code?: string;
  // Added by codeassure:
  status?: string;
  color?: CtxColor;
}

export interface CtxEdge {
  id: string;
  from: string;
  to: string;
  kind?: string;
  label?: string;
  paths?: string[];
  color?: CtxColor;
}

export interface CtxPath {
  id: string;
  nodes: string[];
  source_kind?: string;
  entry_point?: string;
  reachability?: "reachable" | "unreachable" | "deadcode";
  tainted?: boolean;
  protection?: { has_sanitizer?: boolean; has_guard?: boolean };
  // Added by codeassure:
  status?: "vulnerable" | "safe" | "node-protected" | "deadcode" | "unknown";
  color?: CtxColor;
  verdict_reason?: string;
}

export interface ContextGraph {
  schema_version?: string;
  generator?: string;
  language?: string;
  engine?: "joern" | "hybrid" | "treesitter-fallback" | "minimal";
  sink: { node_id: string; file: string; line: number; check_id?: string };
  nodes: CtxNode[];
  edges: CtxEdge[];
  paths: CtxPath[];
  views: {
    summary: { node_ids: string[]; path_ids: string[] };
    complete: { node_ids: string[]; path_ids: string[] };
  };
  stats?: {
    source_count?: number;
    path_count?: number;
    paths_capped?: boolean;
    degraded?: boolean;
    degrade_reason?: string | null;
  };
}

export interface Finding {
  check_id: string;
  path: string;
  start: { line: number; col: number; offset: number };
  end: { line: number; col: number; offset: number };
  extra: {
    message: string;
    severity: string;
    metadata?: {
      category?: string;
      cwe?: string[];
    };
    lines?: string;
    fix?: string;
  };
  verification: Verification;
  context_graph?: ContextGraph;
}

export interface CodebaseEntry {
  path: string;
  type: "file" | "dir";
  size: number;
}

export interface ScanResults {
  results: Finding[];
  codebase_tree?: CodebaseEntry[];
}
