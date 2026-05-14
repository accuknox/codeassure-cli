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

export interface Verification {
  verdict: "true_positive" | "false_positive" | "uncertain";
  is_security_vulnerability: boolean;
  severity?: "critical" | "high" | "medium" | "low";
  confidence: "high" | "medium" | "low";
  reason: string;
  evidence: { location: string }[];
  graph?: FindingGraph;
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
