/** AccuKnox brand theme — from accuknox.com/solutions/agentic-ai-security */

export const brand = {
  /** Page & card backgrounds */
  bg: "#ffffff",
  bgSoft: "#f5f7fe",
  bgDark: "#050525",

  /** Primary action color */
  blue: "#1578F7",
  blueDark: "#1040C5",

  /** Status */
  green: "#14A24A",
  red: "#E80E30",
  orange: "#E86A3E",

  /** Text */
  text: "#212121",
  textSecondary: "#263238",
  textMuted: "rgba(0,0,0,0.55)",

  /** Borders & dividers */
  border: "#e9e9e9",
  borderDark: "#d3d3d3",

  white: "#ffffff",
};

/** Severity → color mapping for findings */
export const severity = {
  critical: { bg: "#fef2f2", border: brand.red, glow: `0 0 20px ${brand.red}33`, text: brand.red },
  high: { bg: "#fff7ed", border: brand.orange, glow: `0 0 16px ${brand.orange}28`, text: brand.orange },
  medium: { bg: "#fefce8", border: "#ca8a04", glow: "0 0 12px #ca8a0420", text: "#a16207" },
  low: { bg: "#eff6ff", border: brand.blue, glow: `0 0 10px ${brand.blue}18`, text: brand.blue },
  none: { bg: brand.bgSoft, border: brand.border, glow: "none", text: "#94a3b8" },
};

/** File extension → color for codebase nodes */
export const fileColor: Record<string, string> = {
  py: "#3572A5",
  ts: "#3178c6",
  tsx: "#3178c6",
  js: "#f0c000",
  jsx: "#f0c000",
  json: "#94a3b8",
  yaml: "#cb171e",
  yml: "#cb171e",
  dockerfile: brand.blue,
  md: "#64748b",
  txt: "#94a3b8",
  toml: "#9c4121",
  cfg: "#94a3b8",
  default: "#6366f1",
};

export function getFileColor(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() || "";
  if (path.toLowerCase().includes("dockerfile")) return fileColor.dockerfile;
  return fileColor[ext] || fileColor.default;
}
