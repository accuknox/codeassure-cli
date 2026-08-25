"use client";

interface Props {
  code: string;
  startLine: number;
  endLine: number;
}

export function CodeBlock({ code, startLine, endLine }: Props) {
  const lines = code.split("\n");
  // Strip trailing empty line from split
  if (lines[lines.length - 1] === "") lines.pop();

  return (
    <div className="rounded-lg overflow-hidden border border-zinc-800 font-mono text-xs">
      {lines.map((line, i) => {
        const lineNum = startLine + i;
        const isHighlighted = lineNum >= startLine && lineNum <= endLine;
        return (
          <div
            key={i}
            className={`flex ${
              isHighlighted
                ? "bg-red-500/15 border-l-2 border-red-400"
                : "border-l-2 border-transparent"
            }`}
          >
            <span
              className={`select-none shrink-0 w-10 text-right pr-3 py-1 ${
                isHighlighted ? "text-red-400" : "text-zinc-600"
              }`}
            >
              {lineNum}
            </span>
            <span
              className={`flex-1 py-1 pr-3 whitespace-pre overflow-x-auto ${
                isHighlighted ? "text-red-100" : "text-zinc-300"
              }`}
            >
              {line || " "}
            </span>
          </div>
        );
      })}
    </div>
  );
}
