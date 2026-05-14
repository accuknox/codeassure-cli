"use client";

import { useCallback } from "react";
import { motion } from "motion/react";

export function FileUpload({ onLoad }: { onLoad: (data: unknown) => void }) {
  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      const file = e.dataTransfer.files[0];
      if (file) readFile(file, onLoad);
    },
    [onLoad]
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) readFile(file, onLoad);
    },
    [onLoad]
  );

  return (
    <motion.label
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      onDragOver={(e) => e.preventDefault()}
      onDrop={handleDrop}
      className="flex flex-col items-center justify-center w-full h-40 rounded-xl cursor-pointer transition-all hover:border-[#1578F7]"
      style={{
        border: "2px dashed #e9e9e9",
        background: "#f5f7fe",
      }}
    >
      <svg className="w-8 h-8 mb-2" fill="none" viewBox="0 0 24 24" stroke="#94a3b8">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 16V4m0 0L8 8m4-4l4 4M4 20h16" />
      </svg>
      <span className="text-sm" style={{ color: "#94a3b8" }}>
        Drop verified_findings.json or click to upload
      </span>
      <input type="file" accept=".json" onChange={handleChange} className="hidden" />
    </motion.label>
  );
}

function readFile(file: File, onLoad: (data: unknown) => void) {
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      onLoad(JSON.parse(e.target?.result as string));
    } catch {
      alert("Invalid JSON file");
    }
  };
  reader.readAsText(file);
}
