import React from "react";
import { CheckCircle2, AlertTriangle, ArrowRight, Copy, Check } from "lucide-react";
import type { PatchDetail } from "../types/security";

interface PatchDiffViewerProps {
  patch: PatchDetail | null;
  unifiedDiff?: string;
  onApplyPatch?: (newCode: string) => void;
}

export const PatchDiffViewer: React.FC<PatchDiffViewerProps> = ({
  patch,
  unifiedDiff,
  onApplyPatch,
}) => {
  const [copied, setCopied] = React.useState(false);
  const diffContent = unifiedDiff || patch?.unified_diff || "";

  if (!diffContent && !patch?.patched_code) {
    return (
      <div className="p-6 text-center text-slate-500 font-mono text-xs">
        No self-healing diff patch generated for this finding.
      </div>
    );
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(diffContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const diffLines = diffContent.split("\n");

  return (
    <div className="space-y-3 my-2">
      {/* Verification Status Banner */}
      <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg border border-slate-800 bg-slate-950/80">
        <div className="flex items-center gap-2">
          {patch?.verified_clean ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          )}
          <div>
            <div className="text-xs font-semibold text-slate-200">
              {patch?.verified_clean
                ? "In-Memory AST Verified Clean"
                : "Heuristic Safety Patch"}
            </div>
            <div className="text-[11px] text-slate-400 font-mono">
              AST Syntax Valid: {patch?.ast_syntax_valid ? "True" : "False"} · Residual Sinks:{" "}
              {patch?.residual_sinks_found ?? 0}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-white text-xs font-mono transition-colors"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? "Copied" : "Copy Diff"}</span>
          </button>

          {patch?.patched_code && onApplyPatch && (
            <button
              onClick={() => onApplyPatch(patch.patched_code)}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-slate-950 text-xs font-semibold font-mono tracking-wide transition-all shadow-md shadow-emerald-950/40 cursor-pointer"
            >
              <span>Apply Fix</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Unified Diff Box */}
      <div className="rounded-lg border border-slate-800 bg-slate-950 font-mono text-xs overflow-x-auto p-3 max-h-[300px]">
        {diffLines.map((line, idx) => {
          let lineClass = "text-slate-400";
          if (line.startsWith("+") && !line.startsWith("+++")) {
            lineClass = "text-emerald-400 bg-emerald-950/30 px-1 rounded block";
          } else if (line.startsWith("-") && !line.startsWith("---")) {
            lineClass = "text-rose-400 bg-rose-950/30 px-1 rounded block";
          } else if (line.startsWith("@@")) {
            lineClass = "text-cyan-400 opacity-80 block";
          }
          return (
            <div key={idx} className={lineClass}>
              {line || "\u00A0"}
            </div>
          );
        })}
      </div>

      {/* Verification Notes */}
      {patch?.verification_notes && patch.verification_notes.length > 0 && (
        <div className="space-y-1 p-2 rounded bg-slate-900/40 border border-slate-800/60">
          <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
            Verification Pipeline Notes:
          </span>
          {patch.verification_notes.map((note, idx) => (
            <p key={idx} className="text-[11px] text-slate-300 font-mono flex items-center gap-1.5">
              <span className="text-emerald-400">✓</span> {note}
            </p>
          ))}
        </div>
      )}
    </div>
  );
};
