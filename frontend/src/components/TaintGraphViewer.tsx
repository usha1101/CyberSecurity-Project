import { Radio, ShieldAlert, AlertOctagon, CornerDownRight } from "lucide-react";
import type { TaintNode, TaintNodeType } from "../types/security";

interface TaintGraphViewerProps {
  nodes: TaintNode[];
}

export const TaintGraphViewer: React.FC<TaintGraphViewerProps> = ({ nodes }) => {
  if (!nodes || nodes.length === 0) {
    return (
      <div className="p-6 text-center text-slate-500 font-mono text-xs">
        No taint propagation steps recorded for this finding.
      </div>
    );
  }

  const getNodeBadge = (type: TaintNodeType) => {
    switch (type) {
      case "SOURCE":
        return {
          label: "TAINT SOURCE",
          color: "text-cyan-400 bg-cyan-950/60 border-cyan-800/80",
          icon: <Radio className="w-3.5 h-3.5 text-cyan-400" />,
        };
      case "PROPAGATION":
        return {
          label: "PROPAGATION",
          color: "text-amber-400 bg-amber-950/60 border-amber-800/80",
          icon: <CornerDownRight className="w-3.5 h-3.5 text-amber-400" />,
        };
      case "SANITIZATION_MISSING":
        return {
          label: "MISSING GUARD",
          color: "text-orange-400 bg-orange-950/60 border-orange-800/80",
          icon: <ShieldAlert className="w-3.5 h-3.5 text-orange-400" />,
        };
      case "SINK":
        return {
          label: "DANGEROUS SINK",
          color: "text-rose-400 bg-rose-950/60 border-rose-800/80",
          icon: <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />,
        };
    }
  };

  return (
    <div className="relative pl-6 space-y-4 my-2">
      {/* Vertical connection line */}
      <div className="absolute left-2.5 top-3 bottom-3 w-0.5 bg-gradient-to-b from-cyan-500 via-amber-500 to-rose-500 opacity-30" />

      {nodes.map((node, idx) => {
        const badge = getNodeBadge(node.node_type);

        return (
          <div key={idx} className="relative group">
            {/* Dot on line */}
            <div
              className={`absolute -left-6 top-3 w-3 h-3 rounded-full border-2 border-slate-950 ${
                node.node_type === "SOURCE"
                  ? "bg-cyan-400 shadow-sm shadow-cyan-400"
                  : node.node_type === "SINK"
                  ? "bg-rose-500 shadow-sm shadow-rose-500"
                  : node.node_type === "SANITIZATION_MISSING"
                  ? "bg-orange-400"
                  : "bg-amber-400"
              }`}
            />

            {/* Step Content Card */}
            <div className="p-3.5 rounded-lg border border-slate-800/90 bg-slate-950/70 hover:border-slate-700 transition-all shadow-md">
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase border ${badge.color}`}
                  >
                    {badge.icon}
                    {badge.label}
                  </span>
                  <span className="text-xs font-mono text-slate-400 font-medium">
                    Step {node.step_index || idx + 1}
                  </span>
                </div>
                <span className="text-[11px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                  Line {node.line_number}
                </span>
              </div>

              {/* Code Snippet Box */}
              {node.code_snippet && (
                <div className="p-2 rounded bg-slate-900 border border-slate-800/80 font-mono text-xs text-cyan-200 overflow-x-auto mb-2">
                  <code>{node.code_snippet}</code>
                </div>
              )}

              {/* Explanation */}
              <p className="text-xs text-slate-300 leading-relaxed">
                {node.explanation}
              </p>

              {node.variable_name && (
                <div className="mt-2 text-[11px] font-mono text-slate-400">
                  Tainted Variable:{" "}
                  <span className="text-amber-300 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-900/40">
                    {node.variable_name}
                  </span>
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};
