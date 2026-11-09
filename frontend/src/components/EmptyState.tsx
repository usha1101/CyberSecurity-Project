import { ShieldCheck, Zap, ArrowRight } from "lucide-react";
import { SAMPLES } from "../services/samples";
import type { CodeSample } from "../services/samples";

interface EmptyStateProps {
  onSelectSample: (sample: CodeSample) => void;
  onRunAudit: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ onSelectSample, onRunAudit }) => {
  return (
    <div className="flex flex-col items-center justify-center h-full min-h-[460px] p-8 text-center border border-dashed border-slate-800 rounded-2xl bg-slate-900/30">
      {/* Radar Shield graphic */}
      <div className="relative flex items-center justify-center w-16 h-16 rounded-2xl bg-slate-900 border border-slate-800 text-cyan-400 mb-4 shadow-xl shadow-cyan-950/20">
        <ShieldCheck className="w-8 h-8 text-cyan-400" />
        <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-cyan-400 animate-ping opacity-75" />
      </div>

      <h3 className="text-base font-bold text-slate-100 mb-1">
        ZeroGuard Security Intelligence Engine Ready
      </h3>
      <p className="text-xs text-slate-400 max-w-md leading-relaxed mb-6 font-mono">
        Select a vulnerability vector preset below, or paste your custom Python source code into the editor and trigger the Tri-Engine AST & LLM reasoning pipeline.
      </p>

      {/* Preset Action Chips */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 max-w-lg w-full mb-6 text-left">
        {SAMPLES.map((sample) => (
          <button
            key={sample.id}
            onClick={() => onSelectSample(sample)}
            className="flex flex-col p-3 rounded-xl border border-slate-800 bg-slate-950/80 hover:border-cyan-500/50 hover:bg-slate-900/80 transition-all cursor-pointer group text-left"
          >
            <div className="flex items-center justify-between text-xs font-semibold text-slate-200 group-hover:text-cyan-300">
              <span>{sample.name}</span>
              <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-transform group-hover:translate-x-0.5" />
            </div>
            <span className="text-[10px] font-mono text-cyan-400/80 mt-1">
              {sample.cwe} · {sample.category}
            </span>
            <p className="text-[11px] text-slate-400 mt-1 line-clamp-1">
              {sample.description}
            </p>
          </button>
        ))}
      </div>

      {/* Start Button */}
      <button
        onClick={onRunAudit}
        className="flex items-center gap-2 px-6 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-cyan-500/20 cursor-pointer"
      >
        <Zap className="w-3.5 h-3.5 fill-current" />
        <span>Launch Security Audit</span>
      </button>
    </div>
  );
};
