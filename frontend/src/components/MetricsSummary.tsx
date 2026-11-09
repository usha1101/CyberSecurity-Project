import { AlertTriangle, Clock, Activity, ShieldCheck } from "lucide-react";
import type { ScanResponse, SeverityLevel } from "../types/security";

interface MetricsSummaryProps {
  data: ScanResponse;
}

export const MetricsSummary: React.FC<MetricsSummaryProps> = ({ data }) => {
  const getSeverityStyle = (level: SeverityLevel) => {
    switch (level) {
      case "CRITICAL":
        return "text-rose-400 bg-rose-950/40 border-rose-800/60";
      case "HIGH":
        return "text-orange-400 bg-orange-950/40 border-orange-800/60";
      case "MEDIUM":
        return "text-amber-400 bg-amber-950/40 border-amber-800/60";
      case "LOW":
        return "text-emerald-400 bg-emerald-950/40 border-emerald-800/60";
      default:
        return "text-slate-400 bg-slate-900 border-slate-800";
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 9.0) return "text-rose-400";
    if (score >= 7.0) return "text-orange-400";
    if (score >= 4.0) return "text-amber-400";
    return "text-emerald-400";
  };

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {/* 1. Overall Risk Score */}
      <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/70 backdrop-blur-sm relative overflow-hidden shadow-lg">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span className="font-mono">CVSS Risk Score</span>
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
        </div>
        <div className="flex items-baseline gap-1.5">
          <span className={`text-2xl font-bold font-mono ${getScoreColor(data.overall_risk_score)}`}>
            {data.overall_risk_score.toFixed(1)}
          </span>
          <span className="text-xs text-slate-500 font-mono">/ 10.0</span>
        </div>
        <div className="w-full bg-slate-800 h-1 rounded-full mt-2 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              data.overall_risk_score >= 9
                ? "bg-rose-500"
                : data.overall_risk_score >= 7
                ? "bg-orange-500"
                : data.overall_risk_score >= 4
                ? "bg-amber-500"
                : "bg-emerald-500"
            }`}
            style={{ width: `${Math.min(100, data.overall_risk_score * 10)}%` }}
          />
        </div>
      </div>

      {/* 2. Total Vulnerabilities */}
      <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/70 backdrop-blur-sm shadow-lg">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span className="font-mono">Detected Flaws</span>
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold font-mono text-slate-100">
            {data.total_vulnerabilities}
          </span>
          <span className="text-xs text-slate-400">Zero-day logic flows</span>
        </div>
        <p className="text-[10px] text-slate-500 font-mono mt-1">
          {data.ast_triage.dangerous_patterns_count} AST sink(s) flagged
        </p>
      </div>

      {/* 3. Highest Severity */}
      <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/70 backdrop-blur-sm shadow-lg">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span className="font-mono">Peak Severity</span>
          <ShieldCheck className="w-3.5 h-3.5 text-rose-400" />
        </div>
        <div>
          <span
            className={`inline-block text-xs font-semibold uppercase px-2.5 py-0.5 rounded-md border font-mono ${getSeverityStyle(
              data.highest_severity
            )}`}
          >
            {data.highest_severity}
          </span>
        </div>
        <p className="text-[10px] text-slate-500 font-mono mt-1">
          Model: {data.llm_provider_used}
        </p>
      </div>

      {/* 4. Execution Latency */}
      <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/70 backdrop-blur-sm shadow-lg">
        <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
          <span className="font-mono">Audit Latency</span>
          <Clock className="w-3.5 h-3.5 text-blue-400" />
        </div>
        <div className="flex items-baseline gap-1">
          <span className="text-2xl font-bold font-mono text-slate-100">
            {data.execution_time_seconds.toFixed(2)}
          </span>
          <span className="text-xs text-slate-400">sec</span>
        </div>
        <p className="text-[10px] text-slate-500 font-mono mt-1">
          {data.ast_triage.total_lines} lines analyzed
        </p>
      </div>
    </div>
  );
};
