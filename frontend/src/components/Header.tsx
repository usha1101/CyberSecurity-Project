import { ShieldAlert, Cpu, Play, Loader2 } from "lucide-react";
import type { ProvidersResponse } from "../types/security";

interface HeaderProps {
  providers: ProvidersResponse | null;
  selectedProvider: "groq" | "gemini" | "ollama";
  onSelectProvider: (p: "groq" | "gemini" | "ollama") => void;
  onRunAudit: () => void;
  isLoading: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  providers,
  selectedProvider,
  onSelectProvider,
  onRunAudit,
  isLoading,
}) => {
  const activeInfo = providers?.available_providers[selectedProvider];

  return (
    <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50 px-6 py-3.5">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-cyan-950/60 border border-cyan-500/40 text-cyan-400 shadow-lg shadow-cyan-950/40">
            <ShieldAlert className="w-5 h-5 animate-pulse" />
            <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-emerald-400 ring-2 ring-slate-950" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-slate-100 via-cyan-200 to-cyan-400 bg-clip-text text-transparent">
                ZeroGuard
              </h1>
              <span className="text-[10px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                Secure Sphere
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              AI Zero-Day & Logic Flaw Engine · Hack Fest 2026
            </p>
          </div>
        </div>

        {/* Right Actions */}
        <div className="flex items-center gap-3">
          {/* Provider selector pill */}
          <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400 font-mono">Engine:</span>
            <select
              value={selectedProvider}
              onChange={(e) => onSelectProvider(e.target.value as any)}
              className="bg-transparent text-slate-200 font-medium focus:outline-none cursor-pointer"
            >
              <option value="groq" className="bg-slate-900 text-slate-200">
                Groq (llama-3.3-70b)
              </option>
              <option value="gemini" className="bg-slate-900 text-slate-200">
                Google Gemini (2.0-flash)
              </option>
              <option value="ollama" className="bg-slate-900 text-slate-200">
                Ollama Local (qwen2.5-coder)
              </option>
            </select>
            <span
              className={`w-2 h-2 rounded-full ${
                activeInfo?.configured ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
              }`}
              title={activeInfo?.configured ? "Configured & Ready" : "Unconfigured"}
            />
          </div>

          {/* Audit Button */}
          <button
            onClick={onRunAudit}
            disabled={isLoading}
            className="flex items-center gap-2 px-5 py-2 rounded-lg font-semibold text-xs tracking-wide uppercase transition-all duration-200 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed hover:shadow-cyan-500/30 cursor-pointer"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
                <span>Auditing AST & Sinks...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Security Audit</span>
                <span className="hidden md:inline-block text-[9px] font-mono opacity-70 bg-slate-950/20 px-1.5 py-0.5 rounded">
                  Ctrl+↵
                </span>
              </>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
