import { useState, useEffect, useCallback } from "react";
import { Header } from "./components/Header";
import { CodeEditor } from "./components/CodeEditor";
import { MetricsSummary } from "./components/MetricsSummary";
import { VulnerabilityCard } from "./components/VulnerabilityCard";
import { EmptyState } from "./components/EmptyState";
import { SAMPLES } from "./services/samples";
import type { CodeSample } from "./services/samples";
import { scanSourceCode, fetchProviders } from "./services/api";
import type { ScanResponse, ProvidersResponse } from "./types/security";
import { AlertCircle, CheckCircle2, Shield, Terminal, ArrowUpRight } from "lucide-react";

export function App() {
  const [code, setCode] = useState<string>(SAMPLES[0].code);
  const [filename, setFilename] = useState<string>(SAMPLES[0].filename);
  const [selectedSampleId, setSelectedSampleId] = useState<string>(SAMPLES[0].id);
  const [selectedProvider, setSelectedProvider] = useState<"groq" | "gemini" | "ollama">("groq");
  const [providers, setProviders] = useState<ProvidersResponse | null>(null);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [patchAppliedBanner, setPatchAppliedBanner] = useState<string | null>(null);

  // Load provider statuses on mount
  useEffect(() => {
    fetchProviders().then((res) => {
      setProviders(res);
      if (res.active_provider && ["groq", "gemini", "ollama"].includes(res.active_provider)) {
        setSelectedProvider(res.active_provider as any);
      }
    });
  }, []);

  const handleSelectSample = (sample: CodeSample) => {
    setSelectedSampleId(sample.id);
    setCode(sample.code);
    setFilename(sample.filename);
    setError(null);
  };

  const handleRunAudit = useCallback(async () => {
    if (!code.trim()) {
      setError("Please provide Python source code to audit.");
      return;
    }

    setIsLoading(true);
    setError(null);
    setPatchAppliedBanner(null);

    try {
      const result = await scanSourceCode(code, filename, selectedProvider);
      setScanResult(result);
    } catch (err: any) {
      setError(
        err.message ||
          "Failed to communicate with ZeroGuard backend. Ensure 'python run.py' is running on http://localhost:8000"
      );
    } finally {
      setIsLoading(false);
    }
  }, [code, filename, selectedProvider]);

  // Keyboard shortcut Ctrl + Enter to trigger audit
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        handleRunAudit();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleRunAudit]);

  const handleApplyPatch = (newCode: string) => {
    setCode(newCode);
    setPatchAppliedBanner("Patch applied to code editor! Re-run audit to verify zero residual sinks.");
    setTimeout(() => setPatchAppliedBanner(null), 6000);
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Header */}
      <Header
        providers={providers}
        selectedProvider={selectedProvider}
        onSelectProvider={setSelectedProvider}
        onRunAudit={handleRunAudit}
        isLoading={isLoading}
      />

      {/* Notification Toast for Patch Application */}
      {patchAppliedBanner && (
        <div className="bg-emerald-950/80 border-b border-emerald-800 text-emerald-300 px-6 py-2 text-xs font-mono flex items-center justify-between animate-in fade-in">
          <div className="flex items-center gap-2 max-w-7xl mx-auto w-full">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>{patchAppliedBanner}</span>
          </div>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="bg-rose-950/80 border-b border-rose-800 text-rose-300 px-6 py-2.5 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2 max-w-7xl mx-auto w-full">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Main Workspace Split View */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Monaco Code Editor (5 Cols on large screens) */}
        <div className="lg:col-span-5 h-full flex flex-col min-h-[560px]">
          <div className="flex items-center justify-between mb-2 px-1">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span>Target Source Code</span>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              Interactive IDE
            </span>
          </div>
          <div className="flex-1">
            <CodeEditor
              code={code}
              onChange={setCode}
              selectedSampleId={selectedSampleId}
              onSelectSample={handleSelectSample}
              filename={filename}
              onFilenameChange={setFilename}
            />
          </div>
        </div>

        {/* Right Column: Security Intelligence Dashboard (7 Cols on large screens) */}
        <div className="lg:col-span-7 flex flex-col gap-4 min-h-[560px]">
          <div className="flex items-center justify-between mb-2 px-1">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span>Security Intelligence & Visual Taint Flow</span>
            </div>
            {scanResult && (
              <span className="text-[11px] font-mono text-slate-500">
                Scan ID: {scanResult.scan_id}
              </span>
            )}
          </div>

          {!scanResult ? (
            <EmptyState
              onSelectSample={handleSelectSample}
              onRunAudit={handleRunAudit}
            />
          ) : (
            <div className="space-y-4">
              {/* Metrics Summary Strip */}
              <MetricsSummary data={scanResult} />

              {/* AST Pre-Filter Triage Card */}
              <div className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/40 text-xs font-mono text-slate-400 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  <span className="text-slate-300 font-medium">Deterministic AST Triage:</span>
                  <span>{scanResult.ast_triage.triage_summary}</span>
                </div>
                <div className="flex items-center gap-3 text-[11px]">
                  <span>Imports: {scanResult.ast_triage.imports.join(", ") || "none"}</span>
                </div>
              </div>

              {/* Detected Vulnerabilities List */}
              <div className="space-y-3">
                <div className="flex items-center justify-between px-1">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                    Audited Vulnerabilities ({scanResult.vulnerabilities.length})
                  </h3>
                  <span className="text-[10px] font-mono text-slate-500">
                    Click card to inspect Taint Graph & Diff
                  </span>
                </div>

                {scanResult.vulnerabilities.length === 0 ? (
                  <div className="p-8 text-center border border-slate-800 rounded-xl bg-slate-900/40 font-mono text-sm text-emerald-400">
                    ✓ Clean: Zero security logic flaws or dangerous sinks detected in this code.
                  </div>
                ) : (
                  scanResult.vulnerabilities.map((vuln, idx) => (
                    <VulnerabilityCard
                      key={vuln.vuln_id || idx}
                      vulnerability={vuln}
                      index={idx}
                      onApplyPatch={handleApplyPatch}
                    />
                  ))
                )}
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 px-6 py-3 text-center text-xs font-mono text-slate-400 mt-auto">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3">
          <span>ZeroGuard © 2026 · AI Zero-Day & Logic Flaw Detection Engine</span>
          <div className="flex items-center gap-4">
            <span className="text-cyan-400">Track: Secure Sphere</span>
            <span>FastAPI ASGI on :8000</span>
            <a
              href="http://localhost:8000/docs"
              target="_blank"
              rel="noreferrer"
              className="text-slate-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
            >
              <span>Swagger API</span>
              <ArrowUpRight className="w-3 h-3" />
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
