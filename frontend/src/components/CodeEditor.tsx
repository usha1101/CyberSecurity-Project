import Editor from "@monaco-editor/react";
import { FileCode, RotateCcw, Trash2, Sparkles } from "lucide-react";
import { SAMPLES } from "../services/samples";
import type { CodeSample } from "../services/samples";

interface CodeEditorProps {
  code: string;
  onChange: (value: string) => void;
  selectedSampleId: string;
  onSelectSample: (sample: CodeSample) => void;
  filename: string;
  onFilenameChange: (name: string) => void;
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
  code,
  onChange,
  selectedSampleId,
  onSelectSample,
  filename,
  onFilenameChange,
}) => {
  const lineCount = code.split("\n").length;
  const charCount = code.length;

  return (
    <div className="flex flex-col h-full rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur-md overflow-hidden shadow-xl">
      {/* Top Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 border-b border-slate-800 bg-slate-950/60">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-cyan-400" />
          <input
            type="text"
            value={filename}
            onChange={(e) => onFilenameChange(e.target.value)}
            className="bg-transparent text-xs font-mono font-medium text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500/40 px-1.5 py-0.5 rounded"
            title="Target Filename"
          />
        </div>

        {/* Preset Selector */}
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-400 text-[11px] font-mono hidden sm:inline">Vector:</span>
            <select
              value={selectedSampleId}
              onChange={(e) => {
                const sample = SAMPLES.find((s) => s.id === e.target.value);
                if (sample) onSelectSample(sample);
              }}
              className="bg-transparent text-slate-200 text-xs font-medium focus:outline-none cursor-pointer"
            >
              {SAMPLES.map((sample) => (
                <option key={sample.id} value={sample.id} className="bg-slate-900 text-slate-200">
                  {sample.name} ({sample.cwe})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => {
              const current = SAMPLES.find((s) => s.id === selectedSampleId);
              if (current) onChange(current.code);
            }}
            title="Reset code to original preset"
            className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={() => onChange("")}
            title="Clear editor"
            className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-rose-400 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Monaco Editor Container */}
      <div className="flex-1 min-h-[420px] relative">
        <Editor
          height="100%"
          defaultLanguage="python"
          language="python"
          theme="vs-dark"
          value={code}
          onChange={(val) => onChange(val || "")}
          options={{
            minimap: { enabled: false },
            fontSize: 13,
            lineNumbers: "on",
            scrollBeyondLastLine: false,
            automaticLayout: true,
            tabSize: 4,
            padding: { top: 12, bottom: 12 },
            fontFamily: "'Fira Code', 'JetBrains Mono', Consolas, monospace",
            renderLineHighlight: "all",
          }}
        />
      </div>

      {/* Editor Footer Status */}
      <div className="flex items-center justify-between px-4 py-1.5 border-t border-slate-800 bg-slate-950/80 text-[11px] font-mono text-slate-400">
        <div className="flex items-center gap-3">
          <span>Python 3.11+</span>
          <span>•</span>
          <span>AST Parsing Active</span>
        </div>
        <div className="flex items-center gap-3">
          <span>{lineCount} lines</span>
          <span>{charCount} chars</span>
        </div>
      </div>
    </div>
  );
};
