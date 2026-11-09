export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";

export type TaintNodeType = "SOURCE" | "PROPAGATION" | "SANITIZATION_MISSING" | "SINK";

export interface TaintNode {
  step_index: number;
  node_type: TaintNodeType;
  line_number: number;
  code_snippet: string;
  variable_name?: string;
  explanation: string;
}

export interface CVSSMetrics {
  vector_string: string;
  base_score: number;
  severity_rating: SeverityLevel;
  exploitability_score: number;
  impact_score: number;
  metrics?: Record<string, string>;
}

export interface PatchDetail {
  patch_strategy: string;
  unified_diff: string;
  patched_code: string;
  verified_clean: boolean;
  ast_syntax_valid: boolean;
  residual_sinks_found: number;
  verification_notes: string[];
}

export interface VulnerabilityDetail {
  vuln_id: string;
  title: string;
  cwe_id: string;
  category: string;
  description: string;
  root_cause: string;
  severity: SeverityLevel;
  cvss: CVSSMetrics;
  cvss_score?: number;
  cvss_vector?: string;
  taint_graph: TaintNode[];
  taint_path?: TaintNode[];
  attack_vector_narrative: string;
  recommended_fix_strategy: string;
  patch?: PatchDetail | null;
  unified_diff?: string;
}

export interface ASTAnalysisResult {
  parsed_successfully: boolean;
  error_message?: string | null;
  total_lines: number;
  imports: string[];
  dangerous_patterns_count: number;
  triage_summary: string;
}

export interface ScanResponse {
  scan_id: string;
  timestamp: string;
  target_name: string;
  llm_provider_used: string;
  model_used: string;
  execution_time_seconds: number;
  ast_triage: ASTAnalysisResult;
  vulnerabilities: VulnerabilityDetail[];
  total_vulnerabilities: number;
  highest_severity: SeverityLevel;
  overall_risk_score: number;
  status: "COMPLETED" | "FAILED" | "CLEAN";
}

export interface ProviderStatus {
  name: string;
  model: string;
  configured: boolean;
  is_primary: boolean;
}

export interface ProvidersResponse {
  active_provider: string;
  available_providers: Record<string, ProviderStatus>;
}
