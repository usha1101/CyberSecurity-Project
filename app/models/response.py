from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field
from app.models.ast_meta import ASTAnalysisResult


class TaintNode(BaseModel):
    """A single node or step in the visual taint propagation graph."""
    step_index: int = Field(..., description="1-based sequence order in the taint chain")
    node_type: Literal["SOURCE", "PROPAGATION", "SANITIZATION_MISSING", "SINK"] = Field(
        ..., description="Role of the node in the vulnerability lifecycle"
    )
    line_number: int
    code_snippet: str
    variable_name: Optional[str] = None
    explanation: str


class CVSSMetrics(BaseModel):
    """CVSS v3.1 standard vector breakdown and scores."""
    vector_string: str = Field(..., json_schema_extra={"example": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    base_score: float = Field(..., ge=0.0, le=10.0)
    severity_rating: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    exploitability_score: float
    impact_score: float
    metrics: Dict[str, str] = Field(
        default_factory=dict,
        description="Individual metrics: AV, AC, PR, UI, S, C, I, A"
    )


class PatchDetail(BaseModel):
    """Verified self-healing patch details."""
    patch_strategy: str
    unified_diff: str
    patched_code: str
    verified_clean: bool
    ast_syntax_valid: bool
    residual_sinks_found: int = 0
    verification_notes: List[str] = Field(default_factory=list)


class VulnerabilityDetail(BaseModel):
    """Complete specification of a detected zero-day vulnerability or logic flaw."""
    vuln_id: str = Field(..., description="Unique vulnerability identifier, e.g., ZG-2026-001")
    title: str
    cwe_id: str = Field(..., description="Common Weakness Enumeration ID, e.g. CWE-367, CWE-89")
    category: str = Field(
        ...,
        description="e.g. ZERO_DAY_LOGIC, RACE_CONDITION_TOCTOU, MASS_ASSIGNMENT, TAINT_PROPAGATION, BROKEN_AUTH"
    )
    description: str
    root_cause: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    cvss: CVSSMetrics
    cvss_score: float = Field(default=0.0, description="CVSS v3.1 base score")
    cvss_vector: str = Field(default="", description="CVSS v3.1 vector string")
    taint_graph: List[TaintNode] = Field(default_factory=list)
    taint_path: List[TaintNode] = Field(default_factory=list, description="Visual taint propagation sequence")
    attack_vector_narrative: str
    recommended_fix_strategy: str
    patch: Optional[PatchDetail] = None
    unified_diff: str = Field(default="", description="Unified diff patch representation")


class ScanResponse(BaseModel):
    """Full triage & reasoning response returned to the client/frontend."""
    scan_id: str
    timestamp: str
    target_name: str = "snippet.py"
    llm_provider_used: str
    model_used: str
    execution_time_seconds: float
    ast_triage: ASTAnalysisResult
    vulnerabilities: List[VulnerabilityDetail] = Field(default_factory=list)
    total_vulnerabilities: int = 0
    highest_severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "NONE"
    overall_risk_score: float = 0.0
    status: Literal["COMPLETED", "FAILED", "CLEAN"] = "COMPLETED"


class PatchVerificationResponse(BaseModel):
    """Result of checking an in-memory patch against syntax and residual sinks."""
    verified_clean: bool
    ast_syntax_valid: bool
    unified_diff_applied: bool
    patched_code: str
    residual_sinks_found: int
    notes: List[str]


class ProviderInfo(BaseModel):
    """Status of configured LLM backends."""
    active_provider: str
    available_providers: Dict[str, Dict[str, Any]]


class HealthResponse(BaseModel):
    """Engine health check response."""
    status: str
    service: str
    version: str
    active_provider: str
    llm_ready: bool
