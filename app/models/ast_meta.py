from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class DetectedSink(BaseModel):
    """Dangerous sink identified during deterministic AST analysis."""
    sink_type: str = Field(..., description="Category, e.g., CODE_EXEC, CMD_EXEC, SQLI, DESERIALIZATION, PATH_TRAVERSAL")
    call_name: str = Field(..., description="Function or method called, e.g., eval, os.system, cursor.execute")
    line_number: int
    col_offset: int = 0
    code_snippet: str
    arguments: List[str] = Field(default_factory=list)
    risk_level: str = Field("HIGH", description="LOW, MEDIUM, HIGH, CRITICAL")
    reason: str


class DetectedSource(BaseModel):
    """Untrusted input or entry point identifier."""
    source_type: str = Field(..., description="HTTP_PARAM, CLI_ARG, USER_INPUT, ENV_VAR, FILE_INPUT, FUNCTION_PARAM")
    identifier: str = Field(..., description="Variable name or attribute, e.g., request.args, sys.argv, user_input")
    line_number: int
    function_context: Optional[str] = None
    reason: str


class VariableAssignment(BaseModel):
    """Tracked variable assignment for local data flow tracing."""
    var_name: str
    line_number: int
    assigned_from: str
    involves_sources: bool = False


class FunctionMeta(BaseModel):
    """Metadata about declared functions and signatures."""
    name: str
    line_number: int
    end_line_number: Optional[int] = None
    parameters: List[str] = Field(default_factory=list)
    calls_made: List[str] = Field(default_factory=list)
    has_auth_check: bool = False
    has_transaction_or_lock: bool = False


class ASTAnalysisResult(BaseModel):
    """Complete structured output from Engine 1 AST triage."""
    parsed_successfully: bool = True
    error_message: Optional[str] = None
    total_lines: int = 0
    imports: List[str] = Field(default_factory=list)
    sinks: List[DetectedSink] = Field(default_factory=list)
    sources: List[DetectedSource] = Field(default_factory=list)
    variable_assignments: List[VariableAssignment] = Field(default_factory=list)
    functions: List[FunctionMeta] = Field(default_factory=list)
    dangerous_patterns_count: int = 0
    triage_summary: str = ""
    control_flow_summary: Dict[str, Any] = Field(default_factory=dict)

