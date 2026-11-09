from typing import Optional, Literal
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Payload to trigger the Tri-Engine security audit."""
    code: str = Field(..., description="Target Python source code to analyze", min_length=1)
    filename: Optional[str] = Field("target.py", description="Virtual or relative filename")
    provider: Optional[Literal["groq", "gemini", "ollama"]] = Field(
        None, description="Optional per-request override of the LLM provider"
    )
    include_diff_patches: bool = Field(
        True, description="Whether Engine 3 should generate and verify diff patches"
    )


class PatchVerificationRequest(BaseModel):
    """Request to verify an existing patch or diff against original code."""
    original_code: str = Field(..., description="The original vulnerable source code")
    patched_code: Optional[str] = Field(None, description="Patched code string (if available)")
    unified_diff: Optional[str] = Field(None, description="Unified diff patch to test apply")
    expected_sink_type: Optional[str] = Field(None, description="Sink type expected to be neutralized")


class DiffApplyRequest(BaseModel):
    """Request to apply a unified diff to a source code string."""
    original_code: str = Field(..., description="Original source code")
    unified_diff: str = Field(..., description="Unified diff string (--- a/ +++ b/)")

