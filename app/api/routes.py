from fastapi import APIRouter, HTTPException, status
from app.models.request import ScanRequest, PatchVerificationRequest, DiffApplyRequest
from app.models.response import (
    ScanResponse,
    PatchVerificationResponse,
    ProviderInfo,
    HealthResponse,
)
from app.services.orchestrator import orchestrator
from app.services.llm_provider import llm_service
from app.utils.patcher import verify_patch_safety, apply_unified_diff
from app.config import settings

router = APIRouter(prefix="/api/v1", tags=["ZeroGuard Core"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    summary="Execute Tri-Engine Zero-Day & Logic Flaw Security Audit",
    status_code=status.HTTP_200_OK,
)
async def scan_source_code(request: ScanRequest) -> ScanResponse:
    """
    Submits Python source code snippet or file to the ZeroGuard Tri-Engine pipeline:
    1. Deterministic AST Triage (sinks, sources, control-flow)
    2. Semantic Zero-Day Reasoning & Visual Taint Flow Mapping
    3. Self-Healing Verified Patch Generation & CVSS v3.1 Scoring
    """
    try:
        response = await orchestrator.run_pipeline(request)
        return response
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pipeline execution encountered an unexpected error: {str(e)}",
        )


@router.post(
    "/verify-patch",
    response_model=PatchVerificationResponse,
    summary="In-Memory AST Patch & Diff Verification",
    status_code=status.HTTP_200_OK,
)
async def verify_patch(request: PatchVerificationRequest) -> PatchVerificationResponse:
    """
    Validates a suggested patch or unified diff in-memory against Python AST parser
    and checks for residual dangerous sinks.
    """
    try:
        result = verify_patch_safety(
            original_code=request.original_code,
            patched_code=request.patched_code,
            unified_diff=request.unified_diff,
            expected_sink_type=request.expected_sink_type,
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Patch verification failed: {str(e)}",
        )


@router.post(
    "/apply-diff",
    summary="Apply Unified Diff to Source Code In-Memory",
    status_code=status.HTTP_200_OK,
)
async def apply_diff_endpoint(request: DiffApplyRequest):
    """Applies a standard unified diff patch to source code and returns the patched output."""
    success, patched_code, notes = apply_unified_diff(
        original_code=request.original_code,
        unified_diff=request.unified_diff
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to apply unified diff: {', '.join(notes)}",
        )
    return {
        "success": True,
        "patched_code": patched_code,
        "notes": notes
    }


@router.get(
    "/providers",
    response_model=ProviderInfo,
    summary="List Free-Tier AI Model Provider Statuses",
    status_code=status.HTTP_200_OK,
)
async def list_providers() -> ProviderInfo:
    """Inspects configuration and availability of Groq, Gemini, and Ollama providers."""
    return ProviderInfo(
        active_provider=settings.LLM_PROVIDER,
        available_providers=llm_service.get_provider_statuses(),
    )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="ZeroGuard Health & Readiness Check",
    status_code=status.HTTP_200_OK,
)
async def health_check() -> HealthResponse:
    """Returns engine health status and active configuration."""
    statuses = llm_service.get_provider_statuses()
    active_ready = statuses.get(settings.LLM_PROVIDER, {}).get("configured", False)

    return HealthResponse(
        status="healthy",
        service="ZeroGuard Detection Engine",
        version="1.0.0-hackfest2026",
        active_provider=settings.LLM_PROVIDER,
        llm_ready=active_ready,
    )

