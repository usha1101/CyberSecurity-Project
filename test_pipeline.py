#!/usr/bin/env python3
"""
ZeroGuard End-to-End Test & Smoke Validation Harness
Hack Fest 2026 (Track: Secure Sphere)

Validates:
1. Environment & Config Validation (.env loading, LLM_PROVIDER=groq, Groq API key, 429 fallback)
2. Dependency & Code Integrity (FastAPI, Pydantic v2 schemas, CORS parsing)
3. End-to-End Pipeline Execution against samples/vulnerable_sample.py
"""

import os
import sys
import time
import json
import asyncio
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import settings
from app.models.request import ScanRequest
from app.services.orchestrator import orchestrator
from app.services.llm_provider import llm_service
from app.engines.engine2_semantic import semantic_engine
from app.api.routes import scan_source_code


import pytest


def print_banner(text: str):
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70)


@pytest.mark.anyio
async def test_environment_and_config():
    print_banner("1. ENVIRONMENT & CONFIGURATION VALIDATION")

    print(f"[+] Loaded LLM_PROVIDER: {settings.LLM_PROVIDER}")
    assert settings.LLM_PROVIDER in ["groq", "gemini", "ollama"], "Invalid LLM_PROVIDER"

    print(f"[+] Groq Model: {settings.GROQ_MODEL}")
    assert settings.GROQ_MODEL == "llama-3.3-70b-versatile", f"Expected llama-3.3-70b-versatile, got {settings.GROQ_MODEL}"

    has_groq_key = bool(settings.GROQ_API_KEY and len(settings.GROQ_API_KEY) > 10)
    print(f"[+] Groq API Key Configured: {'YES (Length: ' + str(len(settings.GROQ_API_KEY)) + ')' if has_groq_key else 'NO'}")

    has_gemini_key = bool(settings.GEMINI_API_KEY and len(settings.GEMINI_API_KEY) > 10)
    print(f"[+] Gemini API Key Configured: {'YES (Length: ' + str(len(settings.GEMINI_API_KEY)) + ')' if has_gemini_key else 'NO'}")

    print(f"[+] CORS Origins Parsed: {settings.CORS_ORIGINS} (Type: {type(settings.CORS_ORIGINS).__name__})")
    assert isinstance(settings.CORS_ORIGINS, list), "CORS_ORIGINS must be a parsed list"

    # Verify provider status mapping
    statuses = llm_service.get_provider_statuses()
    print(f"[+] Provider Readiness:")
    for prov, status in statuses.items():
        print(f"    - {prov.upper()}: configured={status.get('configured')}, is_primary={status.get('is_primary')}")

    # 429 Rate Limit Failover Test (Groq 429 -> Gemini)
    from unittest.mock import patch, MagicMock
    from groq import RateLimitError
    mock_resp = MagicMock()
    mock_resp.request = MagicMock()
    with patch.object(llm_service, "_call_groq", side_effect=RateLimitError("429 Rate Limit Exceeded", response=mock_resp, body=None)):
        with patch.object(llm_service, "_call_gemini", return_value='{"vulnerabilities": []}'):
            _, provider_used, _ = await llm_service.generate_security_analysis("system", "user", preferred_provider="groq")
            print(f"[+] Groq HTTP 429 Simulation: Successfully failed over to -> {provider_used.upper()}")
            assert provider_used == "gemini", f"Expected fallback to gemini, got {provider_used}"


@pytest.mark.anyio
async def test_end_to_end_pipeline():
    print_banner("2. END-TO-END PIPELINE AUDIT ON SAMPLES/VULNERABLE_SAMPLE.PY")

    sample_path = PROJECT_ROOT / "samples" / "vulnerable_sample.py"
    assert sample_path.exists(), f"Sample file not found at {sample_path}"

    with open(sample_path, "r", encoding="utf-8") as f:
        vulnerable_code = f.read()

    print(f"[+] Loaded target snippet ({len(vulnerable_code.splitlines())} lines) from {sample_path.name}")

    scan_req = ScanRequest(
        code=vulnerable_code,
        filename="vulnerable_sample.py",
        include_diff_patches=True
    )

    t0 = time.perf_counter()
    response = await scan_source_code(scan_req)
    latency = round(time.perf_counter() - t0, 3)

    print(f"[+] Scan completed in {latency}s")
    print(f"[+] Scan ID: {response.scan_id}")
    print(f"[+] Provider Used: {response.llm_provider_used} (Model: {response.model_used})")
    print(f"[+] AST Sinks Identified: {len(response.ast_triage.sinks)}")
    print(f"[+] Total Vulnerabilities Detected: {response.total_vulnerabilities}")
    print(f"[+] Highest Severity: {response.highest_severity} (Score: {response.overall_risk_score}/10.0)")

    # Assertions required by smoke test
    assert response.total_vulnerabilities > 0, "Expected non-empty vulnerabilities list"
    assert len(response.vulnerabilities) > 0, "Vulnerabilities list is empty"

    first_vuln = response.vulnerabilities[0]
    print(f"\n[+] Inspecting First Vulnerability: [{first_vuln.vuln_id}] {first_vuln.title}")

    # CVSS score and vector validation
    cvss_score = first_vuln.cvss_score or first_vuln.cvss.base_score
    cvss_vector = first_vuln.cvss_vector or first_vuln.cvss.vector_string
    print(f"    - CVSS v3.1 Score: {cvss_score} ({first_vuln.cvss.severity_rating})")
    print(f"    - CVSS v3.1 Vector: {cvss_vector}")
    assert 0.0 <= cvss_score <= 10.0, f"CVSS score out of range: {cvss_score}"
    assert cvss_vector.startswith("CVSS:3.1"), f"Invalid CVSS vector string: {cvss_vector}"

    # Taint path validation
    taint_nodes = first_vuln.taint_path or first_vuln.taint_graph
    print(f"    - Taint Path Steps: {len(taint_nodes)} node(s)")
    assert len(taint_nodes) > 0, "Taint path sequence is empty"
    for node in taint_nodes:
        print(f"      [Step {node.step_index}] {node.node_type} (Line {node.line_number}): {node.explanation[:60]}...")

    # Unified Diff Patch validation
    diff_patch = first_vuln.unified_diff or (first_vuln.patch.unified_diff if first_vuln.patch else "")
    print(f"    - Verified Patch Generated: {'YES' if diff_patch else 'NO'}")
    assert len(diff_patch.strip()) > 0, "Unified diff patch is empty"
    if first_vuln.patch:
        print(f"    - In-Memory AST Valid: {first_vuln.patch.ast_syntax_valid}")
        print(f"    - Verified Clean: {first_vuln.patch.verified_clean}")

    print_banner("3. STRUCTURED JSON OUTPUT (FIRST VULNERABILITY PREVIEW)")
    clean_json_preview = {
        "scan_id": response.scan_id,
        "execution_time_seconds": latency,
        "llm_provider_used": response.llm_provider_used,
        "vuln_id": first_vuln.vuln_id,
        "title": first_vuln.title,
        "cwe_id": first_vuln.cwe_id,
        "severity": first_vuln.severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "taint_path_length": len(taint_nodes),
        "unified_diff_preview": diff_patch.splitlines()[:8] if diff_patch else []
    }
    print(json.dumps(clean_json_preview, indent=2))

    return response


async def main():
    try:
        await test_environment_and_config()
        await test_end_to_end_pipeline()
        print_banner("SMOKE TEST PASSED: ZeroGuard Backend is fully operational!")
        return 0
    except Exception as e:
        print(f"\n[!] Smoke test encountered failure: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
