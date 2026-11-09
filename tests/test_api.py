import pytest
import asyncio
from app.main import root
from app.api.routes import (
    health_check,
    list_providers,
    scan_source_code,
    verify_patch,
    apply_diff_endpoint,
)
from app.models.request import ScanRequest, PatchVerificationRequest, DiffApplyRequest


def run_async(coro):
    return asyncio.run(coro)


def test_root_endpoint():
    res = run_async(root())
    assert res["engine"] == "ZeroGuard AI-Powered Zero-Day Engine"
    assert res["competition"] == "Hack Fest 2026"
    assert res["track"] == "Secure Sphere"


def test_health_endpoint():
    res = run_async(health_check())
    assert res.status == "healthy"
    assert res.service == "ZeroGuard Detection Engine"
    assert res.version == "1.0.0-hackfest2026"


def test_providers_endpoint():
    res = run_async(list_providers())
    assert res.active_provider in ["groq", "gemini", "ollama"]
    assert "groq" in res.available_providers
    assert "gemini" in res.available_providers
    assert "ollama" in res.available_providers


def test_scan_endpoint_clean_code():
    code = """
def add(a: int, b: int) -> int:
    return a + b
"""
    req = ScanRequest(code=code, filename="safe_math.py")
    res = run_async(scan_source_code(req))
    assert res.scan_id.startswith("zg-")
    assert res.ast_triage.parsed_successfully is True
    assert res.status in ["CLEAN", "COMPLETED"]
    assert res.total_vulnerabilities == 0


def test_scan_endpoint_vulnerable_sqli():
    code = """
def get_user(cursor, user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
"""
    req = ScanRequest(code=code, filename="sqli_demo.py")
    res = run_async(scan_source_code(req))
    assert res.ast_triage.parsed_successfully is True
    assert len(res.vulnerabilities) >= 1

    vuln = res.vulnerabilities[0]
    assert vuln.cwe_id in ["CWE-89", "CWE-699"]
    assert vuln.cvss.base_score >= 7.0
    assert len(vuln.taint_graph) > 0
    assert vuln.patch is not None
    assert vuln.patch.ast_syntax_valid is True


def test_scan_endpoint_toctou_race():
    code = """
import time
balance = 100
def withdraw(amount):
    global balance
    if balance >= amount:
        time.sleep(0.01)
        balance -= amount
"""
    req = ScanRequest(code=code, filename="race_demo.py")
    res = run_async(scan_source_code(req))
    assert len(res.vulnerabilities) >= 1
    race_vulns = [v for v in res.vulnerabilities if v.category == "RACE_CONDITION_TOCTOU"]
    assert len(race_vulns) == 1
    assert race_vulns[0].cwe_id == "CWE-367"


def test_verify_patch_endpoint():
    req = PatchVerificationRequest(
        original_code="eval(user_input)\n",
        patched_code="int(user_input)\n",
        expected_sink_type="CODE_EXEC"
    )
    res = run_async(verify_patch(req))
    assert res.ast_syntax_valid is True
    assert res.verified_clean is True


def test_apply_diff_endpoint():
    req = DiffApplyRequest(
        original_code="val = 1\n",
        unified_diff="--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-val = 1\n+val = 2\n"
    )
    res = run_async(apply_diff_endpoint(req))
    assert res["success"] is True
    assert "val = 2" in res["patched_code"]
