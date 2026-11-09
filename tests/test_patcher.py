import pytest
from app.utils.patcher import generate_unified_diff, apply_unified_diff, verify_patch_safety


def test_generate_and_apply_unified_diff():
    original = "def add(a, b):\n    return a - b\n"
    patched = "def add(a, b):\n    return a + b\n"

    diff = generate_unified_diff(original, patched, filename="math_ops.py")
    assert "--- a/math_ops.py" in diff
    assert "+++ b/math_ops.py" in diff
    assert "-    return a - b" in diff
    assert "+    return a + b" in diff

    success, applied_code, notes = apply_unified_diff(original, diff)
    assert success is True
    assert applied_code.strip() == patched.strip()


def test_verify_patch_syntax_error():
    original = "x = 10\n"
    invalid_patch = "x = (\n"

    res = verify_patch_safety(original, patched_code=invalid_patch)
    assert res.ast_syntax_valid is False
    assert res.verified_clean is False
    assert any("SyntaxError" in note for note in res.notes)


def test_verify_patch_cleans_dangerous_sink():
    original = """
def run_command(cmd):
    eval(cmd)
"""
    safe_patch = """
def run_command(cmd):
    # Safe refactored handler
    return str(cmd)
"""
    res = verify_patch_safety(original, patched_code=safe_patch, expected_sink_type="CODE_EXEC")
    assert res.ast_syntax_valid is True
    assert res.verified_clean is True
    assert res.residual_sinks_found == 0

