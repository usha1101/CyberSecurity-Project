import ast
import difflib
import re
from typing import Tuple, List, Optional
from app.models.response import PatchVerificationResponse


def generate_unified_diff(
    original_code: str,
    patched_code: str,
    filename: str = "target.py"
) -> str:
    """Generates standard unified diff representation between original and patched code."""
    orig_lines = original_code.splitlines()
    patch_lines = patched_code.splitlines()

    diff_lines = list(
        difflib.unified_diff(
            orig_lines,
            patch_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm=""
        )
    )
    return "\n".join(diff_lines) if diff_lines else ""


def apply_unified_diff(original_code: str, unified_diff: str) -> Tuple[bool, str, List[str]]:
    """Applies unified diff patch to original code in-memory."""
    notes = []
    if not unified_diff.strip():
        return True, original_code, ["Empty diff; code unchanged."]

    orig_lines = original_code.splitlines()
    diff_lines = unified_diff.splitlines()

    hunk_regex = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
    applied_lines: List[str] = []
    orig_idx = 0
    in_hunk = False

    try:
        hunk_start_orig = 0
        hunk_orig_count = 0

        for line in diff_lines:
            if line.startswith("---") or line.startswith("+++"):
                continue

            hunk_match = hunk_regex.match(line)
            if hunk_match:
                in_hunk = True
                hunk_start_orig = int(hunk_match.group(1)) - 1
                hunk_orig_count = int(hunk_match.group(2) or 1)

                # Append unmodified lines up to hunk start
                while orig_idx < hunk_start_orig and orig_idx < len(orig_lines):
                    applied_lines.append(orig_lines[orig_idx])
                    orig_idx += 1
                continue

            if in_hunk:
                if line.startswith("+"):
                    applied_lines.append(line[1:])
                elif line.startswith("-"):
                    # Skipped from original
                    orig_idx += 1
                elif line.startswith(" "):
                    if orig_idx < len(orig_lines):
                        applied_lines.append(orig_lines[orig_idx])
                        orig_idx += 1
                    else:
                        applied_lines.append(line[1:])
                elif line.startswith("\\"):
                    # "\ No newline at end of file"
                    continue

        # Append remaining original lines
        while orig_idx < len(orig_lines):
            applied_lines.append(orig_lines[orig_idx])
            orig_idx += 1

        result_code = "\n".join(applied_lines)
        if original_code.endswith("\n") and not result_code.endswith("\n"):
            result_code += "\n"

        notes.append("Unified diff applied cleanly.")
        return True, result_code, notes

    except Exception as e:
        notes.append(f"Diff application error: {str(e)}")
        return False, original_code, notes


def verify_patch_safety(
    original_code: str,
    patched_code: Optional[str] = None,
    unified_diff: Optional[str] = None,
    expected_sink_type: Optional[str] = None
) -> PatchVerificationResponse:
    """Verifies that the patch parses cleanly with Python AST and resolves dangerous sinks."""
    notes: List[str] = []
    diff_applied = False

    final_patched_code = patched_code or ""
    if unified_diff and not final_patched_code:
        success, applied, diff_notes = apply_unified_diff(original_code, unified_diff)
        notes.extend(diff_notes)
        if success:
            final_patched_code = applied
            diff_applied = True
        else:
            return PatchVerificationResponse(
                verified_clean=False,
                ast_syntax_valid=False,
                unified_diff_applied=False,
                patched_code=original_code,
                residual_sinks_found=-1,
                notes=notes
            )
    else:
        diff_applied = bool(unified_diff)

    if not final_patched_code.strip():
        return PatchVerificationResponse(
            verified_clean=False,
            ast_syntax_valid=False,
            unified_diff_applied=diff_applied,
            patched_code="",
            residual_sinks_found=0,
            notes=["No patched code provided for verification."]
        )

    # 1. AST Syntax Check
    try:
        parsed_ast = ast.parse(final_patched_code)
        ast_syntax_valid = True
        notes.append("AST Syntax Check: PASSED. Generated code is valid Python.")
    except SyntaxError as syn_err:
        notes.append(f"AST Syntax Check: FAILED. SyntaxError at line {syn_err.lineno}: {syn_err.msg}")
        return PatchVerificationResponse(
            verified_clean=False,
            ast_syntax_valid=False,
            unified_diff_applied=diff_applied,
            patched_code=final_patched_code,
            residual_sinks_found=-1,
            notes=notes
        )

    # 2. Residual dangerous sink triage on the patched code
    from app.engines.engine1_ast import ASTTriageEngine
    ast_engine = ASTTriageEngine()
    triage_result = ast_engine.analyze(final_patched_code)

    residual_sinks = len(triage_result.sinks)
    if residual_sinks == 0:
        notes.append("Zero residual dangerous sinks identified in patched code.")
        verified_clean = True
    else:
        # Check if the specific expected sink type was eliminated
        if expected_sink_type:
            matching_sinks = [s for s in triage_result.sinks if s.sink_type == expected_sink_type]
            if not matching_sinks:
                notes.append(f"Target sink type '{expected_sink_type}' successfully neutralized.")
                verified_clean = True
            else:
                notes.append(f"Target sink '{expected_sink_type}' still present ({len(matching_sinks)} instance(s)).")
                verified_clean = False
        else:
            # Check if original had more sinks than patched
            orig_triage = ast_engine.analyze(original_code)
            if residual_sinks < len(orig_triage.sinks):
                notes.append(f"Residual sinks reduced from {len(orig_triage.sinks)} to {residual_sinks}.")
                verified_clean = True
            else:
                notes.append(f"Patch retains {residual_sinks} dangerous sinks.")
                verified_clean = False

    return PatchVerificationResponse(
        verified_clean=verified_clean,
        ast_syntax_valid=ast_syntax_valid,
        unified_diff_applied=diff_applied,
        patched_code=final_patched_code,
        residual_sinks_found=residual_sinks,
        notes=notes
    )
