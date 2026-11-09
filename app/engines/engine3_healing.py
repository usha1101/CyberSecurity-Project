import logging
from typing import Dict, Any, List, Optional
from app.models.response import VulnerabilityDetail, PatchDetail, CVSSMetrics, TaintNode
from app.utils.cvss import calculate_cvss_v31
from app.utils.patcher import generate_unified_diff, verify_patch_safety

logger = logging.getLogger("zeroguard.engine3")


class HealingAndScoringEngine:
    """Engine 3: CVSS v3.1 dynamic scoring, unified diff patch generation, and in-memory AST verification."""

    def process_vulnerabilities(
        self,
        raw_vulns_data: List[Dict[str, Any]],
        original_code: str,
        filename: str = "target.py",
        include_diff_patches: bool = True
    ) -> List[VulnerabilityDetail]:
        """Enriches raw vulnerability findings with CVSS v3.1 calculations and verified diff patches."""
        processed_vulns: List[VulnerabilityDetail] = []

        for item in raw_vulns_data:
            # 1. Compute dynamic CVSS v3.1 metrics
            cvss_metrics = self._compute_cvss(item)

            # 2. Build structured Taint Graph nodes
            taint_nodes = self._build_taint_nodes(item.get("taint_graph", []))

            # 3. Generate & Verify Self-Healing Patch
            patch_detail = None
            if include_diff_patches:
                patch_detail = self._generate_and_verify_patch(
                    item=item,
                    original_code=original_code,
                    filename=filename
                )

            vuln = VulnerabilityDetail(
                vuln_id=item.get("vuln_id", "ZG-2026-UNKNOWN"),
                title=item.get("title", "Detected Security Vulnerability"),
                cwe_id=item.get("cwe_id", "CWE-699"),
                category=item.get("category", "ZERO_DAY_LOGIC"),
                description=item.get("description", "Vulnerability detected by semantic reasoning engine."),
                root_cause=item.get("root_cause", "Unvalidated control flow or state transition."),
                severity=cvss_metrics.severity_rating if cvss_metrics.severity_rating != "NONE" else "HIGH",
                cvss=cvss_metrics,
                cvss_score=cvss_metrics.base_score,
                cvss_vector=cvss_metrics.vector_string,
                taint_graph=taint_nodes,
                taint_path=taint_nodes,
                attack_vector_narrative=item.get("attack_vector_narrative", "Adversary exploits unverified preconditions."),
                recommended_fix_strategy=item.get("recommended_fix_strategy", "Apply defensive validation and sanitization."),
                patch=patch_detail,
                unified_diff=patch_detail.unified_diff if patch_detail else "",
            )
            processed_vulns.append(vuln)

        return processed_vulns

    def _compute_cvss(self, item: Dict[str, Any]) -> CVSSMetrics:
        """Calculates CVSS 3.1 base score from suggested vector metrics or severity category."""
        sugg = item.get("cvss_vector_suggestion", {})
        if not sugg or not isinstance(sugg, dict):
            # Fall back to sensible defaults based on severity
            sev = item.get("severity", "HIGH").upper()
            if sev == "CRITICAL":
                sugg = {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"}
            elif sev == "HIGH":
                sugg = {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "N"}
            elif sev == "MEDIUM":
                sugg = {"av": "N", "ac": "H", "pr": "L", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "N"}
            else:
                sugg = {"av": "L", "ac": "H", "pr": "H", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"}

        return calculate_cvss_v31(
            av=sugg.get("av", "N"),
            ac=sugg.get("ac", "L"),
            pr=sugg.get("pr", "N"),
            ui=sugg.get("ui", "N"),
            s=sugg.get("s", "U"),
            c=sugg.get("c", "H"),
            i=sugg.get("i", "H"),
            a=sugg.get("a", "H"),
        )

    def _build_taint_nodes(self, raw_nodes: List[Dict[str, Any]]) -> List[TaintNode]:
        """Normalizes and validates taint graph node objects."""
        nodes: List[TaintNode] = []
        for idx, n in enumerate(raw_nodes, 1):
            ntype = n.get("node_type", "PROPAGATION").upper()
            if ntype not in ["SOURCE", "PROPAGATION", "SANITIZATION_MISSING", "SINK"]:
                ntype = "PROPAGATION"

            nodes.append(
                TaintNode(
                    step_index=n.get("step_index", idx),
                    node_type=ntype,
                    line_number=n.get("line_number", 1),
                    code_snippet=n.get("code_snippet", "<snippet>"),
                    variable_name=n.get("variable_name"),
                    explanation=n.get("explanation", ""),
                )
            )
        return nodes

    def _generate_and_verify_patch(
        self,
        item: Dict[str, Any],
        original_code: str,
        filename: str
    ) -> Optional[PatchDetail]:
        """Synthesizes unified diff patch and performs in-memory AST verification."""
        suggested_code = item.get("suggested_patch_code", "")
        if not suggested_code or not suggested_code.strip():
            return None

        # Clean markdown code blocks if the LLM provided them in suggested_patch_code
        if "```" in suggested_code:
            lines = suggested_code.splitlines()
            code_lines = []
            in_code = False
            for line in lines:
                if line.strip().startswith("```"):
                    in_code = not in_code
                    continue
                if in_code or not any(l.strip().startswith("```") for l in lines):
                    code_lines.append(line)
            suggested_code = "\n".join(code_lines) if code_lines else suggested_code

        # Generate Unified Diff
        diff_str = generate_unified_diff(
            original_code=original_code,
            patched_code=suggested_code,
            filename=filename
        )

        # Run in-memory AST syntax and sink neutralization verification
        expected_sink = None
        category = item.get("category", "")
        if "SQL" in category or "INJECTION" in category:
            expected_sink = "SQLI"
        elif "DESERIALIZATION" in category:
            expected_sink = "DESERIALIZATION"

        verification = verify_patch_safety(
            original_code=original_code,
            patched_code=suggested_code,
            unified_diff=diff_str,
            expected_sink_type=expected_sink
        )

        strategy = item.get("recommended_fix_strategy", "Defensive refactoring and parameter validation.")

        return PatchDetail(
            patch_strategy=strategy,
            unified_diff=diff_str,
            patched_code=suggested_code,
            verified_clean=verification.verified_clean,
            ast_syntax_valid=verification.ast_syntax_valid,
            residual_sinks_found=max(0, verification.residual_sinks_found),
            verification_notes=verification.notes,
        )


healing_engine = HealingAndScoringEngine()

