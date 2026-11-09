import time
import uuid
from datetime import datetime, timezone
import logging
from app.models.request import ScanRequest
from app.models.response import ScanResponse
from app.engines.engine1_ast import ASTTriageEngine
from app.engines.engine2_semantic import semantic_engine
from app.engines.engine3_healing import healing_engine

logger = logging.getLogger("zeroguard.orchestrator")


class TriEngineOrchestrator:
    """Coordinates Engine 1 (AST Triage), Engine 2 (Semantic Reasoning), and Engine 3 (Healing/CVSS)."""

    def __init__(self):
        self.ast_engine = ASTTriageEngine()

    async def run_pipeline(self, request: ScanRequest) -> ScanResponse:
        """Executes the full Tri-Engine audit lifecycle asynchronously."""
        start_time = time.perf_counter()
        scan_id = f"zg-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Stage 1: Engine 1 (Deterministic AST Triage)
        logger.info(f"[{scan_id}] Stage 1: Running Deterministic AST Triage...")
        ast_result = self.ast_engine.analyze(request.code)

        # Stage 2: Engine 2 (Zero-Day Semantic Reasoning & Taint Mapping)
        logger.info(f"[{scan_id}] Stage 2: Running Semantic Reasoning & Taint Extraction...")
        semantic_output = await semantic_engine.analyze(
            code=request.code,
            ast_result=ast_result,
            preferred_provider=request.provider,
        )

        raw_vulns = semantic_output.get("data", {}).get("vulnerabilities", [])
        provider_used = semantic_output.get("provider_used", "unknown")
        model_used = semantic_output.get("model_used", "unknown")

        # Stage 3: Engine 3 (Self-Healing Verification & CVSS v3.1 Scoring)
        logger.info(f"[{scan_id}] Stage 3: Running CVSS Scoring & Self-Healing Verification...")
        processed_vulns = healing_engine.process_vulnerabilities(
            raw_vulns_data=raw_vulns,
            original_code=request.code,
            filename=request.filename or "target.py",
            include_diff_patches=request.include_diff_patches,
        )

        duration = round(time.perf_counter() - start_time, 3)

        # Determine highest severity and overall risk score
        highest_sev = "NONE"
        overall_score = 0.0
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}

        for v in processed_vulns:
            if severity_rank.get(v.severity, 0) > severity_rank.get(highest_sev, 0):
                highest_sev = v.severity
            if v.cvss.base_score > overall_score:
                overall_score = v.cvss.base_score

        status = "COMPLETED"
        if len(processed_vulns) == 0:
            status = "CLEAN"

        logger.info(f"[{scan_id}] Pipeline completed in {duration}s. Detected {len(processed_vulns)} flaws.")

        return ScanResponse(
            scan_id=scan_id,
            timestamp=timestamp,
            target_name=request.filename or "target.py",
            llm_provider_used=provider_used,
            model_used=model_used,
            execution_time_seconds=duration,
            ast_triage=ast_result,
            vulnerabilities=processed_vulns,
            total_vulnerabilities=len(processed_vulns),
            highest_severity=highest_sev,
            overall_risk_score=round(overall_score, 1),
            status=status,
        )


orchestrator = TriEngineOrchestrator()

