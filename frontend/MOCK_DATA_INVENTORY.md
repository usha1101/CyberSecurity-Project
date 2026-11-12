# ZeroGuard — Data Flow & Mock Data Status

> **Platform:** ZeroGuard AI-Powered Zero-Day & Logic Flaw Detection Engine
> **Status:** All Mock Telemetry Data Removed & Replaced by Live Backend Integration

---

## Data Sourcing Verification

| Previous Mock Category | Replaced By Live Backend Feature |
| :--- | :--- |
| **Network IP Alerts & Volumetric Telemetry** | Completely removed. Replaced by real Python source code vulnerability audits from `POST /api/v1/scan`. |
| **Synthetic Attack Simulator** | Completely removed. Replaced by Python Code Scanner auditing real zero-day logic flaws. |
| **Simulated Diagnostic Logs** | Replaced by live backend probe `GET /api/v1/health` and `GET /api/v1/providers`. |
| **Hardcoded Evaluation Numbers** | Removed. Real CVSS v3.1 base scores and vectors calculated dynamically by Engine 3 on scanned code. |
| **Mock Patch Generator** | Replaced by backend Engine 3 unified diff synthesizer and AST verifier (`POST /api/v1/verify-patch`, `POST /api/v1/apply-diff`). |
