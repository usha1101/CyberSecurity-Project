# ZeroGuard — Frontend Architecture & Backend Integration Handoff

> **Platform:** ZeroGuard AI-Powered Zero-Day & Logic Flaw Detection Engine
> **Tagline:** Secure Your Code. Detect Vulnerabilities. Verify Your Fixes.
> **Status:** Production-Ready Frontend Integration
> **Audience:** AppSec Engineers, Full-Stack Developers, Hack Fest 2026 Judges

---

## 1. Executive Summary

The **ZeroGuard Frontend** is an interactive code security console engineered for **Hack Fest 2026 (Track: Secure Sphere)**. It pairs directly with the ZeroGuard FastAPI backend to provide:
1. Python source code vulnerability scanning (SQLi, TOCTOU race conditions, mass assignment, insecure deserialization).
2. Deterministic AST triage reporting.
3. Visual step-by-step taint propagation graphs.
4. CVSS v3.1 dynamic scoring and vector breakdown.
5. In-memory AST patch verification.
6. Unified git diff application.
7. Real-time multi-provider LLM status telemetry (Groq, Gemini, Ollama, Heuristic).

---

## 2. Connected Backend Endpoints

The frontend client (`api.js`) directly binds to all 5 backend routes:

| Route Path | Method | Backend Service | Response Object |
| :--- | :---: | :--- | :--- |
| `/api/v1/scan` | `POST` | `orchestrator.run_pipeline` | `ScanResponse` |
| `/api/v1/verify-patch` | `POST` | `verify_patch_safety` | `PatchVerificationResponse` |
| `/api/v1/apply-diff` | `POST` | `apply_unified_diff` | `{ success, patched_code, notes }` |
| `/api/v1/providers` | `GET` | `llm_service.get_provider_statuses` | `ProviderInfo` |
| `/api/v1/health` | `GET` | `health_check` | `HealthResponse` |

---

## 3. Frontend Architecture

```
frontend/
├── index.html        # Semantic HTML5 SPA shell, branding, and all 6 active views
├── styles.css        # Master design system (60% #0C0C0C, 30% #FFFFFF, 10% #FF6F32)
├── config.js         # Runtime configuration (API_BASE_URL: http://localhost:8000/api/v1)
├── api.js            # ZeroGuardAPI client module wrapping fetch calls with timeouts and error handling
├── app.js            # SPA controller, real-time event handlers, sample loaders, and DOM rendering
├── server.js         # Zero-dependency local Node.js static web server (port 3000)
├── package.json      # Frontend package manifest
├── API_CONTRACT.md   # Exact RESTful API contract specifications
└── README.md         # Quick start guide and feature documentation
```
