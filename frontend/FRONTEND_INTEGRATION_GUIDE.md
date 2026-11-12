# ZeroGuard — Frontend Integration Guide

> **Platform:** ZeroGuard AI-Powered Zero-Day & Logic Flaw Detection Engine
> **Status:** Integrated with Backend

---

## 1. Architecture: Direct Backend API Integration

The ZeroGuard frontend communicates with the FastAPI backend using a centralized API client layer in `frontend/api.js`.

### Configuration (`frontend/config.js`)
```javascript
window.ZEROGUARD_CONFIG = {
  API_BASE_URL: 'http://localhost:8000/api/v1',
  REQUEST_TIMEOUT_MS: 35000,
  APP_NAME: 'ZeroGuard',
  TAGLINE: 'Secure Your Code. Detect Vulnerabilities. Verify Your Fixes.'
};
```

---

## 2. API Method Reference

### `ZeroGuardAPI.getHealth()`
* Probes backend health at `GET /api/v1/health`.
* Returns engine status, service name, version, active provider, and LLM readiness.

### `ZeroGuardAPI.getProviders()`
* Queries configured AI models at `GET /api/v1/providers`.
* Returns statuses for Groq Cloud (`llama-3.3-70b-versatile`), Google Gemini (`gemini-2.0-flash`), and Ollama Local (`qwen2.5-coder:7b`).

### `ZeroGuardAPI.scanCode({ code, filename, provider, include_diff_patches })`
* Sends target code to `POST /api/v1/scan`.
* Triggers Engine 1 (Deterministic AST Triage), Engine 2 (Semantic Reasoning), and Engine 3 (Patch & CVSS Scoring).
* Returns `ScanResponse` with all detected vulnerabilities and AST metadata.

### `ZeroGuardAPI.verifyPatch({ original_code, patched_code, unified_diff, expected_sink_type })`
* In-memory patch verification at `POST /api/v1/verify-patch`.
* Tests syntax safety and residual sink neutralization.

### `ZeroGuardAPI.applyDiff({ original_code, unified_diff })`
* Applies unified git diff at `POST /api/v1/apply-diff`.
* Returns patched code string and hunk notes.
