# ZeroGuard — RESTful API Contract Specification

> **Platform:** ZeroGuard AI-Powered Zero-Day & Logic Flaw Detection Engine
> **Tagline:** Secure Your Code. Detect Vulnerabilities. Verify Your Fixes.
> **Competition:** Hack Fest 2026 — Track: Secure Sphere
> **Base URL:** `http://localhost:8000/api/v1` (with compatibility router at `/api`)

---

## 1. Overview

ZeroGuard pairs deterministic Abstract Syntax Tree (AST) parsing with deep semantic reasoning across a synchronized **Tri-Engine Pipeline** to detect zero-day logic flaws, TOCTOU race conditions, and taint propagation paths in Python code, generating verified self-healing diff patches with CVSS v3.1 scoring.

---

## 2. Core Endpoints

### 2.1 Execute Security Audit (`POST /api/v1/scan`)
- **Summary:** Submits Python source code snippet to the Tri-Engine pipeline.
- **Request Body (`ScanRequest`):**
  ```json
  {
    "code": "def withdraw(amount):\n    if balance >= amount:\n        balance -= amount",
    "filename": "target.py",
    "provider": "groq",
    "include_diff_patches": true
  }
  ```
- **Fields:**
  - `code` *(string, required)*: Target Python source code to analyze.
  - `filename` *(string, optional, default: `"target.py"`)*: Virtual or relative filename.
  - `provider` *(string, optional, enum: `["groq", "gemini", "ollama"]`)*: Per-request LLM provider override.
  - `include_diff_patches` *(boolean, default: `true`)*: Whether Engine 3 should generate and verify diff patches.
- **Response (`ScanResponse`, 200 OK):**
  ```json
  {
    "scan_id": "zg-d9e2a84b1029",
    "timestamp": "2026-11-10T06:50:00Z",
    "target_name": "target.py",
    "llm_provider_used": "groq",
    "model_used": "llama-3.3-70b-versatile",
    "execution_time_seconds": 0.45,
    "ast_triage": {
      "parsed_successfully": true,
      "total_lines": 35,
      "sinks": [],
      "sources": [],
      "triage_summary": "AST Triage parsed 35 lines cleanly."
    },
    "vulnerabilities": [
      {
        "vuln_id": "ZG-2026-001",
        "title": "Time-of-Check to Time-of-Use (TOCTOU) Race Condition",
        "cwe_id": "CWE-367",
        "category": "RACE_CONDITION_TOCTOU",
        "description": "State invariant checked without atomic lock.",
        "root_cause": "Missing synchronization lock on balance check.",
        "severity": "CRITICAL",
        "cvss": {
          "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "base_score": 9.8,
          "severity_rating": "CRITICAL"
        },
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "taint_graph": [],
        "taint_path": [],
        "attack_vector_narrative": "Concurrent requests trigger double spend.",
        "recommended_fix_strategy": "Wrap balance checks in threading.Lock().",
        "patch": {
          "patch_strategy": "atomic_lock",
          "unified_diff": "--- a/target.py\n+++ b/target.py\n...",
          "patched_code": "with account_lock:\n...",
          "verified_clean": true,
          "ast_syntax_valid": true,
          "residual_sinks_found": 0
        },
        "unified_diff": "--- a/target.py\n+++ b/target.py\n..."
      }
    ],
    "total_vulnerabilities": 1,
    "highest_severity": "CRITICAL",
    "overall_risk_score": 9.8,
    "status": "COMPLETED"
  }
  ```

---

### 2.2 In-Memory Patch & Diff Verification (`POST /api/v1/verify-patch`)
- **Summary:** Validates a suggested patch or unified diff in-memory against Python AST parser and checks for residual dangerous sinks.
- **Request Body (`PatchVerificationRequest`):**
  ```json
  {
    "original_code": "eval(user_input)\n",
    "patched_code": "int(user_input)\n",
    "unified_diff": null,
    "expected_sink_type": "CODE_EXEC"
  }
  ```
- **Response (`PatchVerificationResponse`, 200 OK):**
  ```json
  {
    "verified_clean": true,
    "ast_syntax_valid": true,
    "unified_diff_applied": false,
    "patched_code": "int(user_input)\n",
    "residual_sinks_found": 0,
    "notes": ["AST parsed cleanly", "Sink 'CODE_EXEC' neutralized successfully"]
  }
  ```

---

### 2.3 Apply Unified Diff (`POST /api/v1/apply-diff`)
- **Summary:** Applies a unified git diff patch to source code and returns the patched output.
- **Request Body (`DiffApplyRequest`):**
  ```json
  {
    "original_code": "val = 1\n",
    "unified_diff": "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-val = 1\n+val = 2\n"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "success": true,
    "patched_code": "val = 2\n",
    "notes": ["Hunk #1 applied cleanly at line 1"]
  }
  ```

---

### 2.4 List AI Model Providers (`GET /api/v1/providers`)
- **Summary:** Inspects configuration and readiness of Groq, Gemini, and Ollama providers.
- **Response (`ProviderInfo`, 200 OK):**
  ```json
  {
    "active_provider": "groq",
    "available_providers": {
      "groq": {
        "name": "Groq Cloud (Free Tier)",
        "model": "llama-3.3-70b-versatile",
        "configured": true,
        "is_primary": true
      },
      "gemini": {
        "name": "Google Gemini (Free Tier)",
        "model": "gemini-2.0-flash",
        "configured": false,
        "is_primary": false
      },
      "ollama": {
        "name": "Ollama Local Fallback",
        "model": "qwen2.5-coder:7b",
        "endpoint": "http://localhost:11434/v1",
        "configured": true,
        "is_primary": false
      }
    }
  }
  ```

---

### 2.5 Engine Health & Readiness (`GET /api/v1/health`)
- **Summary:** Returns backend engine health status and active configuration.
- **Response (`HealthResponse`, 200 OK):**
  ```json
  {
    "status": "healthy",
    "service": "ZeroGuard Detection Engine",
    "version": "1.0.0-hackfest2026",
    "active_provider": "groq",
    "llm_ready": true
  }
  ```
