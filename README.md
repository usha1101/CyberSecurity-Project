# ZeroGuard 🛡️ — AI-Powered Zero-Day & Logic Flaw Detection Engine
> **Hack Fest 2026 — Track: Secure Sphere**  
> *Beyond static linters: Multi-step zero-day logic flaw reasoning, visual taint graphs, verified self-healing diff patches, and dynamic CVSS v3.1 scoring.*

---

## 🌟 Overview & Problem Statement
Traditional static security linters (like basic Bandit, Flake8, or rule-based Semgrep) operate strictly on regex or fixed AST pattern signatures. While effective at finding hardcoded credentials or simple banned function calls, they are **blind to subtle multi-step zero-day logic flaws**:
- **Time-of-Check to Time-of-Use (TOCTOU) Race Conditions:** Where business invariants (e.g., wallet balance, file locks, quota checks) are verified without atomic locking, enabling concurrent double-spending.
- **Mass-Assignment / Object State Pollution:** Where user-controlled dictionaries tamper with privileged internal attributes (`is_admin`, `role`).
- **Multi-Step Taint Propagation:** Where untrusted inputs travel through layers of variable mutations and business logic before hitting dangerous execution sinks.
- **Broken State Invariants & Auth Bypasses:** Where authorization checks are decoupled from state changes.

**ZeroGuard** solves this by pairing high-speed deterministic AST parsing with deep semantic reasoning across a synchronized **Tri-Engine Pipeline**.

---

## 🚀 Free-Tier AI Model Selection
ZeroGuard supports standard, highly reliable free-tier LLM providers configured seamlessly via `.env` or overridden per-request:

| Provider | Model | Tier / Pricing | Purpose |
| :--- | :--- | :--- | :--- |
| **1. Groq Cloud** *(Primary Default)* | `llama-3.3-70b-versatile` | Free Cloud API (ultra-fast inference) | Default semantic reasoning engine |
| **2. Google Gemini** *(Alternative Cloud)* | `gemini-2.0-flash` / `gemini-1.5-flash` | Free Cloud Tier (`google-genai` SDK) | Cloud fallback with high context window |
| **3. Ollama** *(Local Fallback)* | `qwen2.5-coder:7b` | 100% Free Local API (`http://localhost:11434/v1`) | Offline air-gapped developer mode |

Switch providers instantly by updating `LLM_PROVIDER=groq|gemini|ollama` in `.env` or passing `"provider": "gemini"` in the scan request.

> **Zero-Downtime Fallback:** If cloud keys are unconfigured or local Ollama is offline, ZeroGuard automatically engages its built-in heuristic security analyzer so workflows and tests remain 100% operational.

---

## 🏗️ Architecture: Tri-Engine Pipeline

```
+-----------------------------------------------------------------------------------+
|                                 ZeroGuard Pipeline                                |
+-----------------------------------------------------------------------------------+
                                          |
                         [ Python Code Snippet / File ]
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| Engine 1: Deterministic AST Triage (Native ast module)                            |
| - Parse AST without external binaries                                             |
| - Identify dangerous sinks (eval, os.system, raw SQL, pickle.loads, setattr)      |
| - Extract untrusted sources (request.args, request.json, sys.argv, function args) |
| - Map variable flows & control structures (locks, transactions, branches)         |
+-----------------------------------------------------------------------------------+
                                          |
                         [ AST Security Metadata Payload ]
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| Engine 2: Zero-Day Semantic Reasoning & Taint Mapping                             |
| - AppSec Researcher System Prompt (Zero-day invariants, TOCTOU, Mass Assignment)  |
| - Non-blocking async inference via Groq / Gemini / Ollama                         |
| - Constructs visual node-by-node taint graph:                                     |
|   SOURCE -> PROPAGATION -> SANITIZATION_MISSING -> SINK                           |
| - Produces attack vector exploit narratives & remediation strategies              |
+-----------------------------------------------------------------------------------+
                                          |
                         [ Raw Vulnerabilities & Taint Nodes ]
                                          |
                                          v
+-----------------------------------------------------------------------------------+
| Engine 3: Self-Healing Verification & CVSS v3.1 Scoring                           |
| - Computes standard CVSS v3.1 Vector String and Decimal Base Score (0.0 - 10.0)    |
| - Synthesizes clean standard Unified Diff patches (--- a/ +++ b/)                 |
| - In-Memory AST Sanity Check: Verifies patch syntax & neutralizes sinks           |
| - Flags patch as verified_clean: true                                             |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
                                 [ ScanResponse JSON ]
```

---

## 📁 Project Directory Structure
```
cybersecurity/
├── .env.example              # Environment variables template
├── .gitignore                # Production gitignore
├── requirements.txt          # Python dependencies (FastAPI, Uvicorn, Groq, Gemini, Pydantic)
├── run.py                    # Server launch script
├── README.md                 # Technical documentation
│
├── app/
│   ├── main.py               # FastAPI application setup, CORS, lifespan hooks
│   ├── config.py             # Pydantic v2 BaseSettings configuration
│   ├── api/
│   │   ├── routes.py         # REST API endpoints (/scan, /verify-patch, /apply-diff, /providers, /health)
│   ├── engines/
│   │   ├── engine1_ast.py    # Engine 1: AST Parser, Sink Triage & Taint Pre-filter
│   │   ├── engine2_semantic.py # Engine 2: LLM Semantic Reasoning & Taint Flow Mapping
│   │   └── engine3_healing.py# Engine 3: CVSS v3.1 Calculator & In-Memory Patch Verifier
│   ├── models/
│   │   ├── request.py        # ScanRequest, PatchVerificationRequest, DiffApplyRequest
│   │   ├── response.py       # ScanResponse, VulnerabilityDetail, CVSSMetrics, TaintNode
│   │   └── ast_meta.py       # ASTAnalysisResult, DetectedSink, DetectedSource
│   ├── services/
│   │   ├── llm_provider.py   # Multi-provider client (Groq, Gemini, Ollama, Heuristic)
│   │   └── orchestrator.py   # Tri-Engine Pipeline Orchestrator
│   └── utils/
│       ├── cvss.py           # Pure-Python official CVSS v3.1 specification equations
│       └── patcher.py        # In-memory unified diff generator, applier & AST validator
│
├── samples/                  # Vulnerable sample targets for live evaluation
│   ├── toctou_race.py        # Race condition & broken state invariant
│   ├── unsafe_deserialization.py # Remote code execution via pickle.loads (CWE-502)
│   ├── sql_injection_logic.py# SQL injection & auth bypass (CWE-89)
│   └── mass_assignment.py    # Object state pollution & privilege escalation (CWE-915)
│
└── tests/                    # Complete automated test suite
    ├── test_api.py           # Endpoint integration tests
    ├── test_cvss.py          # CVSS v3.1 spec compliance unit tests
    ├── test_engine1_ast.py   # AST triage detection tests
    └── test_patcher.py       # Unified diff generation & verification tests
```

---

## ⚡ Quickstart

### 1. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Add your free API key for Groq or Gemini (optional; engine runs out of the box with built-in heuristic analyzer):
```env
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_your_groq_api_key_here
```

### 2. Run the ASGI Server
```bash
python run.py
```
The server will start on `http://localhost:8000`.  
- **Interactive Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc Documentation:** [http://localhost:8000/redoc](http://localhost:8000/redoc)

### 3. Run Automated Tests
```bash
python -m pytest -p no:cacheprovider -v
```

---

## 📡 API Reference

### 1. `POST /api/v1/scan`
Executes the full Tri-Engine pipeline on source code.

**Request:**
```json
{
  "code": "def withdraw(acc, amt):\n    if acc.balance >= amt:\n        time.sleep(0.01)\n        acc.balance -= amt",
  "filename": "wallet.py",
  "provider": "groq",
  "include_diff_patches": true
}
```

**Response:**
```json
{
  "scan_id": "zg-c84a51e628e9",
  "timestamp": "2026-11-09T22:00:00Z",
  "target_name": "wallet.py",
  "llm_provider_used": "groq",
  "model_used": "llama-3.3-70b-versatile",
  "execution_time_seconds": 0.45,
  "ast_triage": {
    "parsed_successfully": true,
    "total_lines": 4,
    "dangerous_patterns_count": 0,
    "triage_summary": "AST Triage parsed 4 lines cleanly..."
  },
  "vulnerabilities": [
    {
      "vuln_id": "ZG-2026-TOCTOU-001",
      "title": "Time-of-Check to Time-of-Use (TOCTOU) Concurrency Race Condition",
      "cwe_id": "CWE-367",
      "category": "RACE_CONDITION_TOCTOU",
      "description": "State invariant checked without synchronization or atomic database lock...",
      "root_cause": "Missing synchronization lock across state inspection and mutation boundary.",
      "severity": "HIGH",
      "cvss": {
        "vector_string": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "base_score": 7.5,
        "severity_rating": "HIGH",
        "exploitability_score": 1.6,
        "impact_score": 3.6
      },
      "taint_graph": [
        {
          "step_index": 1,
          "node_type": "SOURCE",
          "line_number": 2,
          "code_snippet": "if acc.balance >= amt:",
          "variable_name": "balance",
          "explanation": "State condition verified without holding an exclusive mutex."
        },
        {
          "step_index": 2,
          "node_type": "PROPAGATION",
          "line_number": 3,
          "code_snippet": "time.sleep(0.01)",
          "variable_name": "execution_thread",
          "explanation": "Control flow progresses into window where balance may be invalidated concurrently."
        },
        {
          "step_index": 3,
          "node_type": "SANITIZATION_MISSING",
          "line_number": 2,
          "code_snippet": "# Missing atomic lock / transaction block",
          "variable_name": "lock",
          "explanation": "No thread lock or database transaction wraps this critical section."
        },
        {
          "step_index": 4,
          "node_type": "SINK",
          "line_number": 4,
          "code_snippet": "acc.balance -= amt",
          "variable_name": "balance",
          "explanation": "Irreversible state mutation executed on stale, invalidated precondition."
        }
      ],
      "attack_vector_narrative": "An attacker launches concurrent asynchronous threads sending simultaneous withdrawal requests...",
      "recommended_fix_strategy": "Enforce atomic state transitions using threading.Lock() or database SELECT FOR UPDATE.",
      "patch": {
        "patch_strategy": "Thread synchronization lock to prevent TOCTOU race conditions",
        "unified_diff": "--- a/wallet.py\n+++ b/wallet.py\n@@ ...",
        "verified_clean": true,
        "ast_syntax_valid": true,
        "residual_sinks_found": 0,
        "verification_notes": [
          "AST Syntax Check: PASSED. Generated code is valid Python.",
          "Zero residual dangerous sinks identified in patched code."
        ]
      }
    }
  ],
  "total_vulnerabilities": 1,
  "highest_severity": "HIGH",
  "overall_risk_score": 7.5,
  "status": "COMPLETED"
}
```

---

### 2. `POST /api/v1/verify-patch`
Validates suggested patches in-memory without touching disk.

**Request:**
```json
{
  "original_code": "def run(cmd):\n    eval(cmd)",
  "patched_code": "def run(cmd):\n    return int(cmd)",
  "expected_sink_type": "CODE_EXEC"
}
```

**Response:**
```json
{
  "verified_clean": true,
  "ast_syntax_valid": true,
  "unified_diff_applied": false,
  "patched_code": "def run(cmd):\n    return int(cmd)",
  "residual_sinks_found": 0,
  "notes": [
    "AST Syntax Check: PASSED. Generated code is valid Python.",
    "Target sink type 'CODE_EXEC' successfully neutralized."
  ]
}
```

---

### 3. `GET /api/v1/providers`
Returns real-time status of configured free-tier LLMs:
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

## 🎯 Hack Fest 2026 (Track: Secure Sphere) Highlights
1. **Beyond Signatures:** Identifies subtle logic bugs (TOCTOU, double spend, broken invariants) that Bandit and Semgrep cannot detect.
2. **Visual Taint Graph Tracing:** Node-by-node graph flow with explicit classifications (`SOURCE` -> `PROPAGATION` -> `SANITIZATION_MISSING` -> `SINK`) ready for React/Vite graph visualization.
3. **Verified Self-Healing:** Generates standardized unified diffs (`--- a/ +++ b/`) that are tested in-memory with Python AST parsing and sink neutralization checks.
4. **Standard CVSS v3.1 Scoring:** Full mathematical implementation of FIRST.org's CVSS v3.1 vector calculation equations.
5. **Production-Ready FastAPI:** Asyncio non-blocking architecture, Pydantic v2 typing, CORS configured for modern frontends.

