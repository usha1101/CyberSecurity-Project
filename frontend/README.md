# ZeroGuard 🛡️ — Frontend Code Security Console

> **Tagline:** Secure Your Code. Detect Vulnerabilities. Verify Your Fixes.
> **Competition:** Hack Fest 2026 — Track: Secure Sphere
> **Brand Palette:** Primary Black `#0C0C0C` (60%), Pure White `#FFFFFF` (30%), Signature Orange `#FF6F32` (10%)

---

## 🌟 Overview

The **ZeroGuard Frontend** is an enterprise-grade Application Security (AppSec) and Code Vulnerability Detection Console. It pairs directly with the ZeroGuard FastAPI Tri-Engine backend (`app/`) to provide real-time AST code triage, LLM-powered zero-day semantic reasoning, visual taint flow mapping, and in-memory verified patch testing.

---

## 🚀 Connected Backend APIs

The frontend connects directly to the 5 production endpoints implemented in the ZeroGuard backend:

| Endpoint Path | HTTP Method | Frontend Functionality |
| :--- | :---: | :--- |
| **`/api/v1/scan`** | `POST` | Submits Python source code snippet to the Tri-Engine pipeline (AST triage + semantic reasoning + self-healing patch generation) |
| **`/api/v1/verify-patch`** | `POST` | In-memory AST patch & diff verification; tests syntax validity and residual sink neutralization |
| **`/api/v1/apply-diff`** | `POST` | In-memory unified git diff patch application to Python source code |
| **`/api/v1/providers`** | `GET` | Inspects availability and readiness of configured AI model providers (Groq, Gemini, Ollama) |
| **`/api/v1/health`** | `GET` | Real-time engine health and readiness probe |

---

## 📱 Navigation Structure & Views

| Route | View Name | Description |
| :--- | :--- | :--- |
| **`#welcome`** | **Welcome Screen** | Brand hero display with official tagline and direct entry into the console. |
| **`#login`** | **Analyst Login** | High-contrast login card for Security Analysts, AppSec Engineers, and Admins. |
| **`#dashboard`** | **Dashboard** | Operational summary showing real-time backend health, active AI provider, session scan counters, and latest audit summary. |
| **`#scanner`** | **Code Scanner** | Monospace Python code editor with line numbers, quick-load sample presets (TOCTOU race, SQLi, Mass Assignment, Deserialization, Clean Code), provider selector, and scan trigger. |
| **`#results`** | **Scan Results** | Detailed breakdown of detected flaws: AST triage summary, CWE IDs, severity badges, dynamic CVSS v3.1 base score & vector, visual taint graph steps, and verified diff patch viewer. |
| **`#verify-patch`** | **Patch Verification** | Interactive form to test Python patches against the backend AST parser for residual sinks and syntax correctness. |
| **`#apply-diff`** | **Apply Diff** | Tool to test-apply unified diff patches in memory and inspect resulting patched code. |
| **`#system-status`**| **System & Providers**| Live engine health probe, active LLM provider display, and multi-provider readiness grid. |

---

## 🎨 Visual Identity & Brand System

* **Primary Black (`#0C0C0C`):** Base canvas, dark code editor panels, and sidebars.
* **Pure White (`#FFFFFF`):** High-contrast content cards, forms, and input fields.
* **Signature Orange (`#FF6F32`):** Primary action buttons, active navigation indicators, and critical alert highlights.
* **Card Style Switcher:** Supports toggling between 30% Pure White surfaces and Dark Stealth card mode.

---

## 🛠️ How to Run

### 1. Start the ZeroGuard Backend (Port 8000)
```powershell
# From project root:
python run.py
```
Backend Swagger API documentation is available at `http://localhost:8000/docs`.

### 2. Start the Frontend Server (Port 3000)
```powershell
# From the frontend folder:
node server.js
```
Open **`http://localhost:3000`** in Google Chrome, Microsoft Edge, or Mozilla Firefox.

---

## 🔒 Security & Code Integrity

- **Zero Hardcoded Secrets:** All credentials remain on the backend server (`.env`).
- **Zero Hallucinated Data:** When no scans have been performed, the frontend shows clean, intuitive empty states. Real scan results and metrics are only displayed when received from actual backend API calls.
