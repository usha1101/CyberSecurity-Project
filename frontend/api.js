/**
 * ZeroGuard — API Service Client (api.js)
 * Connects directly to the ZeroGuard FastAPI backend endpoints:
 *   - POST /api/v1/scan
 *   - POST /api/v1/verify-patch
 *   - POST /api/v1/apply-diff
 *   - GET  /api/v1/providers
 *   - GET  /api/v1/health
 */
const ZeroGuardAPI = (function () {
  'use strict';

  function getBaseUrl() {
    return (window.ZEROGUARD_CONFIG && window.ZEROGUARD_CONFIG.API_BASE_URL)
      || 'http://localhost:8000/api/v1';
  }

  function getTimeoutMs() {
    return (window.ZEROGUARD_CONFIG && window.ZEROGUARD_CONFIG.REQUEST_TIMEOUT_MS)
      || 45000;
  }

  /**
   * Internal fetch executor with timeout and FastAPI error extraction.
   */
  async function executeFetch(url, options, headers, timeoutMs) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        headers,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      const contentType = response.headers.get('content-type') || '';
      let data = null;

      if (contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      if (!response.ok) {
        let errorMsg = `Server error (HTTP ${response.status})`;
        if (data && typeof data === 'object') {
          if (data.detail) {
            if (Array.isArray(data.detail)) {
              errorMsg = data.detail.map(d => `${d.loc ? d.loc.join('.') + ': ' : ''}${d.msg}`).join('; ');
            } else {
              errorMsg = String(data.detail);
            }
          } else if (data.message) {
            errorMsg = data.message;
          }
        } else if (typeof data === 'string' && data.length < 200) {
          errorMsg = data;
        }
        const error = new Error(errorMsg);
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        const timeoutError = new Error(`Request timed out after ${timeoutMs / 1000}s. The LLM or analysis pipeline took too long to respond.`);
        timeoutError.isTimeout = true;
        throw timeoutError;
      }
      if (err.message && (err.message.includes('Failed to fetch') || err.message.includes('NetworkError') || err.message.includes('ECONNREFUSED'))) {
        const connectionError = new Error(`Cannot connect to ZeroGuard backend at ${url}. Ensure the FastAPI server is running with 'python run.py'.`);
        connectionError.isConnectionFailure = true;
        throw connectionError;
      }
      throw err;
    }
  }

  /**
   * Generic fetch wrapper with AbortController timeout, FastAPI error extraction,
   * and automatic reverse-proxy fallback.
   */
  async function request(endpoint, options = {}) {
    const baseUrl = getBaseUrl();
    const url = `${baseUrl}${endpoint}`;
    const timeoutMs = options.timeoutMs || getTimeoutMs();

    const headers = {
      'Accept': 'application/json',
      ...options.headers
    };

    if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      options.body = JSON.stringify(options.body);
    }

    try {
      return await executeFetch(url, options, headers, timeoutMs);
    } catch (err) {
      // If direct backend connection failed and we are targeting port 8000,
      // attempt the same-origin reverse proxy (/api/v1) automatically for resilience.
      if (err.isConnectionFailure && baseUrl.includes(':8000')) {
        const proxyUrl = `/api/v1${endpoint}`;
        try {
          return await executeFetch(proxyUrl, options, headers, timeoutMs);
        } catch (proxyErr) {
          // If proxy also fails, throw original detailed connection error
          throw err;
        }
      }
      throw err;
    }
  }

  return {
    getBaseUrl,

    /**
     * Engine Health Check: GET /api/v1/health
     * Returns: { status, service, version, active_provider, llm_ready }
     */
    async getHealth() {
      return await request('/health', { method: 'GET', timeoutMs: 5000 });
    },

    /**
     * Provider Statuses: GET /api/v1/providers
     * Returns: { active_provider, available_providers: { groq, gemini, ollama } }
     */
    async getProviders() {
      return await request('/providers', { method: 'GET', timeoutMs: 5000 });
    },

    /**
     * Execute Tri-Engine Security Scan: POST /api/v1/scan
     * Payload: { code: string, filename?: string, provider?: string, include_diff_patches?: boolean }
     * Returns: ScanResponse
     */
    async scanCode({ code, filename = 'target.py', provider = null, include_diff_patches = true }) {
      if (!code || !code.trim()) {
        throw new Error('Please provide Python source code to scan.');
      }
      const payload = {
        code,
        filename: filename || 'target.py',
        include_diff_patches: Boolean(include_diff_patches)
      };
      if (provider && ['groq', 'gemini', 'ollama'].includes(provider)) {
        payload.provider = provider;
      }
      return await request('/scan', {
        method: 'POST',
        body: payload,
        timeoutMs: 45000 // LLM reasoning may take 5-15 seconds
      });
    },

    /**
     * Verify Patch Safety: POST /api/v1/verify-patch
     * Payload: { original_code, patched_code?, unified_diff?, expected_sink_type? }
     * Returns: PatchVerificationResponse { verified_clean, ast_syntax_valid, unified_diff_applied, patched_code, residual_sinks_found, notes }
     */
    async verifyPatch({ original_code, patched_code, unified_diff, expected_sink_type }) {
      if (!original_code || !original_code.trim()) {
        throw new Error('Original code is required for patch verification.');
      }
      const payload = {
        original_code,
        patched_code: patched_code || null,
        unified_diff: unified_diff || null,
        expected_sink_type: expected_sink_type || null
      };
      return await request('/verify-patch', {
        method: 'POST',
        body: payload,
        timeoutMs: 10000
      });
    },

    /**
     * Apply Unified Diff: POST /api/v1/apply-diff
     * Payload: { original_code, unified_diff }
     * Returns: { success: true, patched_code: string, notes: string[] }
     */
    async applyDiff({ original_code, unified_diff }) {
      if (!original_code || !original_code.trim()) {
        throw new Error('Original source code is required to apply diff.');
      }
      if (!unified_diff || !unified_diff.trim()) {
        throw new Error('Unified diff string is required.');
      }
      const payload = {
        original_code,
        unified_diff
      };
      return await request('/apply-diff', {
        method: 'POST',
        body: payload,
        timeoutMs: 10000
      });
    }
  };
})();
