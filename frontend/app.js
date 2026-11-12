/**
 * ZeroGuard — Code Security & Zero-Day Detection Platform
 * Frontend Interactive Controller & Real-Time API Integration
 * Official Brand Color Palette:
 *   #0C0C0C (60% Black) | #FFFFFF (30% White) | #FF6F32 (10% Signature Orange)
 */

(function () {
  'use strict';

  // =========================================================================
  // 1. REAL VULNERABLE & CLEAN PYTHON SAMPLES FOR INSTANT CODE TESTING
  // =========================================================================
  const PYTHON_SAMPLES = {
    toctou: {
      filename: 'toctou_race.py',
      code: `import time
from threading import Lock

# In-memory bank account store
accounts = {"alice": 1000}

def withdraw(username: str, amount: int) -> bool:
    """
    Time-of-Check to Time-of-Use (TOCTOU) Race Condition.
    State invariant (balance >= amount) is verified without an atomic lock.
    Concurrent threads can double-spend the balance.
    """
    current_balance = accounts.get(username, 0)

    # Step 1: TIME OF CHECK
    if current_balance >= amount:
        # Simulate network latency or async I/O window
        time.sleep(0.05)

        # Step 2: TIME OF USE (Unatomic state mutation)
        accounts[username] = current_balance - amount
        return True

    return False
`
    },

    sqli: {
      filename: 'sql_injection_logic.py',
      code: `def search_user_records(db_cursor, user_id: str, role_filter: str):
    """
    Vulnerable multi-step SQL Injection & Logic Flaw.
    User input concatenated directly into raw SQL string before execution.
    """
    # Untrusted tainted input from HTTP request
    sanitized_role = role_filter.strip()

    # Raw SQL query constructed with f-string (Injection Sink)
    query = f"SELECT id, username, email, is_admin FROM users WHERE id = '{user_id}' AND role = '{sanitized_role}'"

    # Dangerous DB Sink: raw query executed directly
    db_cursor.execute(query)
    return db_cursor.fetchall()
`
    },

    mass_assignment: {
      filename: 'mass_assignment.py',
      code: `class UserProfile:
    def __init__(self, username: str, email: str):
        self.username = username
        self.email = email
        self.is_admin = False
        self.role = "standard_user"

def update_user_profile(user: UserProfile, payload_dict: dict):
    """
    Mass Assignment / Object State Pollution.
    Arbitrary user-supplied payload dictionary unpacked directly via setattr
    allowing attackers to overwrite 'is_admin' or 'role' fields.
    """
    for key, value in payload_dict.items():
        # Missing whitelist validation: dangerous state mutation
        setattr(user, key, value)

    return user
`
    },

    deserialization: {
      filename: 'unsafe_deserialization.py',
      code: `import pickle
import base64

def process_session_token(token_string: str):
    """
    Unsafe Object Deserialization via Python pickle.
    Allows immediate Remote Code Execution (RCE) via custom __reduce__ exploits.
    """
    try:
        # Untrusted base64 data decoded from header/cookie
        raw_bytes = base64.b64decode(token_string)

        # Critical Sink: Unsafe object deserialization
        session_data = pickle.loads(raw_bytes)
        return session_data
    except Exception as e:
        return {"error": str(e)}
`
    },

    clean: {
      filename: 'safe_math.py',
      code: `from typing import List

def calculate_average(scores: List[float]) -> float:
    """
    Clean, safe Python logic with complete state validation.
    No dangerous sinks, race conditions, or unvalidated taint flows.
    """
    if not scores:
        return 0.0

    # Validated arithmetic without eval or dynamic code execution
    total = sum(score for score in scores if score >= 0)
    return round(total / len(scores), 2)
`
    }
  };

  // Sample Patch for Quick Verifier Testing
  const SAMPLE_PATCH = {
    original: `def execute_command(user_cmd: str):
    import os
    os.system(user_cmd)
`,
    patched: `import shlex
import subprocess

def execute_command(user_cmd: str):
    args = shlex.split(user_cmd)
    subprocess.run(args, shell=False, check=True)
`,
    diff: `--- a/runner.py
+++ b/runner.py
@@ -1,3 +1,5 @@
+import shlex
+import subprocess
 def execute_command(user_cmd: str):
-    import os
-    os.system(user_cmd)
+    args = shlex.split(user_cmd)
+    subprocess.run(args, shell=False, check=True)
`,
    sinkType: 'CMD_EXEC'
  };

  // Sample Diff for Quick Apply Diff Testing
  const SAMPLE_DIFF = {
    original: `def withdraw(balance, amount):
    if balance >= amount:
        balance -= amount
    return balance
`,
    diff: `--- a/wallet.py
+++ b/wallet.py
@@ -1,4 +1,5 @@
 def withdraw(balance, amount):
-    if balance >= amount:
-        balance -= amount
+    with account_lock:
+        if balance >= amount:
+            balance -= amount
     return balance
`
  };

  // =========================================================================
  // 2. SESSION STATE
  // =========================================================================
  const state = {
    user: {
      name: 'Alex Mercer',
      role: 'Security Analyst',
      initials: 'AM',
      isLoggedIn: false
    },
    scansCount: 0,
    totalFlawsDetected: 0,
    latestScan: null,
    cardStyle: 'white',
    backendOnline: false,
    healthData: null,
    providersData: null
  };

  // =========================================================================
  // 3. DOM ELEMENT REFERENCES
  // =========================================================================
  const el = {};

  function cacheDomElements() {
    // Screens & Layout
    el.viewWelcome = document.getElementById('view-welcome');
    el.viewLogin = document.getElementById('view-login');
    el.appShell = document.getElementById('app-shell');
    el.appSidebar = document.getElementById('app-sidebar');
    el.sidebarBackdrop = document.getElementById('sidebar-backdrop');
    el.appMainContent = document.getElementById('app-main-content');
    el.topbarActivePage = document.getElementById('topbar-active-page');
    el.backendStatusPill = document.getElementById('backend-status-pill');
    el.backendStatusText = document.getElementById('backend-status-text');
    el.btnToggleCardStyle = document.getElementById('btn-toggle-card-style');
    el.toggleCardLabel = document.getElementById('toggle-card-label');
    el.toastContainer = document.getElementById('toast-container');

    // User Profile
    el.userAvatar = document.getElementById('user-avatar');
    el.userDisplayName = document.getElementById('user-display-name');
    el.userDisplayRole = document.getElementById('user-display-role');
    el.topbarUserAvatar = document.getElementById('topbar-user-avatar');
    el.dashboardUserName = document.getElementById('dashboard-user-name');
    el.dynUserNames = document.querySelectorAll('.dyn-user-name');
    el.btnLogout = document.getElementById('btn-logout');

    // Welcome & Login
    el.btnWelcomeNext = document.getElementById('btn-welcome-next');
    el.formLogin = document.getElementById('form-login');
    el.inputUsername = document.getElementById('input-username');
    el.inputPassword = document.getElementById('input-password');
    el.btnTogglePassword = document.getElementById('btn-toggle-password');
    el.iconEye = document.getElementById('icon-eye');
    el.iconEyeOff = document.getElementById('icon-eye-off');
    el.roleOptionBtns = document.querySelectorAll('.role-option-btn');

    // Mobile Navigation
    el.btnMobileMenu = document.getElementById('btn-mobile-menu');
    el.btnSidebarClose = document.getElementById('btn-sidebar-close');
    el.navItems = document.querySelectorAll('.sidebar-nav .nav-item');
    el.navFlawsBadge = document.getElementById('nav-flaws-badge');
    el.btnSidebarQuickSample = document.getElementById('btn-sidebar-quick-sample');

    // Content Views
    el.views = {
      dashboard: document.getElementById('content-dashboard'),
      scanner: document.getElementById('content-scanner'),
      results: document.getElementById('content-results'),
      'verify-patch': document.getElementById('content-verify-patch'),
      'apply-diff': document.getElementById('content-apply-diff'),
      'system-status': document.getElementById('content-system-status')
    };

    // Dashboard Elements
    el.dashEngineStatus = document.getElementById('dash-engine-status');
    el.dashEngineDetail = document.getElementById('dash-engine-detail');
    el.dashActiveProvider = document.getElementById('dash-active-provider');
    el.dashProviderDetail = document.getElementById('dash-provider-detail');
    el.dashSessionScans = document.getElementById('dash-session-scans');
    el.dashFlawsDetected = document.getElementById('dash-flaws-detected');
    el.dashEmptyState = document.getElementById('dash-empty-state');
    el.dashLatestScanCard = document.getElementById('dash-latest-scan-card');
    el.dashLatestScanMeta = document.getElementById('dash-latest-scan-meta');
    el.dashLatestScore = document.getElementById('dash-latest-score');
    el.dashLatestSeverity = document.getElementById('dash-latest-severity');
    el.dashLatestCount = document.getElementById('dash-latest-count');
    el.dashLatestSinks = document.getElementById('dash-latest-sinks');
    el.dashLatestDuration = document.getElementById('dash-latest-duration');
    el.dashLatestSummaryText = document.getElementById('dash-latest-summary-text');
    el.btnDashboardScanNow = document.getElementById('btn-dashboard-scan-now');
    el.btnDashStartScan = document.getElementById('btn-dash-start-scan');
    el.btnDashVerifyPatch = document.getElementById('btn-dash-verify-patch');
    el.btnDashViewFullResults = document.getElementById('btn-dash-view-full-results');

    // Scanner Elements
    el.inputScanFilename = document.getElementById('input-scan-filename');
    el.textareaScanCode = document.getElementById('textarea-scan-code');
    el.selectScanProvider = document.getElementById('select-scan-provider');
    el.checkboxIncludeDiffs = document.getElementById('checkbox-include-diffs');
    el.btnExecuteScan = document.getElementById('btn-execute-scan');
    el.btnClearCode = document.getElementById('btn-clear-code');
    el.btnCopyCode = document.getElementById('btn-copy-code');
    el.presetPills = document.querySelectorAll('.btn-preset-pill');
    el.scanFeedbackBanner = document.getElementById('scan-feedback-banner');

    // Results Elements
    el.resultsEmptyState = document.getElementById('results-empty-state');
    el.resultsStage = document.getElementById('results-stage');
    el.btnResultsGoToScanner = document.getElementById('btn-results-go-to-scanner');
    el.btnResultsNewScan = document.getElementById('btn-results-new-scan');
    el.resultsTargetTitle = document.getElementById('results-target-title');
    el.resultsScanIdMeta = document.getElementById('results-scan-id-meta');
    el.resultsHighestSeverityBadge = document.getElementById('results-highest-severity-badge');
    el.resultsStatusBadge = document.getElementById('results-status-badge');
    el.resultsCvssScore = document.getElementById('results-cvss-score');
    el.resultsTotalVulns = document.getElementById('results-total-vulns');
    el.resultsExecTime = document.getElementById('results-exec-time');
    el.resultsModelUsed = document.getElementById('results-model-used');
    el.resultsAstSummaryText = document.getElementById('results-ast-summary-text');
    el.resultsAstLines = document.getElementById('results-ast-lines');
    el.resultsAstParsed = document.getElementById('results-ast-parsed');
    el.resultsAstSinksCount = document.getElementById('results-ast-sinks-count');
    el.resultsAstSourcesCount = document.getElementById('results-ast-sources-count');
    el.resultsAstSinksList = document.getElementById('results-ast-sinks-list');
    el.resultsCleanState = document.getElementById('results-clean-state');
    el.resultsVulnsList = document.getElementById('results-vulns-list');

    // Patch Verification Elements
    el.formVerifyPatch = document.getElementById('form-verify-patch');
    el.verifyOriginalCode = document.getElementById('verify-original-code');
    el.verifyPatchedCode = document.getElementById('verify-patched-code');
    el.verifyUnifiedDiff = document.getElementById('verify-unified-diff');
    el.verifySinkType = document.getElementById('verify-sink-type');
    el.btnSubmitVerifyPatch = document.getElementById('btn-submit-verify-patch');
    el.btnLoadSamplePatch = document.getElementById('btn-load-sample-patch');
    el.verifyPatchResultsContainer = document.getElementById('verify-patch-results-container');

    // Apply Diff Elements
    el.formApplyDiff = document.getElementById('form-apply-diff');
    el.diffOriginalCode = document.getElementById('diff-original-code');
    el.diffUnifiedDiff = document.getElementById('diff-unified-diff');
    el.btnSubmitApplyDiff = document.getElementById('btn-submit-apply-diff');
    el.btnLoadSampleDiff = document.getElementById('btn-load-sample-diff');
    el.applyDiffResultsContainer = document.getElementById('apply-diff-results-container');

    // System Status Elements
    el.btnRefreshSystemStatus = document.getElementById('btn-refresh-system-status');
    el.sysHealthStatusBadge = document.getElementById('sys-health-status-badge');
    el.sysServiceName = document.getElementById('sys-service-name');
    el.sysServiceVersion = document.getElementById('sys-service-version');
    el.sysActiveProvider = document.getElementById('sys-active-provider');
    el.sysLlReady = document.getElementById('sys-llm-ready');
    el.sysProvidersGrid = document.getElementById('sys-providers-grid');
  }

  // =========================================================================
  // 4. TOAST NOTIFICATIONS & VISUAL FEEDBACK
  // =========================================================================
  function showToast(message, type = 'info') {
    if (!el.toastContainer) return;
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconSvg = '';
    if (type === 'success') {
      iconSvg = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    } else if (type === 'error') {
      iconSvg = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    } else {
      iconSvg = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    }

    toast.innerHTML = `
      <div class="toast-icon">${iconSvg}</div>
      <div class="toast-message">${escapeHtml(message)}</div>
      <button class="toast-close" type="button" aria-label="Dismiss">×</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => {
      toast.remove();
    });

    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('show');
    }, 10);

    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // =========================================================================
  // 5. CARD THEME STYLING TOGGLE
  // =========================================================================
  function setCardStyle(style) {
    state.cardStyle = style;
    document.body.setAttribute('data-card-style', style);
    if (el.toggleCardLabel) {
      el.toggleCardLabel.textContent = style === 'white' ? '30% White Cards' : 'Dark Stealth Cards';
    }
    try {
      localStorage.setItem('zg_card_style', style);
    } catch (e) {
      // Ignore storage errors in restricted contexts
    }
  }

  // =========================================================================
  // 6. SPA ROUTING & NAVIGATION
  // =========================================================================
  const VIEW_TITLES = {
    dashboard: 'Dashboard',
    scanner: 'Code Scanner',
    results: 'Scan Results',
    'verify-patch': 'Patch Verification',
    'apply-diff': 'Apply Diff',
    'system-status': 'System & Providers'
  };

  function navigateTo(targetView) {
    if (!el.views[targetView]) {
      targetView = 'dashboard';
    }

    // Hide welcome & login, ensure app-shell is displayed
    if (el.viewWelcome) el.viewWelcome.classList.remove('active');
    if (el.viewLogin) el.viewLogin.classList.remove('active');
    if (el.appShell) el.appShell.classList.remove('hidden');

    // Update active content view
    Object.keys(el.views).forEach(key => {
      const v = el.views[key];
      if (v) {
        if (key === targetView) {
          v.classList.add('active');
        } else {
          v.classList.remove('active');
        }
      }
    });

    // Update sidebar navigation active state
    if (el.navItems) {
      el.navItems.forEach(item => {
        if (item.getAttribute('data-nav') === targetView) {
          item.classList.add('active');
        } else {
          item.classList.remove('active');
        }
      });
    }

    // Update topbar breadcrumb
    if (el.topbarActivePage) {
      el.topbarActivePage.textContent = VIEW_TITLES[targetView] || targetView;
    }

    // Close mobile sidebar if open
    closeMobileSidebar();

    // Reset scroll offset
    if (el.appMainContent) {
      el.appMainContent.scrollTop = 0;
    }
    window.scrollTo(0, 0);

    // Update browser URL hash cleanly without reload
    window.location.hash = `#${targetView}`;

    // Auto-refresh data on view entry
    if (targetView === 'dashboard') {
      updateDashboardView();
    } else if (targetView === 'system-status') {
      fetchSystemStatus();
    }
  }

  function openMobileSidebar() {
    if (el.appSidebar) el.appSidebar.classList.add('open');
    if (el.sidebarBackdrop) el.sidebarBackdrop.classList.add('active');
  }

  function closeMobileSidebar() {
    if (el.appSidebar) el.appSidebar.classList.remove('open');
    if (el.sidebarBackdrop) el.sidebarBackdrop.classList.remove('active');
  }

  // =========================================================================
  // 7. BACKEND PROBING & HEALTH CHECK
  // =========================================================================
  async function checkBackendConnection() {
    try {
      const health = await ZeroGuardAPI.getHealth();
      state.backendOnline = true;
      state.healthData = health;

      if (el.backendStatusPill) {
        el.backendStatusPill.className = 'backend-status-pill status-online';
        el.backendStatusPill.title = `ZeroGuard Engine Online (v${health.version || '1.0.0'})`;
      }
      if (el.backendStatusText) {
        el.backendStatusText.textContent = `Online • ${health.active_provider || 'Engine'}`;
      }
      if (el.dashEngineStatus) {
        el.dashEngineStatus.textContent = 'ONLINE';
        el.dashEngineStatus.style.color = '#2ED573';
      }
      if (el.dashEngineDetail) {
        el.dashEngineDetail.textContent = `${health.service || 'ZeroGuard'} v${health.version || '1.0.0'}`;
      }
      return true;
    } catch (err) {
      state.backendOnline = false;
      state.healthData = null;

      if (el.backendStatusPill) {
        el.backendStatusPill.className = 'backend-status-pill status-offline';
        el.backendStatusPill.title = `Backend connection failed: ${err.message}. Click to retry.`;
      }
      if (el.backendStatusText) {
        el.backendStatusText.textContent = 'Backend Offline';
      }
      if (el.dashEngineStatus) {
        el.dashEngineStatus.textContent = 'OFFLINE';
        el.dashEngineStatus.style.color = '#FF6F32';
      }
      if (el.dashEngineDetail) {
        el.dashEngineDetail.textContent = 'FastAPI server not responding at port 8000';
      }
      return false;
    }
  }

  async function fetchProviderStatus() {
    try {
      const info = await ZeroGuardAPI.getProviders();
      state.providersData = info;
      const active = info.active_provider || 'groq';

      if (el.dashActiveProvider) {
        const provMeta = info.available_providers && info.available_providers[active];
        el.dashActiveProvider.textContent = active.toUpperCase();
      }
      if (el.dashProviderDetail) {
        const provMeta = info.available_providers && info.available_providers[active];
        el.dashProviderDetail.textContent = provMeta ? provMeta.model : 'Multi-provider active';
      }
      return info;
    } catch (err) {
      if (el.dashActiveProvider) el.dashActiveProvider.textContent = 'UNKNOWN';
      if (el.dashProviderDetail) el.dashProviderDetail.textContent = 'Backend unreachable';
      return null;
    }
  }

  async function fetchSystemStatus() {
    // 1. Health
    await checkBackendConnection();
    if (state.healthData) {
      const h = state.healthData;
      if (el.sysHealthStatusBadge) {
        el.sysHealthStatusBadge.textContent = (h.status || 'ONLINE').toUpperCase();
        el.sysHealthStatusBadge.className = 'badge badge-success';
      }
      if (el.sysServiceName) el.sysServiceName.textContent = h.service || 'ZeroGuard Detection Engine';
      if (el.sysServiceVersion) el.sysServiceVersion.textContent = h.version || '1.0.0-hackfest2026';
      if (el.sysActiveProvider) el.sysActiveProvider.textContent = (h.active_provider || 'groq').toUpperCase();
      if (el.sysLlReady) {
        el.sysLlReady.textContent = h.llm_ready ? 'READY (Key Active)' : 'HEURISTIC (No API Key)';
        el.sysLlReady.style.color = h.llm_ready ? '#2ED573' : '#FF6F32';
      }
    } else {
      if (el.sysHealthStatusBadge) {
        el.sysHealthStatusBadge.textContent = 'OFFLINE';
        el.sysHealthStatusBadge.className = 'badge badge-critical';
      }
      if (el.sysServiceName) el.sysServiceName.textContent = 'FastAPI Server';
      if (el.sysServiceVersion) el.sysServiceVersion.textContent = 'Unreachable';
      if (el.sysActiveProvider) el.sysActiveProvider.textContent = '—';
      if (el.sysLlReady) el.sysLlReady.textContent = 'Offline';
    }

    // 2. Providers
    const provs = await fetchProviderStatus();
    renderProvidersGrid(provs);
  }

  function renderProvidersGrid(info) {
    if (!el.sysProvidersGrid) return;
    if (!info || !info.available_providers) {
      el.sysProvidersGrid.innerHTML = `
        <div class="empty-state-box" style="grid-column: 1 / -1; padding: 24px;">
          <p class="text-muted">Unable to retrieve AI provider statuses from backend.</p>
        </div>
      `;
      return;
    }

    const cards = [];
    const active = info.active_provider;

    Object.keys(info.available_providers).forEach(key => {
      const p = info.available_providers[key];
      const isPrimary = p.is_primary || key === active;
      const isConfigured = Boolean(p.configured);

      cards.push(`
        <div class="provider-card">
          <div>
            <div class="provider-card-header">
              <div>
                <span class="provider-title">${escapeHtml(p.name || key)}</span>
                <div class="provider-model-tag">${escapeHtml(p.model || 'Default Model')}</div>
              </div>
              <span class="provider-badge ${isPrimary ? 'badge-primary' : 'badge-fallback'}">
                ${isPrimary ? 'ACTIVE PRIMARY' : 'FALLBACK'}
              </span>
            </div>

            <p class="text-sm text-muted mt-2">
              ${p.endpoint ? `Endpoint: <code>${escapeHtml(p.endpoint)}</code>` : (key === 'groq' ? 'Ultra-fast LLaMA 3.3 70B inference via Groq Cloud API.' : 'Gemini Flash cloud inference with high token context.')}
            </p>
          </div>

          <div class="d-flex align-items-center justify-content-between mt-3 pt-3" style="border-top: 1px solid var(--card-inner-border);">
            <span class="text-xs text-muted">Config Status:</span>
            <span class="badge ${isConfigured ? 'badge-success' : 'badge-muted'}">
              ${isConfigured ? 'KEY CONFIGURED' : 'API KEY NOT SET'}
            </span>
          </div>
        </div>
      `);
    });

    // Add Heuristic Analyzer Card
    cards.push(`
      <div class="provider-card">
        <div>
          <div class="provider-card-header">
            <div>
              <span class="provider-title">Heuristic Security Analyzer</span>
              <div class="provider-model-tag">deterministic-appsec-v1</div>
            </div>
            <span class="provider-badge badge-primary" style="background: rgba(46, 213, 115, 0.15); color: #2ED573; border-color: rgba(46, 213, 115, 0.3);">
              ZERO-DOWNTIME
            </span>
          </div>

          <p class="text-sm text-muted mt-2">
            Built-in deterministic logic analyzer derived from native AST parsing. Automatically engages when cloud or local LLM keys are absent, ensuring tests and audits remain 100% operational.
          </p>
        </div>

        <div class="d-flex align-items-center justify-content-between mt-3 pt-3" style="border-top: 1px solid var(--card-inner-border);">
          <span class="text-xs text-muted">Config Status:</span>
          <span class="badge badge-success">ALWAYS ACTIVE</span>
        </div>
      </div>
    `);

    el.sysProvidersGrid.innerHTML = cards.join('');
  }

  // =========================================================================
  // 8. CODE SCANNER EXECUTION
  // =========================================================================
  function loadSampleCode(sampleKey) {
    const sample = PYTHON_SAMPLES[sampleKey];
    if (!sample) return;

    if (el.inputScanFilename) el.inputScanFilename.value = sample.filename;
    if (el.textareaScanCode) el.textareaScanCode.value = sample.code;

    // Update active pill
    if (el.presetPills) {
      el.presetPills.forEach(pill => {
        if (pill.getAttribute('data-sample') === sampleKey) {
          pill.classList.add('active');
        } else {
          pill.classList.remove('active');
        }
      });
    }

    if (el.scanFeedbackBanner) {
      el.scanFeedbackBanner.className = 'mt-3 hidden';
      el.scanFeedbackBanner.innerHTML = '';
    }
  }

  async function handleExecuteScan() {
    const code = el.textareaScanCode ? el.textareaScanCode.value : '';
    const filename = el.inputScanFilename ? el.inputScanFilename.value.trim() : 'target.py';
    const provider = el.selectScanProvider ? el.selectScanProvider.value : '';
    const includeDiffs = el.checkboxIncludeDiffs ? el.checkboxIncludeDiffs.checked : true;

    if (!code || !code.trim()) {
      showToast('Please provide Python source code to scan.', 'error');
      if (el.textareaScanCode) el.textareaScanCode.focus();
      return;
    }

    // Set UI loading state
    setScanButtonLoading(true);
    showScanFeedback('info', `Running ZeroGuard Tri-Engine pipeline on ${escapeHtml(filename)}... Parsing AST -> Semantic Reasoning -> Patch Verification.`);

    const startTime = performance.now();

    try {
      const response = await ZeroGuardAPI.scanCode({
        code,
        filename,
        provider: provider || null,
        include_diff_patches: includeDiffs
      });

      const elapsed = ((performance.now() - startTime) / 1000).toFixed(2);
      setScanButtonLoading(false);

      // Update session metrics
      state.scansCount += 1;
      const flawCount = response.total_vulnerabilities || (response.vulnerabilities ? response.vulnerabilities.length : 0);
      state.totalFlawsDetected += flawCount;
      state.latestScan = response;

      // Update sidebar badge
      if (el.navFlawsBadge) {
        if (flawCount > 0) {
          el.navFlawsBadge.textContent = flawCount;
          el.navFlawsBadge.classList.remove('hidden');
        } else {
          el.navFlawsBadge.textContent = '0';
          el.navFlawsBadge.classList.add('hidden');
        }
      }

      // Render results view and navigate
      renderScanResults(response, code);
      updateDashboardView();

      showToast(`Scan complete in ${elapsed}s! Found ${flawCount} vulnerability issue(s).`, flawCount > 0 ? 'info' : 'success');
      navigateTo('results');
    } catch (err) {
      setScanButtonLoading(false);
      showScanFeedback('error', `Scan failed: ${err.message}`);
      showToast(err.message, 'error');
    }
  }

  function setScanButtonLoading(isLoading) {
    if (!el.btnExecuteScan) return;
    if (isLoading) {
      el.btnExecuteScan.disabled = true;
      el.btnExecuteScan.innerHTML = `
        <span class="loading-spinner"></span>
        <span>Auditing Code...</span>
      `;
    } else {
      el.btnExecuteScan.disabled = false;
      el.btnExecuteScan.innerHTML = `
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5">
          <circle cx="12" cy="12" r="10"></circle>
          <polygon points="10 8 16 12 10 16 10 8"></polygon>
        </svg>
        <span>Execute Security Audit</span>
      `;
    }
  }

  function showScanFeedback(type, message) {
    if (!el.scanFeedbackBanner) return;
    el.scanFeedbackBanner.className = `mt-3 alert alert-${type === 'error' ? 'critical' : 'info'}`;
    el.scanFeedbackBanner.innerHTML = `
      <div class="d-flex align-items-center gap-2">
        <span>${escapeHtml(message)}</span>
      </div>
    `;
    el.scanFeedbackBanner.classList.remove('hidden');
  }

  // =========================================================================
  // 9. SCAN RESULTS PRESENTATION
  // =========================================================================
  function renderScanResults(scan, originalCode) {
    if (!scan) return;

    if (el.resultsEmptyState) el.resultsEmptyState.classList.add('hidden');
    if (el.resultsStage) el.resultsStage.classList.remove('hidden');

    // Headline Metadata
    if (el.resultsTargetTitle) el.resultsTargetTitle.textContent = `Target: ${scan.target_name || 'target.py'}`;
    if (el.resultsScanIdMeta) el.resultsScanIdMeta.textContent = `Scan ID: ${scan.scan_id || '—'} • ${scan.timestamp || ''}`;

    const highestSev = scan.highest_severity || 'NONE';
    if (el.resultsHighestSeverityBadge) {
      el.resultsHighestSeverityBadge.textContent = highestSev;
      el.resultsHighestSeverityBadge.className = `badge badge-${highestSev.toLowerCase()}`;
    }

    if (el.resultsStatusBadge) {
      el.resultsStatusBadge.textContent = scan.status || 'COMPLETED';
      el.resultsStatusBadge.className = `badge ${scan.status === 'CLEAN' ? 'badge-success' : 'badge-info'}`;
    }

    if (el.resultsCvssScore) el.resultsCvssScore.textContent = `${(scan.overall_risk_score || 0).toFixed(1)} / 10.0`;
    if (el.resultsTotalVulns) el.resultsTotalVulns.textContent = scan.total_vulnerabilities || 0;
    if (el.resultsExecTime) el.resultsExecTime.textContent = `${(scan.execution_time_seconds || 0).toFixed(2)}s`;
    if (el.resultsModelUsed) el.resultsModelUsed.textContent = `${scan.llm_provider_used || 'Auto'} (${scan.model_used || '—'})`;

    // AST Triage Details
    if (scan.ast_triage) {
      const ast = scan.ast_triage;
      if (el.resultsAstSummaryText) el.resultsAstSummaryText.textContent = ast.triage_summary || '';
      if (el.resultsAstLines) el.resultsAstLines.textContent = ast.total_lines || 0;
      if (el.resultsAstParsed) {
        el.resultsAstParsed.textContent = ast.parsed_successfully ? 'YES' : 'FAILED';
        el.resultsAstParsed.className = ast.parsed_successfully ? 'text-success' : 'text-danger';
      }
      if (el.resultsAstSinksCount) el.resultsAstSinksCount.textContent = ast.sinks ? ast.sinks.length : 0;
      if (el.resultsAstSourcesCount) el.resultsAstSourcesCount.textContent = ast.sources ? ast.sources.length : 0;

      // Render Sinks List
      if (el.resultsAstSinksList) {
        if (ast.sinks && ast.sinks.length > 0) {
          el.resultsAstSinksList.innerHTML = ast.sinks.map(sink => `
            <div class="ast-sink-pill">
              <span class="sink-name">${escapeHtml(sink.call_name || sink.sink_type)}</span>
              <span class="sink-meta">Line ${sink.line_number} • ${escapeHtml(sink.sink_type)}</span>
            </div>
          `).join('');
          document.getElementById('results-ast-sinks-container').classList.remove('hidden');
        } else {
          el.resultsAstSinksList.innerHTML = `<span class="text-sm text-muted">No dangerous call sinks identified.</span>`;
        }
      }
    }

    // Clean vs Vulnerable Findings
    const vulns = scan.vulnerabilities || [];
    if (vulns.length === 0) {
      if (el.resultsCleanState) el.resultsCleanState.classList.remove('hidden');
      if (el.resultsVulnsList) el.resultsVulnsList.innerHTML = '';
    } else {
      if (el.resultsCleanState) el.resultsCleanState.classList.add('hidden');
      renderVulnerabilitiesList(vulns, originalCode);
    }
  }

  function renderVulnerabilitiesList(vulns, originalCode) {
    if (!el.resultsVulnsList) return;

    el.resultsVulnsList.innerHTML = vulns.map((v, idx) => {
      const cvssScore = v.cvss_score || (v.cvss ? v.cvss.base_score : 0.0);
      const cvssVector = v.cvss_vector || (v.cvss ? v.cvss.vector_string : '');
      const sevLower = (v.severity || 'high').toLowerCase();

      // Format Taint Graph Sequence
      const taintNodes = v.taint_path || v.taint_graph || [];
      let taintGraphHtml = '';
      if (taintNodes.length > 0) {
        taintGraphHtml = `
          <div class="mt-4">
            <span class="text-xs text-muted text-uppercase font-bold d-block mb-2">Visual Taint Propagation Sequence:</span>
            <div class="taint-flow-chain">
              ${taintNodes.map(node => {
                const nodeType = (node.node_type || 'PROPAGATION').toUpperCase();
                let typeClass = 'type-propagation';
                if (nodeType === 'SOURCE') typeClass = 'type-source';
                else if (nodeType === 'SANITIZATION_MISSING') typeClass = 'type-missing';
                else if (nodeType === 'SINK') typeClass = 'type-sink';

                return `
                  <div class="taint-step-node">
                    <div class="taint-step-index">${node.step_index || idx + 1}</div>
                    <div class="taint-step-content">
                      <div class="taint-step-meta">
                        <span class="taint-node-type ${typeClass}">${nodeType}</span>
                        <span class="taint-step-line">Line ${node.line_number}</span>
                        ${node.variable_name ? `<span class="badge badge-muted">var: ${escapeHtml(node.variable_name)}</span>` : ''}
                      </div>
                      ${node.code_snippet ? `<div class="taint-step-snippet">${escapeHtml(node.code_snippet)}</div>` : ''}
                      <div class="taint-step-desc">${escapeHtml(node.explanation)}</div>
                    </div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>
        `;
      }

      // Format Verified Diff Patch
      const unifiedDiff = v.unified_diff || (v.patch ? v.patch.unified_diff : '');
      let patchSectionHtml = '';
      if (unifiedDiff) {
        const patchMeta = v.patch || {};
        patchSectionHtml = `
          <div class="mt-4 pt-3" style="border-top: 1px solid var(--card-inner-border);">
            <div class="d-flex align-items-center justify-content-between mb-2">
              <span class="text-xs text-muted text-uppercase font-bold">Engine 3: Verified Self-Healing Patch</span>
              <div class="d-flex gap-2">
                <span class="badge ${patchMeta.ast_syntax_valid !== false ? 'badge-success' : 'badge-critical'}">
                  AST Valid: ${patchMeta.ast_syntax_valid !== false ? 'YES' : 'NO'}
                </span>
                <span class="badge ${patchMeta.verified_clean !== false ? 'badge-success' : 'badge-critical'}">
                  Verified Clean: ${patchMeta.verified_clean !== false ? 'YES' : 'NO'}
                </span>
              </div>
            </div>

            <div class="diff-viewer">
              ${formatUnifiedDiffHtml(unifiedDiff)}
            </div>

            <div class="d-flex gap-2 mt-2">
              <button
                type="button"
                class="btn btn-sm btn-secondary btn-bridge-verify"
                data-vuln-index="${idx}"
              >
                Test in Patch Verifier →
              </button>
              <button
                type="button"
                class="btn btn-sm btn-secondary btn-bridge-diff"
                data-vuln-index="${idx}"
              >
                Apply Diff in Memory →
              </button>
            </div>
          </div>
        `;
      }

      return `
        <div class="dashboard-panel-card mb-4" data-vuln-id="${escapeHtml(v.vuln_id)}">
          <div class="panel-header">
            <div>
              <div class="d-flex align-items-center gap-2 mb-1">
                <span class="badge badge-muted font-mono">${escapeHtml(v.vuln_id || `ZG-${idx + 1}`)}</span>
                <span class="badge badge-${sevLower}">${escapeHtml(v.severity || 'HIGH')}</span>
                <span class="badge badge-primary">${escapeHtml(v.cwe_id || 'CWE-699')}</span>
                <span class="badge badge-muted">${escapeHtml(v.category || 'LOGIC_FLAW')}</span>
              </div>
              <h3 class="panel-title">${escapeHtml(v.title || 'Security Vulnerability')}</h3>
            </div>
          </div>

          <div class="panel-body">
            <!-- CVSS Metrics Meter Box -->
            <div class="cvss-meter-box">
              <div class="cvss-score-circle sev-${sevLower}">
                <span class="score-num">${cvssScore.toFixed(1)}</span>
                <span class="score-scale">/ 10.0</span>
              </div>
              <div class="cvss-details">
                <div class="d-flex align-items-center gap-2">
                  <strong>CVSS v3.1 Base Score:</strong>
                  <span>${cvssScore.toFixed(1)} (${escapeHtml(v.severity || 'HIGH')})</span>
                </div>
                ${cvssVector ? `<div class="cvss-vector-str">${escapeHtml(cvssVector)}</div>` : ''}
              </div>
            </div>

            <!-- Vulnerability Description & Root Cause -->
            <div class="mb-3">
              <h4 class="text-sm font-bold text-muted text-uppercase mb-1">Description:</h4>
              <p class="text-sm">${escapeHtml(v.description)}</p>
            </div>

            <div class="mb-3">
              <h4 class="text-sm font-bold text-muted text-uppercase mb-1">Root Cause Coding Invariant:</h4>
              <p class="text-sm font-mono text-muted" style="background: var(--card-inner-surface); padding: 8px 12px; border-radius: 4px;">
                ${escapeHtml(v.root_cause || 'Unvalidated state precondition')}
              </p>
            </div>

            ${v.attack_vector_narrative ? `
              <div class="mb-3">
                <h4 class="text-sm font-bold text-muted text-uppercase mb-1">Exploit Narrative:</h4>
                <p class="text-sm text-muted">${escapeHtml(v.attack_vector_narrative)}</p>
              </div>
            ` : ''}

            ${taintGraphHtml}

            ${v.recommended_fix_strategy ? `
              <div class="mt-3">
                <h4 class="text-sm font-bold text-muted text-uppercase mb-1">Recommended Fix Strategy:</h4>
                <p class="text-sm text-muted">${escapeHtml(v.recommended_fix_strategy)}</p>
              </div>
            ` : ''}

            ${patchSectionHtml}
          </div>
        </div>
      `;
    }).join('');

    // Attach Bridge Event Listeners (Bridge from Results to Verifier and Apply Diff)
    el.resultsVulnsList.querySelectorAll('.btn-bridge-verify').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-vuln-index'), 10);
        bridgeToPatchVerifier(vulns[idx], originalCode);
      });
    });

    el.resultsVulnsList.querySelectorAll('.btn-bridge-diff').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-vuln-index'), 10);
        bridgeToApplyDiff(vulns[idx], originalCode);
      });
    });
  }

  function formatUnifiedDiffHtml(diffText) {
    if (!diffText) return '';
    return diffText.split('\n').map(line => {
      let cls = 'diff-context';
      if (line.startsWith('+++') || line.startsWith('---') || line.startsWith('@@')) {
        cls = 'diff-meta';
      } else if (line.startsWith('+')) {
        cls = 'diff-add';
      } else if (line.startsWith('-')) {
        cls = 'diff-del';
      }
      return `<div class="diff-line ${cls}">${escapeHtml(line)}</div>`;
    }).join('');
  }

  // Inter-view Bridges
  function bridgeToPatchVerifier(vuln, originalCode) {
    if (!vuln) return;
    if (el.verifyOriginalCode) el.verifyOriginalCode.value = originalCode || (el.textareaScanCode ? el.textareaScanCode.value : '');
    if (el.verifyPatchedCode) el.verifyPatchedCode.value = (vuln.patch && vuln.patch.patched_code) || '';
    if (el.verifyUnifiedDiff) el.verifyUnifiedDiff.value = vuln.unified_diff || (vuln.patch ? vuln.patch.unified_diff : '');
    if (el.verifySinkType) el.verifySinkType.value = vuln.cwe_id || vuln.category || '';
    navigateTo('verify-patch');
    showToast(`Loaded ${vuln.vuln_id || 'vulnerability'} patch into verifier.`, 'info');
  }

  function bridgeToApplyDiff(vuln, originalCode) {
    if (!vuln) return;
    if (el.diffOriginalCode) el.diffOriginalCode.value = originalCode || (el.textareaScanCode ? el.textareaScanCode.value : '');
    if (el.diffUnifiedDiff) el.diffUnifiedDiff.value = vuln.unified_diff || (vuln.patch ? vuln.patch.unified_diff : '');
    navigateTo('apply-diff');
    showToast(`Loaded diff for ${vuln.vuln_id || 'vulnerability'}. Click Apply Diff to test.`, 'info');
  }

  // =========================================================================
  // 10. PATCH VERIFICATION FORM HANDLER
  // =========================================================================
  async function handleVerifyPatchSubmit(e) {
    e.preventDefault();
    const original = el.verifyOriginalCode ? el.verifyOriginalCode.value : '';
    const patched = el.verifyPatchedCode ? el.verifyPatchedCode.value : '';
    const diff = el.verifyUnifiedDiff ? el.verifyUnifiedDiff.value : '';
    const sinkType = el.verifySinkType ? el.verifySinkType.value.trim() : '';

    if (!original || !original.trim()) {
      showToast('Original code is required for patch verification.', 'error');
      return;
    }

    if (!patched && !diff) {
      showToast('Please provide either patched code or a unified diff string.', 'error');
      return;
    }

    if (el.btnSubmitVerifyPatch) {
      el.btnSubmitVerifyPatch.disabled = true;
      el.btnSubmitVerifyPatch.innerHTML = '<span class="loading-spinner"></span> Verifying AST Safety...';
    }

    try {
      const result = await ZeroGuardAPI.verifyPatch({
        original_code: original,
        patched_code: patched || null,
        unified_diff: diff || null,
        expected_sink_type: sinkType || null
      });

      if (el.btnSubmitVerifyPatch) {
        el.btnSubmitVerifyPatch.disabled = false;
        el.btnSubmitVerifyPatch.innerHTML = `
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <polyline points="9 12 11 14 15 10"/>
          </svg>
          <span>Verify Patch Safety</span>
        `;
      }

      renderPatchVerificationResults(result);
      showToast(result.verified_clean ? 'Patch verified clean & safe!' : 'Residual sinks detected in patch.', result.verified_clean ? 'success' : 'info');
    } catch (err) {
      if (el.btnSubmitVerifyPatch) {
        el.btnSubmitVerifyPatch.disabled = false;
        el.btnSubmitVerifyPatch.innerHTML = '<span>Verify Patch Safety</span>';
      }
      showToast(`Verification error: ${err.message}`, 'error');
    }
  }

  function renderPatchVerificationResults(res) {
    if (!el.verifyPatchResultsContainer) return;

    const isClean = Boolean(res.verified_clean);
    const syntaxValid = Boolean(res.ast_syntax_valid);
    const diffApplied = Boolean(res.unified_diff_applied);
    const residualSinks = res.residual_sinks_found || 0;
    const notes = res.notes || [];

    el.verifyPatchResultsContainer.innerHTML = `
      <div class="verification-results-panel">
        <div class="verification-status-banner ${isClean ? 'banner-clean' : 'banner-warning'}">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.5">
            ${isClean
              ? '<polyline points="20 6 9 17 4 12"></polyline>'
              : '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>'
            }
          </svg>
          <span>${isClean ? 'VERIFICATION PASSED: Patch is Clean & Syntax-Safe' : 'VERIFICATION CAUTION: Residual Sinks or Syntax Issues Found'}</span>
        </div>

        <div class="verification-checks-list">
          <div class="check-item ${syntaxValid ? 'pass' : 'fail'}">
            <span>${syntaxValid ? '✓' : '✗'}</span>
            <span>AST Syntax Valid: ${syntaxValid ? 'PASS' : 'FAIL'}</span>
          </div>

          <div class="check-item ${diffApplied ? 'pass' : 'fail'}">
            <span>${diffApplied ? '✓' : '—'}</span>
            <span>Unified Diff Applied: ${diffApplied ? 'YES' : 'NO / N/A'}</span>
          </div>

          <div class="check-item ${residualSinks === 0 ? 'pass' : 'fail'}">
            <span>${residualSinks === 0 ? '✓' : '✗'}</span>
            <span>Residual Sinks Found: ${residualSinks}</span>
          </div>
        </div>

        ${notes.length > 0 ? `
          <div class="mb-3">
            <span class="text-xs text-muted text-uppercase font-bold d-block mb-1">Verification Notes:</span>
            <ul class="text-sm text-muted" style="padding-left: 20px;">
              ${notes.map(n => `<li>${escapeHtml(n)}</li>`).join('')}
            </ul>
          </div>
        ` : ''}

        ${res.patched_code ? `
          <div>
            <span class="text-xs text-muted text-uppercase font-bold d-block mb-1">Resulting Patched Code:</span>
            <pre class="diff-viewer" style="padding: 12px; color: #FFFFFF;"><code>${escapeHtml(res.patched_code)}</code></pre>
          </div>
        ` : ''}
      </div>
    `;

    el.verifyPatchResultsContainer.classList.remove('hidden');
  }

  // =========================================================================
  // 11. APPLY DIFF FORM HANDLER
  // =========================================================================
  async function handleApplyDiffSubmit(e) {
    e.preventDefault();
    const original = el.diffOriginalCode ? el.diffOriginalCode.value : '';
    const diff = el.diffUnifiedDiff ? el.diffUnifiedDiff.value : '';

    if (!original || !original.trim()) {
      showToast('Original source code is required.', 'error');
      return;
    }
    if (!diff || !diff.trim()) {
      showToast('Unified diff patch string is required.', 'error');
      return;
    }

    if (el.btnSubmitApplyDiff) {
      el.btnSubmitApplyDiff.disabled = true;
      el.btnSubmitApplyDiff.innerHTML = '<span class="loading-spinner"></span> Applying Unified Diff...';
    }

    try {
      const result = await ZeroGuardAPI.applyDiff({
        original_code: original,
        unified_diff: diff
      });

      if (el.btnSubmitApplyDiff) {
        el.btnSubmitApplyDiff.disabled = false;
        el.btnSubmitApplyDiff.innerHTML = `
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.5">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          <span>Apply Unified Diff</span>
        `;
      }

      renderApplyDiffResults(result);
      showToast('Unified diff applied successfully!', 'success');
    } catch (err) {
      if (el.btnSubmitApplyDiff) {
        el.btnSubmitApplyDiff.disabled = false;
        el.btnSubmitApplyDiff.innerHTML = '<span>Apply Unified Diff</span>';
      }
      showToast(`Failed to apply diff: ${err.message}`, 'error');
      renderApplyDiffError(err.message);
    }
  }

  function renderApplyDiffResults(res) {
    if (!el.applyDiffResultsContainer) return;

    el.applyDiffResultsContainer.innerHTML = `
      <div class="verification-results-panel">
        <div class="verification-status-banner banner-clean">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.5">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          <span>DIFF APPLIED SUCCESSFULLY</span>
        </div>

        ${res.notes && res.notes.length > 0 ? `
          <div class="mb-3">
            <span class="text-xs text-muted text-uppercase font-bold d-block mb-1">Hunk Notes:</span>
            <ul class="text-sm text-muted" style="padding-left: 20px;">
              ${res.notes.map(n => `<li>${escapeHtml(n)}</li>`).join('')}
            </ul>
          </div>
        ` : ''}

        <div>
          <div class="d-flex align-items-center justify-content-between mb-1">
            <span class="text-xs text-muted text-uppercase font-bold">Patched Code Output:</span>
            <button type="button" class="btn btn-xs btn-secondary" id="btn-copy-patched-diff">Copy Code</button>
          </div>
          <pre class="diff-viewer" style="padding: 12px; color: #FFFFFF;"><code id="patched-diff-code-text">${escapeHtml(res.patched_code)}</code></pre>
        </div>
      </div>
    `;

    el.applyDiffResultsContainer.classList.remove('hidden');

    const copyBtn = document.getElementById('btn-copy-patched-diff');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(res.patched_code);
        showToast('Patched code copied to clipboard!', 'info');
      });
    }
  }

  function renderApplyDiffError(errorMsg) {
    if (!el.applyDiffResultsContainer) return;
    el.applyDiffResultsContainer.innerHTML = `
      <div class="verification-results-panel">
        <div class="verification-status-banner banner-warning">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2.5">
            <circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>
          </svg>
          <span>DIFF APPLICATION REJECTED</span>
        </div>
        <p class="text-sm text-muted">${escapeHtml(errorMsg)}</p>
      </div>
    `;
    el.applyDiffResultsContainer.classList.remove('hidden');
  }

  // =========================================================================
  // 12. DASHBOARD VIEW CONTROLLER
  // =========================================================================
  function updateDashboardView() {
    if (el.dashSessionScans) el.dashSessionScans.textContent = state.scansCount;
    if (el.dashFlawsDetected) el.dashFlawsDetected.textContent = state.totalFlawsDetected;

    if (state.latestScan) {
      const scan = state.latestScan;
      if (el.dashEmptyState) el.dashEmptyState.classList.add('hidden');
      if (el.dashLatestScanCard) el.dashLatestScanCard.classList.remove('hidden');

      if (el.dashLatestScanMeta) el.dashLatestScanMeta.textContent = `Scan ID: ${scan.scan_id || '—'} • ${scan.target_name || 'target.py'}`;
      if (el.dashLatestScore) el.dashLatestScore.textContent = `${(scan.overall_risk_score || 0).toFixed(1)} / 10.0`;

      const sev = scan.highest_severity || 'NONE';
      if (el.dashLatestSeverity) {
        el.dashLatestSeverity.textContent = sev;
        el.dashLatestSeverity.className = `badge badge-${sev.toLowerCase()}`;
      }

      const flawCount = scan.total_vulnerabilities || 0;
      if (el.dashLatestCount) el.dashLatestCount.textContent = `${flawCount} detected`;
      if (el.dashLatestSinks) el.dashLatestSinks.textContent = scan.ast_triage && scan.ast_triage.sinks ? scan.ast_triage.sinks.length : 0;
      if (el.dashLatestDuration) el.dashLatestDuration.textContent = `${(scan.execution_time_seconds || 0).toFixed(2)}s`;

      if (el.dashLatestSummaryText) {
        el.dashLatestSummaryText.textContent = scan.ast_triage ? scan.ast_triage.triage_summary : '';
      }
    } else {
      if (el.dashEmptyState) el.dashEmptyState.classList.remove('hidden');
      if (el.dashLatestScanCard) el.dashLatestScanCard.classList.add('hidden');
    }
  }

  // =========================================================================
  // 13. EVENT LISTENERS INITIALIZATION
  // =========================================================================
  function initEvents() {
    // Welcome Next Button
    if (el.btnWelcomeNext) {
      el.btnWelcomeNext.addEventListener('click', () => {
        if (el.viewWelcome) el.viewWelcome.classList.remove('active');
        if (el.viewLogin) el.viewLogin.classList.add('active');
        window.location.hash = '#login';
      });
    }

    // Login Form Submit
    if (el.formLogin) {
      el.formLogin.addEventListener('submit', (e) => {
        e.preventDefault();
        const username = el.inputUsername ? el.inputUsername.value.trim() : 'Alex Mercer';
        state.user.name = username || 'Alex Mercer';

        const activeRoleBtn = document.querySelector('.role-option-btn.active');
        if (activeRoleBtn) {
          state.user.role = activeRoleBtn.getAttribute('data-role') || 'Security Analyst';
        }

        // Derive initials
        const parts = state.user.name.split(' ');
        state.user.initials = parts.length > 1
          ? (parts[0][0] + parts[1][0]).toUpperCase()
          : state.user.name.slice(0, 2).toUpperCase();

        state.user.isLoggedIn = true;

        // Update UI
        if (el.userAvatar) el.userAvatar.textContent = state.user.initials;
        if (el.topbarUserAvatar) el.topbarUserAvatar.textContent = state.user.initials;
        if (el.userDisplayName) el.userDisplayName.textContent = state.user.name;
        if (el.userDisplayRole) el.userDisplayRole.textContent = state.user.role;
        if (el.dashboardUserName) el.dashboardUserName.textContent = state.user.name;
        el.dynUserNames.forEach(n => n.textContent = state.user.name);

        navigateTo('dashboard');
        showToast(`Welcome to ZeroGuard Console, ${state.user.name}!`, 'info');
      });
    }

    // Role Option Buttons
    if (el.roleOptionBtns) {
      el.roleOptionBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          el.roleOptionBtns.forEach(b => {
            b.classList.remove('active');
            b.setAttribute('aria-checked', 'false');
          });
          btn.classList.add('active');
          btn.setAttribute('aria-checked', 'true');
        });
      });
    }

    // Password Toggle
    if (el.btnTogglePassword && el.inputPassword) {
      el.btnTogglePassword.addEventListener('click', () => {
        const isPassword = el.inputPassword.getAttribute('type') === 'password';
        el.inputPassword.setAttribute('type', isPassword ? 'text' : 'password');
        if (el.iconEye) el.iconEye.classList.toggle('hidden', isPassword);
        if (el.iconEyeOff) el.iconEyeOff.classList.toggle('hidden', !isPassword);
      });
    }

    // Logout Button
    if (el.btnLogout) {
      el.btnLogout.addEventListener('click', () => {
        state.user.isLoggedIn = false;
        if (el.appShell) el.appShell.classList.add('hidden');
        if (el.viewLogin) el.viewLogin.classList.add('active');
        window.location.hash = '#login';
        showToast('Signed out of ZeroGuard console.', 'info');
      });
    }

    // Sidebar Navigation Buttons
    if (el.navItems) {
      el.navItems.forEach(item => {
        item.addEventListener('click', () => {
          const target = item.getAttribute('data-nav');
          navigateTo(target);
        });
      });
    }

    // Mobile Sidebar Toggles
    if (el.btnMobileMenu) el.btnMobileMenu.addEventListener('click', openMobileSidebar);
    if (el.btnSidebarClose) el.btnSidebarClose.addEventListener('click', closeMobileSidebar);
    if (el.sidebarBackdrop) el.sidebarBackdrop.addEventListener('click', closeMobileSidebar);

    // Card Surface Style Switcher
    if (el.btnToggleCardStyle) {
      el.btnToggleCardStyle.addEventListener('click', () => {
        const currentStyle = document.body.getAttribute('data-card-style') || 'white';
        setCardStyle(currentStyle === 'white' ? 'dark' : 'white');
      });
    }

    // Backend Status Pill Click to Retest
    if (el.backendStatusPill) {
      el.backendStatusPill.addEventListener('click', async () => {
        showToast('Probing backend health at /api/v1/health...', 'info');
        const ok = await checkBackendConnection();
        showToast(ok ? 'Backend is online and responding!' : 'Backend is unreachable. Ensure server is running on port 8000.', ok ? 'success' : 'error');
      });
    }

    // Preset Sample Buttons
    if (el.presetPills) {
      el.presetPills.forEach(pill => {
        pill.addEventListener('click', () => {
          const sampleKey = pill.getAttribute('data-sample');
          loadSampleCode(sampleKey);
        });
      });
    }

    // Sidebar Quick Sample Button
    if (el.btnSidebarQuickSample) {
      el.btnSidebarQuickSample.addEventListener('click', () => {
        loadSampleCode('toctou');
        navigateTo('scanner');
      });
    }

    // Scanner Action Buttons
    if (el.btnExecuteScan) el.btnExecuteScan.addEventListener('click', handleExecuteScan);
    if (el.btnClearCode) {
      el.btnClearCode.addEventListener('click', () => {
        if (el.textareaScanCode) el.textareaScanCode.value = '';
        if (el.presetPills) el.presetPills.forEach(p => p.classList.remove('active'));
      });
    }
    if (el.btnCopyCode) {
      el.btnCopyCode.addEventListener('click', () => {
        if (el.textareaScanCode && el.textareaScanCode.value) {
          navigator.clipboard.writeText(el.textareaScanCode.value);
          showToast('Code copied to clipboard!', 'info');
        }
      });
    }

    // Dashboard Quick Action Buttons
    if (el.btnDashboardScanNow) el.btnDashboardScanNow.addEventListener('click', () => navigateTo('scanner'));
    if (el.btnDashStartScan) el.btnDashStartScan.addEventListener('click', () => navigateTo('scanner'));
    if (el.btnDashVerifyPatch) el.btnDashVerifyPatch.addEventListener('click', () => navigateTo('verify-patch'));
    if (el.btnDashViewFullResults) el.btnDashViewFullResults.addEventListener('click', () => navigateTo('results'));

    // Results Navigation
    if (el.btnResultsGoToScanner) el.btnResultsGoToScanner.addEventListener('click', () => navigateTo('scanner'));
    if (el.btnResultsNewScan) el.btnResultsNewScan.addEventListener('click', () => navigateTo('scanner'));

    // Patch Verification Form & Load Sample
    if (el.formVerifyPatch) el.formVerifyPatch.addEventListener('submit', handleVerifyPatchSubmit);
    if (el.btnLoadSamplePatch) {
      el.btnLoadSamplePatch.addEventListener('click', () => {
        if (el.verifyOriginalCode) el.verifyOriginalCode.value = SAMPLE_PATCH.original;
        if (el.verifyPatchedCode) el.verifyPatchedCode.value = SAMPLE_PATCH.patched;
        if (el.verifyUnifiedDiff) el.verifyUnifiedDiff.value = SAMPLE_PATCH.diff;
        if (el.verifySinkType) el.verifySinkType.value = SAMPLE_PATCH.sinkType;
        showToast('Sample patch loaded into verifier.', 'info');
      });
    }

    // Apply Diff Form & Load Sample
    if (el.formApplyDiff) el.formApplyDiff.addEventListener('submit', handleApplyDiffSubmit);
    if (el.btnLoadSampleDiff) {
      el.btnLoadSampleDiff.addEventListener('click', () => {
        if (el.diffOriginalCode) el.diffOriginalCode.value = SAMPLE_DIFF.original;
        if (el.diffUnifiedDiff) el.diffUnifiedDiff.value = SAMPLE_DIFF.diff;
        showToast('Sample diff loaded.', 'info');
      });
    }

    // System Refresh Button
    if (el.btnRefreshSystemStatus) {
      el.btnRefreshSystemStatus.addEventListener('click', async () => {
        showToast('Refreshing system status...', 'info');
        await fetchSystemStatus();
        showToast('System status updated.', 'info');
      });
    }

    // Window Hash Change Handling (Browser Back / Forward buttons)
    window.addEventListener('hashchange', () => {
      const hash = window.location.hash.replace('#', '') || 'dashboard';
      if (hash === 'welcome') {
        if (el.appShell) el.appShell.classList.add('hidden');
        if (el.viewLogin) el.viewLogin.classList.remove('active');
        if (el.viewWelcome) el.viewWelcome.classList.add('active');
      } else if (hash === 'login') {
        if (el.appShell) el.appShell.classList.add('hidden');
        if (el.viewWelcome) el.viewWelcome.classList.remove('active');
        if (el.viewLogin) el.viewLogin.classList.add('active');
      } else if (el.views[hash]) {
        navigateTo(hash);
      }
    });
  }

  // =========================================================================
  // 14. APPLICATION INITIALIZATION
  // =========================================================================
  async function init() {
    cacheDomElements();
    initEvents();

    // Restore saved card style if present
    try {
      const savedCardStyle = localStorage.getItem('zg_card_style');
      if (savedCardStyle === 'dark' || savedCardStyle === 'white') {
        setCardStyle(savedCardStyle);
      }
    } catch (e) {}

    // Preload default sample in scanner
    loadSampleCode('toctou');

    // Route based on URL hash
    const initialHash = window.location.hash.replace('#', '');
    if (initialHash && el.views[initialHash]) {
      navigateTo(initialHash);
    } else if (initialHash === 'login') {
      if (el.viewWelcome) el.viewWelcome.classList.remove('active');
      if (el.viewLogin) el.viewLogin.classList.add('active');
    } else if (initialHash === 'welcome') {
      if (el.viewWelcome) el.viewWelcome.classList.add('active');
    } else {
      // Default to welcome screen on fresh visit
      if (el.viewWelcome) el.viewWelcome.classList.add('active');
    }

    // Initial background health probe
    await checkBackendConnection();
    await fetchProviderStatus();
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
