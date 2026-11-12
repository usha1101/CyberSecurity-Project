/**
 * ZeroGuard — Runtime Configuration
 * Single source of truth for frontend environment variables and API endpoint bindings.
 */
(function () {
  'use strict';

  // Allow override via window.ZEROGUARD_CONFIG if defined before this script
  const existingConfig = window.ZEROGUARD_CONFIG || {};

  // Infer default backend URL:
  // If frontend is opened on localhost or 127.0.0.1, target FastAPI on port 8000.
  const host = (typeof window !== 'undefined' && window.location.hostname) || 'localhost';
  const isLocal = host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0';
  const defaultApiBase = isLocal
    ? `http://${host}:8000/api/v1`
    : 'http://localhost:8000/api/v1';

  window.ZEROGUARD_CONFIG = {
    API_BASE_URL: existingConfig.API_BASE_URL || defaultApiBase,
    REQUEST_TIMEOUT_MS: existingConfig.REQUEST_TIMEOUT_MS || 45000,
    APP_NAME: 'ZeroGuard',
    APP_VERSION: '1.0.0-hackfest2026',
    TAGLINE: 'Secure Your Code. Detect Vulnerabilities. Verify Your Fixes.'
  };
})();
