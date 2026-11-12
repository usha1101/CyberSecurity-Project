const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const BACKEND_HOST = process.env.BACKEND_HOST || '127.0.0.1';
const BACKEND_PORT = process.env.BACKEND_PORT || 8000;
const PUBLIC_DIR = __dirname;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf'
};

const server = http.createServer((req, res) => {
  // 1. Reverse Proxy for /api/ requests to the FastAPI Backend
  if (req.url.startsWith('/api/')) {
    const proxyReq = http.request(
      {
        hostname: BACKEND_HOST,
        port: BACKEND_PORT,
        path: req.url,
        method: req.method,
        headers: {
          ...req.headers,
          host: `${BACKEND_HOST}:${BACKEND_PORT}`
        }
      },
      (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );

    proxyReq.on('error', (err) => {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
      }
      res.end(
        JSON.stringify({
          detail: `Cannot connect to ZeroGuard backend at http://${BACKEND_HOST}:${BACKEND_PORT}. Make sure FastAPI is running with 'python run.py'. Error: ${err.message}`
        })
      );
    });

    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'DELETE') {
      proxyReq.end();
    } else {
      req.pipe(proxyReq);
    }
    return;
  }

  // 2. Dynamic config.js override if BACKEND_URL environment variable is provided
  let reqPath = req.url.split('?')[0];
  if (reqPath === '/config.js' && process.env.BACKEND_URL) {
    const dynamicConfig = `
window.ZEROGUARD_CONFIG = {
  API_BASE_URL: ${JSON.stringify(process.env.BACKEND_URL)},
  REQUEST_TIMEOUT_MS: 45000,
  APP_NAME: 'ZeroGuard',
  APP_VERSION: '1.0.0-hackfest2026',
  TAGLINE: 'Secure Your Code. Detect Vulnerabilities. Verify Your Fixes.'
};
`;
    res.writeHead(200, {
      'Content-Type': 'text/javascript; charset=utf-8',
      'Cache-Control': 'no-cache'
    });
    res.end(dynamicConfig);
    return;
  }

  // 3. Static File Serving
  if (reqPath === '/') {
    reqPath = '/index.html';
  }

  const safePath = path.normalize(reqPath).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, safePath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Fallback to index.html for SPA routing
      const indexPath = path.join(PUBLIC_DIR, 'index.html');
      fs.readFile(indexPath, (readErr, content) => {
        if (readErr) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end('404 Not Found');
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(content);
      });
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('500 Internal Server Error');
        return;
      }
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': 'no-cache'
      });
      res.end(content);
    });
  });
});

server.listen(PORT, () => {
  console.log(`\n========================================`);
  console.log(`  ZeroGuard Code Security Platform  `);
  console.log(`  Frontend server: http://localhost:${PORT}`);
  console.log(`  Backend target:  http://${BACKEND_HOST}:${BACKEND_PORT}`);
  console.log(`========================================\n`);
});
