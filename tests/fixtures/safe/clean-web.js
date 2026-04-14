// SAFE: Properly secured web application patterns
// These should NOT trigger detection patterns

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// SAFE: Fetch with allowlist — not SSRF
const ALLOWED_HOSTS = ['api.internal.com', 'cdn.example.com'];
app.post('/api/proxy', async (req, res) => {
  const url = new URL(req.body.url);
  if (!ALLOWED_HOSTS.includes(url.hostname)) {
    return res.status(403).json({ error: 'Host not allowed' });
  }
  const response = await fetch(url.toString());
  res.json(await response.json());
});

// SAFE: No eval — using JSON.parse for data
app.post('/api/calculate', (req, res) => {
  const { a, b, op } = req.body;
  const ops = { add: (x, y) => x + y, sub: (x, y) => x - y };
  if (!ops[op]) return res.status(400).json({ error: 'Invalid operation' });
  res.json({ result: ops[op](Number(a), Number(b)) });
});

// SAFE: Path traversal prevented with path.resolve + check
const path = require('path');
const UPLOADS_DIR = path.resolve('/uploads');
app.get('/api/files', (req, res) => {
  const filePath = path.resolve(UPLOADS_DIR, req.query.filename);
  if (!filePath.startsWith(UPLOADS_DIR)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.sendFile(filePath);
});

// SAFE: Authentication middleware present
const requireAuth = require('./middleware/auth');
app.delete('/api/admin/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ deleted: true });
});

// SAFE: Input validation
app.post('/api/process', [
  body('input').isString().trim().isLength({ min: 1, max: 1000 }),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  processChecked(req.body.input);
  res.json({ ok: true });
});

// SAFE: Static string, not user-controlled exec
const { execFile } = require('child_process');
function checkDiskSpace() {
  execFile('df', ['-h'], (err, stdout) => {
    console.log(stdout);
  });
}

// SAFE: Proper prototype pollution prevention
app.post('/api/config', (req, res) => {
  const safeKeys = ['theme', 'lang', 'timezone'];
  const config = {};
  for (const key of safeKeys) {
    if (req.body[key]) config[key] = String(req.body[key]);
  }
  res.json(config);
});

app.listen(3000);
