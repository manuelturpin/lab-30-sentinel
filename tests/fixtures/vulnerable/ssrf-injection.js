// INTENTIONALLY VULNERABLE — Sentinel rule-tester fixtures
// DO NOT use in production. Every pattern here is a known vulnerability.
// CWE-918, CWE-94, CWE-22, CWE-306, CWE-284, CWE-269, CWE-20

const express = require('express');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const app = express();
app.use(express.json());

// CWE-918: SSRF — user-controlled URL fetched server-side
app.post('/api/proxy', async (req, res) => {
  const response = await fetch(req.body.url);
  const data = await response.text();
  res.send(data);
});

// CWE-918: SSRF via URL parameter
app.get('/api/preview', async (req, res) => {
  const response = await fetch(req.query.target_url);
  res.json(await response.json());
});

// CWE-94: Code injection via eval
app.post('/api/calculate', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// CWE-94: Code injection via Function constructor
app.post('/api/template', (req, res) => {
  const fn = new Function('data', req.body.template);
  res.send(fn(req.body.data));
});

// CWE-94: Command injection via exec
app.get('/api/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, stdout) => {
    res.send(stdout);
  });
});

// CWE-22: Path traversal — unsanitized file path
app.get('/api/files', (req, res) => {
  const filePath = path.join('/uploads', req.query.filename);
  const content = fs.readFileSync(filePath, 'utf8');
  res.send(content);
});

// CWE-22: Directory traversal via params
app.get('/api/download/:name', (req, res) => {
  res.sendFile('/data/' + req.params.name);
});

// CWE-306: Missing authentication on admin endpoint
app.delete('/api/admin/users/:id', (req, res) => {
  db.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.json({ deleted: true });
});

// CWE-284: Improper access control — no role check
app.put('/api/users/:id/role', (req, res) => {
  db.query('UPDATE users SET role = ? WHERE id = ?', [req.body.role, req.params.id]);
  res.json({ updated: true });
});

// CWE-269: Privilege escalation — self-promotion
app.post('/api/promote', (req, res) => {
  db.query('UPDATE users SET is_admin = true WHERE id = ?', [req.user.id]);
  res.json({ promoted: true });
});

// CWE-20: No input validation
app.post('/api/process', (req, res) => {
  const data = req.body;
  processUnchecked(data.input);
  res.json({ ok: true });
});
