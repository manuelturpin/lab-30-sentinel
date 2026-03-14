// INTENTIONALLY VULNERABLE APP — FOR SENTINEL E2E TESTING ONLY
// DO NOT use in production. Every pattern here is a known vulnerability.

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// VULN: Permissive CORS
app.use(cors());

// VULN: Hardcoded secret
const JWT_SECRET = 'super-secret-key-12345';
const API_KEY = 'sk-proj-abcdef1234567890abcdef1234567890';

// VULN: Hardcoded DB credentials
const pool = new Pool({
  connectionString: 'postgres://admin:password123@localhost:5432/mydb'
});

// VULN: SQL injection via string concatenation
app.get('/api/users/:id', async (req, res) => {
  const result = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(result.rows);
});

// VULN: No auth check on admin endpoint
app.delete('/api/admin/users/:id', async (req, res) => {
  await pool.query(`DELETE FROM users WHERE id = ${req.params.id}`);
  res.json({ deleted: true });
});

// VULN: XSS via innerHTML pattern
app.get('/api/search', (req, res) => {
  const html = `<div>${req.query.q}</div>`;
  res.send(html);
});

// VULN: JWT without expiration
app.post('/api/login', (req, res) => {
  const token = jwt.sign({ user: req.body.username }, JWT_SECRET);
  res.json({ token });
});

// VULN: SSRF - user controlled URL
app.post('/api/fetch-url', async (req, res) => {
  const response = await fetch(req.body.url);
  const data = await response.text();
  res.send(data);
});

// VULN: Sensitive data in logs
app.post('/api/register', (req, res) => {
  console.log('New user registration:', req.body.password);
  res.json({ success: true });
});

// VULN: No rate limiting on login
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
