// VULNERABLE: Input Validation and Prototype Pollution
// CWE-20 (Improper Input Validation), CWE-913 (Resource Control / Prototype Pollution)

const _ = require('lodash');
const express = require('express');
const app = express();

// CWE-913: Prototype pollution via Object.assign
app.post('/api/config', (req, res) => {
  const defaults = { theme: 'light', lang: 'en' };
  const config = Object.assign(defaults, req.body);
  res.json(config);
});

// CWE-913: Prototype pollution via spread + merge
app.put('/api/settings', (req, res) => {
  const settings = { ...globalSettings };
  deepMerge(settings, req.body);
  res.json(settings);
});

// CWE-913: lodash merge (pre-fix versions)
app.post('/api/user/preferences', (req, res) => {
  const prefs = _.merge({}, defaultPrefs, req.body);
  res.json(prefs);
});

// CWE-20: No validation on numeric input
app.get('/api/items', (req, res) => {
  const page = req.query.page;
  const limit = req.query.limit;
  db.query('SELECT * FROM items LIMIT ' + limit + ' OFFSET ' + (page * limit));
});

// CWE-20: No type checking
app.post('/api/transfer', (req, res) => {
  const amount = req.body.amount;
  // No validation — could be negative, NaN, or huge
  processTransfer(req.body.from, req.body.to, amount);
});

// CWE-913: Dynamic property access
app.post('/api/update', (req, res) => {
  const obj = {};
  for (const [key, value] of Object.entries(req.body)) {
    obj[key] = value; // __proto__ pollution possible
  }
  res.json(obj);
});

// CWE-20: Regex DoS — catastrophic backtracking
const EMAIL_REGEX = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
app.post('/api/validate-email', (req, res) => {
  const valid = EMAIL_REGEX.test(req.body.email);
  res.json({ valid });
});
