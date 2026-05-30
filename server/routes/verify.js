const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const { computeScore } = require('../scorer');

const router = express.Router();

// POST /api/signal — called by the JS SDK (browser → SilentShield)
router.post('/signal', (req, res) => {
  try {
    const signals = req.body || {};
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
    const ua = req.headers['user-agent'] || '';
    const siteId = signals.siteId || null;

    if (siteId) {
      const site = db.prepare('SELECT * FROM sites WHERE public_key = ?').get(siteId);
      if (!site) return res.status(403).json({ error: 'Unknown site key' });
      if (site.plan === 'free' && site.monthly_requests >= 50000) {
        return res.status(429).json({ error: 'Monthly limit reached. Upgrade at silentshield.io' });
      }
    }

    const { score, verdict, breakdown } = computeScore(signals, ip, ua);
    const token = uuidv4();
    const signalsJson = JSON.stringify(signals);

    db.prepare(`INSERT INTO tokens (token, site_id, signals, score, verdict) VALUES (?, ?, ?, ?, ?)`).run(token, siteId, signalsJson, score, verdict);

    const ipHash = Buffer.from(ip).toString('base64').slice(0, 16);
    db.prepare(`
      INSERT INTO submissions (id, site_id, score, verdict, behavior_score, input_score, env_score, ip_hash, user_agent, form_fill_ms, mouse_events, scroll_events, honeypot_triggered, spam_detected, signals)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      uuidv4(), siteId, score, verdict,
      breakdown.behaviorScore, breakdown.inputScore, breakdown.envScore,
      ipHash, ua, signals.formFillMs || 0,
      signals.mouseEvents || 0, signals.scrollEvents || 0,
      breakdown.honeypotScore < 0 ? 1 : 0,
      breakdown.spamScore < 0 ? 1 : 0,
      signalsJson
    );

    if (siteId) {
      db.prepare(`UPDATE sites SET monthly_requests = monthly_requests + 1 WHERE public_key = ?`).run(siteId);
    }

    res.json({ token, score, verdict });
  } catch (err) {
    console.error('[/api/signal]', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// POST /api/verify — called by the developer's server
router.post('/verify', (req, res) => {
  try {
    const { token, secret } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token required' });

    if (secret) {
      const site = db.prepare('SELECT id FROM sites WHERE secret_key = ?').get(secret);
      if (!site) return res.status(403).json({ error: 'Invalid secret key' });
    }

    const record = db.prepare('SELECT * FROM tokens WHERE token = ?').get(token);
    if (!record) return res.json({ valid: false, error: 'Token not found or expired' });
    if (record.used) return res.json({ valid: false, error: 'Token already used' });

    db.prepare('UPDATE tokens SET used = 1 WHERE token = ?').run(token);

    const valid = record.verdict === 'human' || record.verdict === 'suspicious';
    res.json({ valid, score: record.score, verdict: record.verdict, timestamp: record.created_at });
  } catch (err) {
    console.error('[/api/verify]', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// POST /api/register — register a new site
router.post('/register', (req, res) => {
  try {
    const { domain, name } = req.body || {};
    if (!domain) return res.status(400).json({ error: 'domain required' });

    const cleanDomain = domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    const existing = db.prepare('SELECT public_key, secret_key, plan, monthly_requests FROM sites WHERE domain = ?').get(cleanDomain);
    if (existing) {
      return res.json({ message: 'Site already registered', ...existing });
    }

    const id = uuidv4();
    const publicKey = 'pk_' + uuidv4().replace(/-/g, '').slice(0, 24);
    const secretKey = 'sk_' + uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');

    db.prepare(`INSERT INTO sites (id, domain, name, public_key, secret_key) VALUES (?, ?, ?, ?, ?)`).run(id, cleanDomain, name || cleanDomain, publicKey, secretKey);

    res.json({ message: 'Site registered successfully', public_key: publicKey, secret_key: secretKey, plan: 'free', monthly_limit: 50000 });
  } catch (err) {
    console.error('[/api/register]', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

module.exports = router;
