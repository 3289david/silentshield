const express = require('express');
const { v4: uuidv4 } = require('uuid');
const db = require('../db');
const { computeScore } = require('../scorer');

const router = express.Router();

// POST /api/signal — called by the JS SDK. No key required.
router.post('/signal', (req, res) => {
  try {
    const signals = req.body || {};
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
    const ua = req.headers['user-agent'] || '';
    // siteId is purely optional — for analytics grouping only
    const siteId = signals.siteId || null;

    const { score, verdict, breakdown } = computeScore(signals, ip, ua);
    const token = uuidv4();
    const signalsJson = JSON.stringify(signals);

    db.prepare(`INSERT INTO tokens (token, site_id, signals, score, verdict) VALUES (?, ?, ?, ?, ?)`).run(token, siteId, signalsJson, score, verdict);

    const ipHash = Buffer.from(ip).toString('base64').slice(0, 16);
    db.prepare(`
      INSERT INTO submissions (id, site_id, score, verdict, behavior_score, input_score, env_score,
        ip_hash, user_agent, form_fill_ms, mouse_events, scroll_events,
        honeypot_triggered, spam_detected, signals)
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

    res.json({ token, score, verdict });
  } catch (err) {
    console.error('[/api/signal]', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// POST /api/verify — verify a token server-side. Secret key optional.
router.post('/verify', (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token required' });

    const record = db.prepare('SELECT * FROM tokens WHERE token = ?').get(token);
    if (!record) return res.json({ valid: false, error: 'Token not found or expired' });
    if (record.used) return res.json({ valid: false, error: 'Token already used' });

    db.prepare('UPDATE tokens SET used = 1 WHERE token = ?').run(token);

    const valid = record.verdict !== 'bot';
    res.json({ valid, score: record.score, verdict: record.verdict, timestamp: record.created_at });
  } catch (err) {
    console.error('[/api/verify]', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// POST /api/register — optional site registration for dashboard analytics
router.post('/register', (req, res) => {
  try {
    const { domain, name } = req.body || {};
    if (!domain) return res.status(400).json({ error: 'domain required' });

    const cleanDomain = domain.toLowerCase().trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
    const existing = db.prepare('SELECT public_key, secret_key FROM sites WHERE domain = ?').get(cleanDomain);
    if (existing) return res.json({ message: 'Site already registered', ...existing });

    const id = uuidv4();
    const publicKey  = 'pk_' + uuidv4().replace(/-/g, '').slice(0, 24);
    const secretKey  = 'sk_' + uuidv4().replace(/-/g, '') + uuidv4().replace(/-/g, '');

    db.prepare(`INSERT INTO sites (id, domain, name, public_key, secret_key) VALUES (?, ?, ?, ?, ?)`).run(id, cleanDomain, name || cleanDomain, publicKey, secretKey);

    res.json({
      message: 'Site registered — dashboard analytics enabled',
      public_key: publicKey,
      secret_key: secretKey,
      note: 'Keys are optional — SilentShield works without them. Use them only for analytics.',
    });
  } catch (err) {
    console.error('[/api/register]', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

module.exports = router;
