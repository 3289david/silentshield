const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../db');

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-me';
const JWT_EXPIRY = '30d';

// POST /api/auth/login — verify secret key, return 30-day JWT
router.post('/login', (req, res) => {
  try {
    const secret = req.body.secret_key || req.headers['x-secret-key'];
    if (!secret) return res.status(400).json({ error: 'secret_key required' });

    const site = db.prepare('SELECT * FROM sites WHERE secret_key = ?').get(secret);
    if (!site) return res.status(403).json({ error: 'Invalid secret key' });

    const token = jwt.sign(
      { site_id: site.id, public_key: site.public_key, domain: site.domain },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    res.json({
      token,
      expires_in: 30 * 24 * 3600,
      site: {
        domain: site.domain,
        public_key: site.public_key,
      },
    });
  } catch (err) {
    console.error('[/api/auth/login]', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// GET /api/auth/me — verify JWT, return site info
router.get('/me', (req, res) => {
  try {
    const auth = req.headers['authorization'] || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Bearer token required' });

    const payload = jwt.verify(token, JWT_SECRET);
    const site = db.prepare('SELECT public_key, secret_key, domain FROM sites WHERE public_key = ?').get(payload.public_key);
    if (!site) return res.status(404).json({ error: 'Site not found' });

    res.json({
      domain: site.domain,
      public_key: site.public_key,
      secret_key: site.secret_key,
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expired' });
    if (err.name === 'JsonWebTokenError') return res.status(401).json({ error: 'Invalid token' });
    console.error('[/api/auth/me]', err);
    res.status(500).json({ error: 'Internal error' });
  }
});

module.exports = router;
module.exports.JWT_SECRET = JWT_SECRET;
