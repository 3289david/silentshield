const express = require('express');
const db = require('../db');

const router = express.Router();

function requireSecret(req, res, next) {
  const secret = req.headers['x-secret-key'] || req.query.secret;
  if (!secret) return res.status(401).json({ error: 'x-secret-key header required' });

  const site = db.prepare('SELECT * FROM sites WHERE secret_key = ?').get(secret);
  if (!site) return res.status(403).json({ error: 'Invalid secret key' });

  req.site = site;
  next();
}

// GET /api/analytics/overview
router.get('/overview', requireSecret, (req, res) => {
  const { site } = req;
  const since24h = new Date(Date.now() - 86400000).toISOString();
  const since7d = new Date(Date.now() - 7 * 86400000).toISOString();

  const today = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN verdict='bot' THEN 1 ELSE 0 END) as blocked,
      SUM(CASE WHEN verdict='human' THEN 1 ELSE 0 END) as passed,
      SUM(CASE WHEN verdict='suspicious' THEN 1 ELSE 0 END) as suspicious,
      AVG(score) as avg_score
    FROM submissions WHERE site_id = ? AND timestamp > ?
  `).get(site.public_key, since24h);

  const week = db.prepare(`
    SELECT
      strftime('%Y-%m-%d', timestamp) as date,
      COUNT(*) as total,
      SUM(CASE WHEN verdict='bot' THEN 1 ELSE 0 END) as blocked
    FROM submissions WHERE site_id = ? AND timestamp > ?
    GROUP BY date ORDER BY date DESC
  `).all(site.public_key, since7d);

  const threats = db.prepare(`
    SELECT
      SUM(CASE WHEN honeypot_triggered=1 THEN 1 ELSE 0 END) as honeypot,
      SUM(CASE WHEN spam_detected=1 THEN 1 ELSE 0 END) as spam,
      SUM(CASE WHEN verdict='bot' THEN 1 ELSE 0 END) as bot_submissions
    FROM submissions WHERE site_id = ? AND timestamp > ?
  `).get(site.public_key, since24h);

  res.json({
    site: {
      domain: site.domain,
      plan: site.plan,
      monthly_requests: site.monthly_requests,
      monthly_limit: 50000,
    },
    today,
    week,
    threats,
  });
});

// GET /api/analytics/patterns — learned bot patterns
router.get('/patterns', requireSecret, (req, res) => {
  const patterns = db.prepare(`
    SELECT pattern_type, pattern_value, score_adjustment, hit_count, confidence, last_updated
    FROM bot_patterns
    ORDER BY hit_count DESC, confidence DESC
    LIMIT 50
  `).all();

  res.json({ patterns });
});

// GET /api/analytics/recent — recent submissions
router.get('/recent', requireSecret, (req, res) => {
  const { site } = req;
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);

  const rows = db.prepare(`
    SELECT id, score, verdict, behavior_score, input_score, env_score,
           country, user_agent, form_fill_ms, mouse_events, scroll_events,
           honeypot_triggered, spam_detected, timestamp
    FROM submissions WHERE site_id = ?
    ORDER BY timestamp DESC LIMIT ?
  `).all(site.public_key, limit);

  res.json({ submissions: rows });
});

// GET /api/analytics/admin — admin-only global stats (for dashboard)
router.get('/admin', (req, res) => {
  const adminSecret = req.headers['x-admin-secret'] || req.query.adminSecret;
  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  const since24h = new Date(Date.now() - 86400000).toISOString();

  const global = db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN verdict='bot' THEN 1 ELSE 0 END) as blocked,
      SUM(CASE WHEN verdict='human' THEN 1 ELSE 0 END) as passed
    FROM submissions WHERE timestamp > ?
  `).get(since24h);

  const sites = db.prepare('SELECT COUNT(*) as count FROM sites').get();
  const patterns = db.prepare('SELECT COUNT(*) as count FROM bot_patterns').get();
  const topPatterns = db.prepare(`
    SELECT pattern_type, pattern_value, hit_count, confidence
    FROM bot_patterns ORDER BY hit_count DESC LIMIT 10
  `).all();

  const hourly = db.prepare(`
    SELECT strftime('%H:00', timestamp) as hour,
           COUNT(*) as total,
           SUM(CASE WHEN verdict='bot' THEN 1 ELSE 0 END) as blocked
    FROM submissions WHERE timestamp > ?
    GROUP BY hour ORDER BY hour
  `).all(since24h);

  res.json({ global, sites, patterns, topPatterns, hourly });
});

module.exports = router;
