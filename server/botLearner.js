const cron = require('node-cron');

function analyzePeriod(windowMinutes = 10) {
  const db = require('./db');
  const since = new Date(Date.now() - windowMinutes * 60 * 1000).toISOString();

  const recent = db.prepare(`SELECT * FROM submissions WHERE timestamp > ? ORDER BY timestamp DESC`).all(since);
  if (recent.length < 3) return;

  const bots = recent.filter((r) => r.verdict === 'bot');
  const humans = recent.filter((r) => r.verdict === 'human');
  if (bots.length === 0) return;

  console.log(`[BotLearner] Analyzing ${recent.length} submissions (${bots.length} bots, ${humans.length} humans)`);

  // Learn user agent patterns
  const uaCounts = {};
  for (const s of bots) {
    const ua = s.user_agent || '';
    const match = ua.match(/^([A-Za-z][\w\-]+)[\/\s]/);
    if (match) {
      const key = match[1];
      uaCounts[key] = (uaCounts[key] || 0) + 1;
    }
  }

  for (const [ua, count] of Object.entries(uaCounts)) {
    if (count >= 2) {
      const humanMatch = humans.filter((h) => (h.user_agent || '').startsWith(ua)).length;
      if (humanMatch === 0) {
        const confidence = Math.min(0.99, 0.5 + count / (bots.length * 2));
        const adj = Math.max(-50, -20 - count * 2);
        const existing = db.prepare(`SELECT id FROM bot_patterns WHERE pattern_type='user_agent' AND pattern_value=?`).get(ua);
        if (existing) {
          db.prepare(`UPDATE bot_patterns SET hit_count=hit_count+?, confidence=MIN(0.99,confidence+0.05), score_adjustment=MAX(-50,score_adjustment-1), last_updated=datetime('now') WHERE pattern_type='user_agent' AND pattern_value=?`).run(count, ua);
        } else {
          db.prepare(`INSERT INTO bot_patterns (pattern_type,pattern_value,score_adjustment,hit_count,confidence) VALUES ('user_agent',?,?,?,?)`).run(ua, adj, count, confidence);
          console.log(`[BotLearner] New UA pattern: ${ua} (conf: ${confidence.toFixed(2)})`);
        }
      }
    }
  }

  // Learn timing patterns — fast form fills
  const fastFills = bots.filter((s) => s.form_fill_ms > 0 && s.form_fill_ms < 500);
  if (fastFills.length >= 2) {
    const humanFast = humans.filter((h) => h.form_fill_ms > 0 && h.form_fill_ms < 500).length;
    if (fastFills.length > humanFast * 2) {
      const existing = db.prepare(`SELECT id FROM bot_patterns WHERE pattern_type='timing' AND pattern_value='fill_under_500ms'`).get();
      if (existing) {
        db.prepare(`UPDATE bot_patterns SET hit_count=hit_count+?, confidence=MIN(0.99,confidence+0.02), last_updated=datetime('now') WHERE pattern_type='timing' AND pattern_value='fill_under_500ms'`).run(fastFills.length);
      } else {
        const conf = Math.min(0.99, 0.5 + fastFills.length / (bots.length * 2));
        db.prepare(`INSERT INTO bot_patterns (pattern_type,pattern_value,score_adjustment,hit_count,confidence) VALUES ('timing','fill_under_500ms',-25,?,?)`).run(fastFills.length, conf);
        console.log(`[BotLearner] New timing pattern: fill_under_500ms (conf: ${conf.toFixed(2)})`);
      }
    }
  }

  // Learn behavior patterns — no mouse+scroll activity
  const noInteraction = bots.filter((s) => s.mouse_events === 0 && s.scroll_events === 0);
  if (noInteraction.length >= 2) {
    const humanNoInteract = humans.filter((h) => h.mouse_events === 0 && h.scroll_events === 0).length;
    if (noInteraction.length > humanNoInteract * 2) {
      const existing = db.prepare(`SELECT id FROM bot_patterns WHERE pattern_type='behavior' AND pattern_value='no_mouse_no_scroll'`).get();
      if (existing) {
        db.prepare(`UPDATE bot_patterns SET hit_count=hit_count+?, confidence=MIN(0.99,confidence+0.02), last_updated=datetime('now') WHERE pattern_type='behavior' AND pattern_value='no_mouse_no_scroll'`).run(noInteraction.length);
      } else {
        const conf = Math.min(0.99, 0.5 + noInteraction.length / (bots.length * 2));
        db.prepare(`INSERT INTO bot_patterns (pattern_type,pattern_value,score_adjustment,hit_count,confidence) VALUES ('behavior','no_mouse_no_scroll',-30,?,?)`).run(noInteraction.length, conf);
        console.log(`[BotLearner] New behavior pattern: no_mouse_no_scroll (conf: ${conf.toFixed(2)})`);
      }
    }
  }

  // Learn zero-time pattern — instant submissions
  const zeroTime = bots.filter((s) => s.form_fill_ms === 0);
  if (zeroTime.length >= 3 && zeroTime.length > humans.filter(h => h.form_fill_ms === 0).length * 2) {
    const existing = db.prepare(`SELECT id FROM bot_patterns WHERE pattern_type='timing' AND pattern_value='zero_fill_time'`).get();
    if (existing) {
      db.prepare(`UPDATE bot_patterns SET hit_count=hit_count+?, confidence=MIN(0.99,confidence+0.03), last_updated=datetime('now') WHERE pattern_type='timing' AND pattern_value='zero_fill_time'`).run(zeroTime.length);
    } else {
      db.prepare(`INSERT INTO bot_patterns (pattern_type,pattern_value,score_adjustment,hit_count,confidence) VALUES ('timing','zero_fill_time',-35,?,?)`).run(zeroTime.length, 0.75);
      console.log('[BotLearner] New timing pattern: zero_fill_time');
    }
  }

  // Honeypot pattern
  const honeypotBots = bots.filter(s => s.honeypot_triggered);
  if (honeypotBots.length >= 2) {
    const existing = db.prepare(`SELECT id FROM bot_patterns WHERE pattern_type='behavior' AND pattern_value='honeypot_triggered'`).get();
    if (existing) {
      db.prepare(`UPDATE bot_patterns SET hit_count=hit_count+?, confidence=MIN(0.99,confidence+0.03), last_updated=datetime('now') WHERE pattern_type='behavior' AND pattern_value='honeypot_triggered'`).run(honeypotBots.length);
    } else {
      db.prepare(`INSERT INTO bot_patterns (pattern_type,pattern_value,score_adjustment,hit_count,confidence) VALUES ('behavior','honeypot_triggered',-50,?,0.95)`).run(honeypotBots.length);
      console.log('[BotLearner] New behavior pattern: honeypot_triggered');
    }
  }

  // Decay old low-confidence patterns
  db.prepare(`UPDATE bot_patterns SET confidence=MAX(0.1,confidence-0.01) WHERE last_updated < datetime('now','-6 hours') AND pattern_type='user_agent'`).run();

  console.log(`[BotLearner] Learning cycle complete. Patterns in DB: ${db.prepare('SELECT COUNT(*) as c FROM bot_patterns').get().c}`);
}

function startBotLearner() {
  // Run immediately on startup with a wider window to pick up historical data
  setTimeout(() => {
    try {
      console.log('[BotLearner] Initial analysis (last 24h)...');
      analyzePeriod(60 * 24);
    } catch(err) {
      console.error('[BotLearner] Initial run error:', err.message);
    }
  }, 3000);

  // Every 10 minutes — analyze recent window
  cron.schedule('*/10 * * * *', () => {
    try { analyzePeriod(10); }
    catch (err) { console.error('[BotLearner] Error:', err.message); }
  });

  // Every hour — clean expired tokens
  cron.schedule('0 * * * *', () => {
    const db = require('./db');
    db.prepare(`DELETE FROM tokens WHERE created_at < datetime('now','-1 hour')`).run();
  });

  console.log('[BotLearner] Scheduled — runs every 10 minutes');
}

module.exports = { startBotLearner, analyzePeriod };
