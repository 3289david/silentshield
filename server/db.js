const path = require('path');
const fs = require('fs');
require('dotenv').config();

const { DbWrapper } = require('./db-wrapper');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'silentshield.db');

let _db = null;

// Proxy: routes import `db` at module load time (before init).
// Proxy delegates to real db once init() has been called.
const db = new Proxy({}, {
  get(_, prop) {
    if (prop === 'init') return init;
    if (!_db) throw new Error('[SilentShield] Database not initialized. await db.init() first.');
    const val = _db[prop];
    return typeof val === 'function' ? val.bind(_db) : val;
  },
});

async function init() {
  if (_db) return db;

  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs();

  let sqliteDb;
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    sqliteDb = new SQL.Database(buf);
  } else {
    sqliteDb = new SQL.Database();
  }

  _db = new DbWrapper(sqliteDb, DB_PATH);

  _db.exec(`
    CREATE TABLE IF NOT EXISTS sites (
      id TEXT PRIMARY KEY,
      domain TEXT NOT NULL,
      name TEXT,
      public_key TEXT UNIQUE NOT NULL,
      secret_key TEXT UNIQUE NOT NULL,
      plan TEXT DEFAULT 'free',
      monthly_requests INTEGER DEFAULT 0,
      month_reset TEXT DEFAULT (strftime('%Y-%m', 'now')),
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS submissions (
      id TEXT PRIMARY KEY,
      site_id TEXT,
      score INTEGER NOT NULL,
      verdict TEXT NOT NULL,
      behavior_score INTEGER DEFAULT 0,
      input_score INTEGER DEFAULT 0,
      env_score INTEGER DEFAULT 0,
      ip_hash TEXT,
      country TEXT DEFAULT 'XX',
      user_agent TEXT,
      form_fill_ms INTEGER DEFAULT 0,
      mouse_events INTEGER DEFAULT 0,
      scroll_events INTEGER DEFAULT 0,
      honeypot_triggered INTEGER DEFAULT 0,
      spam_detected INTEGER DEFAULT 0,
      signals TEXT,
      timestamp TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS bot_patterns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pattern_type TEXT NOT NULL,
      pattern_value TEXT NOT NULL,
      score_adjustment INTEGER DEFAULT -30,
      hit_count INTEGER DEFAULT 0,
      confidence REAL DEFAULT 0.5,
      last_updated TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS tokens (
      token TEXT PRIMARY KEY,
      site_id TEXT,
      signals TEXT NOT NULL,
      score INTEGER,
      verdict TEXT,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Seed initial known bot patterns
  const seed = _db.prepare(`
    INSERT OR IGNORE INTO bot_patterns (pattern_type, pattern_value, score_adjustment, hit_count, confidence)
    SELECT ?, ?, ?, ?, ?
    WHERE NOT EXISTS (SELECT 1 FROM bot_patterns WHERE pattern_type = ? AND pattern_value = ?)
  `);

  const patterns = [
    ['user_agent', 'HeadlessChrome', -40, 0, 0.95],
    ['user_agent', 'PhantomJS', -50, 0, 0.99],
    ['user_agent', 'Puppeteer', -50, 0, 0.99],
    ['user_agent', 'Selenium', -50, 0, 0.99],
    ['user_agent', 'python-requests', -50, 0, 0.99],
    ['user_agent', 'curl/', -40, 0, 0.95],
    ['user_agent', 'wget/', -40, 0, 0.95],
    ['user_agent', 'Go-http-client', -40, 0, 0.9],
    ['user_agent', 'axios/', -30, 0, 0.85],
    ['user_agent', 'scrapy', -50, 0, 0.99],
    ['timing', 'fill_under_500ms', -40, 0, 0.9],
    ['timing', 'fill_under_1000ms', -20, 0, 0.75],
    ['behavior', 'no_mouse_no_scroll', -25, 0, 0.85],
    ['behavior', 'perfect_timing', -20, 0, 0.8],
  ];

  for (const [type, val, adj, hits, conf] of patterns) {
    seed.run(type, val, adj, hits, conf, type, val);
  }

  console.log(`[DB] Initialized — ${fs.existsSync(DB_PATH) ? 'loaded from disk' : 'new database'}`);
  return db;
}

db.init = init;

module.exports = db;
