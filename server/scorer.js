const KNOWN_BOT_UAS = [
  'headlesschrome', 'phantomjs', 'puppeteer', 'selenium', 'webdriver',
  'python-requests', 'python-urllib', 'curl/', 'wget/', 'go-http-client',
  'java/', 'scrapy', 'mechanize', 'httpie', 'axios/', 'got/',
  'node-fetch', 'undici', 'okhttp', 'apache-httpclient',
];

const CLOUD_RANGES = [
  /^3\.(8[0-9]|9[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\./,
  /^104\.(1[6-9][0-9]|2[0-4][0-9]|25[0-5])\./,
  /^35\./, /^34\./, /^13\./, /^52\./,
];

function isCloudIP(ip) {
  if (!ip) return false;
  return CLOUD_RANGES.some((r) => r.test(ip));
}

function getDB() {
  return require('./db');
}

function scoreUserAgent(ua) {
  if (!ua) return -20;
  const lower = ua.toLowerCase();
  for (const bot of KNOWN_BOT_UAS) {
    if (lower.includes(bot)) return -40;
  }
  // Check learned patterns
  try {
    const db = getDB();
    const patterns = db.prepare(`
      SELECT score_adjustment FROM bot_patterns
      WHERE pattern_type = 'user_agent'
      ORDER BY confidence DESC
    `).all();
    for (const p of patterns) {
      if (lower.includes((p.pattern_value || '').toLowerCase())) {
        return p.score_adjustment;
      }
    }
  } catch (_) {}
  if (/chrome|firefox|safari|edge|opera/i.test(ua)) return 10;
  return 0;
}

function scoreBehavior(signals) {
  let score = 0;
  const { mouseEvents = 0, scrollEvents = 0, clickEvents = 0 } = signals;
  if (mouseEvents > 10) score += 15;
  else if (mouseEvents > 0) score += 5;
  if (scrollEvents > 0) score += 10;
  if (clickEvents > 0) score += 5;
  if (mouseEvents === 0 && scrollEvents === 0) score -= 25;
  return Math.max(-40, Math.min(30, score));
}

function scoreInput(signals) {
  let score = 0;
  const {
    formFillMs = 0,
    keystrokeIntervals = [],
    backspaceCount = 0,
    tabCount = 0,
  } = signals;

  if (formFillMs > 0 && formFillMs < 500) score -= 40;
  else if (formFillMs > 0 && formFillMs < 1000) score -= 20;
  else if (formFillMs > 3000 && formFillMs < 300000) score += 20;
  else if (formFillMs >= 300000) score += 5;

  const intervals = Array.isArray(keystrokeIntervals) ? keystrokeIntervals : [];
  if (intervals.length > 2) {
    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, v) => sum + Math.pow(v - avg, 2), 0) / intervals.length;
    if (variance > 500) score += 15;
    else if (variance < 10 && intervals.length > 5) score -= 20;
  }

  if (backspaceCount > 0) score += 5;
  if (tabCount > 0) score += 5;
  return Math.max(-40, Math.min(30, score));
}

function scoreEnvironment(signals, ip) {
  if (signals.webdriver) return -50;
  let score = 0;
  const { screenWidth = 0, screenHeight = 0, colorDepth = 0, pluginCount = 0, hardwareConcurrency = 0 } = signals;
  if (screenWidth > 800 && screenHeight > 600) score += 8;
  else if (screenWidth === 0) score -= 10;
  if (colorDepth >= 24) score += 5;
  if (pluginCount > 0) score += 7;
  if (hardwareConcurrency > 0) score += 5;
  if (isCloudIP(ip)) score -= 30;
  return Math.max(-50, Math.min(25, score));
}

function scoreSpam(signals) {
  const text = (signals.formText || '').toLowerCase();
  if (!text) return 0;
  const keywords = ['seo service','backlink','buy followers','crypto investment','click here','make money fast','casino','viagra','cheap meds','loan offer','prize winner'];
  for (const kw of keywords) {
    if (text.includes(kw)) return -50;
  }
  return 0;
}

function computeScore(signals, ip, ua) {
  const behaviorScore = scoreBehavior(signals);
  const inputScore = scoreInput(signals);
  const envScore = scoreEnvironment(signals, ip);
  const spamScore = scoreSpam(signals);
  const uaScore = scoreUserAgent(ua);
  const honeypotScore = signals.honeypotFilled ? -100 : 0;

  const raw = 50 + behaviorScore + inputScore + envScore + spamScore + uaScore + honeypotScore;
  const score = Math.max(0, Math.min(100, raw));

  let verdict;
  if (score >= 70) verdict = 'human';
  else if (score >= 45) verdict = 'suspicious';
  else verdict = 'bot';

  return { score, verdict, breakdown: { behaviorScore, inputScore, envScore, uaScore, honeypotScore, spamScore } };
}

module.exports = { computeScore };
