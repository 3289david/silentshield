const crypto = require('crypto');

const KNOWN_BOT_UAS = [
  'headlesschrome','phantomjs','puppeteer','selenium','webdriver',
  'python-requests','python-urllib','curl/','wget/','go-http-client',
  'java/','scrapy','mechanize','httpie','axios/','got/',
  'node-fetch','undici','okhttp','apache-httpclient','libwww-perl',
  'lwp-useragent','perl','ruby','php','perl ','perl/',
];

const CLOUD_RANGES = [
  /^3\.(8[0-9]|9[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\./,
  /^104\.(1[6-9][0-9]|2[0-4][0-9]|25[0-5])\./,
  /^35\./, /^34\./, /^13\./, /^52\./, /^54\./,
  /^18\.(2[0-9]{2}|[0-9]{2})\./,
  /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private (server-side)
];

// Known headless WebGL renderer substrings
const HEADLESS_GL = ['swiftshader','llvmpipe','softpipe','mesa','angle (','vmware','virtualbox','parallels','microsoft basic render'];

// Known blank/identical canvas fingerprints from headless (detected empirically)
const HEADLESS_CANVAS_SUFFIXES = [
  'AAAAAAAAAA==',
  'wAAAANSUhEUg',
];

function isCloudIP(ip) {
  return ip ? CLOUD_RANGES.some((r) => r.test(ip)) : false;
}

function verifyPoW(challenge, nonce, hash, difficulty) {
  if (!challenge || nonce === undefined || !hash) return false;
  try {
    const expected = crypto.createHash('sha256').update(String(challenge) + String(nonce)).digest('hex');
    const target   = '0'.repeat(difficulty || 3);
    return expected === hash && hash.startsWith(target);
  } catch (_) { return false; }
}

function getDB() { return require('./db'); }

function scoreUserAgent(ua) {
  if (!ua) return -25;
  const lower = ua.toLowerCase();
  for (const bot of KNOWN_BOT_UAS) {
    if (lower.includes(bot)) return -45;
  }
  try {
    const patterns = getDB().prepare(
      `SELECT score_adjustment, pattern_value FROM bot_patterns WHERE pattern_type = 'user_agent' ORDER BY confidence DESC`
    ).all();
    for (const p of patterns) {
      if (lower.includes((p.pattern_value || '').toLowerCase())) return p.score_adjustment;
    }
  } catch (_) {}
  if (/chrome|firefox|safari|edge|opera/i.test(ua)) return 10;
  return 0;
}

function scoreBehavior(signals) {
  let score = 0;
  const { mouseEvents = 0, scrollEvents = 0, clickEvents = 0, mouseEntropy = 0, blurEvents = 0 } = signals;

  if (mouseEvents > 20) score += 15;
  else if (mouseEvents > 5) score += 8;
  else if (mouseEvents > 0) score += 3;

  if (scrollEvents > 2) score += 10;
  else if (scrollEvents > 0) score += 5;

  if (clickEvents > 0) score += 5;

  // Mouse entropy: humans move in curves, bots in straight lines or not at all
  if (mouseEntropy > 0.05) score += 10;  // curved paths
  else if (mouseEntropy > 0.001) score += 5;
  else if (mouseEvents > 5 && mouseEntropy < 0.0001) score -= 15; // suspiciously linear

  // Tab switching (real browser usage)
  if (blurEvents > 0) score += 3;

  if (mouseEvents === 0 && scrollEvents === 0) score -= 25;

  return Math.max(-40, Math.min(35, score));
}

function scoreInput(signals) {
  let score = 0;
  const {
    formFillMs = 0,
    keystrokeIntervals = [],
    backspaceCount = 0,
    deleteCount = 0,
    tabCount = 0,
    pasteCount = 0,
  } = signals;

  if (formFillMs > 0 && formFillMs < 300) score -= 50;
  else if (formFillMs > 0 && formFillMs < 800) score -= 30;
  else if (formFillMs > 0 && formFillMs < 1500) score -= 10;
  else if (formFillMs > 3000 && formFillMs < 600000) score += 20;
  else if (formFillMs >= 600000) score += 5;

  const intervals = Array.isArray(keystrokeIntervals) ? keystrokeIntervals : [];
  if (intervals.length > 3) {
    const avg      = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((s, v) => s + Math.pow(v - avg, 2), 0) / intervals.length;
    // Human typing has high variance. Bot typing is perfectly metronomic.
    if (variance > 2000) score += 15;
    else if (variance > 500) score += 8;
    else if (variance < 20 && intervals.length > 5) score -= 25;
  }

  if (backspaceCount > 0 || deleteCount > 0) score += 8; // humans make typos
  if (tabCount > 0) score += 5;
  if (pasteCount > 2) score -= 5; // excessive paste is suspicious

  return Math.max(-50, Math.min(30, score));
}

function scoreEnvironment(signals, ip) {
  if (signals.webdriver) return -60; // definitive bot

  let score = 0;
  const {
    screenWidth = 0, screenHeight = 0, colorDepth = 0,
    pluginCount = 0, hardwareConcurrency = 0, deviceMemory = 0,
    cookieEnabled = false, pixelRatio = 1,
    connectionType = '', permissionState = '',
  } = signals;

  if (screenWidth > 800 && screenHeight > 600) score += 8;
  else if (screenWidth === 0 || screenHeight === 0) score -= 15;

  if (colorDepth >= 24) score += 5;
  if (pixelRatio >= 1) score += 3;
  if (pluginCount > 0) score += 8;
  else score -= 5; // headless has 0 plugins
  if (hardwareConcurrency > 0) score += 5;
  if (deviceMemory > 0) score += 3;
  if (cookieEnabled) score += 3;

  // Connection type (only real browsers expose this)
  if (['4g','3g','wifi'].includes(connectionType)) score += 5;

  // Permission prompt available = real browser
  if (permissionState === 'prompt' || permissionState === 'granted') score += 5;

  if (isCloudIP(ip)) score -= 30;

  return Math.max(-60, Math.min(30, score));
}

function scoreFingerprints(signals) {
  let score = 0;
  const { canvasFingerprint = '', webglRenderer = '', webglHeadless = false, audioFingerprint = '' } = signals;

  // WebGL headless renderer check
  if (webglHeadless) score -= 30;
  else if (webglRenderer && webglRenderer !== 'none' && webglRenderer !== 'error') score += 10;

  // Known headless canvas patterns
  const isHeadlessCanvas = HEADLESS_CANVAS_SUFFIXES.some((s) => canvasFingerprint.includes(s));
  if (isHeadlessCanvas) score -= 20;
  else if (canvasFingerprint && canvasFingerprint !== 'blocked' && canvasFingerprint !== 'error') score += 8;
  else if (canvasFingerprint === 'blocked') score -= 5; // privacy mode, slight penalty

  // Audio context (headless Chrome has no real audio pipeline)
  if (typeof audioFingerprint === 'number' && audioFingerprint !== 0) score += 7;
  else if (audioFingerprint === 'error' || audioFingerprint === 'unsupported') score -= 5;

  return Math.max(-50, Math.min(25, score));
}

function scorePoW(signals) {
  const { powChallenge, powNonce, powHash, powMs, powDifficulty = 3 } = signals;

  if (!powChallenge) return -10; // SDK not loaded / signal missing

  const valid = verifyPoW(powChallenge, powNonce, powHash, powDifficulty);
  if (!valid) return -30; // Failed or spoofed PoW

  // Check timing: too fast = pre-computed, too slow = odd
  if (powMs < 5)    return -20;  // solved in <5ms — pre-computed / spoofed
  if (powMs > 60000) return 5;   // took forever but valid
  return 15; // Valid PoW, solved in realistic time
}

function scoreSpam(signals) {
  const text = (signals.formText || '').toLowerCase();
  if (!text) return 0;
  const keywords = [
    'seo service','backlink','buy followers','crypto investment','click here',
    'make money fast','casino','viagra','cheap meds','loan offer','prize winner',
    'work from home','binary options','forex signal','nft drop','free bitcoin',
    'enlargement','weight loss pills','online pharmacy',
  ];
  for (const kw of keywords) { if (text.includes(kw)) return -50; }
  return 0;
}

function computeScore(signals, ip, ua) {
  const behaviorScore     = scoreBehavior(signals);
  const inputScore        = scoreInput(signals);
  const envScore          = scoreEnvironment(signals, ip);
  const fingerprintScore  = scoreFingerprints(signals);
  const powScore          = scorePoW(signals);
  const spamScore         = scoreSpam(signals);
  const uaScore           = scoreUserAgent(ua);
  const honeypotScore     = signals.honeypotFilled ? -100 : 0;

  const raw   = 50 + behaviorScore + inputScore + envScore + fingerprintScore + powScore + spamScore + uaScore + honeypotScore;
  const score = Math.max(0, Math.min(100, raw));

  let verdict;
  if (score >= 70)      verdict = 'human';
  else if (score >= 45) verdict = 'suspicious';
  else                  verdict = 'bot';

  return {
    score,
    verdict,
    breakdown: { behaviorScore, inputScore, envScore, fingerprintScore, powScore, spamScore, uaScore, honeypotScore },
  };
}

module.exports = { computeScore, verifyPoW };
