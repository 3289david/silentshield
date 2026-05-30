const crypto = require('crypto');

const KNOWN_BOT_UAS = [
  'headlesschrome','phantomjs','puppeteer','selenium','webdriver',
  'python-requests','python-urllib','curl/','wget/','go-http-client',
  'java/','scrapy','mechanize','httpie','axios/','got/',
  'node-fetch','undici','okhttp','apache-httpclient','libwww-perl',
  'lwp-useragent','perl ','perl/','ruby','php-http','libcurl',
  'aiohttp','httpx','pycurl','perl-mojo','dataprovider',
];

// Cloud/datacenter IP prefixes that bots commonly use
const CLOUD_RANGES = [
  /^3\.(8[0-9]|9[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\./,
  /^104\.(1[6-9][0-9]|2[0-4][0-9]|25[0-5])\./,
  /^35\./, /^34\./, /^13\./, /^52\./, /^54\./,
  /^18\.(2[0-9]{2}|[0-9]{2})\./,
  /^10\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^64\.(18|233)\./,        // known scraper ranges
  /^185\.220\./,            // Tor exit nodes
  /^66\.(249)\./,           // Googlebot
];

const HEADLESS_GL = [
  'swiftshader','llvmpipe','softpipe','mesa','angle (',
  'vmware','virtualbox','parallels','microsoft basic render','google swiftshader',
];

const HEADLESS_CANVAS_SUFFIXES = [
  'AAAAAAAAAA==',
  'wAAAANSUhEUg',
  'AAAAA4AAAAB',
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
    if (lower.includes(bot)) return -50;
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
  if (/mozilla/i.test(ua) && ua.length > 60) return 5;
  return 0;
}

function scoreBehavior(signals) {
  let score = 0;
  const {
    mouseEvents = 0, scrollEvents = 0, clickEvents = 0,
    mouseEntropy = 0, mouseSpeedVariance = 0,
    blurEvents = 0, focusEvents = 0,
    dblClickEvents = 0, contextMenuEvents = 0, mouseDownEvents = 0,
  } = signals;

  // Mouse movement
  if (mouseEvents > 50)      score += 18;
  else if (mouseEvents > 20) score += 14;
  else if (mouseEvents > 5)  score += 8;
  else if (mouseEvents > 0)  score += 3;

  // Scroll
  if (scrollEvents > 5)      score += 10;
  else if (scrollEvents > 2) score += 7;
  else if (scrollEvents > 0) score += 4;

  // Click
  if (clickEvents > 0)       score += 5;
  if (dblClickEvents > 0)    score += 4;  // bots rarely dblclick
  if (contextMenuEvents > 0) score += 3;  // bots rarely right-click

  // Mouse entropy: humans move in curves
  if (mouseEntropy > 0.05)        score += 12;
  else if (mouseEntropy > 0.01)   score += 7;
  else if (mouseEntropy > 0.001)  score += 3;
  else if (mouseEvents > 10 && mouseEntropy < 0.0001) score -= 18; // suspiciously linear

  // Mouse speed variance: humans accelerate/decelerate
  if (mouseSpeedVariance > 0.5)   score += 5;
  else if (mouseSpeedVariance > 0.1) score += 2;

  // Mouse down (real clicks have mousedown events)
  if (mouseDownEvents > 0 && clickEvents > 0) score += 3;

  // Tab/focus switching indicates real browser session
  if (blurEvents > 0) score += 3;
  if (focusEvents > 0) score += 2;

  // Zero interaction = no real user
  if (mouseEvents === 0 && scrollEvents === 0 && clickEvents === 0) score -= 30;

  return Math.max(-45, Math.min(40, score));
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

  if (formFillMs > 0 && formFillMs < 300)       score -= 55;
  else if (formFillMs > 0 && formFillMs < 800)   score -= 35;
  else if (formFillMs > 0 && formFillMs < 1500)  score -= 15;
  else if (formFillMs > 2000 && formFillMs < 600000) score += 20;
  else if (formFillMs >= 600000)                 score += 5;

  const intervals = Array.isArray(keystrokeIntervals) ? keystrokeIntervals : [];
  if (intervals.length > 5) {
    const avg      = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((s, v) => s + Math.pow(v - avg, 2), 0) / intervals.length;
    if (variance > 5000)      score += 18;  // very human-like typing
    else if (variance > 2000) score += 13;
    else if (variance > 500)  score += 8;
    else if (variance < 50 && intervals.length > 5) score -= 30; // robot-perfect
    else if (variance < 10 && intervals.length > 3) score -= 45; // definitely scripted
  }

  if (backspaceCount > 0 || deleteCount > 0) score += 10; // humans make typos
  if (tabCount > 0) score += 5;
  if (pasteCount > 3) score -= 8; // lots of pasting is suspicious
  else if (pasteCount > 0) score -= 2;

  return Math.max(-55, Math.min(35, score));
}

function scoreEnvironment(signals, ip) {
  if (signals.webdriver) return -70; // definitive bot indicator

  let score = 0;
  const {
    screenWidth = 0, screenHeight = 0, colorDepth = 0,
    pluginCount = 0, hardwareConcurrency = 0, deviceMemory = 0,
    cookieEnabled = false, pixelRatio = 1, innerWidth = 0, innerHeight = 0,
    connectionType = '', permissionState = '',
    // New API flags
    hasLocalStorage = false, hasSessionStorage = false, hasIndexedDB = false,
    hasWebWorker = false, hasNotifications = false, hasChrome = false,
    hasBattery = false, hasServiceWorker = false,
    // Media queries
    pointerFine = false, hoverCapable = false,
    // Speech, fonts, perf
    fontCount = 0, speechVoiceCount = 0, perfPrecision = 0,
  } = signals;

  // Screen dimensions
  if (screenWidth > 800 && screenHeight > 600) score += 8;
  else if (screenWidth === 0 || screenHeight === 0) score -= 15;

  // Headless browsers often report innerWidth === screenWidth exactly
  if (innerWidth > 0 && innerHeight > 0 && screenWidth > 0) {
    const wRatio = innerWidth / screenWidth;
    if (wRatio > 0.4 && wRatio < 0.99) score += 4; // real browser has window chrome
    else if (wRatio >= 0.99) score -= 5; // exact match = headless
  }

  if (colorDepth >= 24) score += 5;
  if (pixelRatio > 1)   score += 5;   // retina/HiDPI = real device
  else if (pixelRatio === 1) score += 2;

  // Plugins: headless has none
  if (pluginCount > 3)  score += 12;
  else if (pluginCount > 0) score += 7;
  else score -= 8;

  if (hardwareConcurrency > 1) score += 6;
  else if (hardwareConcurrency > 0) score += 3;
  if (deviceMemory > 0) score += 4;
  if (cookieEnabled) score += 4;

  // Connection type (only real mobile/desktop browsers expose this)
  if (['4g','3g','2g','wifi'].includes(connectionType)) score += 5;

  // Permission state: real browsers show 'default' or 'granted'
  if (permissionState === 'prompt' || permissionState === 'granted') score += 6;
  else if (permissionState === 'denied') score += 2; // still a real browser

  // Pointer: fine = mouse, real desktop
  if (pointerFine) score += 3;
  if (hoverCapable) score += 2;

  // API availability — headless is missing many of these
  const apiFlags = [hasLocalStorage, hasSessionStorage, hasIndexedDB, hasWebWorker, hasNotifications, hasServiceWorker];
  const apiScore = apiFlags.filter(Boolean).length;
  score += Math.min(apiScore * 2, 10);
  if (hasChrome) score += 8;    // window.chrome only in real Chrome/Chromium
  if (hasBattery) score += 3;

  // Font count: headless/sandboxed environments have very few fonts
  if (fontCount > 15) score += 10;
  else if (fontCount > 8) score += 6;
  else if (fontCount > 0) score += 2;
  else if (fontCount === 0) score -= 8;

  // Speech voices: headless has none
  if (speechVoiceCount > 5)     score += 10;
  else if (speechVoiceCount > 0) score += 5;
  else score -= 5;

  // Performance precision: browsers clamp to 0.1ms, headless/node varies
  if (perfPrecision > 0 && perfPrecision < 0.5) score += 4;

  if (isCloudIP(ip)) score -= 35;

  return Math.max(-70, Math.min(45, score));
}

function scoreFingerprints(signals) {
  let score = 0;
  const {
    canvasFingerprint = '', webglRenderer = '', webglHeadless = false,
    audioFingerprint = '', webglParams = '',
  } = signals;

  // WebGL: headless software renderer
  if (webglHeadless)                                    score -= 35;
  else if (webglRenderer === 'none' || !webglRenderer)  score -= 10;
  else                                                  score += 12;

  // WebGL params uniqueness (real GPUs have diverse param values)
  if (webglParams && webglParams.length > 3)            score += 3;

  // Canvas: headless renders produce known artifacts
  const isHeadlessCanvas = HEADLESS_CANVAS_SUFFIXES.some((s) => canvasFingerprint.includes(s));
  if (isHeadlessCanvas)                                score -= 25;
  else if (!canvasFingerprint || canvasFingerprint === 'blocked') score -= 8;
  else                                                 score += 10;

  // Audio: headless lacks a real audio pipeline
  if (typeof audioFingerprint === 'number' && audioFingerprint > 0)  score += 8;
  else if (audioFingerprint === 'error' || audioFingerprint === 'unsupported') score -= 8;
  else if (audioFingerprint === 0)                     score -= 5;

  return Math.max(-55, Math.min(30, score));
}

function scorePoW(signals) {
  const { powChallenge, powNonce, powHash, powMs, powDifficulty = 3 } = signals;
  if (!powChallenge) return -10;

  const valid = verifyPoW(powChallenge, powNonce, powHash, powDifficulty);
  if (!valid) return -35;

  if (powMs < 5)      return -25; // pre-computed or spoofed
  if (powMs < 20)     return 8;   // very fast but valid
  if (powMs > 60000)  return 5;   // took forever
  return 15;
}

function scoreSpam(signals) {
  const text = (signals.formText || '').toLowerCase();
  if (!text) return 0;
  const keywords = [
    'seo service','backlink','buy followers','crypto investment','click here',
    'make money fast','casino','viagra','cheap meds','loan offer','prize winner',
    'work from home','binary options','forex signal','nft drop','free bitcoin',
    'enlargement','weight loss pills','online pharmacy','best price','100% free',
    'act now','limited time offer','winner selected','you have been chosen',
    'congratulations you won','discount pharmacy','adult content',
  ];
  let spamHits = 0;
  for (const kw of keywords) { if (text.includes(kw)) spamHits++; }
  if (spamHits >= 3) return -80;
  if (spamHits >= 2) return -60;
  if (spamHits >= 1) return -50;
  return 0;
}

function computeScore(signals, ip, ua) {
  const behaviorScore    = scoreBehavior(signals);
  const inputScore       = scoreInput(signals);
  const envScore         = scoreEnvironment(signals, ip);
  const fingerprintScore = scoreFingerprints(signals);
  const powScore         = scorePoW(signals);
  const spamScore        = scoreSpam(signals);
  const uaScore          = scoreUserAgent(ua);
  const honeypotScore    = signals.honeypotFilled ? -100 : 0;

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
