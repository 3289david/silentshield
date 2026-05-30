# 🛡️ SilentShield

**Invisible bot protection — no CAPTCHAs, no friction, no puzzles. Free forever.**

Stop bots silently using 12 layers of behavioral analysis, browser fingerprinting, biometrics, and Proof-of-Work. Users never see a CAPTCHA or challenge. Open source, MIT licensed.

[![npm](https://img.shields.io/npm/v/silentshield)](https://www.npmjs.com/package/silentshield)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![jsDelivr](https://data.jsdelivr.com/v1/package/npm/silentshield/badge)](https://www.jsdelivr.com/package/npm/silentshield)

**Website:** https://silentshield.krl.kr  
**API:** https://silentshield.krl.kr/api  
**CDN:** https://cdn.jsdelivr.net/npm/silentshield@latest/dist/silentshield.min.js  
**GitHub:** https://github.com/3289david/silentshield

---

## Why SilentShield?

| | SilentShield | reCAPTCHA v3 | hCaptcha | Cloudflare Turnstile |
|---|---|---|---|---|
| **Free** | ✓ Unlimited | 1M req/mo | 1M req/mo | Free tier only |
| **No API key** | ✓ | ✗ | ✗ | ✗ |
| **No CAPTCHAs** | ✓ | ✓ | ✗ | ✓ |
| **Open source** | ✓ MIT | ✗ | ✗ | ✗ |
| **Self-hostable** | ✓ | ✗ | ✗ | ✗ |
| **GDPR-safe** | ✓ | ✗ | ✗ | ✗ |
| **Keyboard biometrics** | ✓ | ✗ | ✗ | ✗ |
| **Font enumeration** | ✓ | ✗ | ✗ | ✗ |
| **Bot learning** | ✓ every 10min | Google ML | Proprietary | Proprietary |

---

## Quick Start (30 seconds)

### Option A — CDN (no build step)

```html
<!-- 1. Add to <head> -->
<script src="https://cdn.jsdelivr.net/npm/silentshield@latest/dist/silentshield.min.js"></script>

<!-- 2. Tag your form -->
<form data-silentshield action="/submit" method="POST">
  <input type="text" name="name" />
  <input type="email" name="email" />
  <button type="submit">Send</button>
</form>

<!-- 3. Done. Token is auto-injected as _ss_token hidden input on submit. -->
```

No API key needed. No registration. It just works.

### Option B — npm

```bash
npm install silentshield
```

```js
import SilentShield from 'silentshield';

const shield = new SilentShield({
  apiUrl: 'https://silentshield.krl.kr',  // or your self-hosted URL
});

shield.protect('#my-form');
```

### Step 3 — Verify on your server

```js
// Node.js
const res = await fetch('https://silentshield.krl.kr/api/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: req.body._ss_token }),
});
const { valid, score, verdict } = await res.json();
// { valid: true, score: 91, verdict: 'human' }
if (!valid) return res.status(403).send('Blocked');
```

```php
// PHP
$data = json_decode(file_get_contents('https://silentshield.krl.kr/api/verify', false,
  stream_context_create(['http' => [
    'method' => 'POST',
    'header' => 'Content-Type: application/json',
    'content' => json_encode(['token' => $_POST['_ss_token']])
  ]])
), true);
if (!$data['valid']) { http_response_code(403); exit; }
```

```python
# Python
import requests
r = requests.post('https://silentshield.krl.kr/api/verify', json={'token': token})
if not r.json().get('valid'): abort(403)
```

---

## Detection Layers (12 total)

### Layer 1 — Proof of Work (PoW)
**Score weight: +15 / -35**

The SDK starts solving a SHA-256 hashcash puzzle in the background the moment the page loads:

```
find nonce where SHA256(challenge + nonce).startsWith("000")
```

Real browsers solve it in ~100–400ms using `crypto.subtle.digest()`. The server verifies the solution on every submission. A missing or invalid PoW deducts 35 points. A pre-computed answer solved in <5ms deducts 25 points.

---

### Layer 2 — Behavioral Analysis
**Score weight: up to +40**

Tracks raw interaction counts:

| Signal | Human | Bot |
|--------|-------|-----|
| Mouse events | >20 | 0 |
| Scroll events | >2 | 0 |
| Click events | >0 | 0 |
| Double-click | Occasional | Never |
| Right-click (contextmenu) | Occasional | Never |
| Mouse down events | Matches clicks | 0 or mismatched |
| Tab/blur events | Occasional | Never |

Zero interaction on all signals deducts 30 points.

---

### Layer 3 — Mouse Path Entropy
**Score weight: +12 / -18**

Measures the **angle-change variance** across every recorded mouse position. Humans move the mouse in natural, organic curves with random micro-tremors. The variance is typically >0.01 radians/event.

Bots either produce no mouse movement or move in perfectly straight lines (near-zero variance). Linear paths where `mouseEntropy < 0.0001` with >10 events deducts 18 points.

---

### Layer 4 — Mouse Speed Variance
**Score weight: +5**

Calculates speed (pixels/ms) between consecutive mouse positions and measures its variance. Humans accelerate and decelerate constantly. Automated mouse injection tools typically move at constant speed, producing near-zero speed variance.

---

### Layer 5 — Keyboard Biometrics
**Score weight: +18 / -45**

Captures inter-keystroke timing intervals (up to 120 stored). The variance of these intervals reveals:

| Variance | Interpretation |
|----------|----------------|
| >5000 | Very human-like typing |
| >2000 | Human |
| >500 | Slightly irregular but plausible |
| <50 with >5 keys | Robot typing (metronomic) |
| <10 with >3 keys | Definitely scripted |

Also scores: backspace/delete usage (+10, humans make typos), tab navigation (+5), excessive pasting (-8).

Form fill time scoring:
- <300ms total fill time: **-55 points** (programmatic)
- <800ms: **-35 points**
- >2000ms real fill: **+20 points**

---

### Layer 6 — Canvas Fingerprinting
**Score weight: +10 / -25**

Renders a multi-layer canvas (gradient, two fonts, arc, bezier) and reads the last 80 bytes of the PNG data. Headless Chromium, PhantomJS, and server-side renderers produce characteristic patterns due to missing GPU acceleration and font rendering differences.

Known headless fingerprint patterns:
- `AAAAAAAAAA==` suffix (empty/flat render)
- `wAAAANSUhEUg` (SwiftShader artifact)

---

### Layer 7 — WebGL Renderer Detection
**Score weight: +12 / -35**

Calls `WEBGL_debug_renderer_info` to read the GPU vendor and renderer strings. Known software renderers used by headless environments:

| Renderer string | Verdict |
|----------------|---------|
| SwiftShader | Bot (-35) |
| llvmpipe | Bot (-35) |
| Mesa | Bot (-35) |
| ANGLE (software) | Bot (-35) |
| VMware SVGA | Bot (-35) |
| Real GPU (NVIDIA, AMD, Apple M) | Human (+12) |

Also reads `MAX_TEXTURE_SIZE` and `MAX_VERTEX_ATTRIBS` for additional GPU fingerprinting.

---

### Layer 8 — Audio Fingerprinting
**Score weight: +8 / -8**

Creates an `AudioContext`, routes a triangle oscillator through an `AnalyserNode`, and captures the frequency data signature (50-point FFT). Headless environments lack a real audio pipeline — they either throw errors or produce flat zero output.

---

### Layer 9 — Font Enumeration
**Score weight: +10 / -8**

Renders a test string in 28 known fonts and measures the pixel width using canvas. A font is "detected" when its rendered width differs from the monospace baseline. Real desktop browsers have 10–25 fonts installed. Headless/sandboxed environments typically have 0–2.

---

### Layer 10 — Environment & API Flags
**Score weight: up to +45 / -70**

Checks 20+ browser environment signals:

| Signal | Real Browser | Headless |
|--------|-------------|---------|
| `navigator.webdriver` | false | **true → -70** |
| Plugin count | >3 | 0 |
| `window.chrome` defined | ✓ in Chrome | Often absent |
| `localStorage` available | ✓ | Sometimes blocked |
| `indexedDB` available | ✓ | Sometimes blocked |
| `speechSynthesis.getVoices()` | >5 voices | 0 |
| `navigator.getBattery` | ✓ | Absent |
| `window.innerWidth` / `screen.width` | ratio 0.4–0.99 | ratio ≥0.99 |
| `navigator.hardwareConcurrency` | >1 | Often 1 |
| `pointer: fine` media query | ✓ on desktop | Absent |
| `hover: hover` media query | ✓ on desktop | Absent |
| `colorDepth` ≥ 24 | ✓ | Sometimes 8 |
| Cloud/datacenter IP | Unusual | Common |
| `pixelRatio` > 1 | HiDPI device | Often 1 |

---

### Layer 11 — Speech Synthesis
**Score weight: +10 / -5**

`speechSynthesis.getVoices()` returns the list of TTS voices installed on the OS. Real desktop browsers return 5–60 voices. Headless Chrome on a bare VPS returns 0.

---

### Layer 12 — Rotating Smart Honeypot
**Score weight: -100 if triggered**

Injects a CSS-invisible input field with one of 25 rotating names (`website`, `homepage`, `company_url`, `phone2`, etc.). The name rotates on every page load to defeat bot databases that learn to skip known honeypot names. Real users never fill it. Any value in the field = **automatic bot verdict**.

---

### Bonus: Spam Content Filter
**Score weight: -50 to -80**

Analyzes submitted form text against 25+ spam keyword patterns (crypto, pharma, SEO, gambling, etc.). Multiple keyword hits compound the penalty.

---

### Bonus: User Agent Matching
**Score weight: -50 for known bots, +10 for real browsers**

Checks against 23+ known bot/scraper user agents (curl, wget, Python requests, Selenium, Puppeteer, etc.) plus learned patterns from the bot learning system.

---

### Bonus: Bot Learning (every 10 minutes)
A background `node-cron` job runs every 10 minutes and analyzes recent submissions to:
- Learn new UA patterns from bot-scored traffic
- Identify timing patterns unique to known bots
- Update confidence scores on known bot signatures
- Auto-expire stale patterns (>7 days without hits)

---

## SDK Configuration

```js
const shield = new SilentShield({
  // Optional: your domain's public key (for analytics only)
  publicKey: 'pk_abc123',

  // API endpoint (default: https://silentshield.krl.kr)
  apiUrl: 'https://your-own-server.com',

  // Score threshold below which to block (default: 45)
  // Score 0-100. Recommended: 45 (balanced) or 60 (strict)
  threshold: 45,

  // Show fake success to blocked bots (default: true)
  fakeSuccess: true,

  // Callback when a bot is detected
  onBot: (result) => console.log('Bot blocked', result.score),
});

// Protect a specific form
shield.protect('#contact-form');

// Or protect all [data-silentshield] forms
SilentShield.init({ apiUrl: 'https://silentshield.krl.kr' });
```

---

## API Reference

### `POST /api/signal`
Called automatically by the JS SDK. Accepts all behavioral signals and returns a one-time token.

**Request:** All signals collected by the SDK (see SDK source)

**Response:**
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "score": 91,
  "verdict": "human"
}
```

Verdicts: `"human"` (≥70) · `"suspicious"` (45–69) · `"bot"` (<45)

---

### `POST /api/verify`
Your server calls this to validate a token before processing a form submission.

**Request:**
```json
{ "token": "550e8400-e29b-41d4-a716-446655440000" }
```

**Response:**
```json
{
  "valid": true,
  "score": 91,
  "verdict": "human",
  "timestamp": "2025-01-01T00:00:00.000Z"
}
```

Tokens are **one-time use** — calling verify twice on the same token returns `valid: false`.

---

### `POST /api/register` _(optional)_
Register your domain to get analytics keys. Completely optional.

**Request:**
```json
{ "domain": "mysite.com", "name": "My Project" }
```

**Response:**
```json
{
  "public_key": "pk_abc...",
  "secret_key": "sk_xyz...",
  "message": "Site registered — dashboard analytics enabled"
}
```

---

### `GET /api/analytics/overview`
Requires header: `x-secret-key: sk_...`

Returns 7-day traffic stats, bot rate, detection breakdown by layer.

---

## Self-Hosting

### One-command deploy (Ubuntu 22.04)

```bash
curl -fsSL https://raw.githubusercontent.com/3289david/silentshield/main/deploy.sh | bash
```

This script:
1. Installs Node.js 20 via NodeSource
2. Installs PM2 process manager
3. Clones the repo to `/opt/silentshield`
4. Builds the SDK (`node build.js`)
5. Installs server dependencies
6. Creates a `.env` with a random `ADMIN_SECRET`
7. Starts the server with PM2 and saves the process list

### Add SSL with nginx

```bash
apt install nginx certbot python3-certbot-nginx
certbot --nginx -d silentshield.krl.kr
cp nginx.conf /etc/nginx/sites-available/silentshield
ln -s /etc/nginx/sites-available/silentshield /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `DB_PATH` | `./silentshield.db` | SQLite database path |
| `ADMIN_SECRET` | (random) | Dashboard admin password |
| `CORS_ORIGINS` | `*` | Allowed CORS origins |
| `RATE_LIMIT_MAX` | `200` | Requests per window |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window (ms) |
| `NODE_ENV` | `development` | Set to `production` on VPS |

---

## GitHub Actions CI/CD

Set these secrets in your repo → **Settings → Secrets**:

| Secret | Value |
|--------|-------|
| `VPS_HOST` | Your VPS IP address |
| `VPS_USER` | SSH username (usually `root`) |
| `VPS_SSH_KEY` | Private SSH key (RSA/ED25519) |
| `NPM_TOKEN` | npm automation token |

- Push to `main` → auto-deploys to VPS via SSH
- Tag `vX.Y.Z` → auto-publishes to npm

---

## License

MIT — free to use, modify, self-host, and redistribute.

---

## Support

If SilentShield saves you from paying for reCAPTCHA Enterprise or hCaptcha, consider buying a coffee:

☕ **[buymeacoffee.com/rukkitofficial](https://buymeacoffee.com/rukkitofficial)**
