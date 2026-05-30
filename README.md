# 🛡️ SilentShield

**Invisible bot protection — no CAPTCHAs, no friction, no puzzles.**

Stop bots silently using behavioral signals, browser fingerprinting, and Proof-of-Work. Users never see a CAPTCHA. Free up to 50,000 requests/month.

[![npm](https://img.shields.io/npm/v/silentshield-js)](https://www.npmjs.com/package/silentshield-js)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![jsDelivr](https://data.jsdelivr.com/v1/package/npm/silentshield-js/badge)](https://www.jsdelivr.com/package/npm/silentshield-js)

**Website:** https://silentshield.krl.rk  
**API:** https://api.silentshield.krl.rk  
**CDN:** https://cdn.jsdelivr.net/npm/silentshield-js@latest/dist/silentshield.min.js

---

## How it works — 8 layers of detection

| Layer | Signal | Human | Bot |
|-------|--------|-------|-----|
| 1 | **Proof of Work** | Solved in ~100–300ms | Failed / spoofed |
| 2 | **Behavior** | Mouse, scroll, click | No interaction |
| 3 | **Mouse entropy** | Curved, organic paths | Linear or zero |
| 4 | **Input timing** | Natural typing variance | Machine-perfect speed |
| 5 | **Canvas fingerprint** | Real browser rendering | Headless rendering artifacts |
| 6 | **WebGL renderer** | GPU-accelerated | SwiftShader / llvmpipe |
| 7 | **Audio fingerprint** | Real audio pipeline | No audio context |
| 8 | **Environment** | Real browser APIs | Missing plugins, cloud IP |

**Scores:** 70–100 = human ✓ · 45–69 = suspicious · 0–44 = bot ✗

Bot patterns update automatically every **10 minutes** from live attack data.

---

## Quick Start (30 seconds)

### Option A — CDN (copy-paste)

```html
<!-- jsdelivr CDN — fastest, globally cached -->
<script
  src="https://cdn.jsdelivr.net/npm/silentshield-js@latest/dist/silentshield.min.js"
  data-silentshield-key="pk_your_public_key">
</script>

<!-- Tag your form -->
<form data-silentshield action="/submit" method="POST">
  <input type="text" name="name" placeholder="Your name" />
  <input type="email" name="email" placeholder="Email" />
  <button type="submit">Send</button>
</form>
```

### Option B — npm

```bash
npm install silentshield-js
```

```js
import SilentShield from 'silentshield-js';

SilentShield.init({
  publicKey: 'pk_your_public_key',
  apiUrl: 'https://api.silentshield.krl.rk',  // or your self-hosted URL
});
```

### Step 3 — Verify on your server

```js
// Node.js example
const res = await fetch('https://api.silentshield.krl.rk/api/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    token: req.body._ss_token,
    secret: 'sk_your_secret_key',
  }),
});

const { valid, score, verdict } = await res.json();
// { valid: true, score: 91, verdict: 'human' }

if (!valid) return res.status(403).send('Blocked');
```

---

## API Reference

### `POST /api/signal` — Submit signals (SDK → SilentShield)

Called automatically by the SDK. Payload includes all behavioral signals.

Returns:
```json
{ "token": "uuid", "score": 91, "verdict": "human" }
```

### `POST /api/verify` — Verify a token (your server → SilentShield)

```json
{ "token": "uuid", "secret": "sk_..." }
```

Returns:
```json
{ "valid": true, "score": 91, "verdict": "human", "timestamp": "..." }
```

### `POST /api/register` — Get free API keys

```json
{ "domain": "mysite.com", "name": "My Project" }
```

Returns:
```json
{
  "public_key": "pk_...",
  "secret_key": "sk_...",
  "plan": "free",
  "monthly_limit": 50000
}
```

### `GET /api/analytics/overview` — Dashboard data

Requires header: `x-secret-key: sk_...`

---

## Detection Details

### Proof of Work (PoW)
The SDK starts solving a SHA-256 challenge (difficulty 3 = 000...) in the background the moment the page loads. The browser finds a nonce such that `SHA256(challenge + nonce)` starts with `000`. This takes real browsers ~100–300ms using Web Crypto API. The server verifies the solution — spoofed or missing PoW deducts 30 points.

### Canvas Fingerprinting
Renders styled text and shapes to a canvas element and captures the last 64 bytes of the PNG data. Headless Chrome, PhantomJS, and server-side renderers produce different outputs due to missing or software-based font rendering.

### WebGL Fingerprinting
Queries the unmasked GPU vendor and renderer. Known software renderers (SwiftShader, llvmpipe, Mesa, ANGLE) are used by headless browsers and deduct 30 points.

### Audio Fingerprinting
Creates an AudioContext, renders a triangle oscillator through an analyser, and captures the frequency data signature. Headless environments lack a real audio pipeline.

### Mouse Entropy
Measures the variance of angle changes along the mouse path. Humans move in natural curves (high entropy). Bots that simulate mouse movement tend to move in straight lines (near-zero entropy).

### Keyboard Biometrics
Measures inter-keystroke intervals and their variance. Human typing has natural irregularity. Bot-submitted forms filled programmatically show near-zero variance across keystrokes, or a fill time under 1 second for multi-field forms.

---

## Features

- **Fake Success Mode** — blocked bots see "Sent successfully!" but data is never saved
- **Smart Honeypot** — 20 randomized hidden field names, rotated per page load
- **AI Spam Filter** — content-level keyword blocking (crypto, SEO, pharma, etc.)
- **10-Minute Learning** — bot patterns auto-updated from live traffic
- **Real-time Dashboard** — traffic, threats, bot patterns, submission log
- **Privacy First** — no cookies, no Google, IPs hashed, GDPR-friendly

---

## Self-hosting on VPS

```bash
git clone https://github.com/3289david/silentshield /opt/silentshield
cd /opt/silentshield
chmod +x deploy.sh && sudo ./deploy.sh
```

Then set up nginx + SSL:
```bash
apt install nginx certbot python3-certbot-nginx
certbot --nginx -d silentshield.krl.rk -d api.silentshield.krl.rk
cp nginx.conf /etc/nginx/sites-available/silentshield
ln -s /etc/nginx/sites-available/silentshield /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

---

## GitHub Actions CI/CD

Set secrets in your repo → Settings → Secrets:

| Secret | Value |
|--------|-------|
| `VPS_HOST` | Your VPS IP |
| `VPS_USER` | SSH username |
| `VPS_SSH_KEY` | Private SSH key |
| `NPM_TOKEN` | npm auth token |

- Push to `main` → auto-deploys to VPS
- Tag `v1.x.x` → auto-publishes to npm

---

## License

MIT — free to use, modify, and self-host.
