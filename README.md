# 🛡️ SilentShield

**Invisible bot protection — no CAPTCHAs, no friction, no puzzles.**

Stop bots silently using behavioral signals. Users never see a CAPTCHA. Free up to 50,000 requests/month.

[![npm](https://img.shields.io/npm/v/@silentshield/js)](https://www.npmjs.com/package/@silentshield/js)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## How it works

SilentShield scores every visitor 0–100 using:

| Signal | Human | Bot |
|--------|-------|-----|
| Mouse movement | +15 | +0 |
| Scroll events | +10 | +0 |
| Natural typing speed | +20 | -40 (too fast) |
| Backspace used | +5 | -0 |
| Normal browser env | +10 | -40 (headless) |
| Cloud/datacenter IP | +0 | -30 |
| Honeypot triggered | +0 | -100 |

Scores: **70–100** = human ✓ · **45–69** = suspicious · **0–44** = bot ✗

Bot patterns update automatically every **10 minutes** as new attacks are seen.

---

## Quick Start (30 seconds)

### 1. Add the script tag

```html
<script
  src="https://cdn.silentshield.io/v1/sdk.js"
  data-silentshield-key="pk_your_public_key">
</script>
```

### 2. Tag your form

```html
<form data-silentshield action="/submit" method="POST">
  <input type="text" name="name" />
  <button type="submit">Send</button>
</form>
```

### 3. Verify on your server

```js
const res = await fetch('https://api.silentshield.io/api/verify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    token: req.body._ss_token,
    secret: 'sk_your_secret_key'
  })
});

const { valid, score, verdict } = await res.json();
// { valid: true, score: 92, verdict: 'human' }

if (!valid) return res.status(403).send('Bot detected');
```

---

## Install via npm

```bash
npm install @silentshield/js
```

```js
import SilentShield from '@silentshield/js';

SilentShield.init({ publicKey: 'pk_your_key' });
```

---

## Features

- **Fake Success Mode** — blocked bots see "Successfully submitted!" but data is never saved
- **Smart Honeypot** — randomized hidden field names, rotated to prevent bot learning
- **AI Spam Filter** — content-level spam detection (SEO offers, crypto, backlinks)
- **AI Agent Detection** — detects Playwright, Puppeteer, Selenium, Browser Use
- **10-Minute Learning** — bot patterns updated automatically from real attack data
- **Real-time Dashboard** — see traffic, blocked bots, threat types, country breakdown
- **Privacy First** — no cookies, no Google dependencies, IPs hashed, GDPR-friendly

---

## API Reference

### `POST /api/signal` — Submit signals (called by SDK)

```json
{ "siteId": "pk_...", "mouseEvents": 42, "formFillMs": 4200, ... }
```

Returns: `{ "token": "uuid", "score": 92, "verdict": "human" }`

### `POST /api/verify` — Verify a token (server-side)

```json
{ "token": "uuid", "secret": "sk_..." }
```

Returns: `{ "valid": true, "score": 92, "verdict": "human", "timestamp": "..." }`

### `POST /api/register` — Register a site

```json
{ "domain": "mysite.com", "name": "My Project" }
```

Returns: `{ "public_key": "pk_...", "secret_key": "sk_..." }`

### `GET /api/analytics/overview` — Analytics (requires `x-secret-key` header)

---

## Self-hosting

### Quick deploy to Ubuntu VPS

```bash
git clone https://github.com/YOUR_USERNAME/silentshield
cd silentshield
chmod +x deploy.sh
sudo ./deploy.sh
```

### Manual

```bash
cd server
cp ../.env.example .env
# Edit .env with your settings
npm install
npm start
```

### Docker

```bash
docker build -t silentshield .
docker run -p 3000:3000 -v $(pwd)/data:/data silentshield
```

---

## GitHub Actions CI/CD

Set these secrets in your GitHub repo:

| Secret | Value |
|--------|-------|
| `VPS_HOST` | Your VPS IP or domain |
| `VPS_USER` | SSH username (usually `root`) |
| `VPS_SSH_KEY` | Private SSH key |
| `NPM_TOKEN` | npm auth token (for publishing) |

Push to `main` → auto-deploys to VPS.  
Tag `v1.x.x` → auto-publishes to npm.

---

## Dashboard

Visit `https://yourdomain.com/dashboard` and enter your secret key.

Features: traffic overview, threat breakdown, submission log, bot patterns, API key management.

---

## License

MIT — free to use, modify, and self-host.
