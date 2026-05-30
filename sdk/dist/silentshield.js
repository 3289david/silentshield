/**
 * SilentShield JS SDK v2.1
 * Invisible bot detection ??12-layer analysis: PoW, behavioral, biometrics, fingerprinting.
 * https://sh.krl.kr
 * CDN: https://cdn.jsdelivr.net/npm/silentshield@latest/dist/silentshield.min.js
 */
(function (global, factory) {
  if (typeof module !== 'undefined' && module.exports) module.exports = factory();
  else if (typeof define === 'function' && define.amd) define(factory);
  else global.SilentShield = factory();
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  var DEFAULT_API = 'https://sh.krl.kr';
  var POW_DIFFICULTY = 3;

  var HONEYPOT_NAMES = [
    'phone2','website2','contact_alt','url_field','company2','fax_number',
    'address2','city2','zip2','ref_code','email2','name2','subject2','ref_id',
    'hp_field','bot_check','second_email','alt_phone','web_url','extra_field',
    'homepage','business_url','your_website','website_address','company_url',
  ];

  // ??? Proof of Work ???????????????????????????????????????????????????????????
  function bytesToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(function(b){ return b.toString(16).padStart(2,'0'); }).join('');
  }

  function solvePoW(challenge, difficulty) {
    return new Promise(function(resolve) {
      if (typeof crypto === 'undefined' || !crypto.subtle) {
        return resolve({ nonce: 0, hash: '', skipped: true, ms: 0 });
      }
      var target = Array(difficulty + 1).join('0');
      var enc = new TextEncoder();
      var nonce = 0;
      var start = Date.now();
      function attempt() {
        var batch = 0;
        function loop() {
          crypto.subtle.digest('SHA-256', enc.encode(challenge + nonce)).then(function(buf) {
            var hex = bytesToHex(buf);
            if (hex.slice(0, difficulty) === target) {
              resolve({ nonce: nonce, hash: hex, ms: Date.now() - start });
            } else {
              nonce++;
              batch++;
              if (batch < 50) loop();
              else { batch = 0; setTimeout(loop, 0); }
            }
          });
        }
        loop();
      }
      attempt();
    });
  }

  // ??? Canvas fingerprint ??????????????????????????????????????????????????????
  function getCanvasFingerprint() {
    try {
      var c = document.createElement('canvas');
      c.width = 280; c.height = 60;
      var ctx = c.getContext('2d');
      // Layer 1: gradient fill
      var grad = ctx.createLinearGradient(0, 0, 280, 0);
      grad.addColorStop(0, '#f0f'); grad.addColorStop(0.5, '#06f'); grad.addColorStop(1, '#0f6');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 280, 60);
      // Layer 2: text with multiple fonts
      ctx.textBaseline = 'alphabetic';
      ctx.font = '16px Arial';
      ctx.fillStyle = '#fff';
      ctx.fillText('SilentShield ✨ bot⚡', 4, 24);
      ctx.font = '13px Georgia';
      ctx.fillStyle = 'rgba(102,204,0,0.85)';
      ctx.fillText('1l0OαβΒ♥é', 4, 48);
      // Layer 3: arc + bezier curve
      ctx.beginPath();
      ctx.arc(220, 30, 20, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255,100,0,0.6)';
      ctx.fill();
      var data = c.toDataURL('image/png');
      return data.slice(data.length - 80);
    } catch (e) { return 'blocked'; }
  }

  // ??? WebGL fingerprint ???????????????????????????????????????????????????????
  function getWebGLInfo() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return { vendor: 'none', renderer: 'none', headless: true, params: '' };
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      var vendor   = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   : gl.getParameter(gl.VENDOR);
      var renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      var headlessMarkers = ['swiftshader','llvmpipe','softpipe','mesa','angle','vmware','virtualbox','parallels','microsoft basic render','google swiftshader'];
      var isHeadless = headlessMarkers.some(function(m){ return (renderer||'').toLowerCase().indexOf(m) !== -1; });
      // Extra params to harden fingerprint
      var maxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);
      var maxVA  = gl.getParameter(gl.MAX_VERTEX_ATTRIBS);
      return { vendor: vendor, renderer: renderer, headless: isHeadless, params: maxTex + ',' + maxVA };
    } catch (e) { return { vendor: 'error', renderer: 'error', headless: false, params: '' }; }
  }

  // ??? Audio fingerprint ???????????????????????????????????????????????????????
  function getAudioFingerprint() {
    try {
      var AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return 'unsupported';
      var ctx = new AudioCtx();
      var osc = ctx.createOscillator();
      var analyser = ctx.createAnalyser();
      var gain = ctx.createGain();
      gain.gain.value = 0;
      osc.type = 'triangle';
      osc.connect(analyser);
      analyser.connect(gain);
      gain.connect(ctx.destination);
      osc.start(0);
      var data = new Float32Array(analyser.frequencyBinCount);
      analyser.getFloatFrequencyData(data);
      osc.stop();
      ctx.close();
      var sum = 0;
      for (var i = 0; i < Math.min(50, data.length); i++) sum += Math.abs(data[i]);
      return Math.round(sum * 1000) / 1000;
    } catch (e) { return 'error'; }
  }

  // ??? Font enumeration (canvas width trick) ??????????????????????????????????
  function getFontCount() {
    try {
      if (!document.createElement) return 0;
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d');
      if (!ctx) return 0;
      var testString = 'mmmmmmmmmmlli';
      var testFonts = [
        'Arial','Verdana','Times New Roman','Courier New','Georgia','Trebuchet MS',
        'Impact','Comic Sans MS','Palatino','Garamond','Bookman','Tahoma',
        'Helvetica Neue','Calibri','Cambria','Segoe UI','Roboto','Ubuntu',
        'Consolas','Lucida Console','Monaco','Courier','Optima','Futura',
        'Gill Sans','Century Gothic','Franklin Gothic','Rockwell',
      ];
      var baseline = ctx.measureText(testString).width;
      var found = 0;
      testFonts.forEach(function(font) {
        ctx.font = '16px "' + font + '", monospace';
        if (ctx.measureText(testString).width !== baseline) found++;
      });
      return found;
    } catch (e) { return -1; }
  }

  // ??? Speech synthesis voices ?????????????????????????????????????????????????
  function getSpeechVoiceCount() {
    try {
      if (typeof window === 'undefined' || !window.speechSynthesis) return 0;
      return window.speechSynthesis.getVoices().length;
    } catch (e) { return 0; }
  }

  // ??? CSS media query signals ?????????????????????????????????????????????????
  function getMediaQuerySignals() {
    try {
      if (typeof window === 'undefined' || !window.matchMedia) return {};
      return {
        prefersColorSchemeDark: window.matchMedia('(prefers-color-scheme: dark)').matches,
        prefersReducedMotion:   window.matchMedia('(prefers-reduced-motion: reduce)').matches,
        pointerFine:            window.matchMedia('(pointer: fine)').matches,
        hoverCapable:           window.matchMedia('(hover: hover)').matches,
        anyPointerCoarse:       window.matchMedia('(any-pointer: coarse)').matches,
      };
    } catch (e) { return {}; }
  }

  // ??? Storage / API availability checks ??????????????????????????????????????
  function getApiFlags() {
    var flags = {
      hasLocalStorage:  false,
      hasSessionStorage: false,
      hasIndexedDB:     false,
      hasWebWorker:     false,
      hasNotifications: false,
      hasChrome:        false,
      hasServiceWorker: false,
      hasBattery:       false,
      hasWebBluetooth:  false,
      hasCredentials:   false,
    };
    try { localStorage.setItem('_ss','1'); localStorage.removeItem('_ss'); flags.hasLocalStorage = true; } catch(e) {}
    try { sessionStorage.setItem('_ss','1'); sessionStorage.removeItem('_ss'); flags.hasSessionStorage = true; } catch(e) {}
    try { flags.hasIndexedDB = typeof indexedDB !== 'undefined'; } catch(e) {}
    flags.hasWebWorker     = typeof Worker !== 'undefined';
    flags.hasNotifications = typeof Notification !== 'undefined';
    flags.hasChrome        = typeof window !== 'undefined' && typeof window.chrome !== 'undefined';
    flags.hasServiceWorker = typeof navigator !== 'undefined' && 'serviceWorker' in navigator;
    flags.hasBattery       = typeof navigator !== 'undefined' && typeof navigator.getBattery === 'function';
    flags.hasWebBluetooth  = typeof navigator !== 'undefined' && typeof navigator.bluetooth !== 'undefined';
    flags.hasCredentials   = typeof navigator !== 'undefined' && typeof navigator.credentials !== 'undefined';
    return flags;
  }

  // ??? Performance timing precision ????????????????????????????????????????????
  // Real browsers clamp performance.now() to 0.1ms (COOP/COEP), headless/node vary
  function getPerfPrecision() {
    try {
      if (typeof performance === 'undefined') return -1;
      var samples = [];
      for (var i = 0; i < 30; i++) samples.push(performance.now());
      var diffs = [];
      for (var j = 1; j < samples.length; j++) {
        var d = samples[j] - samples[j-1];
        if (d > 0) diffs.push(d);
      }
      if (!diffs.length) return 0;
      return Math.round(Math.min.apply(null, diffs) * 10000) / 10000;
    } catch (e) { return -1; }
  }

  // ??? Mouse path entropy ??????????????????????????????????????????????????????
  function calcMouseEntropy(path) {
    if (!path || path.length < 4) return 0;
    var angles = [];
    for (var i = 1; i < path.length - 1; i++) {
      var dx1 = path[i].x - path[i-1].x, dy1 = path[i].y - path[i-1].y;
      var dx2 = path[i+1].x - path[i].x, dy2 = path[i+1].y - path[i].y;
      angles.push(Math.atan2(dy2, dx2) - Math.atan2(dy1, dx1));
    }
    var mean = angles.reduce(function(a,b){return a+b;},0) / angles.length;
    var variance = angles.reduce(function(s,a){return s+Math.pow(a-mean,2);},0) / angles.length;
    return Math.round(variance * 10000) / 10000;
  }

  // ??? Mouse speed variance ????????????????????????????????????????????????????
  function calcMouseSpeedVariance(path) {
    if (!path || path.length < 4) return 0;
    var speeds = [];
    for (var i = 1; i < path.length; i++) {
      var dt = (path[i].t || 0) - (path[i-1].t || 0);
      if (dt <= 0) continue;
      var dx = path[i].x - path[i-1].x, dy = path[i].y - path[i-1].y;
      speeds.push(Math.sqrt(dx*dx + dy*dy) / dt);
    }
    if (speeds.length < 3) return 0;
    var mean = speeds.reduce(function(a,b){return a+b;},0) / speeds.length;
    var variance = speeds.reduce(function(s,v){return s+Math.pow(v-mean,2);},0) / speeds.length;
    return Math.round(variance * 1000) / 1000;
  }

  // ??? Permission probing ??????????????????????????????????????????????????????
  function getPermissionState(cb) {
    if (typeof navigator === 'undefined' || !navigator.permissions) return cb('unsupported');
    navigator.permissions.query({ name: 'notifications' }).then(function(r){ cb(r.state); }).catch(function(){ cb('error'); });
  }

  // ??? SilentShield constructor ?????????????????????????????????????????????????
  function SilentShield(opts) {
    this.publicKey   = opts.publicKey || null;
    this.apiUrl      = (opts.apiUrl || DEFAULT_API).replace(/\/$/, '');
    this.onBot       = opts.onBot || null;
    this.fakeSuccess = opts.fakeSuccess !== false;
    this.threshold   = opts.threshold || 45;
    this._signals    = this._initSignals();
    this._forms      = typeof Map !== 'undefined' ? new Map() : { _m: [], has: function(k){ return this._m.some(function(e){return e[0]===k;}); }, set: function(k,v){ this._m.push([k,v]); } };
    this._mousePath  = [];
    this._powPromise = null;
  }

  SilentShield.prototype._initSignals = function() {
    var nav = typeof navigator !== 'undefined' ? navigator : {};
    var scr = typeof screen !== 'undefined' ? screen : {};
    var win = typeof window !== 'undefined' ? window : {};
    var mq  = getMediaQuerySignals();
    var api = getApiFlags();
    return {
      // Timing
      pageEnterTime:       Date.now(),
      // Interaction counts
      mouseEvents:         0,
      scrollEvents:        0,
      clickEvents:         0,
      dblClickEvents:      0,
      contextMenuEvents:   0,
      keydownEvents:       0,
      focusEvents:         0,
      blurEvents:          0,
      mouseDownEvents:     0,
      // Keystroke biometrics
      keystrokeIntervals:  [],
      lastKeystrokeTime:   null,
      formFillMs:          0,
      formFillStart:       null,
      backspaceCount:      0,
      deleteCount:         0,
      tabCount:            0,
      fieldCount:          0,
      pasteCount:          0,
      // Form
      honeypotFilled:      false,
      formText:            '',
      // Mouse analytics
      mouseEntropy:        0,
      mouseSpeedVariance:  0,
      // Environment
      screenWidth:         scr.width      || 0,
      screenHeight:        scr.height     || 0,
      screenAvailWidth:    scr.availWidth || 0,
      innerWidth:          win.innerWidth  || 0,
      innerHeight:         win.innerHeight || 0,
      colorDepth:          scr.colorDepth  || 0,
      pixelRatio:          win.devicePixelRatio || 1,
      timezone:            (typeof Intl !== 'undefined') ? Intl.DateTimeFormat().resolvedOptions().timeZone : '',
      timezoneOffset:      new Date().getTimezoneOffset(),
      languages:           nav.languages ? Array.prototype.slice.call(nav.languages) : [],
      pluginCount:         nav.plugins ? nav.plugins.length : 0,
      webdriver:           nav.webdriver || false,
      hardwareConcurrency: nav.hardwareConcurrency || 0,
      deviceMemory:        nav.deviceMemory || 0,
      touchSupport:        'ontouchstart' in win || (nav.maxTouchPoints > 0),
      maxTouchPoints:      nav.maxTouchPoints || 0,
      platform:            nav.platform   || '',
      cookieEnabled:       nav.cookieEnabled || false,
      doNotTrack:          nav.doNotTrack || '',
      connectionType:      (nav.connection && nav.connection.effectiveType) || '',
      onLine:              nav.onLine !== undefined ? nav.onLine : true,
      // Media queries
      prefersColorSchemeDark: mq.prefersColorSchemeDark || false,
      prefersReducedMotion:   mq.prefersReducedMotion   || false,
      pointerFine:            mq.pointerFine             || false,
      hoverCapable:           mq.hoverCapable            || false,
      // API flags
      hasLocalStorage:     api.hasLocalStorage,
      hasSessionStorage:   api.hasSessionStorage,
      hasIndexedDB:        api.hasIndexedDB,
      hasWebWorker:        api.hasWebWorker,
      hasNotifications:    api.hasNotifications,
      hasChrome:           api.hasChrome,
      hasServiceWorker:    api.hasServiceWorker,
      hasBattery:          api.hasBattery,
      hasWebBluetooth:     api.hasWebBluetooth,
      // Fingerprints (filled in by _collectFingerprints)
      canvasFingerprint:   '',
      webglVendor:         '',
      webglRenderer:       '',
      webglHeadless:       false,
      webglParams:         '',
      audioFingerprint:    '',
      fontCount:           0,
      speechVoiceCount:    0,
      perfPrecision:       0,
      permissionState:     '',
      // PoW
      powChallenge:        '',
      powNonce:            0,
      powHash:             '',
      powMs:               0,
      powDifficulty:       POW_DIFFICULTY,
    };
  };

  SilentShield.prototype._collectFingerprints = function() {
    var s = this._signals;
    s.canvasFingerprint = getCanvasFingerprint();
    var wgl = getWebGLInfo();
    s.webglVendor   = wgl.vendor;
    s.webglRenderer = wgl.renderer;
    s.webglHeadless = wgl.headless;
    s.webglParams   = wgl.params;
    s.fontCount         = getFontCount();
    s.speechVoiceCount  = getSpeechVoiceCount();
    s.perfPrecision     = getPerfPrecision();
    // inner dimensions (headless often equals screen dimensions exactly)
    var win = typeof window !== 'undefined' ? window : {};
    s.innerWidth  = win.innerWidth  || 0;
    s.innerHeight = win.innerHeight || 0;
    getPermissionState(function(state){ s.permissionState = state; });
  };

  SilentShield.prototype._startPoW = function() {
    var s = this._signals;
    var challenge = Math.random().toString(36).slice(2) + Date.now().toString(36);
    s.powChallenge = challenge;
    this._powPromise = solvePoW(challenge, POW_DIFFICULTY).then(function(result) {
      s.powNonce = result.nonce;
      s.powHash  = result.hash;
      s.powMs    = result.ms;
      return result;
    });
    return this._powPromise;
  };

  SilentShield.prototype._trackGlobal = function() {
    var s = this._signals;
    var path = this._mousePath;

    document.addEventListener('mousemove', function(e) {
      s.mouseEvents++;
      if (path.length < 300) path.push({ x: e.clientX, y: e.clientY, t: Date.now() });
    }, { passive: true });

    document.addEventListener('mousedown', function() { s.mouseDownEvents++; }, { passive: true });
    document.addEventListener('scroll', function() { s.scrollEvents++; }, { passive: true });
    document.addEventListener('click', function() { s.clickEvents++; }, { passive: true });
    document.addEventListener('dblclick', function() { s.dblClickEvents++; }, { passive: true });
    document.addEventListener('contextmenu', function() { s.contextMenuEvents++; });

    document.addEventListener('keydown', function(e) {
      s.keydownEvents++;
      var now = Date.now();
      if (s.lastKeystrokeTime) {
        var interval = now - s.lastKeystrokeTime;
        s.keystrokeIntervals.push(interval);
        if (s.keystrokeIntervals.length > 120) s.keystrokeIntervals.shift();
      }
      s.lastKeystrokeTime = now;
      if (!s.formFillStart) s.formFillStart = now;
      if (e.key === 'Backspace') s.backspaceCount++;
      if (e.key === 'Delete')    s.deleteCount++;
      if (e.key === 'Tab')       s.tabCount++;
    }, { passive: true });

    document.addEventListener('paste', function() { s.pasteCount++; }, { passive: true });

    if (typeof window !== 'undefined') {
      window.addEventListener('focus', function() { s.focusEvents++; }, { passive: true });
      window.addEventListener('blur',  function() { s.blurEvents++;  }, { passive: true });
    }
  };

  SilentShield.prototype._addHoneypot = function(form) {
    var name = HONEYPOT_NAMES[Math.floor(Math.random() * HONEYPOT_NAMES.length)];
    var wrap = document.createElement('div');
    wrap.setAttribute('style', 'position:absolute;left:-9999px;top:-9999px;height:0;width:0;overflow:hidden;opacity:0;pointer-events:none;visibility:hidden;');
    var input = document.createElement('input');
    input.type         = 'text';
    input.name         = name;
    input.tabIndex     = -1;
    input.autocomplete = 'off';
    input.setAttribute('aria-hidden', 'true');
    wrap.appendChild(input);
    form.appendChild(wrap);
    var self = this;
    input.addEventListener('input', function() { if (input.value) self._signals.honeypotFilled = true; });
  };

  SilentShield.prototype._collectFormText = function(form) {
    var texts = [], inputs = form.querySelectorAll('input[type=text],input[type=email],input[type=tel],textarea');
    for (var i = 0; i < inputs.length; i++) {
      var el = inputs[i];
      if (el.value && el.name && el.name.indexOf('2') === -1 && el.name.indexOf('alt') === -1 && el.name.indexOf('hp_') === -1) {
        texts.push(el.value);
      }
    }
    this._signals.formText         = texts.join(' ');
    this._signals.fieldCount       = inputs.length;
    this._signals.mouseEntropy     = calcMouseEntropy(this._mousePath);
    this._signals.mouseSpeedVariance = calcMouseSpeedVariance(this._mousePath);
  };

  SilentShield.prototype._showFakeSuccess = function(form) {
    var msg = document.createElement('div');
    msg.setAttribute('style', 'padding:14px 20px;background:#22c55e;color:#fff;border-radius:8px;margin-top:12px;font-family:sans-serif;font-size:15px;');
    msg.textContent = 'Your message has been sent successfully!';
    if (form.parentNode) form.parentNode.insertBefore(msg, form.nextSibling);
    form.style.display = 'none';
  };

  SilentShield.prototype._submit = function(signals) {
    var payload = {};
    for (var k in signals) payload[k] = signals[k];
    payload.siteId = this.publicKey;
    return fetch(this.apiUrl + '/api/signal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'omit',
    }).then(function(r){ return r.json(); });
  };

  SilentShield.prototype.protect = function(formSelector) {
    var self = this;
    if (typeof document === 'undefined') return this;

    this._collectFingerprints();
    this._trackGlobal();
    this._startPoW();

    var selector = formSelector || 'form[data-silentshield]';
    var forms = document.querySelectorAll(selector);

    for (var i = 0; i < forms.length; i++) {
      (function(form) {
        if (self._forms.has(form)) return;
        self._forms.set(form, true);
        self._addHoneypot(form);

        form.addEventListener('submit', function(e) {
          e.preventDefault();
          e.stopImmediatePropagation();

          var s = self._signals;
          s.formFillMs = s.formFillStart ? Date.now() - s.formFillStart : 0;
          s.audioFingerprint = getAudioFingerprint();
          self._collectFormText(form);

          (self._powPromise || Promise.resolve()).then(function() {
            return self._submit(s);
          }).then(function(result) {
            // Inject token hidden field
            var tokenInput = form.querySelector('input[name=_ss_token]');
            if (!tokenInput) {
              tokenInput = document.createElement('input');
              tokenInput.type = 'hidden';
              tokenInput.name = '_ss_token';
              form.appendChild(tokenInput);
            }
            tokenInput.value = result.token || '';

            // If onSubmit callback registered, hand control to caller and stop here
            if (typeof self._onSubmitCb === 'function') {
              self._onSubmitCb(result);
              return;
            }

            // Bot: show fake success or fire onBot hook
            if (result.verdict === 'bot' && result.score < self.threshold) {
              if (typeof self.onBot === 'function') self.onBot(result);
              if (self.fakeSuccess) self._showFakeSuccess(form);
              return;
            }

            // Human: actually submit the form
            HTMLFormElement.prototype.submit.call(form);
          }).catch(function() {
            // Fail open — never block real users on network error
            if (typeof self._onSubmitCb === 'function') {
              self._onSubmitCb({ token: null, score: null, verdict: 'unknown', error: true });
              return;
            }
            HTMLFormElement.prototype.submit.call(form);
          });
        }, { capture: true });
      })(forms[i]);
    }
    return this;
  };

  // Convenience: SilentShield.init(opts) ??auto-protects all [data-silentshield] forms
  SilentShield.init = function(opts) {
    var instance = new SilentShield(opts || {});
    if (typeof document !== 'undefined') {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function(){ instance.protect(); });
      } else {
        instance.protect();
      }
    }
    return instance;
  };

  // onSubmit helper ??call cb(token) when a human submits
  SilentShield.prototype.onSubmit = function(cb) {
    this._onSubmitCb = cb;
    return this;
  };

  // Auto-init from script data attribute
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', function() {
      var script = document.querySelector('script[data-silentshield-key]');
      if (script) SilentShield.init({ publicKey: script.getAttribute('data-silentshield-key') });
    });
  }

  return SilentShield;
});

