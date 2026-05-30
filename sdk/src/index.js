/**
 * SilentShield JS SDK v2.0
 * Invisible bot detection ??PoW, behavioral analysis, canvas/WebGL fingerprinting.
 * https://silentshield.krl.rk
 * CDN: https://cdn.jsdelivr.net/npm/silentshield-js@latest/dist/silentshield.min.js
 */
(function (global, factory) {
  if (typeof module !== 'undefined' && module.exports) module.exports = factory();
  else if (typeof define === 'function' && define.amd) define(factory);
  else global.SilentShield = factory();
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  var DEFAULT_API = 'https://api.silentshield.krl.rk';
  var POW_DIFFICULTY = 3; // leading zero bits ??solved in ~100-300ms by real browsers

  var HONEYPOT_NAMES = [
    'phone2','website2','contact_alt','url_field','company2','fax_number',
    'address2','city2','zip2','ref_code','email2','name2','subject2','ref_id',
    'hp_field','bot_check','second_email','alt_phone','web_url','extra_field',
  ];

  // ?? Proof of Work ??????????????????????????????????????????????????????????
  function sha256(str) {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      // async via Web Crypto ??handled in solvePoW
      return null;
    }
    return null;
  }

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
              if (batch < 50) loop(); // batch 50 sync, then yield
              else { batch = 0; setTimeout(loop, 0); }
            }
          });
        }
        loop();
      }
      attempt();
    });
  }

  // ?? Canvas fingerprint ?????????????????????????????????????????????????????
  function getCanvasFingerprint() {
    try {
      var canvas = document.createElement('canvas');
      canvas.width = 220; canvas.height = 30;
      var ctx = canvas.getContext('2d');
      ctx.textBaseline = 'alphabetic';
      ctx.fillStyle = '#f0f';
      ctx.fillRect(0, 0, 220, 30);
      ctx.font = '15px Arial';
      ctx.fillStyle = '#069';
      ctx.fillText('SilentShield ?썳截?1l0O', 2, 22);
      ctx.fillStyle = 'rgba(102,204,0,0.8)';
      ctx.font = '14px Georgia';
      ctx.fillText('bot?', 100, 22);
      var data = canvas.toDataURL('image/png');
      // Return a short signature ??enough to detect headless rendering differences
      return data.slice(data.length - 64);
    } catch (e) { return 'blocked'; }
  }

  // ?? WebGL fingerprint ??????????????????????????????????????????????????????
  function getWebGLInfo() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return { vendor: 'none', renderer: 'none', headless: true };
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      var vendor   = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)   : gl.getParameter(gl.VENDOR);
      var renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      // Known headless/software renderers
      var headlessMarkers = ['swiftshader','llvmpipe','softpipe','mesa','angle','vmware','virtualbox','parallels'];
      var isHeadless = headlessMarkers.some(function(m){ return (renderer||'').toLowerCase().includes(m); });
      return { vendor: vendor, renderer: renderer, headless: isHeadless };
    } catch (e) { return { vendor: 'error', renderer: 'error', headless: false }; }
  }

  // ?? Audio fingerprint ??????????????????????????????????????????????????????
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
      // Sum a slice as a fingerprint value
      var sum = 0;
      for (var i = 0; i < Math.min(30, data.length); i++) sum += Math.abs(data[i]);
      return Math.round(sum * 1000) / 1000;
    } catch (e) { return 'error'; }
  }

  // ?? Mouse path entropy ?????????????????????????????????????????????????????
  function calcMouseEntropy(path) {
    if (!path || path.length < 3) return 0;
    // Measure angle changes ??human movement is curved, bots move linearly
    var angles = [];
    for (var i = 1; i < path.length - 1; i++) {
      var dx1 = path[i].x - path[i-1].x, dy1 = path[i].y - path[i-1].y;
      var dx2 = path[i+1].x - path[i].x, dy2 = path[i+1].y - path[i].y;
      var angle = Math.atan2(dy2, dx2) - Math.atan2(dy1, dx1);
      angles.push(angle);
    }
    var mean = angles.reduce(function(a,b){return a+b;},0) / angles.length;
    var variance = angles.reduce(function(s,a){return s+Math.pow(a-mean,2);},0) / angles.length;
    return Math.round(variance * 10000) / 10000;
  }

  // ?? Permission probing ?????????????????????????????????????????????????????
  function getPermissionState(cb) {
    if (typeof navigator === 'undefined' || !navigator.permissions) return cb('unsupported');
    navigator.permissions.query({ name: 'notifications' }).then(function(r){ cb(r.state); }).catch(function(){ cb('error'); });
  }

  // ?? SilentShield constructor ???????????????????????????????????????????????
  function SilentShield(opts) {
    this.publicKey = opts.publicKey || null;
    this.apiUrl    = (opts.apiUrl || DEFAULT_API).replace(/\/$/, '');
    this.onBot     = opts.onBot || null;
    this.fakeSuccess = opts.fakeSuccess !== false;
    this.threshold = opts.threshold || 45;
    this._signals  = this._initSignals();
    this._forms    = new Map ? new Map() : { _m: [], has: function(k){ return this._m.some(function(e){return e[0]===k;}); }, set: function(k,v){ this._m.push([k,v]); } };
    this._mousePath = [];
    this._powPromise = null;
  }

  SilentShield.prototype._initSignals = function() {
    var nav = typeof navigator !== 'undefined' ? navigator : {};
    var scr = typeof screen !== 'undefined' ? screen : {};
    var win = typeof window !== 'undefined' ? window : {};
    return {
      pageEnterTime:      Date.now(),
      mouseEvents:        0,
      scrollEvents:       0,
      clickEvents:        0,
      keydownEvents:      0,
      focusEvents:        0,
      blurEvents:         0,
      keystrokeIntervals: [],
      lastKeystrokeTime:  null,
      formFillStart:      null,
      formFillMs:         0,
      backspaceCount:     0,
      deleteCount:        0,
      tabCount:           0,
      fieldCount:         0,
      pasteCount:         0,
      honeypotFilled:     false,
      formText:           '',
      // Environment
      screenWidth:        scr.width    || 0,
      screenHeight:       scr.height   || 0,
      screenAvailWidth:   scr.availWidth || 0,
      colorDepth:         scr.colorDepth || 0,
      pixelRatio:         win.devicePixelRatio || 1,
      timezone:           (typeof Intl !== 'undefined') ? Intl.DateTimeFormat().resolvedOptions().timeZone : '',
      timezoneOffset:     new Date().getTimezoneOffset(),
      languages:          nav.languages ? Array.prototype.slice.call(nav.languages) : [],
      pluginCount:        nav.plugins   ? nav.plugins.length : 0,
      webdriver:          nav.webdriver || false,
      hardwareConcurrency: nav.hardwareConcurrency || 0,
      deviceMemory:       nav.deviceMemory || 0,
      touchSupport:       'ontouchstart' in win || (nav.maxTouchPoints > 0),
      platform:           nav.platform  || '',
      cookieEnabled:      nav.cookieEnabled || false,
      doNotTrack:         nav.doNotTrack || '',
      connectionType:     (nav.connection && nav.connection.effectiveType) || '',
      // Fingerprints ??filled in during protect()
      canvasFingerprint:  '',
      webglVendor:        '',
      webglRenderer:      '',
      webglHeadless:      false,
      audioFingerprint:   '',
      mouseEntropy:       0,
      permissionState:    '',
      // PoW
      powChallenge:       '',
      powNonce:           0,
      powHash:            '',
      powMs:              0,
      powDifficulty:      POW_DIFFICULTY,
    };
  };

  SilentShield.prototype._collectFingerprints = function() {
    var s = this._signals;
    s.canvasFingerprint = getCanvasFingerprint();
    var wgl = getWebGLInfo();
    s.webglVendor   = wgl.vendor;
    s.webglRenderer = wgl.renderer;
    s.webglHeadless = wgl.headless;
    s.audioFingerprint = getAudioFingerprint();
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
    var lastX = 0, lastY = 0, lastScrollY = 0;

    document.addEventListener('mousemove', function(e) {
      s.mouseEvents++;
      if (path.length < 200) path.push({ x: e.clientX, y: e.clientY, t: Date.now() });
      lastX = e.clientX; lastY = e.clientY;
    }, { passive: true });

    document.addEventListener('scroll', function() {
      s.scrollEvents++;
      var newY = window.scrollY || document.documentElement.scrollTop || 0;
      lastScrollY = newY;
    }, { passive: true });

    document.addEventListener('click', function() { s.clickEvents++; }, { passive: true });

    document.addEventListener('keydown', function(e) {
      s.keydownEvents++;
      var now = Date.now();
      if (s.lastKeystrokeTime) {
        var interval = now - s.lastKeystrokeTime;
        s.keystrokeIntervals.push(interval);
        if (s.keystrokeIntervals.length > 100) s.keystrokeIntervals.shift();
      }
      s.lastKeystrokeTime = now;
      if (!s.formFillStart) s.formFillStart = now;
      if (e.key === 'Backspace') s.backspaceCount++;
      if (e.key === 'Delete')    s.deleteCount++;
      if (e.key === 'Tab')       s.tabCount++;
    }, { passive: true });

    document.addEventListener('paste', function() { s.pasteCount++; }, { passive: true });
    window.addEventListener('focus', function() { s.focusEvents++; }, { passive: true });
    window.addEventListener('blur',  function() { s.blurEvents++;  }, { passive: true });
  };

  SilentShield.prototype._addHoneypot = function(form) {
    var name = HONEYPOT_NAMES[Math.floor(Math.random() * HONEYPOT_NAMES.length)];
    var wrap  = document.createElement('div');
    wrap.setAttribute('style', 'position:absolute;left:-9999px;height:0;overflow:hidden;opacity:0;pointer-events:none;');
    var input = document.createElement('input');
    input.type          = 'text';
    input.name          = name;
    input.tabIndex      = -1;
    input.autocomplete  = 'off';
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
      if (el.value && el.name && !el.name.includes('2') && !el.name.includes('alt') && !el.name.includes('hp')) {
        texts.push(el.value);
      }
    }
    this._signals.formText  = texts.join(' ');
    this._signals.fieldCount = inputs.length;
    this._signals.mouseEntropy = calcMouseEntropy(this._mousePath);
  };

  SilentShield.prototype._showFakeSuccess = function(form) {
    var msg = document.createElement('div');
    msg.setAttribute('style', 'padding:14px 20px;background:#22c55e;color:#fff;border-radius:8px;margin-top:12px;font-family:sans-serif;font-size:15px;');
    msg.textContent = 'Your message has been sent successfully!';
    form.parentNode && form.parentNode.insertBefore(msg, form.nextSibling);
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

    // Collect fingerprints and start PoW immediately
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
          self._collectFormText(form);

          // Wait for PoW to finish, then submit
          (self._powPromise || Promise.resolve()).then(function() {
            return self._submit(s);
          }).then(function(result) {
            if (result.verdict === 'bot' && result.score < self.threshold) {
              if (typeof self.onBot === 'function') self.onBot(result);
              if (self.fakeSuccess) self._showFakeSuccess(form);
              return;
            }

            var tokenInput = form.querySelector('input[name=_ss_token]');
            if (!tokenInput) {
              tokenInput = document.createElement('input');
              tokenInput.type = 'hidden';
              tokenInput.name = '_ss_token';
              form.appendChild(tokenInput);
            }
            tokenInput.value = result.token;
            HTMLFormElement.prototype.submit.call(form);
          }).catch(function() {
            // Fail open ??don't block real users on network error
            HTMLFormElement.prototype.submit.call(form);
          });
        }, { capture: true });
      })(forms[i]);
    }
    return this;
  };

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

  // Auto-init from script data attribute
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', function() {
      var script = document.querySelector('script[data-silentshield-key]');
      if (script) SilentShield.init({ publicKey: script.getAttribute('data-silentshield-key') });
    });
  }

  return SilentShield;
});

