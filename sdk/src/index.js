/**
 * SilentShield JS SDK
 * Invisible bot detection — no CAPTCHAs, no friction.
 * https://silentshield.io
 */

(function (global, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else if (typeof define === 'function' && define.amd) {
    define(factory);
  } else {
    global.SilentShield = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this, function () {
  'use strict';

  const DEFAULT_API = 'https://api.silentshield.io';
  const HONEYPOT_NAMES = [
    'phone2', 'website2', 'contact_alt', 'url_field', 'company2',
    'fax_number', 'address2', 'city2', 'zip2', 'country2',
    'email2', 'name2', 'subject2', 'message2', 'ref_code',
  ];

  function SilentShield(opts) {
    this.publicKey = opts.publicKey || null;
    this.apiUrl = (opts.apiUrl || DEFAULT_API).replace(/\/$/, '');
    this.onBot = opts.onBot || null;
    this.fakeSuccess = opts.fakeSuccess !== false;
    this.threshold = opts.threshold || 45;
    this._signals = this._initSignals();
    this._forms = new Map();
  }

  SilentShield.prototype._initSignals = function () {
    return {
      pageEnterTime: Date.now(),
      mouseEvents: 0,
      scrollEvents: 0,
      clickEvents: 0,
      keydownEvents: 0,
      focusEvents: 0,
      keystrokeIntervals: [],
      lastKeystrokeTime: null,
      formFillStart: null,
      formFillMs: 0,
      backspaceCount: 0,
      tabCount: 0,
      fieldCount: 0,
      honeypotFilled: false,
      formText: '',
      screenWidth: (typeof screen !== 'undefined' && screen.width) || 0,
      screenHeight: (typeof screen !== 'undefined' && screen.height) || 0,
      colorDepth: (typeof screen !== 'undefined' && screen.colorDepth) || 0,
      timezone: (typeof Intl !== 'undefined' && Intl.DateTimeFormat().resolvedOptions().timeZone) || '',
      languages: (typeof navigator !== 'undefined' && navigator.languages) ? Array.from(navigator.languages) : [],
      pluginCount: (typeof navigator !== 'undefined' && navigator.plugins) ? navigator.plugins.length : 0,
      webdriver: (typeof navigator !== 'undefined' && navigator.webdriver) || false,
      hardwareConcurrency: (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || 0,
      deviceMemory: (typeof navigator !== 'undefined' && navigator.deviceMemory) || 0,
      touchSupport: (typeof window !== 'undefined' && 'ontouchstart' in window) || false,
      platform: (typeof navigator !== 'undefined' && navigator.platform) || '',
    };
  };

  SilentShield.prototype._trackGlobal = function () {
    const s = this._signals;
    if (typeof document === 'undefined') return;

    document.addEventListener('mousemove', function () { s.mouseEvents++; }, { passive: true });
    document.addEventListener('scroll', function () { s.scrollEvents++; }, { passive: true });
    document.addEventListener('click', function () { s.clickEvents++; }, { passive: true });

    document.addEventListener('keydown', function (e) {
      s.keydownEvents++;
      const now = Date.now();
      if (s.lastKeystrokeTime) {
        s.keystrokeIntervals.push(now - s.lastKeystrokeTime);
        if (s.keystrokeIntervals.length > 50) s.keystrokeIntervals.shift();
      }
      s.lastKeystrokeTime = now;
      if (e.key === 'Backspace') s.backspaceCount++;
      if (e.key === 'Tab') s.tabCount++;
      if (!s.formFillStart) s.formFillStart = now;
    }, { passive: true });
  };

  SilentShield.prototype._addHoneypot = function (form) {
    const name = HONEYPOT_NAMES[Math.floor(Math.random() * HONEYPOT_NAMES.length)];
    const wrap = document.createElement('div');
    wrap.style.cssText = 'position:absolute;left:-9999px;height:0;overflow:hidden;opacity:0;';
    const input = document.createElement('input');
    input.type = 'text';
    input.name = name;
    input.tabIndex = -1;
    input.autocomplete = 'off';
    input.setAttribute('aria-hidden', 'true');
    wrap.appendChild(input);
    form.appendChild(wrap);

    const self = this;
    input.addEventListener('input', function () {
      if (input.value) self._signals.honeypotFilled = true;
    });
  };

  SilentShield.prototype._collectFormText = function (form) {
    const texts = [];
    const inputs = form.querySelectorAll('input[type=text], input[type=email], textarea');
    inputs.forEach(function (el) {
      if (el.value && !el.name.includes('2') && !el.name.includes('alt')) {
        texts.push(el.value);
      }
    });
    this._signals.formText = texts.join(' ');
    this._signals.fieldCount = inputs.length;
  };

  SilentShield.prototype.protect = function (formSelector) {
    const self = this;
    if (typeof document === 'undefined') return;

    this._trackGlobal();

    const selector = formSelector || 'form[data-silentshield]';
    const forms = document.querySelectorAll(selector);

    forms.forEach(function (form) {
      if (self._forms.has(form)) return;
      self._forms.set(form, true);
      self._addHoneypot(form);

      form.addEventListener('submit', function (e) {
        e.preventDefault();
        e.stopImmediatePropagation();

        self._signals.formFillMs = self._signals.formFillStart
          ? Date.now() - self._signals.formFillStart
          : 0;
        self._collectFormText(form);

        self._submit(self._signals).then(function (result) {
          if (result.verdict === 'bot' && self._signals.score < self.threshold) {
            if (typeof self.onBot === 'function') {
              self.onBot(result);
            }
            if (self.fakeSuccess) {
              // Show fake success — bot doesn't know it failed
              self._showFakeSuccess(form);
            }
            return;
          }

          // Inject token into form
          let tokenInput = form.querySelector('input[name=_ss_token]');
          if (!tokenInput) {
            tokenInput = document.createElement('input');
            tokenInput.type = 'hidden';
            tokenInput.name = '_ss_token';
            form.appendChild(tokenInput);
          }
          tokenInput.value = result.token;

          // Re-submit form
          const nativeSubmit = HTMLFormElement.prototype.submit;
          nativeSubmit.call(form);
        }).catch(function () {
          // On network error, allow submission (fail open to avoid blocking real users)
          const nativeSubmit = HTMLFormElement.prototype.submit;
          nativeSubmit.call(form);
        });
      }, { capture: true });
    });

    return this;
  };

  SilentShield.prototype._showFakeSuccess = function (form) {
    const msg = document.createElement('div');
    msg.style.cssText = 'padding:12px;background:#4caf50;color:#fff;border-radius:6px;margin-top:8px;';
    msg.textContent = 'Successfully submitted!';
    form.parentNode.insertBefore(msg, form.nextSibling);
    form.style.display = 'none';
  };

  SilentShield.prototype._submit = function (signals) {
    const payload = Object.assign({}, signals, { siteId: this.publicKey });
    return fetch(this.apiUrl + '/api/signal', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'omit',
    }).then(function (r) { return r.json(); });
  };

  // Static factory
  SilentShield.init = function (opts) {
    const instance = new SilentShield(opts || {});
    if (typeof document !== 'undefined') {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { instance.protect(); });
      } else {
        instance.protect();
      }
    }
    return instance;
  };

  // Auto-init from script tag attributes
  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', function () {
      const script = document.querySelector('script[data-silentshield-key]');
      if (script) {
        SilentShield.init({ publicKey: script.getAttribute('data-silentshield-key') });
      }
    });
  }

  return SilentShield;
});
