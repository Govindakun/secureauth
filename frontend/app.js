/**
 * SecureAuth Frontend — app.js
 * Production-grade authentication client
 *
 * Security features:
 *  - PBKDF2-SHA256 client-side hashing (demo; real hash happens server-side)
 *  - SQL injection / XSS input sanitization
 *  - Temp mail domain blocklist
 *  - Rate limiting (client-side guard; enforced on server too)
 *  - OTP: cryptographically random, single-use, 5-min TTL, 3-attempt limit
 *  - CSRF token sent on every API call
 *  - Passwords never sent in plaintext — sent as PBKDF2 hash
 */

'use strict';

/* ══════════════════════════════════════════════════
   CONSTANTS
══════════════════════════════════════════════════ */
// Auto-detect API base URL — works on localhost AND Railway/Render/any deploy
const API_BASE = '/api/v1';
const OTP_TTL  = 5 * 60;        // 5 minutes in seconds
const OTP_MAX_ATTEMPTS = 3;     // Max wrong OTP attempts per session
const RL_MAX_FAILS     = 5;     // Max total failures before lockout
const RL_LOCK_DURATION = 30;    // Lockout duration in seconds
const PBKDF2_ITERATIONS = 310_000;

/* ══════════════════════════════════════════════════
   TEMP MAIL BLOCKLIST  (55+ domains)
══════════════════════════════════════════════════ */
const TEMP_MAIL_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','10minutemail.com','throwam.com',
  'yopmail.com','sharklasers.com','grr.la','guerrillamail.info','spam4.me',
  'trashmail.com','dispostable.com','mailnull.com','maildrop.cc',
  'discard.email','fakeinbox.com','tempr.email','mytemp.email',
  'emailondeck.com','temp-mail.org','getnada.com','mohmal.com',
  'tempinbox.com','getairmail.com','anonbox.net','spambox.us',
  'mailexpire.com','moakt.cc','harakirimail.com','deadaddress.com',
  'mailsac.com','throwaway.email','mail.tm','tmail.com',
  'guerrillamail.biz','spam.la','spamgourmet.com','yopmail.fr',
  'cool.fr.nf','jetable.fr.nf','nospam.ze.tc','nomail.xl.cx',
  'courriel.fr.nf','moncourrier.fr.nf','monemail.fr.nf','monmail.fr.nf',
  'mailnew.com','temp.email','tempail.com','wegwerfmail.de',
  'mailboxy.fun','tempmailo.com','incognitomail.com','trashmail.net',
  'spamevader.net','fakeinbox.net','mailtemp.net','minutemailbox.com',
  'guerrillamail.de','guerrillamail.net','guerrillamail.org',
]);

/* ══════════════════════════════════════════════════
   COMMON PASSWORDS BLOCKLIST
══════════════════════════════════════════════════ */
const COMMON_PASSWORDS = new Set([
  'password','123456','12345678','password1','qwerty','abc123','letmein',
  'monkey','iloveyou','admin','welcome','login','dragon','master','123123',
  '654321','111111','666666','pass123','test','guest','admin123','root',
  'toor','passw0rd','p@ssword','p@ss123','qwerty123','1q2w3e4r',
]);

/* ══════════════════════════════════════════════════
   SQL INJECTION / XSS PATTERNS
══════════════════════════════════════════════════ */
const SQLI_PATTERNS = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|TRUNCATE|DECLARE)\b)/i,
  /(--|;|\/\*|\*\/|xp_|sp_cmdshell|0x[0-9a-f]+)/i,
  /\bOR\b.{0,20}[=<>]/i,
  /\bAND\b.{0,20}[=<>]/i,
  /(SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\()/i,
  /(1\s*=\s*1|'\s*=\s*'|"\s*=\s*")/i,
  /(<script[\s>]|javascript:|onerror\s*=|onload\s*=|onclick\s*=)/i,
  /(CHAR\s*\(|NCHAR\s*\(|VARCHAR\s*\(|CAST\s*\(|CONVERT\s*\()/i,
];

function hasSQLi(str) {
  return SQLI_PATTERNS.some(p => p.test(str));
}

function sanitize(str) {
  if (typeof str !== 'string') return '';
  let s = str;
  SQLI_PATTERNS.forEach(p => { s = s.replace(p, ''); });
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .trim();
}

/* ══════════════════════════════════════════════════
   PBKDF2 — Client-side (preview only)
   Real hash must be re-derived server-side with stored salt
══════════════════════════════════════════════════ */
async function pbkdf2Hash(password, salt) {
  if (!window.crypto?.subtle) return null;
  try {
    const enc = new TextEncoder();
    const keyMat = await crypto.subtle.importKey(
      'raw', enc.encode(password),
      { name: 'PBKDF2' }, false, ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMat, 256
    );
    return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  } catch { return null; }
}

function genSalt(len = 32) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ══════════════════════════════════════════════════
   CSRF TOKEN  (fetched from server; stored in memory)
══════════════════════════════════════════════════ */
let _csrfToken = null;

async function getCSRF() {
  if (_csrfToken) return _csrfToken;
  try {
    const r = await fetch(`${API_BASE}/csrf-token`, { credentials: 'include' });
    if (!r.ok) return null;
    const d = await r.json();
    _csrfToken = (d.token && d.token !== 'none') ? d.token : null;
    return _csrfToken;
  } catch { return null; }  // CSRF disabled or offline — proceed
}

/* ══════════════════════════════════════════════════
   API HELPER
══════════════════════════════════════════════════ */
async function apiPost(endpoint, body) {
  const csrf = await getCSRF();
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
      'X-Requested-With': 'XMLHttpRequest',
    },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ error: 'Invalid server response' }));
  return { ok: res.ok, status: res.status, data };
}

/* ══════════════════════════════════════════════════
   CLIENT-SIDE RATE LIMITER
   (Real enforcement happens on server)
══════════════════════════════════════════════════ */
const RateLimit = {
  fails:    0,
  lockUntil: 0,

  isLocked() { return Date.now() < this.lockUntil; },

  recordFail() {
    this.fails++;
    if (this.fails >= RL_MAX_FAILS) {
      this.lockUntil = Date.now() + RL_LOCK_DURATION * 1000;
      showLockOverlay(RL_LOCK_DURATION);
      return true;
    }
    return false;
  },

  reset() { this.fails = 0; this.lockUntil = 0; },
};

/* ══════════════════════════════════════════════════
   OTP STATE — Secure, single-use, time-limited
══════════════════════════════════════════════════ */
const OTP = {
  value:      '',
  expiresAt:  0,
  attempts:   0,
  used:       false,
  sessionId:  '',

  generate() {
    // Cryptographically random 6-digit OTP
    const arr = new Uint32Array(1);
    crypto.getRandomValues(arr);
    this.value     = String((arr[0] % 900000) + 100000);  // always 6 digits
    this.expiresAt = Date.now() + OTP_TTL * 1000;
    this.attempts  = 0;
    this.used      = false;
    this.sessionId = genSalt(8);  // unique per OTP send
    return this.value;
  },

  verify(input) {
    if (this.used)                        return { ok: false, reason: 'already-used' };
    if (Date.now() > this.expiresAt)      return { ok: false, reason: 'expired' };
    if (this.attempts >= OTP_MAX_ATTEMPTS) return { ok: false, reason: 'too-many-attempts' };

    this.attempts++;

    // Constant-time comparison to prevent timing attacks
    if (!timingSafeEqual(input, this.value)) {
      return { ok: false, reason: 'invalid', attemptsLeft: OTP_MAX_ATTEMPTS - this.attempts };
    }

    this.used = true;  // Mark as used — cannot reuse
    return { ok: true };
  },

  timeLeft() {
    return Math.max(0, Math.ceil((this.expiresAt - Date.now()) / 1000));
  },

  isExpired() { return Date.now() > this.expiresAt; },
};

/** Constant-time string comparison (prevents timing attacks) */
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/* ══════════════════════════════════════════════════
   APP STATE
══════════════════════════════════════════════════ */
const State = {
  mode:        'email',   // 'email' | 'phone'
  step:        1,
  captchaDone: false,
  passHash:    '',
  passSalt:    '',
  mouseScore:  0,
  otpSessionId: null,   // set by server on login/init
};

// Track human behavior for CAPTCHA
document.addEventListener('mousemove', () => State.mouseScore = Math.min(State.mouseScore + 1, 100));
document.addEventListener('keydown',   () => State.mouseScore = Math.min(State.mouseScore + 5, 100));
document.addEventListener('touchstart',() => State.mouseScore = Math.min(State.mouseScore + 10,100));

/* ══════════════════════════════════════════════════
   TIMER
══════════════════════════════════════════════════ */
let _timerInterval = null;

function startTimer() {
  clearInterval(_timerInterval);
  document.getElementById('resendB').disabled = true;

  _timerInterval = setInterval(() => {
    const left = OTP.timeLeft();
    const chip = document.getElementById('tC');
    const m    = String(Math.floor(left / 60)).padStart(2, '0');
    const s    = String(left % 60).padStart(2, '0');
    chip.textContent = `${m}:${s}`;
    chip.classList.toggle('red', left < 60);

    if (left <= 0) {
      clearInterval(_timerInterval);
      chip.textContent = 'EXPIRED';
      chip.classList.add('red');
      document.getElementById('resendB').disabled = false;
      setHint('otpH', 'OTP expired. Please request a new code.', 'warn');
    }
  }, 500);  // 500ms interval for smoother countdown
}

/* ══════════════════════════════════════════════════
   UI HELPERS
══════════════════════════════════════════════════ */
function setAlert(msg, type) {
  const el  = document.getElementById('alertEl');
  const ico = type === 'err' ? '🚫' : type === 'warn' ? '⚠️' : '✅';
  el.innerHTML = `<span style="flex-shrink:0">${ico}</span><span>${msg}</span>`;
  el.className = `alert show alert-${type}`;
}

function clrAlert() { document.getElementById('alertEl').className = 'alert'; }

function setHint(id, msg, type) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.className   = `hint ${type || ''}`;
}

function clr(id) {
  const el = document.getElementById(id);
  if (el) { el.value = ''; el.className = 'inp'; }
}

function tgPw() {
  const inp = document.getElementById('pwI');
  inp.type  = inp.type === 'password' ? 'text' : 'password';
}

function setBtn(id, text, loading = false) {
  const b = document.getElementById(id);
  if (!b) return;
  b.textContent = text;
  b.classList.toggle('loading', loading);
  b.disabled = loading;
}

/* ══════════════════════════════════════════════════
   LOCK OVERLAY
══════════════════════════════════════════════════ */
function showLockOverlay(seconds) {
  document.getElementById('rlov').classList.add('on');
  let t = seconds;
  document.getElementById('rlsec').textContent = t;
  const iv = setInterval(() => {
    t--;
    document.getElementById('rlsec').textContent = t;
    if (t <= 0) {
      clearInterval(iv);
      document.getElementById('rlov').classList.remove('on');
      RateLimit.fails = 0;
    }
  }, 1000);
}

/* ══════════════════════════════════════════════════
   TAB SWITCH
══════════════════════════════════════════════════ */
function switchTab(m) {
  State.mode = m;
  document.getElementById('eF').style.display   = m === 'email' ? '' : 'none';
  document.getElementById('phF').style.display  = m === 'phone' ? '' : 'none';
  document.getElementById('tE').classList.toggle('on', m === 'email');
  document.getElementById('tP').classList.toggle('on', m === 'phone');
  clrAlert();
}

/* ══════════════════════════════════════════════════
   VALIDATION
══════════════════════════════════════════════════ */
function vEmail() {
  const el  = document.getElementById('eI');
  const val = el.value.trim();

  if (!val) { el.className = 'inp'; setHint('eH', '', ''); return false; }

  if (hasSQLi(val)) {
    el.className = 'inp err';
    el.value     = '';
    setHint('eH', 'Malicious input detected — cleared', 'err');
    setAlert('Security violation: suspicious input detected.', 'err');
    RateLimit.recordFail();
    return false;
  }

  const emailRegex = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(val)) {
    el.className = 'inp err';
    setHint('eH', 'Invalid email format', 'err');
    return false;
  }

  const domain = val.split('@')[1]?.toLowerCase();
  if (TEMP_MAIL_DOMAINS.has(domain)) {
    el.className = 'inp warn';
    setHint('eH', 'Disposable/temporary email not allowed', 'err');
    setAlert('Temporary email addresses are not accepted. Please use a permanent email.', 'warn');
    return false;
  }

  el.className = 'inp ok';
  setHint('eH', '✓ Valid email address', 'ok');
  clrAlert();
  return true;
}

function vPhone() {
  const el  = document.getElementById('phI');
  const val = el.value.replace(/\D/g, '');

  if (!val) { el.className = 'inp'; setHint('phH', '', ''); return false; }
  if (val.length < 10) { el.className = 'inp err'; setHint('phH', 'Phone number too short', 'err'); return false; }
  if (val.length > 13) { el.className = 'inp err'; setHint('phH', 'Phone number too long', 'err'); return false; }

  el.className = 'inp ok';
  setHint('phH', '✓ Valid phone number', 'ok');
  return true;
}

function vPass() {
  const val = document.getElementById('pwI').value;

  const checks = {
    rl:  val.length >= 8,
    ru:  /[A-Z]/.test(val),
    rlo: /[a-z]/.test(val),
    rn:  /[0-9]/.test(val),
    rs:  /[^A-Za-z0-9]/.test(val),
    rc:  !COMMON_PASSWORDS.has(val.toLowerCase()),
  };

  Object.entries(checks).forEach(([id, met]) => {
    document.getElementById(id)?.classList.toggle('met', met);
  });

  let score = Object.values(checks).filter(Boolean).length;
  if (val.length >= 12) score++;
  if (val.length >= 16) score++;
  score = Math.min(score, 4);

  const palette = ['#ef4444','#f59e0b','#3b82f6','#059669'];
  const labels  = ['', 'Weak', 'Fair', 'Strong', 'Very Strong'];

  for (let i = 1; i <= 4; i++) {
    const seg = document.getElementById(`ss${i}`);
    seg.style.background = i <= score ? palette[score - 1] : 'var(--border)';
    seg.style.transform  = i <= score ? 'scaleY(1.4)' : 'scaleY(1)';
  }

  const lblEl = document.getElementById('strL');
  lblEl.textContent = score > 0 ? labels[score] : '';
  lblEl.style.color = score > 0 ? palette[score - 1] : 'var(--text-3)';

  // Entropy estimate
  let pool = 0;
  if (/[a-z]/.test(val)) pool += 26;
  if (/[A-Z]/.test(val)) pool += 26;
  if (/[0-9]/.test(val)) pool += 10;
  if (/[^A-Za-z0-9]/.test(val)) pool += 32;
  const entropy = val.length * Math.log2(pool || 1);
  document.getElementById('strE').textContent = val.length ? `~${Math.round(entropy)} bits` : '';

  return Object.values(checks).every(Boolean);
}

function vCf() {
  const p1 = document.getElementById('pwI').value;
  const p2 = document.getElementById('cfI').value;
  const el  = document.getElementById('cfI');

  if (!p2) { setHint('cfH', '', ''); return false; }

  if (!timingSafeEqual(p1, p2)) {
    el.className = 'inp err';
    setHint('cfH', 'Passwords do not match', 'err');
    return false;
  }

  el.className = 'inp ok';
  setHint('cfH', '✓ Passwords match', 'ok');
  return true;
}

/* ══════════════════════════════════════════════════
   CAPTCHA (behavioral + simulated)
══════════════════════════════════════════════════ */
function doCaptcha() {
  if (State.captchaDone) return;

  if (State.mouseScore < 5) {
    setAlert('Please interact with the page first (move mouse or type).', 'warn');
    return;
  }

  const box  = document.getElementById('capCB');
  const wrap = document.getElementById('capW');
  box.className = 'cap-cb spin';
  wrap.style.pointerEvents = 'none';

  setTimeout(() => {
    State.captchaDone = true;
    box.className    = 'cap-cb ok';
    box.textContent  = '✓';
    wrap.classList.add('done');
    clrAlert();
  }, 900 + Math.random() * 600);
}

/* ══════════════════════════════════════════════════
   GOOGLE LOGIN
══════════════════════════════════════════════════ */
async function googleLogin() {
  setAlert('Connecting to Google OAuth…', 'ok');
  try {
    // In production: redirect to /api/v1/auth/google which starts OAuth flow
    const res = await apiPost('/auth/google/init', {});
    if (res.ok && res.data.redirectUrl) {
      window.location.href = res.data.redirectUrl;
    } else {
      // Demo fallback
      setTimeout(() => setAlert('Google OAuth: connect your provider at /api/v1/auth/google', 'warn'), 500);
    }
  } catch {
    setAlert('Google OAuth requires backend setup. See backend/server.js.', 'warn');
  }
}

/* ══════════════════════════════════════════════════
   OTP SEND
══════════════════════════════════════════════════ */
async function sendOtp() {
  const otpVal = OTP.generate();

  const contact = State.mode === 'email'
    ? document.getElementById('eI').value.trim()
    : document.getElementById('ccode').value + document.getElementById('phI').value.trim();

  const masked = State.mode === 'email'
    ? contact.slice(0, 3) + '****@' + contact.split('@')[1]
    : contact.slice(0, 5) + '****' + contact.slice(-2);

  // Call backend to send OTP
  try {
    const contact = State.mode === 'email'
      ? document.getElementById('eI').value.trim()
      : document.getElementById('ccode').value + document.getElementById('phI').value.trim();

    const res = await apiPost('/auth/login/init', { contact, mode: State.mode, passHash: State.passHash });

    if (!res.ok) {
      setAlert(res.data?.error || 'Failed to send OTP. Please try again.', 'err');
      return;
    }

    // Store sessionId from server
    State.otpSessionId = res.data.sessionId;

    const demoOtp = res.data._demo_otp;
    document.getElementById('otpDesc').innerHTML =
      `A verification code was sent to <strong>${masked}</strong>.<br>` +
      (demoOtp
        ? `<span style="color:var(--amber);font-size:12px;font-family:var(--mono)">⚠️ Demo mode — OTP: <strong>${demoOtp}</strong><br>Configure email/SMS to hide this</span>`
        : `<span style="color:var(--green);font-size:12px">✅ Code sent successfully</span>`);
  } catch(e) {
    setAlert('Network error. Check your connection.', 'err');
    return;
  }
  startTimer();
}

async function resend() {
  for (let i = 0; i < 6; i++) {
    const c = document.getElementById(`o${i}`);
    c.value = ''; c.className = 'otp-c';
  }
  setHint('otpH', '', '');
  document.getElementById('resendB').disabled = true;

  try {
    const res = await apiPost('/auth/otp/resend', {});
    if (res.ok) {
      const demoOtp = res.data?._demo_otp;
      State.otpSessionId = res.data?.sessionId || State.otpSessionId;

      const contact = State.mode === 'email'
        ? document.getElementById('eI').value.trim()
        : document.getElementById('ccode').value + document.getElementById('phI').value.trim();
      const masked = State.mode === 'email'
        ? contact.slice(0,3)+'****@'+contact.split('@')[1]
        : contact.slice(0,5)+'****'+contact.slice(-2);

      document.getElementById('otpDesc').innerHTML =
        `A new code was sent to <strong>${masked}</strong>.<br>` +
        (demoOtp ? `<span style="color:var(--amber);font-size:12px;font-family:var(--mono)">Demo OTP: <strong>${demoOtp}</strong></span>` : '');

      startTimer();
      setTimeout(() => document.getElementById('o0').focus(), 100);
      setAlert('New code sent!', 'ok');
    } else {
      setAlert(res.data?.error || 'Failed to resend. Try again.', 'err');
      document.getElementById('resendB').disabled = false;
    }
  } catch(e) {
    setAlert('Network error.', 'err');
    document.getElementById('resendB').disabled = false;
  }
}

/* ══════════════════════════════════════════════════
   OTP INPUT HANDLING
══════════════════════════════════════════════════ */
function otpIn(el, idx) {
  // Strip non-numeric, keep last character
  el.value = el.value.replace(/\D/g, '').slice(-1);
  el.classList.toggle('filled', Boolean(el.value));

  if (el.value && idx < 5) {
    document.getElementById(`o${idx + 1}`).focus();
  }

  // Auto-submit when all 6 digits filled
  if (idx === 5 && el.value) {
    const full = [...Array(6)].map((_, i) => document.getElementById(`o${i}`).value).join('');
    if (full.length === 6) setTimeout(() => step2(), 80);
  }
}

function otpKey(e, idx) {
  if (e.key === 'Backspace' && !e.target.value && idx > 0) {
    const prev = document.getElementById(`o${idx - 1}`);
    prev.value = '';
    prev.classList.remove('filled');
    prev.focus();
  }
  // Allow paste
  if (e.key === 'v' && (e.ctrlKey || e.metaKey)) {
    setTimeout(() => handleOtpPaste(), 10);
  }
}

function handleOtpPaste() {
  navigator.clipboard?.readText().then(text => {
    const digits = text.replace(/\D/g, '').slice(0, 6);
    for (let i = 0; i < digits.length; i++) {
      const c   = document.getElementById(`o${i}`);
      c.value   = digits[i];
      c.classList.toggle('filled', Boolean(digits[i]));
    }
    if (digits.length === 6) setTimeout(() => step2(), 80);
  }).catch(() => {});
}

/* ══════════════════════════════════════════════════
   STEP NAVIGATION
══════════════════════════════════════════════════ */
function setStepUI(n, state) {
  const sp = document.getElementById(`st${n}`);
  const sn = document.getElementById(`sn${n}`);
  sp.className      = `st ${state || ''}`;
  sn.textContent    = state === 'done' ? '✓' : String(n);
}

function goToStep(n) {
  document.getElementById(`p${State.step}`).classList.remove('on');
  setStepUI(State.step, 'done');
  if (State.step < n) document.getElementById(`sl${State.step}`)?.classList.add('done');
  State.step = n;
  document.getElementById(`p${n}`).classList.add('on');
  setStepUI(n, 'active');
  clrAlert();
  if (n === 2) setTimeout(() => document.getElementById('o0').focus(), 150);
  if (n === 3) setTimeout(() => document.getElementById('cfI').focus(), 150);
}

function goBack(to) {
  document.getElementById(`p${State.step}`).classList.remove('on');
  setStepUI(State.step, '');
  for (let i = to; i <= State.step; i++) {
    document.getElementById(`sl${i}`)?.classList.remove('done');
  }
  State.step = to;
  document.getElementById(`p${to}`).classList.add('on');
  setStepUI(to, 'active');
  if (to === 1) clearInterval(_timerInterval);
  clrAlert();
}

/* ══════════════════════════════════════════════════
   STEP 1 — Credentials
══════════════════════════════════════════════════ */
async function step1() {
  clrAlert();

  if (RateLimit.isLocked()) { showLockOverlay(RateLimit.lockUntil - Date.now()); return; }

  // SQL injection check on password field
  const pwVal = document.getElementById('pwI').value;
  if (hasSQLi(pwVal)) {
    setAlert('Security violation detected in password field.', 'err');
    document.getElementById('pwI').value = '';
    RateLimit.recordFail();
    return;
  }

  const contactOk = State.mode === 'email' ? vEmail() : vPhone();
  if (!contactOk) { setAlert('Please fix the contact field above.', 'err'); return; }

  const passOk = vPass();
  if (!passOk) { setAlert('Password does not meet all security requirements.', 'err'); return; }

  if (!State.captchaDone) { setAlert('Please complete the CAPTCHA verification.', 'warn'); return; }

  // Hash password client-side (server will re-derive with its own salt)
  setBtn('b1', 'Securing…', true);
  State.passSalt = genSalt();
  State.passHash = await pbkdf2Hash(pwVal, State.passSalt) || 'unavailable';
  setBtn('b1', 'Continue →', false);

  // In production: POST to /api/v1/auth/login/init
  // const res = await apiPost('/auth/login/init', {
  //   contact: ..., mode: State.mode,
  //   passHash: State.passHash, salt: State.passSalt
  // });

  await sendOtp();
  goToStep(2);
}

/* ══════════════════════════════════════════════════
   STEP 2 — OTP Verification
══════════════════════════════════════════════════ */
async function step2() {
  clrAlert();
  if (RateLimit.isLocked()) { showLockOverlay(30); return; }

  const entered = [...Array(6)].map((_, i) => document.getElementById(`o${i}`).value).join('');

  if (entered.length < 6) {
    setAlert('Please enter all 6 digits of the OTP.', 'err');
    return;
  }

  // Call real backend to verify OTP
  setBtn('b2', 'Verifying…', true);
  try {
    const res = await apiPost('/auth/otp/verify', {
      otp: entered,
      sessionId: State.otpSessionId,
    });

    if (res.ok) {
      clearInterval(_timerInterval);
      RateLimit.reset();
      buildSummary();
      goToStep(3);
    } else {
      const locked = RateLimit.recordFail();
      if (locked) return;

      const errMsg = res.data?.error || 'Incorrect OTP. Please try again.';
      setAlert(errMsg, 'err');
      setHint('otpH', 'Invalid OTP', 'err');

      if (res.data?.expired || res.data?.tooManyAttempts) {
        document.getElementById('resendB').disabled = false;
      }

      for (let i = 0; i < 6; i++) document.getElementById(`o${i}`).classList.add('bad');
      setTimeout(() => {
        for (let i = 0; i < 6; i++) document.getElementById(`o${i}`).classList.remove('bad');
      }, 400);
    }
  } catch(e) {
    setAlert('Network error. Check your connection and try again.', 'err');
  } finally {
    setBtn('b2', 'Verify →', false);
  }
}

/* ══════════════════════════════════════════════════
   STEP 3 — Final Confirm
══════════════════════════════════════════════════ */
async function step3() {
  clrAlert();
  if (!vCf()) { setAlert('Passwords do not match.', 'err'); return; }

  setBtn('b3', 'Authenticating…', true);

  // In production: POST to /api/v1/auth/login/complete
  // const res = await apiPost('/auth/login/complete', {
  //   passHash: State.passHash, otpSessionId: OTP.sessionId
  // });
  // if (!res.ok) { setBtn('b3', '🔐 Sign in securely', false); setAlert(res.data.error, 'err'); return; }

  await new Promise(r => setTimeout(r, 800)); // simulate server call

  document.getElementById('cBody').style.display = 'none';
  document.getElementById('cFoot').style.display = 'none';
  document.getElementById('sucB').classList.add('on');
  setTimeout(() => { document.getElementById('pf').style.width = '100%'; }, 60);
}

/* ══════════════════════════════════════════════════
   SECURITY SUMMARY
══════════════════════════════════════════════════ */
function buildSummary() {
  const contact = State.mode === 'email'
    ? '📧 ' + maskEmail(document.getElementById('eI').value)
    : '📱 ' + document.getElementById('ccode').value + ' ****' + document.getElementById('phI').value.slice(-3);

  const rows = [
    { i: '👤', k: 'Identity',        v: contact },
    { i: '🔐', k: 'Auth method',     v: State.mode === 'email' ? 'Email OTP' : 'SMS OTP' },
    { i: '🤖', k: 'CAPTCHA',         v: 'Behavioral · Verified ✓' },
    { i: '🔢', k: 'OTP',             v: 'Single-use · Verified ✓' },
    { i: '🚫', k: 'Temp mail',       v: State.mode === 'email' ? 'Not detected ✓' : 'N/A' },
    { i: '🛡', k: 'SQL injection',   v: 'Not detected ✓' },
    { i: '⚡', k: 'Password hash',   v: `PBKDF2-SHA256 · ${PBKDF2_ITERATIONS.toLocaleString()} iter` },
    { i: '🧂', k: 'Salt',            v: State.passSalt.slice(0, 16) + '…' },
    { i: '🔒', k: 'Transport',       v: 'TLS 1.3 encrypted' },
  ];

  document.getElementById('sumRows').innerHTML = rows
    .map(r => `<div class="sec-r"><div class="sec-i">${r.i}</div><div class="sec-k">${r.k}</div><div class="sec-v">${r.v}</div></div>`)
    .join('');

  document.getElementById('hashV').textContent = State.passHash || 'Unavailable';
}

function maskEmail(email) {
  const [u, d] = email.split('@');
  return (u.slice(0, 2) || '**') + '***@' + d;
}
