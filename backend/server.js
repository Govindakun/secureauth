/**
 * SecureAuth Backend — server.js
 * Production-grade Node.js / Express authentication server
 *
 * Run:
 *   npm install
 *   node server.js
 *
 * Environment variables (create .env file):
 *   PORT=3000
 *   SESSION_SECRET=<64-char random string>
 *   DB_URI=mongodb://localhost:27017/secureauth  OR  postgresql://...
 *   EMAIL_HOST=smtp.sendgrid.net
 *   EMAIL_USER=apikey
 *   EMAIL_PASS=<your-sendgrid-api-key>
 *   TWILIO_ACCOUNT_SID=<sid>
 *   TWILIO_AUTH_TOKEN=<token>
 *   TWILIO_PHONE=+1xxxxxxxxxx
 *   GOOGLE_CLIENT_ID=<google-oauth-client-id>
 *   GOOGLE_CLIENT_SECRET=<google-oauth-client-secret>
 *   GOOGLE_CALLBACK_URL=http://localhost:3000/api/v1/auth/google/callback
 *   FRONTEND_URL=http://localhost:3000
 *   BCRYPT_ROUNDS=12
 *   OTP_TTL_SECONDS=300
 *   OTP_MAX_ATTEMPTS=3
 *   RATE_LIMIT_WINDOW_MS=900000
 *   RATE_LIMIT_MAX=100
 */

'use strict';

require('dotenv').config();
const express        = require('express');
const session        = require('express-session');
const helmet         = require('helmet');
const cors           = require('cors');
const rateLimit      = require('express-rate-limit');
const slowDown       = require('express-slow-down');
const csrf           = require('csurf');
const cookieParser   = require('cookie-parser');
const bcrypt         = require('bcrypt');
const crypto         = require('crypto');
const validator      = require('validator');
const DOMPurify      = require('isomorphic-dompurify');
const nodemailer     = require('nodemailer');
const twilio         = require('twilio');
const passport       = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoSanitize  = require('express-mongo-sanitize');
const hpp            = require('hpp');
const path           = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

/* ══════════════════════════════════════════════════
   CONSTANTS
══════════════════════════════════════════════════ */
const BCRYPT_ROUNDS       = parseInt(process.env.BCRYPT_ROUNDS)       || 12;
const OTP_TTL_SECONDS     = parseInt(process.env.OTP_TTL_SECONDS)     || 300;
const OTP_MAX_ATTEMPTS    = parseInt(process.env.OTP_MAX_ATTEMPTS)    || 3;
const OTP_LENGTH          = 6;
const SESSION_MAX_AGE     = 24 * 60 * 60 * 1000; // 24 hours



/* ══════════════════════════════════════════════════
   TEMP MAIL DOMAINS BLOCKLIST
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
]);

/* ══════════════════════════════════════════════════
   SQL INJECTION PATTERNS (server-side check)
══════════════════════════════════════════════════ */
const SQLI_PATTERNS = [
  /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|TRUNCATE|DECLARE)\b)/i,
  /(--|;|\/\*|\*\/|xp_|sp_cmdshell|0x[0-9a-fA-F]+)/,
  /\bOR\b.{0,20}[=<>]/i,
  /\bAND\b.{0,20}[=<>]/i,
  /(SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\()/i,
  /(1\s*=\s*1|'\s*=\s*'|"\s*=\s*")/,
  /(<script[\s>]|javascript:|onerror\s*=|onload\s*=)/i,
];

function hasSQLi(str) {
  return typeof str === 'string' && SQLI_PATTERNS.some(p => p.test(str));
}

function sanitizeInput(str) {
  if (typeof str !== 'string') return '';
  let s = DOMPurify.sanitize(str, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  SQLI_PATTERNS.forEach(p => { s = s.replace(p, ''); });
  return s.trim();
}

/* ══════════════════════════════════════════════════
   CRYPTOGRAPHIC UTILITIES
══════════════════════════════════════════════════ */

/** Cryptographically secure random OTP */
function generateSecureOTP() {
  const max = Math.pow(10, OTP_LENGTH);
  // Use rejection sampling for uniform distribution
  let num;
  do {
    const buf = crypto.randomBytes(4);
    num = buf.readUInt32BE(0);
  } while (num >= Math.floor(0xFFFFFFFF / max) * max);
  return String(num % max).padStart(OTP_LENGTH, '0');
}

/** Constant-time string comparison (prevents timing attacks) */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) {
    // Still run comparison to avoid timing leak on length difference
    crypto.timingSafeEqual(
      Buffer.alloc(a.length), Buffer.alloc(a.length)
    );
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** Hash password with bcrypt (argon2id preferred in production) */
async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/** Verify bcrypt hash */
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

/* ══════════════════════════════════════════════════
   IN-MEMORY STORES
   Replace with Redis/DB in production
══════════════════════════════════════════════════ */

/** OTP Store: otpStore[sessionId] = { otp, expiresAt, attempts, contact, used } */
const otpStore = new Map();

/** Cleanup expired OTPs every 5 minutes */
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of otpStore.entries()) {
    if (now > v.expiresAt + 60000) otpStore.delete(k);  // +1min grace
  }
}, 5 * 60 * 1000);

/* ══════════════════════════════════════════════════
   SECURITY MIDDLEWARE STACK
══════════════════════════════════════════════════ */

// 1. Trust proxy (if behind nginx/load balancer)
app.set('trust proxy', 1);

// 2. Security headers (Helmet)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'"],  // tighten in prod: use nonces
      styleSrc:       ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc:        ["'self'", 'https://fonts.gstatic.com'],
      imgSrc:         ["'self'", 'data:', 'https:'],
      connectSrc:     ["'self'"],
      frameSrc:       ["'none'"],
      objectSrc:      ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  noSniff:        true,
  frameguard:     { action: 'deny' },
  xssFilter:      true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// 3. CORS
app.use(cors({
  origin:      process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
  methods:     ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'X-CSRF-Token', 'X-Requested-With'],
}));

// 4. Body parsers (limit size to prevent DoS)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());

// 5. MongoDB query injection prevention (strips $ and .)
app.use(mongoSanitize({ replaceWith: '_', onSanitizeError: (req, res) => {
  res.status(400).json({ error: 'Malicious input detected' });
}}));

// 6. HTTP Parameter Pollution prevention
app.use(hpp());

// 7. Session
app.use(session({
  secret:            process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',  // HTTPS only in prod
    httpOnly: true,    // XSS protection — JS cannot access
    sameSite: 'strict',
    maxAge:   SESSION_MAX_AGE,
  },
}));

// 8. CSRF protection
const csrfProtection = csrf({ cookie: false }); // store in session
app.use(csrfProtection);
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'Invalid or expired CSRF token' });
  }
  next(err);
});

// 9. Passport (OAuth)
app.use(passport.initialize());
app.use(passport.session());

/* ══════════════════════════════════════════════════
   RATE LIMITERS
══════════════════════════════════════════════════ */

/** General API limiter */
const apiLimiter = rateLimit({
  windowMs:        parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  max:             parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: 'Too many requests. Please try again later.' },
});

/** Strict login limiter — 5 attempts per 15 min per IP */
const loginLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             5,
  standardHeaders: true,
  legacyHeaders:   false,
  skipSuccessfulRequests: true,
  message:         { error: 'Too many login attempts. Account temporarily locked.' },
});

/** OTP send limiter — 3 sends per 10 min per IP */
const otpSendLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max:      3,
  message:  { error: 'Too many OTP requests. Please wait before requesting again.' },
});

/** OTP verify limiter — 5 tries per 10 min per IP */
const otpVerifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max:      5,
  message:  { error: 'Too many OTP attempts. Please wait or request a new code.' },
});

/** Slow down repeated requests */
const speedLimiter = slowDown({
  windowMs:          15 * 60 * 1000,
  delayAfter:        2,
  delayMs:           (hits) => hits * 200,
  maxDelayMs:        5000,
});

/* ══════════════════════════════════════════════════
   INPUT VALIDATION MIDDLEWARE
══════════════════════════════════════════════════ */
function validateAndSanitize(req, res, next) {
  // Check all string fields for SQL injection
  const fields = [
    req.body?.email, req.body?.phone, req.body?.password,
    req.body?.otp, req.body?.passHash, req.params?.id,
  ].filter(Boolean);

  for (const f of fields) {
    if (hasSQLi(f)) {
      return res.status(400).json({ error: 'Invalid input: security violation detected' });
    }
  }

  // Sanitize string fields
  if (req.body?.email)    req.body.email    = sanitizeInput(req.body.email);
  if (req.body?.phone)    req.body.phone    = sanitizeInput(req.body.phone);
  if (req.body?.passHash) req.body.passHash = sanitizeInput(req.body.passHash);

  // OTP must be exactly 6 digits
  if (req.body?.otp !== undefined) {
    req.body.otp = String(req.body.otp).replace(/\D/g, '').slice(0, 6);
  }

  next();
}

/* ══════════════════════════════════════════════════
   EMAIL / SMS SENDERS
══════════════════════════════════════════════════ */
const mailer = nodemailer.createTransport({
  host:   process.env.EMAIL_HOST   || 'smtp.ethereal.email',
  port:   parseInt(process.env.EMAIL_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || '',
  },
});

const twilioClient = process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;

async function sendOtpEmail(to, otp) {
  await mailer.sendMail({
    from:    `"SecureAuth" <noreply@secureauth.com>`,
    to,
    subject: 'Your SecureAuth verification code',
    text:    `Your verification code is: ${otp}\n\nThis code expires in ${OTP_TTL_SECONDS / 60} minutes.\nDo not share this code with anyone.`,
    html: `
      <div style="font-family:system-ui;max-width:480px;margin:0 auto;padding:32px">
        <h2 style="font-size:24px;font-weight:800;margin-bottom:8px">Verification Code</h2>
        <p style="color:#4b5563;margin-bottom:24px">Use the code below to sign in. It expires in ${OTP_TTL_SECONDS / 60} minutes.</p>
        <div style="background:#f4f6fb;border:1px solid #e1e5ef;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px">
          <div style="font-family:monospace;font-size:36px;font-weight:700;letter-spacing:8px;color:#2563eb">${otp}</div>
        </div>
        <p style="color:#9ca3af;font-size:12px">If you didn't request this code, please ignore this email. Do not share this code with anyone — SecureAuth staff will never ask for it.</p>
      </div>
    `,
  });
}

async function sendOtpSMS(phone, otp) {
  if (!twilioClient) throw new Error('Twilio not configured');
  await twilioClient.messages.create({
    body: `Your SecureAuth code: ${otp}. Valid for ${OTP_TTL_SECONDS / 60} mins. Do not share.`,
    from: process.env.TWILIO_PHONE,
    to:   phone,
  });
}

/* ══════════════════════════════════════════════════
   GOOGLE OAUTH
══════════════════════════════════════════════════ */
passport.use(new GoogleStrategy({
  clientID:     process.env.GOOGLE_CLIENT_ID     || 'GOOGLE_CLIENT_ID',
  clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'GOOGLE_CLIENT_SECRET',
  callbackURL:  process.env.GOOGLE_CALLBACK_URL  || 'http://localhost:3000/api/v1/auth/google/callback',
  scope:        ['profile', 'email'],
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email  = profile.emails?.[0]?.value;
    const domain = email?.split('@')[1]?.toLowerCase();

    if (domain && TEMP_MAIL_DOMAINS.has(domain)) {
      return done(null, false, { message: 'Temporary email addresses are not allowed' });
    }

    // In production: find or create user in DB
    const user = { id: profile.id, email, name: profile.displayName, provider: 'google' };
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done)   => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

/* ══════════════════════════════════════════════════
   ROUTES — Static
══════════════════════════════════════════════════ */
app.use(express.static(path.join(__dirname, '../frontend')));

/* ══════════════════════════════════════════════════
   ROUTES — API
══════════════════════════════════════════════════ */
const router = express.Router();
router.use(apiLimiter);

/** GET /api/v1/csrf-token */
router.get('/csrf-token', (req, res) => {
  res.json({ token: req.csrfToken() });
});

/* ── AUTH: Login Init ── */
router.post('/auth/login/init',
  loginLimiter,
  speedLimiter,
  validateAndSanitize,
  async (req, res) => {
    try {
      const { contact, mode, passHash } = req.body;

      if (!contact || !mode || !passHash) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      if (!['email', 'phone'].includes(mode)) {
        return res.status(400).json({ error: 'Invalid mode' });
      }

      // Validate contact
      if (mode === 'email') {
        if (!validator.isEmail(contact)) {
          return res.status(400).json({ error: 'Invalid email address' });
        }
        const domain = contact.split('@')[1]?.toLowerCase();
        if (TEMP_MAIL_DOMAINS.has(domain)) {
          return res.status(400).json({ error: 'Disposable email addresses are not allowed' });
        }
      } else {
        const digits = contact.replace(/\D/g, '');
        if (digits.length < 10 || digits.length > 15) {
          return res.status(400).json({ error: 'Invalid phone number' });
        }
      }

      // Validate passHash format (should be 64-char hex)
      if (!/^[a-f0-9]{64}$/.test(passHash)) {
        return res.status(400).json({ error: 'Invalid credential format' });
      }

      /*
       * In production:
       *   1. Look up user by contact in DB
       *   2. Verify passHash against stored bcrypt hash
       *   3. On success, generate OTP and send
       *
       * const user = await db.users.findOne({ email: contact });
       * if (!user) return res.status(401).json({ error: 'Invalid credentials' });
       * const valid = await verifyPassword(passHash, user.passwordHash);
       * if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
       */

      // Generate and store OTP
      const otp       = generateSecureOTP();
      const sessionId = crypto.randomBytes(16).toString('hex');

      otpStore.set(sessionId, {
        otp,
        expiresAt:  Date.now() + OTP_TTL_SECONDS * 1000,
        attempts:   0,
        contact,
        mode,
        used:       false,
      });

      req.session.otpSessionId = sessionId;
      req.session.authContact  = contact;
      req.session.authMode     = mode;

      // Send OTP
      try {
        if (mode === 'email') {
          await sendOtpEmail(contact, otp);
        } else {
          await sendOtpSMS(contact, otp);
        }
      } catch (sendErr) {
        console.error('OTP send error:', sendErr.message);
        // Don't reveal send errors in production
      }

      // In dev mode, include OTP in response for testing
      const devMode = process.env.NODE_ENV !== 'production';
      res.json({
        success:    true,
        sessionId,
        ...(devMode ? { _dev_otp: otp } : {}),
      });

    } catch (err) {
      console.error('Login init error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/* ── AUTH: OTP Verify ── */
router.post('/auth/otp/verify',
  otpVerifyLimiter,
  speedLimiter,
  validateAndSanitize,
  async (req, res) => {
    try {
      const { otp, sessionId } = req.body;

      if (!otp || !sessionId) {
        return res.status(400).json({ error: 'Missing OTP or session ID' });
      }

      // Validate sessionId format
      if (!/^[a-f0-9]{32}$/.test(sessionId)) {
        return res.status(400).json({ error: 'Invalid session' });
      }

      // Session must match server-side session
      if (req.session.otpSessionId !== sessionId) {
        return res.status(403).json({ error: 'Session mismatch' });
      }

      const record = otpStore.get(sessionId);

      if (!record) {
        return res.status(400).json({ error: 'OTP session not found or expired' });
      }

      // Check expiry
      if (Date.now() > record.expiresAt) {
        otpStore.delete(sessionId);
        return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
      }

      // Check max attempts
      if (record.attempts >= OTP_MAX_ATTEMPTS) {
        otpStore.delete(sessionId);
        return res.status(429).json({ error: `Maximum attempts (${OTP_MAX_ATTEMPTS}) reached. Please request a new OTP.` });
      }

      // Check already used
      if (record.used) {
        return res.status(400).json({ error: 'OTP has already been used' });
      }

      record.attempts++;

      // Constant-time comparison
      if (!timingSafeEqual(otp.trim(), record.otp)) {
        const left = OTP_MAX_ATTEMPTS - record.attempts;
        return res.status(400).json({
          error: left > 0
            ? `Incorrect OTP. ${left} attempt${left === 1 ? '' : 's'} remaining.`
            : 'No attempts remaining. Please request a new OTP.',
          attemptsLeft: left,
        });
      }

      // ✅ OTP verified — mark as used immediately
      record.used = true;
      req.session.otpVerified = true;
      req.session.otpVerifiedAt = Date.now();

      // Clean up OTP from store
      otpStore.delete(sessionId);

      res.json({ success: true, message: 'OTP verified' });

    } catch (err) {
      console.error('OTP verify error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/* ── AUTH: OTP Resend ── */
router.post('/auth/otp/resend',
  otpSendLimiter,
  async (req, res) => {
    try {
      const sessionId = req.session.otpSessionId;
      if (!sessionId) return res.status(400).json({ error: 'No active session' });

      const contact = req.session.authContact;
      const mode    = req.session.authMode;

      const otp         = generateSecureOTP();
      const newSessionId = crypto.randomBytes(16).toString('hex');

      // Invalidate old OTP
      if (sessionId) otpStore.delete(sessionId);

      otpStore.set(newSessionId, {
        otp, expiresAt: Date.now() + OTP_TTL_SECONDS * 1000,
        attempts: 0, contact, mode, used: false,
      });

      req.session.otpSessionId = newSessionId;

      try {
        if (mode === 'email') await sendOtpEmail(contact, otp);
        else await sendOtpSMS(contact, otp);
      } catch (e) { console.error('Resend error:', e.message); }

      const devMode = process.env.NODE_ENV !== 'production';
      res.json({ success: true, ...(devMode ? { _dev_otp: otp } : {}) });

    } catch (err) {
      console.error('OTP resend error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/* ── AUTH: Login Complete ── */
router.post('/auth/login/complete',
  loginLimiter,
  validateAndSanitize,
  async (req, res) => {
    try {
      // OTP must be verified in this session
      if (!req.session.otpVerified) {
        return res.status(403).json({ error: 'OTP verification required' });
      }

      // OTP verification must be recent (within 10 minutes)
      const verifiedAge = Date.now() - (req.session.otpVerifiedAt || 0);
      if (verifiedAge > 10 * 60 * 1000) {
        return res.status(403).json({ error: 'Verification expired. Please start again.' });
      }

      /*
       * In production:
       *   1. Verify passHash against DB
       *   2. Create authenticated session
       *   3. Return JWT or set httpOnly session cookie
       *   4. Log security event
       *
       * req.session.userId    = user.id;
       * req.session.loggedIn  = true;
       * req.session.loginTime = Date.now();
       */

      // Regenerate session to prevent session fixation
      req.session.regenerate((err) => {
        if (err) return res.status(500).json({ error: 'Session error' });
        req.session.loggedIn  = true;
        req.session.loginTime = Date.now();
        res.json({ success: true, message: 'Authenticated', redirectTo: '/dashboard' });
      });

    } catch (err) {
      console.error('Login complete error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/* ── AUTH: Google OAuth ── */
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login?error=google' }),
  (req, res) => {
    req.session.loggedIn  = true;
    req.session.loginTime = Date.now();
    res.redirect(process.env.FRONTEND_URL || '/');
  }
);

router.post('/auth/google/init', (req, res) => {
  const redirectUrl = `/api/v1/auth/google`;
  res.json({ redirectUrl });
});

/* ── AUTH: Logout ── */
router.post('/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie('connect.sid');
    if (err) return res.status(500).json({ error: 'Logout error' });
    res.json({ success: true });
  });
});

/* ── REGISTER ── */
router.post('/auth/register',
  loginLimiter,
  validateAndSanitize,
  async (req, res) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
      }

      if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Invalid email' });
      }

      const domain = email.split('@')[1]?.toLowerCase();
      if (TEMP_MAIL_DOMAINS.has(domain)) {
        return res.status(400).json({ error: 'Disposable emails not allowed' });
      }

      if (password.length < 8) {
        return res.status(400).json({ error: 'Password too short (min 8 chars)' });
      }

      // Hash with bcrypt (server always rehashes — never trust client hash)
      const passwordHash = await hashPassword(password);

      /*
       * In production:
       *   await db.users.create({ email, passwordHash, createdAt: new Date() });
       */

      res.json({ success: true, message: 'Registration successful' });

    } catch (err) {
      console.error('Register error:', err);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
);

/* ── HEALTH CHECK ── */
router.get('/health', (req, res) => {
  res.json({
    status:    'ok',
    timestamp: new Date().toISOString(),
    uptime:    process.uptime(),
    version:   '1.0.0',
  });
});

app.use('/api/v1', router);

/* ══════════════════════════════════════════════════
   ERROR HANDLERS
══════════════════════════════════════════════════ */

// 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler — never leak stack traces in production
app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({ error: 'Internal server error' });
  } else {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

/* ══════════════════════════════════════════════════
   START SERVER
══════════════════════════════════════════════════ */
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║       SecureAuth Server Running      ║
╠══════════════════════════════════════╣
║  Port    : ${PORT.toString().padEnd(26)}║
║  Mode    : ${(process.env.NODE_ENV || 'development').padEnd(26)}║
║  URL     : http://localhost:${PORT.toString().padEnd(9)}║
╚══════════════════════════════════════╝
  `);
});

module.exports = app;
