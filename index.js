import 'dotenv/config';
import bcrypt from 'bcryptjs';
import cors from 'cors';
import express from 'express';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import nodemailer from 'nodemailer';
import { v2 as cloudinary } from 'cloudinary';
import { createHash, randomBytes, randomInt, randomUUID } from 'node:crypto';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-change-JWT_SECRET';
if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('Set JWT_SECRET in production');
  process.exit(1);
}

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

/** Avoid leaking stack / driver messages to API clients in production. */
function publicServerErrorMessage(e, fallback = 'Server error') {
  if (IS_PRODUCTION) return fallback;
  return e?.message || fallback;
}

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    passwordHash: { type: String, required: true },
    ownerId: { type: String, required: true, unique: true, index: true },
    pinResetCodeHash: { type: String, default: null },
    pinResetExpiresAt: { type: Date, default: null },
    /** SHA-256 hex of opaque refresh token; rotated on login and refresh. */
    refreshTokenHash: { type: String, default: null, sparse: true, index: true },
    refreshTokenExpiresAt: { type: Date, default: null },
    /** Multiple devices: each entry is one signed-in device (max enforced in app code). */
    refreshSessions: {
      type: [
        {
          tokenHash: { type: String, required: true },
          expiresAt: { type: Date, required: true },
        },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);

const customerSchema = new mongoose.Schema(
  {
    ownerId: { type: String, required: true, index: true },
    name: { type: String, required: true },
    phone: { type: String, default: '' },
    address: { type: String, default: '' },
    balance: { type: Number, default: 0 },
    lastTransactionAt: { type: Date, default: null },
  },
  { timestamps: true }
);

const transactionSchema = new mongoose.Schema({
  ownerId: { type: String, required: true, index: true },
  customerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Customer',
    required: true,
  },
  type: { type: String, enum: ['utang', 'payment'], required: true },
  amount: { type: Number, required: true },
  note: { type: String, default: '' },
  /** Set true when balance hits 0 after payment; utang rows only. */
  archived: { type: Boolean, default: false, index: true },
  createdAt: { type: Date, default: Date.now },
});

transactionSchema.index({ ownerId: 1, customerId: 1, createdAt: -1 });
transactionSchema.index({ ownerId: 1, createdAt: -1 });

const lineItemSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    description: { type: String, default: '' },
    amount: { type: Number, required: true },
    note: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const pagePaymentSchema = new mongoose.Schema(
  {
    id: { type: String, required: true },
    amount: { type: Number, required: true },
    note: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const utangPageSchema = new mongoose.Schema(
  {
    ownerId: { type: String, required: true, index: true },
    customerId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Customer',
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ['open', 'paid'],
      default: 'open',
      index: true,
    },
    items: { type: [lineItemSchema], default: [] },
    payments: { type: [pagePaymentSchema], default: [] },
    paidAt: { type: Date, default: null },
  },
  { timestamps: true }
);

utangPageSchema.index({ ownerId: 1, customerId: 1, status: 1 });
utangPageSchema.index(
  { ownerId: 1, customerId: 1 },
  {
    unique: true,
    partialFilterExpression: { status: 'open' },
  }
);

const Customer = mongoose.model('Customer', customerSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const UtangPage = mongoose.model('UtangPage', utangPageSchema);

const inventoryItemSchema = new mongoose.Schema(
  {
    ownerId: { type: String, required: true, index: true },
    name: { type: String, required: true, trim: true },
    /** Optional default price (₱) suggested when adding a utang line. */
    unitPrice: { type: Number, default: null },
    /** Optional product type / shelf group (free text; API trims to 80 chars). */
    category: { type: String, default: '', trim: true },
    /** Optional HTTPS URL (e.g. Cloudinary) for product sticker image. */
    imageUrl: { type: String, default: null, maxlength: 2048 },
  },
  { timestamps: true }
);

inventoryItemSchema.index({ ownerId: 1, name: 1 }, { unique: true });

const InventoryItem = mongoose.model('InventoryItem', inventoryItemSchema);

const auditLogSchema = new mongoose.Schema(
  {
    ownerId: { type: String, required: true, index: true },
    actorEmail: { type: String, default: '', maxlength: 254 },
    action: { type: String, required: true, maxlength: 96, index: true },
    meta: { type: mongoose.Schema.Types.Mixed, default: {} },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);
auditLogSchema.index({ ownerId: 1, createdAt: -1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

function roundMoney(n) {
  return Math.round((Number(n) || 0) * 100) / 100;
}

const MAX_EMAIL_LEN = 254;
const MAX_PASSWORD_LEN = 128;
const MAX_CUSTOMER_NAME_LEN = 200;
const MAX_CUSTOMER_PHONE_LEN = 40;
const MAX_CUSTOMER_ADDRESS_LEN = 500;
const MAX_INVENTORY_NAME_LEN = 200;

/** Same response for duplicate email, race on unique index, and other blocked signups. */
const MSG_REGISTER_FAILED =
  'Hindi makapag-rehistro gamit ang impormasyong ito. Kung may account na, mag-sign in.';
/** Same for wrong current password or unexpected account state (authenticated route). */
const MSG_CHANGE_PASSWORD_FAILED =
  'Hindi makumpleto ang pagpapalit ng password.';

function isValidEmailShape(email) {
  const e = String(email || '').trim().toLowerCase();
  if (!e || e.length > MAX_EMAIL_LEN) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}

function passwordPolicyError(password) {
  const s = String(password ?? '');
  if (s.length < 8) return 'Ang password ay dapat 8+ character';
  if (s.length > MAX_PASSWORD_LEN) {
    return `Ang password ay hindi dapat lumampas sa ${MAX_PASSWORD_LEN} character`;
  }
  if (!/[A-Za-z]/.test(s)) {
    return 'Ang password ay dapat may hindi bababa sa isang titik (A–Z).';
  }
  if (!/\d/.test(s)) {
    return 'Ang password ay dapat may hindi bababa sa isang numero (0–9).';
  }
  return null;
}

function totalsFromPageDoc(page) {
  const items = page.items || [];
  const payments = page.payments || [];
  const itemsTotal = roundMoney(
    items.reduce((s, i) => s + (Math.abs(Number(i.amount)) || 0), 0)
  );
  const paidTotal = roundMoney(
    payments.reduce((s, p) => s + (Math.abs(Number(p.amount)) || 0), 0)
  );
  return {
    itemsTotal,
    paidTotal,
    due: roundMoney(Math.max(0, itemsTotal - paidTotal)),
  };
}

function serializePage(p) {
  const items = p.items || [];
  const payments = p.payments || [];
  const itemsTotal = roundMoney(
    items.reduce((s, i) => s + (Number(i.amount) || 0), 0)
  );
  const paidTotal = roundMoney(
    payments.reduce((s, x) => s + (Number(x.amount) || 0), 0)
  );
  const due = roundMoney(Math.max(0, itemsTotal - paidTotal));
  return {
    id: p._id.toString(),
    ownerId: p.ownerId,
    customerId: p.customerId.toString(),
    status: p.status,
    items: items.map((i) => ({
      id: i.id,
      description: i.description ?? '',
      amount: i.amount,
      note: i.note ?? '',
      createdAt: i.createdAt,
    })),
    payments: payments.map((x) => ({
      id: x.id,
      amount: x.amount,
      note: x.note ?? '',
      createdAt: x.createdAt,
    })),
    itemsTotal,
    paidTotal,
    due,
    paidAt: p.paidAt ?? null,
    createdAt: p.createdAt,
    updatedAt: p.updatedAt,
  };
}

const DEFAULT_REFRESH_MS = 30 * 24 * 60 * 60 * 1000;

function parseDurationToMs(s, fallbackMs) {
  const v = String(s ?? '')
    .trim()
    .toLowerCase()
    .replace(/\s/g, '');
  const m = /^(\d+)([smhdw])$/.exec(v);
  if (!m) return fallbackMs;
  const n = parseInt(m[1], 10);
  if (!Number.isFinite(n) || n < 1) return fallbackMs;
  const u = m[2];
  if (u === 's') return n * 1000;
  if (u === 'm') return n * 60_000;
  if (u === 'h') return n * 3600_000;
  if (u === 'd') return n * 86400_000;
  if (u === 'w') return n * 7 * 86400_000;
  return fallbackMs;
}

function refreshTokenLifetimeMs() {
  const raw = process.env.JWT_REFRESH_EXPIRES_IN;
  if (raw && String(raw).trim()) {
    const ms = parseDurationToMs(String(raw).trim(), DEFAULT_REFRESH_MS);
    if (ms >= 60_000 && ms <= 400 * 86400_000) return ms;
  }
  const legacy = process.env.JWT_EXPIRES_IN;
  if (legacy && String(legacy).trim()) {
    const ms = parseDurationToMs(String(legacy).trim(), DEFAULT_REFRESH_MS);
    if (ms >= 60_000 && ms <= 400 * 86400_000) return ms;
  }
  return DEFAULT_REFRESH_MS;
}

function accessTokenExpiresIn() {
  const v = String(process.env.JWT_ACCESS_EXPIRES_IN || '').trim();
  if (v) return v;
  return '15m';
}

function signAccessToken(user) {
  return jwt.sign(
    { ownerId: user.ownerId, email: user.email },
    JWT_SECRET,
    { expiresIn: accessTokenExpiresIn() }
  );
}

function hashRefreshToken(plain) {
  return createHash('sha256')
    .update(String(plain), 'utf8')
    .digest('hex');
}

const MAX_REFRESH_DEVICES = 10;

function pruneExpiredSessions(sessions) {
  const now = Date.now();
  if (!Array.isArray(sessions)) return [];
  return sessions.filter((s) => s?.expiresAt && new Date(s.expiresAt).getTime() > now);
}

/**
 * @param {import('mongoose').Document} user
 * @param {{ replaceAll?: boolean }} [opts] replaceAll=true revokes every other device (password / PIN reset).
 */
async function issueSessionTokens(user, opts = {}) {
  const replaceAll = Boolean(opts.replaceAll);
  const refreshPlain = randomBytes(48).toString('base64url');
  const refreshHash = hashRefreshToken(refreshPlain);
  const exp = new Date(Date.now() + refreshTokenLifetimeMs());

  let sessions = replaceAll
    ? []
    : pruneExpiredSessions([...(user.refreshSessions || [])]);

  sessions.push({ tokenHash: refreshHash, expiresAt: exp });
  sessions.sort((a, b) => new Date(a.expiresAt) - new Date(b.expiresAt));
  while (sessions.length > MAX_REFRESH_DEVICES) {
    sessions.shift();
  }

  user.refreshSessions = sessions;
  user.refreshTokenHash = null;
  user.refreshTokenExpiresAt = null;
  await user.save();
  return {
    token: signAccessToken(user),
    refreshToken: refreshPlain,
    ownerId: user.ownerId,
    email: user.email,
  };
}

async function rotateRefreshToken(user, oldPlain) {
  const oldHash = hashRefreshToken(oldPlain);
  const now = new Date();
  const sessions = pruneExpiredSessions([...(user.refreshSessions || [])]);

  const idx = sessions.findIndex(
    (s) => s.tokenHash === oldHash && new Date(s.expiresAt) > now
  );
  const legacyOk =
    user.refreshTokenHash === oldHash &&
    user.refreshTokenExpiresAt &&
    new Date(user.refreshTokenExpiresAt) > now;

  if (idx < 0 && !legacyOk) {
    const err = new Error('INVALID_REFRESH');
    err.code = 'INVALID_REFRESH';
    throw err;
  }

  const refreshPlain = randomBytes(48).toString('base64url');
  const refreshHash = hashRefreshToken(refreshPlain);
  const exp = new Date(Date.now() + refreshTokenLifetimeMs());

  if (idx >= 0) {
    sessions[idx] = { tokenHash: refreshHash, expiresAt: exp };
  } else {
    sessions.push({ tokenHash: refreshHash, expiresAt: exp });
  }

  user.refreshSessions = sessions;
  user.refreshTokenHash = null;
  user.refreshTokenExpiresAt = null;
  await user.save();

  return {
    token: signAccessToken(user),
    refreshToken: refreshPlain,
    ownerId: user.ownerId,
    email: user.email,
  };
}

const pinResetCooldownMs = Math.max(
  30_000,
  Number(process.env.PIN_RESET_COOLDOWN_MS || 60_000) || 60_000
);
const pinResetLastSent = new Map();

function pinResetPepper() {
  return process.env.PIN_RESET_PEPPER || JWT_SECRET;
}

function hashPinResetCode(email, code) {
  return createHash('sha256')
    .update(`${pinResetPepper()}:${email}:${String(code).trim()}`)
    .digest('hex');
}

function pinResetMailContent(code) {
  const safeCode = String(code).replace(/[^0-9]/g, '');
  const subject = 'SukiTrack — Your PIN reset code';
  const text = [
    'SukiTrack — PIN reset',
    '═'.repeat(36),
    '',
    'Use this code in the app to reset your PIN:',
    '',
    `  ${safeCode}`,
    '',
    'This code expires in 15 minutes.',
    '',
    "If you didn't ask to reset your PIN, ignore this email —",
    'nothing has been changed on your account.',
    '',
    '— SukiTrack',
  ].join('\n');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <title>PIN reset</title>
</head>
<body style="margin:0;padding:0;background-color:#e8f0ea;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#e8f0ea;">
    <tr>
      <td align="center" style="padding:32px 16px 48px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:560px;background-color:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 8px 32px rgba(26,92,46,0.12);">
          <tr>
            <td bgcolor="#1a5c2e" style="background:linear-gradient(135deg,#1a5c2e 0%,#2d8a4e 55%,#3cb96a 100%);padding:28px 32px;">
              <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;font-weight:bold;letter-spacing:0.2em;text-transform:uppercase;color:rgba(255,255,255,0.85);">SukiTrack</p>
              <h1 style="margin:8px 0 0;font-family:Arial,Helvetica,sans-serif;font-size:22px;font-weight:bold;line-height:1.25;color:#ffffff;">Reset your app PIN</h1>
              <p style="margin:10px 0 0;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;color:rgba(255,255,255,0.92);">Enter this code in the app to continue. Your account password is unchanged.</p>
            </td>
          </tr>
          <tr>
            <td style="padding:32px 32px 8px;">
              <p style="margin:0 0 16px;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.55;color:#3d4a42;">Your verification code is:</p>
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%">
                <tr>
                  <td align="center" style="background-color:#e8f7ee;border:2px solid #c5e6d4;border-radius:14px;padding:20px 24px;">
                    <p style="margin:0;font-family:'Courier New',Courier,monospace;font-size:32px;font-weight:bold;letter-spacing:0.35em;color:#1a5c2e;line-height:1.2;">${safeCode}</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:8px 32px 28px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#fffbeb;border:1px solid #fed7aa;border-radius:12px;">
                <tr>
                  <td style="padding:14px 16px;">
                    <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.5;color:#9a3412;"><strong style="color:#c2410c;">Expires in 15 minutes</strong> — for your security, this code stops working after that.</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:0 32px 32px;">
              <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.55;color:#6b7a72;">If you did not request a PIN reset, you can safely ignore this message. No one can change your PIN without this code.</p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 32px;border-top:1px solid #e8ede9;background-color:#f7faf8;">
              <p style="margin:0;font-family:Arial,Helvetica,sans-serif;font-size:11px;line-height:1.5;color:#8a9a92;">This is an automated message from SukiTrack (Utang Tracker). Do not reply to this email.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;

  return { subject, html, text };
}

/** @returns {{ transport: object, from: string } | null} */
function resolvePinResetSmtp() {
  if (process.env.SMTP_HOST) {
    const hostLower = String(process.env.SMTP_HOST).toLowerCase();
    const port = Number(process.env.SMTP_PORT || 587);
    let secure =
      process.env.SMTP_SECURE === 'true' ||
      process.env.SMTP_SECURE === '1' ||
      port === 465;
    // Port 587 expects STARTTLS (plain socket first). Implicit TLS here → "wrong version number".
    if (hostLower === 'smtp.gmail.com' && port === 587) {
      secure = false;
    }
    return {
      transport: {
        host: process.env.SMTP_HOST,
        port,
        secure,
        ...(process.env.SMTP_USER
          ? {
              auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS || '',
              },
            }
          : {}),
      },
      from:
        process.env.SMTP_FROM ||
        process.env.EMAIL_FROM ||
        process.env.SMTP_USER ||
        'noreply@localhost',
    };
  }

  const gmailUser = String(process.env.GMAIL_USER || '').trim();
  const gmailPass = String(process.env.GMAIL_APP_PASSWORD || '')
    .replace(/\s/g, '')
    .trim();
  if (gmailUser && gmailPass) {
    // Nodemailer "Gmail" profile = smtp.gmail.com:465 + implicit TLS (avoids STARTTLS
    // "wrong version number" issues common on 587 with some networks / Node+OpenSSL).
    return {
      transport: {
        service: 'Gmail',
        auth: { user: gmailUser, pass: gmailPass },
      },
      from:
        String(process.env.EMAIL_FROM || '').trim() ||
        String(process.env.SMTP_FROM || '').trim() ||
        gmailUser,
    };
  }

  return null;
}

async function sendPinResetEmail(email, code) {
  const { subject, html, text } = pinResetMailContent(code);

  const smtp = resolvePinResetSmtp();
  if (smtp) {
    const transporter = nodemailer.createTransport(smtp.transport);
    try {
      await transporter.sendMail({
        from: smtp.from,
        to: email,
        subject,
        html,
        text,
      });
    } catch (e) {
      console.error('[PIN RESET] SMTP error', e);
      throw new Error('Hindi naipadala ang email');
    }
    return;
  }

  const resendFrom = process.env.RESEND_FROM;
  const resendKey = process.env.RESEND_API_KEY;
  if (resendKey && resendFrom) {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${resendKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: resendFrom,
        to: [email],
        subject,
        html,
        text,
      }),
    });
    if (!r.ok) {
      const t = await r.text();
      console.error('[PIN RESET] Resend error', r.status, t);
      throw new Error('Hindi naipadala ang email');
    }
    return;
  }

  if (process.env.NODE_ENV === 'production') {
    console.warn(
      '[PIN RESET] Walang SMTP / Resend — hindi naipadala ang code. Itakda ang SMTP o RESEND_API_KEY.'
    );
  } else {
    console.warn(
      `[PIN RESET] Walang SMTP_HOST / GMAIL_USER+GMAIL_APP_PASSWORD o RESEND — dev log lang. ${email} code: ${code}`
    );
  }
}

function requireAuth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Kailangan ang login (Bearer token)' });
  }
  try {
    const payload = jwt.verify(h.slice(7), JWT_SECRET);
    req.ownerId = payload.ownerId;
    req.email = payload.email;
    next();
  } catch {
    return res.status(401).json({ error: 'Expired o maling session' });
  }
}

async function appendAudit(ownerId, actorEmail, action, meta) {
  if (!ownerId || !action) return;
  try {
    const safeMeta =
      meta && typeof meta === 'object' && !Array.isArray(meta) ? meta : {};
    await AuditLog.create({
      ownerId: String(ownerId),
      actorEmail: String(actorEmail || '').trim().toLowerCase().slice(0, 254),
      action: String(action).slice(0, 96),
      meta: safeMeta,
    });
  } catch (e) {
    console.error('[AuditLog]', e?.message || e);
  }
}

function auditFromReq(req, action, meta) {
  void appendAudit(req.ownerId, req.email, action, meta);
}

const app = express();
if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

const rateLimitJson = {
  error: 'Masyadong maraming kahilingan mula sa IP na ito. Subukan muli mamaya.',
};

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_LOGIN_MAX || 30),
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitJson,
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_REGISTER_MAX || 12),
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitJson,
});

const forgotPinRequestLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_FORGOT_PIN_REQUEST_MAX || 20),
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitJson,
});

const forgotPinVerifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_FORGOT_PIN_VERIFY_MAX || 25),
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitJson,
});

const passwordChangeLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_CHANGE_PASSWORD_MAX || 15),
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitJson,
});

const refreshLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_REFRESH_MAX || 60),
  standardHeaders: true,
  legacyHeaders: false,
  message: rateLimitJson,
});

function buildCorsMiddleware() {
  const raw = String(process.env.CORS_ORIGINS || '').trim();
  if (!raw || raw === '*') {
    if (process.env.NODE_ENV === 'production' && !raw) {
      console.warn(
        '[CORS] Set CORS_ORIGINS to a comma-separated list of allowed web origins (e.g. https://app.example.com). Using permissive CORS until then.'
      );
    }
    return cors({ origin: true });
  }
  const list = raw.split(',').map((s) => s.trim()).filter(Boolean);
  return cors({
    origin(origin, callback) {
      if (!origin) return callback(null, true);
      if (list.includes(origin)) return callback(null, true);
      return callback(null, false);
    },
    credentials: true,
  });
}

app.use(buildCorsMiddleware());
app.use(express.json({ limit: '6mb' }));

function cloudinaryConfigured() {
  return !!(
    process.env.CLOUDINARY_CLOUD_NAME &&
    process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET
  );
}

function configureCloudinary() {
  if (!cloudinaryConfigured()) return false;
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
  return true;
}

function sanitizeInventoryImageUrl(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  if (!s) return null;
  if (!/^https:\/\//i.test(s)) return null;
  if (s.length > 2048) return null;
  return s;
}

/** Allowed image MIME types for inventory Cloudinary upload (client-provided). */
const INVENTORY_UPLOAD_MIME = new Map([
  ['image/jpeg', 'image/jpeg'],
  ['image/jpg', 'image/jpeg'],
  ['image/pjpeg', 'image/jpeg'],
  ['image/png', 'image/png'],
  ['image/webp', 'image/webp'],
  ['image/gif', 'image/gif'],
  ['image/heic', 'image/heic'],
  ['image/heif', 'image/heif'],
]);

function normalizeInventoryUploadMime(v) {
  const key = String(v || 'image/jpeg')
    .trim()
    .toLowerCase()
    .slice(0, 80);
  return INVENTORY_UPLOAD_MIME.get(key) || null;
}

/** Walang auth — para macheck kung ang tamang server ang tumatakbo (may /pages/* routes). */
app.get('/api/v1/health', (req, res) => {
  res.json({
    ok: true,
    name: 'sukitrack-api',
    pagesApi: true,
    hint: 'Kung 404 pa rin ang POST .../pages/items, i-restart ang node process mula sa folder na ito.',
  });
});

app.post('/api/v1/auth/register', registerLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!isValidEmailShape(email)) {
      return res.status(400).json({ error: 'Valid email ang kailangan' });
    }
    const pwErr = passwordPolicyError(req.body.password);
    if (pwErr) {
      return res.status(400).json({ error: pwErr });
    }
    const password = String(req.body.password);
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ error: MSG_REGISTER_FAILED });
    }
    const ownerId = randomUUID();
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ email, passwordHash, ownerId });
    const out = await issueSessionTokens(user);
    res.json(out);
  } catch (e) {
    if (e?.code === 11000) {
      return res.status(400).json({ error: MSG_REGISTER_FAILED });
    }
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/v1/auth/login', loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!isValidEmailShape(email)) {
      return res.status(400).json({ error: 'Valid email ang kailangan' });
    }
    const password = req.body.password;
    if (
      password != null &&
      String(password).length > MAX_PASSWORD_LEN
    ) {
      return res.status(401).json({ error: 'Maling email o password' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Maling email o password' });
    }
    const ok = await bcrypt.compare(String(password || ''), user.passwordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Maling email o password' });
    }
    const out = await issueSessionTokens(user);
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/** Generic OK — huwag i-reveal kung may account ang email. */
app.post('/api/v1/auth/forgot-pin/request', forgotPinRequestLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!isValidEmailShape(email)) {
      return res.status(400).json({ error: 'Valid email ang kailangan' });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ ok: true });
    }
    const last = pinResetLastSent.get(email) || 0;
    if (Date.now() - last < pinResetCooldownMs) {
      return res.json({ ok: true });
    }
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    const pinResetCodeHash = hashPinResetCode(email, code);
    const pinResetExpiresAt = new Date(Date.now() + 15 * 60 * 1000);
    user.pinResetCodeHash = pinResetCodeHash;
    user.pinResetExpiresAt = pinResetExpiresAt;
    await user.save();
    try {
      await sendPinResetEmail(email, code);
    } catch (sendErr) {
      console.error('[PIN RESET] send failed', sendErr);
      user.pinResetCodeHash = null;
      user.pinResetExpiresAt = null;
      await user.save();
      /** Same body as success so SMTP errors do not reveal that the account exists. */
      return res.json({ ok: true });
    }
    pinResetLastSent.set(email, Date.now());
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/v1/auth/forgot-pin/verify', forgotPinVerifyLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const rawCode = String(req.body.code || '').trim().replace(/\D/g, '');
    if (!isValidEmailShape(email)) {
      return res.status(400).json({ error: 'Valid email ang kailangan' });
    }
    if (!rawCode || rawCode.length !== 6) {
      return res.status(400).json({ error: '6-digit na code ang kailangan' });
    }
    const user = await User.findOne({ email });
    if (
      !user ||
      !user.pinResetCodeHash ||
      !user.pinResetExpiresAt ||
      user.pinResetExpiresAt.getTime() < Date.now()
    ) {
      return res.status(401).json({ error: 'Maling o expired na code' });
    }
    const h = hashPinResetCode(email, rawCode);
    if (h !== user.pinResetCodeHash) {
      return res.status(401).json({ error: 'Maling o expired na code' });
    }
    user.pinResetCodeHash = null;
    user.pinResetExpiresAt = null;
    await user.save();
    const out = await issueSessionTokens(user, { replaceAll: true });
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/v1/auth/refresh', refreshLimiter, async (req, res) => {
  try {
    const raw = String(req.body.refreshToken || '').trim();
    if (!raw || raw.length > 256) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    const hash = hashRefreshToken(raw);
    const now = new Date();
    const user = await User.findOne({
      $or: [
        {
          refreshSessions: {
            $elemMatch: { tokenHash: hash, expiresAt: { $gt: now } },
          },
        },
        { refreshTokenHash: hash, refreshTokenExpiresAt: { $gt: now } },
      ],
    });
    if (!user) {
      return res.status(401).json({ error: 'Invalid session' });
    }
    try {
      const out = await rotateRefreshToken(user, raw);
      res.json(out);
    } catch (e) {
      if (e?.code === 'INVALID_REFRESH') {
        return res.status(401).json({ error: 'Invalid session' });
      }
      throw e;
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/v1/auth/logout', requireAuth, async (req, res) => {
  try {
    const user = await User.findOne({ ownerId: req.ownerId });
    if (user) {
      user.refreshSessions = [];
      user.refreshTokenHash = null;
      user.refreshTokenExpiresAt = null;
      await user.save();
    }
    auditFromReq(req, 'auth.logout', {});
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post(
  '/api/v1/auth/change-password',
  passwordChangeLimiter,
  requireAuth,
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const pwErr = passwordPolicyError(newPassword);
      if (pwErr) {
        return res.status(400).json({ error: pwErr });
      }
      if (
        currentPassword != null &&
        String(currentPassword).length > MAX_PASSWORD_LEN
      ) {
        return res.status(400).json({ error: MSG_CHANGE_PASSWORD_FAILED });
      }
      const user = await User.findOne({ ownerId: req.ownerId });
      if (!user) {
        return res.status(400).json({ error: MSG_CHANGE_PASSWORD_FAILED });
      }
      const ok = await bcrypt.compare(String(currentPassword || ''), user.passwordHash);
      if (!ok) {
        return res.status(400).json({ error: MSG_CHANGE_PASSWORD_FAILED });
      }
      user.passwordHash = await bcrypt.hash(String(newPassword), 10);
      await user.save();
      const out = await issueSessionTokens(user, { replaceAll: true });
      auditFromReq(req, 'auth.change_password', {});
      res.json({ ok: true, ...out });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

function serializeCustomer(c) {
  return {
    id: c._id.toString(),
    ownerId: c.ownerId,
    name: c.name,
    phone: c.phone ?? '',
    address: c.address ?? '',
    balance: c.balance ?? 0,
    lastTransactionAt: c.lastTransactionAt ?? null,
    createdAt: c.createdAt ?? null,
    updatedAt: c.updatedAt ?? null,
  };
}

function serializeInventoryItem(doc) {
  const up = doc.unitPrice;
  return {
    id: doc._id.toString(),
    ownerId: doc.ownerId,
    name: doc.name ?? '',
    category: doc.category != null ? String(doc.category).trim() : '',
    unitPrice:
      up === null || up === undefined || Number.isNaN(Number(up))
        ? null
        : Number(up),
    imageUrl: sanitizeInventoryImageUrl(doc.imageUrl),
    createdAt: doc.createdAt ?? null,
    updatedAt: doc.updatedAt ?? null,
  };
}

app.get('/api/v1/bootstrap', requireAuth, async (req, res) => {
  try {
    const ownerId = req.ownerId;
    const [customers, pages, inventory] = await Promise.all([
      Customer.find({ ownerId }).sort({ name: 1 }).lean(),
      UtangPage.find({ ownerId }).sort({ updatedAt: -1 }).lean(),
      InventoryItem.find({ ownerId }).sort({ name: 1 }).lean(),
    ]);
    res.json({
      customers: customers.map((c) => serializeCustomer(c)),
      pages: pages.map((p) => serializePage(p)),
      inventory: inventory.map((row) => serializeInventoryItem(row)),
      features: {
        inventoryCloudinary: cloudinaryConfigured(),
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

app.get('/api/v1/audit-log', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));
    const rows = await AuditLog.find({ ownerId: req.ownerId })
      .sort({ createdAt: -1 })
      .limit(limit)
      .select('action meta createdAt')
      .lean();
    res.json({
      items: rows.map((r) => ({
        id: r._id.toString(),
        action: r.action,
        meta: r.meta || {},
        createdAt: r.createdAt,
      })),
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

app.post('/api/v1/inventory/upload-image', requireAuth, async (req, res) => {
  if (!configureCloudinary()) {
    return res
      .status(503)
      .json({ error: 'Hindi naka-set ang Cloudinary', ok: false });
  }
  try {
    const raw = req.body.base64;
    const mimeType = normalizeInventoryUploadMime(req.body.mimeType);
    if (!mimeType) {
      return res.status(400).json({ error: 'Hindi suportadong uri ng larawan' });
    }
    if (!raw || typeof raw !== 'string') {
      return res.status(400).json({ error: 'Kailangan ang base64 ng larawan' });
    }
    const b64 = String(raw).replace(/^data:image\/\w+;base64,/, '');
    if (b64.length > 5_000_000) {
      return res.status(400).json({ error: 'Masiyadong malaki ang larawan' });
    }
    const dataUri = `data:${mimeType};base64,${b64}`;
    const uploaded = await cloudinary.uploader.upload(dataUri, {
      folder: `sukitrack/inventory/${req.ownerId}`,
      resource_type: 'image',
      transformation: [{ width: 512, height: 512, crop: 'limit' }],
    });
    res.json({ ok: true, url: uploaded.secure_url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e, 'Upload error'), ok: false });
  }
});

app.post('/api/v1/inventory', requireAuth, async (req, res) => {
  try {
    const name = String(req.body.name || '')
      .trim()
      .slice(0, MAX_INVENTORY_NAME_LEN);
    if (!name) {
      return res.status(400).json({ error: 'Kailangan ang pangalan ng produkto' });
    }
    let unitPrice = null;
    const rawPrice = req.body.unitPrice;
    if (rawPrice !== undefined && rawPrice !== null && rawPrice !== '') {
      const n = Number(rawPrice);
      if (!Number.isFinite(n) || n < 0) {
        return res.status(400).json({ error: 'Maling presyo' });
      }
      unitPrice = n;
    }
    let category = '';
    if (req.body.category !== undefined && req.body.category !== null) {
      category = String(req.body.category).trim().slice(0, 80);
    }
    let imageUrl = null;
    if (req.body.imageUrl !== undefined && req.body.imageUrl !== null) {
      imageUrl = sanitizeInventoryImageUrl(req.body.imageUrl);
      if (String(req.body.imageUrl || '').trim() && !imageUrl) {
        return res.status(400).json({ error: 'Maling URL ng larawan' });
      }
    }
    const doc = await InventoryItem.create({
      ownerId: req.ownerId,
      name,
      unitPrice,
      category,
      imageUrl,
    });
    res.json(serializeInventoryItem(doc.toObject()));
  } catch (e) {
    if (e?.code === 11000) {
      return res
        .status(409)
        .json({ error: 'May produkto na sa pangalan na ito' });
    }
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

app.patch('/api/v1/inventory/:id', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'Maling ID' });
    }
    const doc = await InventoryItem.findOne({ _id: id, ownerId: req.ownerId });
    if (!doc) {
      return res.status(404).json({ error: 'Hindi mahanap' });
    }
    if (req.body.name !== undefined) {
      const name = String(req.body.name || '')
        .trim()
        .slice(0, MAX_INVENTORY_NAME_LEN);
      if (!name) {
        return res.status(400).json({ error: 'Kailangan ang pangalan ng produkto' });
      }
      doc.name = name;
    }
    if (req.body.unitPrice !== undefined) {
      if (req.body.unitPrice === null || req.body.unitPrice === '') {
        doc.unitPrice = null;
      } else {
        const n = Number(req.body.unitPrice);
        if (!Number.isFinite(n) || n < 0) {
          return res.status(400).json({ error: 'Maling presyo' });
        }
        doc.unitPrice = n;
      }
    }
    if (req.body.category !== undefined) {
      doc.category =
        req.body.category === null || req.body.category === ''
          ? ''
          : String(req.body.category).trim().slice(0, 80);
    }
    if (req.body.imageUrl !== undefined) {
      const next = sanitizeInventoryImageUrl(req.body.imageUrl);
      if (String(req.body.imageUrl || '').trim() && !next) {
        return res.status(400).json({ error: 'Maling URL ng larawan' });
      }
      doc.imageUrl = next;
    }
    await doc.save();
    res.json(serializeInventoryItem(doc.toObject()));
  } catch (e) {
    if (e?.code === 11000) {
      return res
        .status(409)
        .json({ error: 'May produkto na sa pangalan na ito' });
    }
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

app.delete('/api/v1/inventory/:id', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'Maling ID' });
    }
    const r = await InventoryItem.deleteOne({ _id: id, ownerId: req.ownerId });
    if (r.deletedCount === 0) {
      return res.status(404).json({ error: 'Hindi mahanap' });
    }
    auditFromReq(req, 'inventory.delete', { inventoryId: id });
    res.status(204).send();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

app.post('/api/v1/customers', requireAuth, async (req, res) => {
  try {
    const { name = '', phone = '', address = '' } = req.body;
    const nameT = String(name).trim().slice(0, MAX_CUSTOMER_NAME_LEN);
    if (!nameT) {
      return res.status(400).json({ error: 'Kailangan ang pangalan' });
    }
    const phoneT = String(phone || '').trim().slice(0, MAX_CUSTOMER_PHONE_LEN);
    const addressT = String(address || '').trim().slice(0, MAX_CUSTOMER_ADDRESS_LEN);
    const doc = await Customer.create({
      ownerId: req.ownerId,
      name: nameT,
      phone: phoneT,
      address: addressT,
      balance: 0,
      lastTransactionAt: null,
    });
    res.json({ id: doc._id.toString() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

app.patch('/api/v1/customers/:id', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'Maling ID' });
    }
    const c = await Customer.findOne({ _id: id, ownerId: req.ownerId });
    if (!c) {
      return res.status(404).json({ error: 'Hindi mahanap' });
    }
    const name = String(req.body.name || '').trim().slice(0, MAX_CUSTOMER_NAME_LEN);
    if (!name) {
      return res.status(400).json({ error: 'Kailangan ang pangalan' });
    }
    c.name = name;
    c.phone = String(req.body.phone || '').trim().slice(0, MAX_CUSTOMER_PHONE_LEN);
    c.address = String(req.body.address || '').trim().slice(0, MAX_CUSTOMER_ADDRESS_LEN);
    await c.save();
    res.json(serializeCustomer(c.toObject()));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

app.delete('/api/v1/customers/:id', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'Maling ID' });
    }
    const c = await Customer.findOne({ _id: id, ownerId: req.ownerId });
    if (!c) {
      return res.status(404).json({ error: 'Hindi mahanap' });
    }
    await UtangPage.deleteMany({
      customerId: id,
      ownerId: req.ownerId,
    });
    await Transaction.deleteMany({
      customerId: id,
      ownerId: req.ownerId,
    });
    await Customer.deleteOne({ _id: id, ownerId: req.ownerId });
    auditFromReq(req, 'customer.delete', { customerId: id });
    res.status(204).send();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

/** Clears a customer's pages/transactions and resets balance. */
app.post('/api/v1/customers/:id/clear-records', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).json({ error: 'Maling customer ID' });
    }
    const c = await Customer.findOne({ _id: id, ownerId: req.ownerId });
    if (!c) {
      return res.status(404).json({ error: 'Hindi mahanap ang customer' });
    }

    await UtangPage.deleteMany({ customerId: id, ownerId: req.ownerId });
    await Transaction.deleteMany({ customerId: id, ownerId: req.ownerId });

    c.balance = 0;
    c.lastTransactionAt = null;
    await c.save();
    auditFromReq(req, 'customer.clear_records', { customerId: id });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  }
});

/** One “sheet” per customer: line items + payments; when fully paid, page is closed and archived in the app. */
app.post('/api/v1/customers/:id/pages/items', requireAuth, async (req, res) => {
  const customerId = req.params.id;
  if (!mongoose.isValidObjectId(customerId)) {
    return res.status(400).json({ error: 'Maling customer ID' });
  }
  const abs = Math.abs(Number(req.body.amount));
  if (!abs || Number.isNaN(abs)) {
    return res.status(400).json({ error: 'Maling halaga' });
  }
  const description = (
    String(req.body.description || req.body.note || '').trim() || 'Item'
  ).slice(0, 400);

  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    const cust = await Customer.findOne({
      _id: customerId,
      ownerId: req.ownerId,
    }).session(session);
    if (!cust) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang customer' });
    }

    let page = await UtangPage.findOne({
      ownerId: req.ownerId,
      customerId: cust._id,
      status: 'open',
    }).session(session);

    if (!page) {
      try {
        const [created] = await UtangPage.create(
          [
            {
              ownerId: req.ownerId,
              customerId: cust._id,
              status: 'open',
              items: [],
              payments: [],
            },
          ],
          { session }
        );
        page = created;
      } catch (err) {
        if (err?.code === 11000) {
          page = await UtangPage.findOne({
            ownerId: req.ownerId,
            customerId: cust._id,
            status: 'open',
          }).session(session);
        }
        if (!page) {
          await session.abortTransaction();
          console.error(err);
          return res.status(500).json({ error: publicServerErrorMessage(err) });
        }
      }
    }

    const itemId = randomUUID();
    page.items.push({
      id: itemId,
      description,
      amount: abs,
      note: '',
      createdAt: new Date(),
    });

    cust.balance = (Number(cust.balance) || 0) + abs;
    cust.lastTransactionAt = new Date();
    await cust.save({ session });
    await page.save({ session });
    await session.commitTransaction();
    res.json({ ok: true, pageId: page._id.toString(), itemId });
  } catch (e) {
    await session.abortTransaction();
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  } finally {
    session.endSession();
  }
});

app.post('/api/v1/customers/:id/pages/payments', requireAuth, async (req, res) => {
  const customerId = req.params.id;
  if (!mongoose.isValidObjectId(customerId)) {
    return res.status(400).json({ error: 'Maling customer ID' });
  }
  const abs = Math.abs(Number(req.body.amount));
  if (!abs || Number.isNaN(abs)) {
    return res.status(400).json({ error: 'Maling halaga' });
  }
  const note = String(req.body.note || '').trim().slice(0, 200);

  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    const cust = await Customer.findOne({
      _id: customerId,
      ownerId: req.ownerId,
    }).session(session);
    if (!cust) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang customer' });
    }

    const page = await UtangPage.findOne({
      ownerId: req.ownerId,
      customerId: cust._id,
      status: 'open',
    }).session(session);

    if (!page) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Walang bukas na pahina ng utang' });
    }

    const { itemsTotal, paidTotal, due } = totalsFromPageDoc(page);
    if (itemsTotal <= 0) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Walang item sa pahina' });
    }
    const dueR = roundMoney(due);
    if (dueR <= 0) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Walang kulang sa pahinang ito.' });
    }
    const payR = roundMoney(abs);
    if (payR > dueR + 0.001) {
      await session.abortTransaction();
      return res.status(400).json({
        error: `Lampas sa kulang. Pinakamataas na bayad: ${dueR}.`,
        maxDue: dueR,
      });
    }

    const paymentId = randomUUID();
    page.payments.push({
      id: paymentId,
      amount: payR,
      note,
      createdAt: new Date(),
    });

    const newPaidTotal = roundMoney(paidTotal + payR);
    cust.balance = Math.max(0, roundMoney((Number(cust.balance) || 0) - payR));
    cust.lastTransactionAt = new Date();

    if (newPaidTotal >= itemsTotal - 0.0001) {
      page.status = 'paid';
      page.paidAt = new Date();
    }

    await page.save({ session });
    await cust.save({ session });
    await session.commitTransaction();
    res.json({
      ok: true,
      pageId: page._id.toString(),
      paymentId,
      pagePaid: page.status === 'paid',
    });
  } catch (e) {
    await session.abortTransaction();
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  } finally {
    session.endSession();
  }
});

app.patch('/api/v1/customers/:id/pages/items/:itemId', requireAuth, async (req, res) => {
  const customerId = req.params.id;
  const itemId = String(req.params.itemId || '').trim();
  if (!mongoose.isValidObjectId(customerId)) {
    return res.status(400).json({ error: 'Maling customer ID' });
  }
  if (!itemId) {
    return res.status(400).json({ error: 'Kulang ang item ID' });
  }
  const abs = Math.abs(Number(req.body.amount));
  if (!abs || Number.isNaN(abs)) {
    return res.status(400).json({ error: 'Maling halaga' });
  }
  const description = (
    String(req.body.description || req.body.note || '').trim() || 'Item'
  ).slice(0, 400);
  const note = String(req.body.note || '').trim().slice(0, 200);

  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    const cust = await Customer.findOne({
      _id: customerId,
      ownerId: req.ownerId,
    }).session(session);
    if (!cust) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang customer' });
    }
    const page = await UtangPage.findOne({
      ownerId: req.ownerId,
      customerId: cust._id,
      status: 'open',
    }).session(session);
    if (!page) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Walang bukas na pahina ng utang' });
    }
    const idx = (page.items || []).findIndex((x) => x.id === itemId);
    if (idx < 0) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang item' });
    }

    const prevAmt = Math.abs(Number(page.items[idx].amount)) || 0;
    page.items[idx].amount = abs;
    page.items[idx].description = description;
    page.items[idx].note = note;

    const delta = roundMoney(abs - prevAmt);
    cust.balance = roundMoney((Number(cust.balance) || 0) + delta);
    if (cust.balance < 0) cust.balance = 0;
    cust.lastTransactionAt = new Date();

    await page.save({ session });
    await cust.save({ session });
    await session.commitTransaction();
    res.json({ ok: true });
  } catch (e) {
    await session.abortTransaction();
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  } finally {
    session.endSession();
  }
});

app.delete('/api/v1/customers/:id/pages/items/:itemId', requireAuth, async (req, res) => {
  const customerId = req.params.id;
  const itemId = String(req.params.itemId || '').trim();
  if (!mongoose.isValidObjectId(customerId)) {
    return res.status(400).json({ error: 'Maling customer ID' });
  }
  if (!itemId) {
    return res.status(400).json({ error: 'Kulang ang item ID' });
  }

  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    const cust = await Customer.findOne({
      _id: customerId,
      ownerId: req.ownerId,
    }).session(session);
    if (!cust) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang customer' });
    }
    const page = await UtangPage.findOne({
      ownerId: req.ownerId,
      customerId: cust._id,
      status: 'open',
    }).session(session);
    if (!page) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Walang bukas na pahina ng utang' });
    }
    const items = page.items || [];
    const idx = items.findIndex((x) => x.id === itemId);
    if (idx < 0) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang item' });
    }
    const prevAmt = Math.abs(Number(items[idx].amount)) || 0;
    page.items = items.filter((x) => x.id !== itemId);

    cust.balance = roundMoney((Number(cust.balance) || 0) - prevAmt);
    if (cust.balance < 0) cust.balance = 0;
    cust.lastTransactionAt = new Date();

    await page.save({ session });
    await cust.save({ session });
    await session.commitTransaction();
    auditFromReq(req, 'page.item.delete', { customerId, itemId });
    res.status(204).send();
  } catch (e) {
    await session.abortTransaction();
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  } finally {
    session.endSession();
  }
});

app.patch('/api/v1/customers/:id/pages/payments/:paymentId', requireAuth, async (req, res) => {
  const customerId = req.params.id;
  const paymentId = String(req.params.paymentId || '').trim();
  if (!mongoose.isValidObjectId(customerId)) {
    return res.status(400).json({ error: 'Maling customer ID' });
  }
  if (!paymentId) {
    return res.status(400).json({ error: 'Kulang ang payment ID' });
  }
  const abs = Math.abs(Number(req.body.amount));
  if (!abs || Number.isNaN(abs)) {
    return res.status(400).json({ error: 'Maling halaga' });
  }
  const note = String(req.body.note || '').trim().slice(0, 200);

  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    const cust = await Customer.findOne({
      _id: customerId,
      ownerId: req.ownerId,
    }).session(session);
    if (!cust) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang customer' });
    }
    const page = await UtangPage.findOne({
      ownerId: req.ownerId,
      customerId: cust._id,
      status: 'open',
    }).session(session);
    if (!page) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Walang bukas na pahina ng utang' });
    }
    const idx = (page.payments || []).findIndex((x) => x.id === paymentId);
    if (idx < 0) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang bayad' });
    }

    const { itemsTotal, paidTotal } = totalsFromPageDoc(page);
    const prevAmt = Math.abs(Number(page.payments[idx].amount)) || 0;
    const nextPaidTotal = roundMoney(paidTotal - prevAmt + abs);
    if (itemsTotal <= 0) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Walang item sa pahina' });
    }
    if (nextPaidTotal > itemsTotal + 0.001) {
      await session.abortTransaction();
      return res.status(400).json({
        error: `Lampas sa kulang. Pinakamataas na bayad: ${roundMoney(itemsTotal - (paidTotal - prevAmt))}.`,
      });
    }

    page.payments[idx].amount = abs;
    page.payments[idx].note = note;

    const delta = roundMoney(abs - prevAmt);
    cust.balance = roundMoney((Number(cust.balance) || 0) - delta);
    if (cust.balance < 0) cust.balance = 0;
    cust.lastTransactionAt = new Date();

    const recalc = totalsFromPageDoc(page);
    if (recalc.itemsTotal > 0 && recalc.paidTotal >= recalc.itemsTotal - 0.0001) {
      page.status = 'paid';
      page.paidAt = new Date();
    } else {
      page.status = 'open';
      page.paidAt = null;
    }

    await page.save({ session });
    await cust.save({ session });
    await session.commitTransaction();
    res.json({ ok: true });
  } catch (e) {
    await session.abortTransaction();
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  } finally {
    session.endSession();
  }
});

app.delete('/api/v1/customers/:id/pages/payments/:paymentId', requireAuth, async (req, res) => {
  const customerId = req.params.id;
  const paymentId = String(req.params.paymentId || '').trim();
  if (!mongoose.isValidObjectId(customerId)) {
    return res.status(400).json({ error: 'Maling customer ID' });
  }
  if (!paymentId) {
    return res.status(400).json({ error: 'Kulang ang payment ID' });
  }

  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    const cust = await Customer.findOne({
      _id: customerId,
      ownerId: req.ownerId,
    }).session(session);
    if (!cust) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang customer' });
    }
    const page = await UtangPage.findOne({
      ownerId: req.ownerId,
      customerId: cust._id,
      status: 'open',
    }).session(session);
    if (!page) {
      await session.abortTransaction();
      return res.status(400).json({ error: 'Walang bukas na pahina ng utang' });
    }
    const pays = page.payments || [];
    const idx = pays.findIndex((x) => x.id === paymentId);
    if (idx < 0) {
      await session.abortTransaction();
      return res.status(404).json({ error: 'Hindi mahanap ang bayad' });
    }
    const prevAmt = Math.abs(Number(pays[idx].amount)) || 0;
    page.payments = pays.filter((x) => x.id !== paymentId);

    cust.balance = roundMoney((Number(cust.balance) || 0) + prevAmt);
    cust.lastTransactionAt = new Date();

    const recalc = totalsFromPageDoc(page);
    if (recalc.itemsTotal > 0 && recalc.paidTotal >= recalc.itemsTotal - 0.0001) {
      page.status = 'paid';
      page.paidAt = new Date();
    } else {
      page.status = 'open';
      page.paidAt = null;
    }

    await page.save({ session });
    await cust.save({ session });
    await session.commitTransaction();
    auditFromReq(req, 'page.payment.delete', { customerId, paymentId });
    res.status(204).send();
  } catch (e) {
    await session.abortTransaction();
    console.error(e);
    res.status(500).json({ error: publicServerErrorMessage(e) });
  } finally {
    session.endSession();
  }
});

const PORT = Number(process.env.PORT) || 3847;
const MONGODB_URI =
  process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/utang_tracker_ph';

process.on('unhandledRejection', (reason) => {
  console.error('[unhandledRejection]', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err);
  process.exit(1);
});

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log('MongoDB connected');
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`SukiTrack API listening on port ${PORT}`);
    });

    /** Graceful shutdown — required for Render (sends SIGTERM on deploy/scale-down). */
    function shutdown(signal) {
      console.log(`${signal} received — shutting down gracefully`);
      server.close(() => {
        console.log('HTTP server closed');
        mongoose.connection.close(false).then(() => {
          console.log('MongoDB connection closed');
          process.exit(0);
        }).catch((e) => {
          console.error('Error closing MongoDB connection', e);
          process.exit(1);
        });
      });

      // Force-kill if shutdown takes too long (Render allows ~30 s)
      setTimeout(() => {
        console.error('Shutdown timed out — forcing exit');
        process.exit(1);
      }, 25_000).unref();
    }

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  })
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });