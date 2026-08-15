import crypto from 'node:crypto';

const records = new Map();
const COOLDOWN_MS = 60_000;
const TTL_MS = 10 * 60_000;
const MAX_ATTEMPTS = 5;
const PEPPER = crypto.randomBytes(32);

function hash(email, otp) {
  return crypto.createHmac('sha256', PEPPER).update(`${email}:${otp}`).digest();
}

export function requestOtp(email) {
  const key = email.toLowerCase();
  const now = Date.now();
  const rec = records.get(key);
  if (rec && now - rec.lastSent < COOLDOWN_MS) {
    return { ok: false, retryAfter: Math.ceil((COOLDOWN_MS - (now - rec.lastSent)) / 1000) };
  }
  const otp = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  records.set(key, { digest: hash(key, otp), expires: now + TTL_MS, attempts: 0, lastSent: now });
  return { ok: true, otp };
}

export function verifyOtp(email, otp) {
  const key = email.toLowerCase();
  const rec = records.get(key);
  if (!rec) return { ok: false, error: 'Request a new code first.' };
  if (Date.now() > rec.expires) {
    records.delete(key);
    return { ok: false, error: 'Code expired. Request a new one.' };
  }
  if (rec.attempts >= MAX_ATTEMPTS) {
    records.delete(key);
    return { ok: false, error: 'Too many incorrect attempts. Request a new code.' };
  }
  rec.attempts++;
  const given = hash(key, String(otp).trim());
  if (given.length !== rec.digest.length || !crypto.timingSafeEqual(given, rec.digest)) {
    return { ok: false, error: 'Invalid code.' };
  }
  records.delete(key);
  return { ok: true };
}

setInterval(() => {
  const now = Date.now();
  for (const [k, r] of records) if (now > r.expires + COOLDOWN_MS) records.delete(k);
}, 60_000).unref();
