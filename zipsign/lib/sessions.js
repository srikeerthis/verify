import crypto from 'node:crypto';

const sessions = new Map();
const TTL_MS = 60 * 60 * 1000;

export function createSession(email) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, { email, expires: Date.now() + TTL_MS });
  return token;
}

export function getEmailFromToken(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) {
    sessions.delete(token);
    return null;
  }
  return s.email;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now > s.expires) sessions.delete(k);
}, 60_000).unref();
