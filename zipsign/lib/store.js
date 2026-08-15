import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { PACKAGES_DIR } from './paths.js';

const ID_RE = /^[A-Za-z0-9_-]{8,20}$/;

export function maskEmail(email) {
  const [name, domain] = email.split('@');
  if (!name || !domain) return 'unknown';
  return `${name[0]}\u2026@${domain}`;
}

export function sanitizeFilename(name) {
  return String(name).replace(/[^A-Za-z0-9._-]/g, '_');
}

export async function createPackage({ email, originalName, tmpPath, privateKey, publicKeyPem }) {
  const id = crypto.randomBytes(9).toString('base64url');
  const dir = path.join(PACKAGES_DIR, id);
  await fsp.mkdir(dir, { recursive: true });

  const zipPath = path.join(dir, 'package.zip');
  await fsp.rename(tmpPath, zipPath);

  const data = await fsp.readFile(zipPath);
  const sha256 = crypto.createHash('sha256').update(data).digest('hex');
  const signature = crypto.sign(null, data, privateKey).toString('base64');

  const meta = {
    id,
    algorithm: 'ed25519',
    originalName,
    signedBy: maskEmail(email),
    size: data.length,
    sha256,
    signature,
    publicKey: publicKeyPem,
    createdAt: new Date().toISOString(),
  };
  await fsp.writeFile(path.join(dir, 'meta.json'), JSON.stringify(meta, null, 2));
  return meta;
}

export async function getPackage(id) {
  if (!ID_RE.test(id)) return null;
  try {
    const meta = JSON.parse(await fsp.readFile(path.join(PACKAGES_DIR, id, 'meta.json'), 'utf8'));
    return meta;
  } catch {
    return null;
  }
}

export function packageZipPath(id) {
  return path.join(PACKAGES_DIR, id, 'package.zip');
}
