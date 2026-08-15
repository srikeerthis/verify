import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { KEYS_DIR } from './paths.js';

export function fingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

export function getOrCreateKeyPair(email) {
  const slug = crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex').slice(0, 32);
  const dir = path.join(KEYS_DIR, slug);
  fs.mkdirSync(dir, { recursive: true });
  const privPath = path.join(dir, 'private.pem');
  const pubPath = path.join(dir, 'public.pem');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    return {
      privateKey: crypto.createPrivateKey(fs.readFileSync(privPath, 'utf8')),
      publicKeyPem: fs.readFileSync(pubPath, 'utf8'),
    };
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(privPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  fs.writeFileSync(pubPath, pem);
  return { privateKey, publicKeyPem: pem };
}
