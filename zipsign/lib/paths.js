import './env.js';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

export const DATA_DIR = process.env.DATA_DIR || path.join(root, 'data');
export const PACKAGES_DIR = path.join(DATA_DIR, 'packages');
export const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
export const KEYS_DIR = path.join(DATA_DIR, 'keys');

export function ensureDataDirs() {
  for (const dir of [DATA_DIR, PACKAGES_DIR, UPLOADS_DIR, KEYS_DIR]) {
    fs.mkdirSync(dir, { recursive: true });
  }
}
