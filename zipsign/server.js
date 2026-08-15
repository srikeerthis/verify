import express from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ensureDataDirs, UPLOADS_DIR } from './lib/paths.js';
import { requestOtp, verifyOtp } from './lib/otp.js';
import { createSession, getEmailFromToken } from './lib/sessions.js';
import { sendOtp } from './lib/mail.js';
import { getOrCreateKeyPair, fingerprint } from './lib/keys.js';
import { createPackage, getPackage, packageZipPath, sanitizeFilename } from './lib/store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
ensureDataDirs();

const PORT = Number(process.env.PORT) || 3000;
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB) || 100;
const DEV_MODE = process.env.DEV_MODE === '1';
const INTEGRATION_API_KEY = process.env.INTEGRATION_API_KEY || '';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  dest: UPLOADS_DIR,
  limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1 },
});

const ipHits = new Map();
function ipLimit(max = 30, windowMs = 15 * 60_000) {
  return (req, res, next) => {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const hits = (ipHits.get(ip) || []).filter((t) => now - t < windowMs);
    if (hits.length >= max) {
      return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    }
    hits.push(now);
    ipHits.set(ip, hits);
    next();
  };
}
app.use('/api/auth', ipLimit());

app.post('/api/auth/request-otp', async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 254) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  const r = requestOtp(email);
  if (!r.ok) {
    return res.status(429).json({ error: `A code was just sent. Try again in ${r.retryAfter}s.` });
  }
  try {
    await sendOtp(email, r.otp);
  } catch (err) {
    console.error('Failed to send OTP email:', err.message);
    return res.status(500).json({ error: 'Could not send the email right now. Try again shortly.' });
  }
  const out = { ok: true, message: `Code sent to ${email}. It expires in 10 minutes.` };
  if (DEV_MODE) out.devOtp = r.otp;
  res.json(out);
});

app.post('/api/auth/verify', (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const otp = String(req.body?.otp || '').trim();
  if (!EMAIL_RE.test(email) || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ error: 'Enter the 6-digit code that was sent to you.' });
  }
  const r = verifyOtp(email, otp);
  if (!r.ok) return res.status(400).json({ error: r.error });

  const { publicKeyPem } = getOrCreateKeyPair(email);
  const token = createSession(email);
  const base = `${req.protocol}://${req.get('host')}`;
  const out = {
    ok: true,
    email,
    token,
    successUrl: '/done',
    keyFingerprint: fingerprint(publicKeyPem),
    publicKeyUrl: `${base}/api/keys/${encodeURIComponent(email)}`,
  };
  if (DEV_MODE) out.devNote = 'DEV_MODE is on.';
  res.json(out);
});

app.get('/api/keys/:email', (req, res) => {
  const email = String(req.params.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Invalid email.' });
  const { publicKeyPem } = getOrCreateKeyPair(email);
  res.type('application/x-pem-file');
  res.attachment('public.pem');
  res.send(publicKeyPem);
});

app.get('/api/me', requireAuth, (req, res) => {
  const { publicKeyPem } = getOrCreateKeyPair(req.userEmail);
  res.json({ email: req.userEmail, keyFingerprint: fingerprint(publicKeyPem) });
});

app.get('/u/:token', (req, res) => {
  const email = getEmailFromToken(req.params.token);
  if (!email) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'upload.html'));
});

app.get('/done', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'done.html'));
});

app.get('/done/:id', async (req, res) => {
  const meta = await getPackage(req.params.id);
  if (!meta) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'done.html'));
});

function requireAuth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  const email = getEmailFromToken(token);
  if (!email) return res.status(401).json({ error: 'Session expired or invalid. Verify your email again.' });
  req.userEmail = email;
  next();
}

function packageLinks(req, meta) {
  const base = `${req.protocol}://${req.get('host')}`;
  return {
    ...meta,
    downloadUrl: `${base}/api/packages/${meta.id}/download`,
    signatureUrl: `${base}/api/packages/${meta.id}/signature`,
    publicKeyUrl: `${base}/api/packages/${meta.id}/publickey`,
    verifyUrl: `${base}/v/${meta.id}`,
  };
}

async function signUpload(req, res, email, { toPipeline = false } = {}) {
  const tmp = req.file?.path;
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded. Send multipart/form-data with a "file" field.' });

    const originalName = path.basename(String(req.file.originalname || 'package.zip'));
    if (!/\.zip$/i.test(originalName)) {
      await fsp.rm(tmp, { force: true });
      return res.status(400).json({ error: 'Only .zip files are accepted.' });
    }

    const fh = await fsp.open(tmp, 'r');
    const magic = Buffer.alloc(2);
    await fh.read(magic, 0, 2, 0);
    await fh.close();
    if (magic.toString('latin1') !== 'PK') {
      await fsp.rm(tmp, { force: true });
      return res.status(400).json({ error: 'This does not look like a zip file (missing PK signature).' });
    }

    const companyPhone = String(req.body?.company_phone || '').trim();
    const candidatePhone = String(req.body?.candidate_phone || '').trim();
    if (toPipeline) {
      for (const [label, value] of [['Your', companyPhone], ["The candidate's", candidatePhone]]) {
        if (!E164.test(value)) {
          await fsp.rm(tmp, { force: true });
          return res.status(400).json({ error: `${label} number needs the country code, like +15551234567.` });
        }
      }
    }

    const { privateKey, publicKeyPem } = getOrCreateKeyPair(email);
    const meta = await createPackage({ email, originalName, tmpPath: tmp, privateKey, publicKeyPem });
    const links = packageLinks(req, meta);

    if (!toPipeline) return res.status(201).json(links);

    // The package is signed and safe either way — a pipeline outage must not
    // cost the recruiter their upload, so this failure is reported, not fatal.
    try {
      const accepted = await sendToPipeline({ links, email, companyPhone, candidatePhone });
      res.status(201).json({ ...links, pipeline: accepted });
    } catch (err) {
      console.error('Pipeline handoff failed:', err);
      res.status(201).json({
        ...links,
        pipelineError: 'Signed, but the scan pipeline could not be reached — nobody was texted.',
      });
    }
  } catch (err) {
    console.error('Package upload failed:', err);
    if (tmp) await fsp.rm(tmp, { force: true }).catch(() => {});
    res.status(500).json({ error: 'Failed to sign the package.' });
  }
}

function requireApiKey(req, res, next) {
  if (!INTEGRATION_API_KEY) {
    return res.status(503).json({ error: 'Integration endpoint disabled — set INTEGRATION_API_KEY to enable it.' });
  }
  const given = Buffer.from(String(req.headers['x-api-key'] || ''));
  const expected = Buffer.from(INTEGRATION_API_KEY);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
    return res.status(401).json({ error: 'Invalid API key.' });
  }
  next();
}

app.post('/api/integration/packages', requireApiKey, upload.single('file'), async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) {
    if (req.file?.path) await fsp.rm(req.file.path, { force: true }).catch(() => {});
    return res.status(400).json({ error: 'A valid "email" field is required (the signer identity).' });
  }
  await signUpload(req, res, email);
});

// The recruiter's own upload — this is the one that kicks off the SMS flow.
// The integration route above deliberately does not, or the pipeline
// publishing a scanned package back to us would start an endless loop.
app.post('/api/packages', requireAuth, upload.single('file'), async (req, res) => {
  await signUpload(req, res, req.userEmail, { toPipeline: true });
});

// --- hand a signed package to the scan pipeline ----------------------------
// The web app signs; the pipeline scans and does all the texting. We pass the
// download URL as the source so the pipeline fetches exactly the bytes we
// signed, plus the links we already minted so it does not publish a duplicate
// copy back to us.
const PIPELINE_URL = process.env.PIPELINE_URL || '';
const E164 = /^\+[1-9]\d{7,14}$/;

async function sendToPipeline({ links, email, companyPhone, candidatePhone }) {
  if (!PIPELINE_URL) {
    console.warn('PIPELINE_URL not set — package signed but nobody will be texted.');
    return;
  }
  const form = new URLSearchParams({
    source_url: links.downloadUrl,
    company_email: email,
    company_phone: companyPhone,
    candidate_phone: candidatePhone,
    webapp_id: links.id,
    webapp_verify_url: links.verifyUrl,
    webapp_download_url: links.downloadUrl,
    webapp_signature_url: links.signatureUrl,
    webapp_publickey_url: links.publicKeyUrl,
  });

  const res = await fetch(`${PIPELINE_URL.replace(/\/$/, '')}/packages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  if (!res.ok) {
    throw new Error(`pipeline returned ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  return res.json();
}

app.get('/api/packages/:id', async (req, res) => {
  const meta = await getPackage(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Package not found.' });
  res.json(packageLinks(req, meta));
});

app.get('/api/packages/:id/download', async (req, res) => {
  const meta = await getPackage(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Package not found.' });
  res.download(packageZipPath(meta.id), meta.originalName);
});

app.get('/api/packages/:id/signature', async (req, res) => {
  const meta = await getPackage(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Package not found.' });
  res.type('application/octet-stream');
  res.attachment(`${sanitizeFilename(meta.originalName)}.sig`);
  res.send(Buffer.from(meta.signature, 'base64'));
});

app.get('/api/packages/:id/publickey', async (req, res) => {
  const meta = await getPackage(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Package not found.' });
  res.type('application/x-pem-file');
  res.attachment('public.pem');
  res.send(meta.publicKey);
});

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

app.get('/v/:id', async (req, res) => {
  const meta = await getPackage(req.params.id);
  if (!meta) return res.status(404).send('<!doctype html><meta charset="utf-8"><title>Verify</title><p style="font-family:sans-serif;text-align:center;margin-top:80px">Package not found.</p>');
  const base = `${req.protocol}://${req.get('host')}`;
  const dl = `${base}/api/packages/${meta.id}/download`;
  const sig = `${base}/api/packages/${meta.id}/signature`;
  const pub = `${base}/api/packages/${meta.id}/publickey`;
  const kb = (meta.size / 1024).toFixed(1);
  const nav = `<header class="nav"><div class="nav-inner">
    <a class="brand" href="/"><span class="brand-mark"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg></span>Verify</a>
    <span class="nav-tag">Secure package signing</span>
  </div></header>`;
  res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verify — ${esc(meta.originalName)}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/style.css"></head>
<body>${nav}
<main class="wrap narrow">
<div class="hero">
  <h1 class="headline">Verify this package</h1>
  <p class="tag">Check the signature, or download the file, signature, and public key.</p>
</div>
<section class="card">
  <h2>Package details</h2>
  <table class="meta">
    <tr><td>File</td><td><b>${esc(meta.originalName)}</b></td></tr>
    <tr><td>Signed by</td><td>${esc(meta.signedBy)}</td></tr>
    <tr><td>Signed at</td><td>${esc(new Date(meta.createdAt).toUTCString())}</td></tr>
    <tr><td>Size</td><td>${kb} KB</td></tr>
    <tr><td>Algorithm</td><td>${esc(meta.algorithm)}</td></tr>
    <tr><td>SHA-256</td><td><code class="hash">${esc(meta.sha256)}</code> <button class="btn tiny copy" data-copy="${esc(meta.sha256)}">Copy</button></td></tr>
  </table>
  <div class="dl-links">
    <a class="btn primary" href="${dl}">Download package</a>
    <a class="btn" href="${sig}">Signature (.sig)</a>
    <a class="btn" href="${pub}">Public key (.pem)</a>
  </div>
</section>
<section class="card">
  <h2>Verify from the command line</h2>
  <pre class="cli">curl -OJ '${dl}'
curl -o pkg.sig '${sig}'
curl -o public.pem '${pub}'

# check integrity
shasum -a 256 ${esc(sanitizeFilename(meta.originalName))}

# check signature (OpenSSL 1.1.1+)
openssl pkeyutl -verify -pubin -inkey public.pem \\
  -rawin -in ${esc(sanitizeFilename(meta.originalName))} -sigfile pkg.sig</pre>
  <p class="hint" style="margin-top:14px">If signature verification prints "Signature Verified Successfully", the file is exactly what <b>${esc(meta.signedBy)}</b> signed.</p>
</section>
<p class="footer">Verify &middot; ed25519 signatures &middot; recipients can confirm every file they receive</p>
</main>
<script>
document.querySelectorAll('button.copy').forEach(function (b) {
  b.onclick = function () {
    navigator.clipboard.writeText(b.dataset.copy).then(function () {
      b.textContent = 'Copied';
      setTimeout(function () { b.textContent = 'Copy'; }, 1200);
    });
  };
});
</script>
</body></html>`);
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err?.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: `File too large. Maximum is ${MAX_UPLOAD_MB} MB.` });
  }
  if (err?.name === 'MulterError' || err?.type === 'entity.too.large') {
    return res.status(400).json({ error: err.message });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`Verify running at http://localhost:${PORT}`);
  console.log(`  OTP delivery: ${process.env.SMTP_URL ? 'SMTP' : 'console (set SMTP_URL in .env to send real email)'}`);
  if (DEV_MODE) console.log('  DEV_MODE=1: OTP codes are also returned in API responses.');
});
