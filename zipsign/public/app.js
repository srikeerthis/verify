const $ = (s) => document.querySelector(s);

let email = null;
let token = null;
let file = null;

const emailInput = $('#email');
const sendBtn = $('#sendBtn');
const emailStatus = $('#emailStatus');
const otpInput = $('#otp');
const verifyBtn = $('#verifyBtn');
const otpStatus = $('#otpStatus');
const dropzone = $('#dropzone');
const fileInput = $('#fileInput');
const fileInfo = $('#fileInfo');
const signBtn = $('#signBtn');
const signStatus = $('#signStatus');
const progress = $('#progress');
const progressBar = $('#progressBar');

// Landing directly on a /u/:token link means the email is already verified —
// hide the auth steps while the session is checked so nothing flickers.
if (window.location.pathname.startsWith('/u/')) $('#step1').hidden = true;

function showStatus(el, msg, ok) {
  el.textContent = msg;
  el.hidden = false;
  el.className = `status ${ok ? 'ok' : 'err'}`;
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// --- email confirmation ------------------------------------------------------

async function sendCode() {
  const value = emailInput.value.trim().toLowerCase();
  if (!value) return showStatus(emailStatus, 'Enter your email first.', false);
  sendBtn.disabled = true;
  emailStatus.hidden = true;
  try {
    const data = await postJson('/api/auth/request-otp', { email: value });
    email = value;
    $('#otpEmail').textContent = value;
    showStatus(emailStatus, data.message, true);
    if (data.devOtp) {
      // Test mode: no mail server, so the code goes on the screen. It also
      // fills the box, because retyping it on a phone is the slowest part of
      // every test run.
      otpInput.value = data.devOtp;
      showStatus(otpStatus, `Test mode — your code is ${data.devOtp}, already filled in.`, true);
    }
    $('#step2').hidden = false;
    otpInput.focus();
  } catch (err) {
    showStatus(emailStatus, err.message, false);
  } finally {
    sendBtn.disabled = false;
  }
}

async function verifyCode() {
  const otp = otpInput.value.trim();
  if (!/^\d{6}$/.test(otp)) return showStatus(otpStatus, 'Enter the 6-digit code.', false);
  verifyBtn.disabled = true;
  otpStatus.hidden = true;
  try {
    const data = await postJson('/api/auth/verify', { email, otp });
    enterVerified(data.token, data);
  } catch (err) {
    showStatus(otpStatus, err.message, false);
    verifyBtn.disabled = false;
  }
}

// Verified: swap the auth steps for the identity card and reveal the drop.
// Rewriting the URL to /u/:token makes refresh work without re-verification.
function enterVerified(t, { email: who, keyFingerprint }) {
  token = t;
  email = who;
  history.replaceState(null, '', `/u/${t}`);
  $('#step1').hidden = true;
  $('#step2').hidden = true;
  $('#identity').hidden = false;
  $('#step3').hidden = false;
  $('#step4').hidden = false;
  $('#who').textContent = who;
  $('#fp').textContent = keyFingerprint.match(/.{1,8}/g).join(' ');
  $('#companyPhone').focus();
}

(async function restoreSession() {
  const m = window.location.pathname.match(/^\/u\/([A-Za-z0-9_-]+)$/);
  if (!m) return;
  try {
    const res = await fetch('/api/me', { headers: { Authorization: `Bearer ${m[1]}` } });
    if (!res.ok) throw new Error();
    enterVerified(m[1], await res.json());
  } catch {
    window.location.replace('/');
  }
})();

// --- zip drop ----------------------------------------------------------------

function setFile(f) {
  if (!f) return;
  if (!/\.zip$/i.test(f.name)) {
    return showStatus(signStatus, 'Only .zip files are accepted.', false);
  }
  file = f;
  $('#fileName').textContent = f.name;
  $('#fileSize').textContent = fmtBytes(f.size);
  fileInfo.hidden = false;
  signBtn.disabled = false;
  signStatus.hidden = true;
}

function clearFile() {
  file = null;
  fileInput.value = '';
  fileInfo.hidden = true;
  signBtn.disabled = true;
}

// Same rule the pipeline enforces server-side: E.164, no spaces or dashes.
// Catching it here saves a round trip and explains itself better than a 422.
const E164 = /^\+[1-9]\d{7,14}$/;

function phones() {
  const company = $('#companyPhone').value.trim();
  const candidate = $('#candidatePhone').value.trim();
  for (const [label, value] of [['Your', company], ["The candidate's", candidate]]) {
    if (!E164.test(value)) {
      showStatus($('#phoneStatus'), `${label} number needs the country code, like +15551234567.`, false);
      return null;
    }
  }
  $('#phoneStatus').hidden = true;
  return { company, candidate };
}

function upload(f, to) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/packages');
    xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) progressBar.style.width = `${Math.round((e.loaded / e.total) * 100)}%`;
    };
    xhr.onload = () => {
      let body = {};
      try { body = JSON.parse(xhr.responseText); } catch {}
      if (xhr.status === 201) resolve(body);
      else if (xhr.status === 401) {
        window.location.href = '/';
        reject(new Error('Session expired.'));
      } else reject(new Error(body.error || `Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new Error('Network error during upload.'));
    const fd = new FormData();
    fd.append('file', f, f.name);
    // The server signs first, then hands these to the scan pipeline, which is
    // what actually texts the candidate.
    fd.append('company_phone', to.company);
    fd.append('candidate_phone', to.candidate);
    xhr.send(fd);
  });
}

async function signAndUpload() {
  if (!file) return;
  const to = phones();
  if (!to) return;
  signBtn.disabled = true;
  progress.hidden = false;
  progressBar.style.width = '0%';
  showStatus(signStatus, 'Uploading and signing\u2026', true);
  try {
    const pkg = await upload(file, to);
    progressBar.style.width = '100%';
    showStatus(signStatus, 'Signed and sent for scanning. We\u2019ll text you both\u2026', true);
    window.location.href = `/done/${pkg.id}`;
  } catch (err) {
    showStatus(signStatus, err.message, false);
    signBtn.disabled = false;
  } finally {
    setTimeout(() => (progress.hidden = true), 600);
  }
}

// --- wiring ------------------------------------------------------------------

sendBtn.addEventListener('click', sendCode);
emailInput.addEventListener('keydown', (e) => e.key === 'Enter' && sendCode());
verifyBtn.addEventListener('click', verifyCode);
otpInput.addEventListener('keydown', (e) => e.key === 'Enter' && verifyCode());

signBtn.addEventListener('click', signAndUpload);
$('#clearFile').addEventListener('click', clearFile);

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('keydown', (e) => (e.key === 'Enter' || e.key === ' ') && fileInput.click());
fileInput.addEventListener('change', () => setFile(fileInput.files[0]));
['dragenter', 'dragover'].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.add('drag');
  })
);
['dragleave', 'drop'].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag');
  })
);
dropzone.addEventListener('drop', (e) => setFile(e.dataTransfer.files[0]));
