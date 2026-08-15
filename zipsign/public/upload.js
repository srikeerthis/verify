const $ = (s) => document.querySelector(s);

const token = window.location.pathname.split('/').pop();
let file = null;

const dropzone = $('#dropzone');
const fileInput = $('#fileInput');
const fileInfo = $('#fileInfo');
const signBtn = $('#signBtn');
const signStatus = $('#signStatus');
const progress = $('#progress');
const progressBar = $('#progressBar');

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function showStatus(el, msg, ok) {
  el.textContent = msg;
  el.hidden = false;
  el.className = `status ${ok ? 'ok' : 'err'}`;
}

(async function loadIdentity() {
  try {
    const res = await fetch('/api/me', { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) throw new Error();
    const me = await res.json();
    $('#who').textContent = me.email;
    $('#fp').textContent = me.keyFingerprint.match(/.{1,8}/g).join(' ');
  } catch {
    window.location.href = '/';
  }
})();

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
