const $ = (s) => document.querySelector(s);

let email = null;

const emailInput = $('#email');
const sendBtn = $('#sendBtn');
const emailStatus = $('#emailStatus');
const otpInput = $('#otp');
const verifyBtn = $('#verifyBtn');
const otpStatus = $('#otpStatus');

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

async function sendCode() {
  const value = emailInput.value.trim().toLowerCase();
  if (!value) return showStatus(emailStatus, 'Enter your email first.', false);
  sendBtn.disabled = true;
  emailStatus.hidden = true;
  try {
    const data = await postJson('/api/auth/request-otp', { email: value });
    email = value;
    $('#otpEmail').textContent = value;
    showStatus(emailStatus, data.devOtp ? `${data.message} Dev code: ${data.devOtp}` : data.message, true);
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
    otpStatus.className = 'status ok';
    otpStatus.textContent = 'Email verified \u2014 you\u2019re all set\u2026';
    otpStatus.hidden = false;
    window.location.href = data.successUrl || '/done';
  } catch (err) {
    showStatus(otpStatus, err.message, false);
    verifyBtn.disabled = false;
  }
}

sendBtn.addEventListener('click', sendCode);
emailInput.addEventListener('keydown', (e) => e.key === 'Enter' && sendCode());
verifyBtn.addEventListener('click', verifyCode);
otpInput.addEventListener('keydown', (e) => e.key === 'Enter' && verifyCode());
