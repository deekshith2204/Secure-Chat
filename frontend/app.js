const API_BASE = 'http://localhost:8000';

const state = {
  email: '',
  keyPair: null,
  publicJwk: null,
  privateJwk: null,
};

const el = {
  email: document.getElementById('email'),
  otp: document.getElementById('otp'),
  senderEmail: document.getElementById('sender-email'),
  recipientEmail: document.getElementById('recipient-email'),
  messageText: document.getElementById('message-text'),
  messages: document.getElementById('messages'),
  statusBadge: document.getElementById('status-badge'),
  requestOtp: document.getElementById('request-otp'),
  generateKeys: document.getElementById('generate-keys'),
  verifyRegister: document.getElementById('verify-register'),
  sendMessage: document.getElementById('send-message'),
  refreshMessages: document.getElementById('refresh-messages'),
  clearConsole: document.getElementById('clear-console'),
  themeToggle: document.querySelector('[data-theme-toggle]')
};

function setStatus(text, type = 'idle') {
  el.statusBadge.textContent = text;
  const colors = {
    idle: 'rgba(1,105,111,.12)',
    success: 'rgba(67,122,34,.15)',
    error: 'rgba(161,44,123,.15)',
    warn: 'rgba(150,66,25,.15)'
  };
  el.statusBadge.style.background = colors[type] || colors.idle;
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function generateKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );

  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

  state.keyPair = keyPair;
  state.publicJwk = publicJwk;
  state.privateJwk = privateJwk;

  localStorage.setItem('securechat_public_jwk', JSON.stringify(publicJwk));
  localStorage.setItem('securechat_private_jwk', JSON.stringify(privateJwk));
  setStatus('Keys generated', 'success');
}

async function loadKeysFromStorage() {
  const pub = localStorage.getItem('securechat_public_jwk');
  const priv = localStorage.getItem('securechat_private_jwk');
  if (!pub || !priv) return;

  state.publicJwk = JSON.parse(pub);
  state.privateJwk = JSON.parse(priv);
  state.keyPair = {
    publicKey: await crypto.subtle.importKey('jwk', state.publicJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']),
    privateKey: await crypto.subtle.importKey('jwk', state.privateJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt'])
  };
}

async function api(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.message || 'Request failed');
  return data;
}

async function requestOtp() {
  const email = el.email.value.trim();
  if (!email) return alert('Enter email');
  await api('/api/auth/request-otp', {
    method: 'POST',
    body: JSON.stringify({ email })
  });
  setStatus('OTP sent', 'success');
}

async function verifyAndRegister() {
  const email = el.email.value.trim();
  const code = el.otp.value.trim();
  if (!email || !code) return alert('Enter email and OTP');
  if (!state.publicJwk) return alert('Generate keys first');

  await api('/api/auth/verify-otp', {
    method: 'POST',
    body: JSON.stringify({ email, code })
  });

  await api('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, public_key: JSON.stringify(state.publicJwk) })
  });

  state.email = email;
  el.senderEmail.value = email;
  localStorage.setItem('securechat_email', email);
  setStatus('Registered', 'success');
}

async function encryptForRecipient(plaintext, recipientPublicKeyJson) {
  const recipientPublicKey = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(recipientPublicKeyJson),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );

  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPublicKey, encoded);
  return arrayBufferToBase64(ciphertext);
}

async function decryptMessage(ciphertextBase64) {
  if (!state.keyPair?.privateKey) throw new Error('Private key unavailable');
  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    state.keyPair.privateKey,
    base64ToArrayBuffer(ciphertextBase64)
  );
  return new TextDecoder().decode(plaintextBuffer);
}

async function sendMessage() {
  const sender = el.senderEmail.value.trim();
  const recipient = el.recipientEmail.value.trim();
  const message = el.messageText.value.trim();
  if (!sender || !recipient || !message) return alert('Complete sender, recipient, message');

  const keyLookup = await api(`/api/users/${encodeURIComponent(recipient)}/public-key`);
  const ciphertext = await encryptForRecipient(message, keyLookup.public_key);

  await api('/api/messages/send', {
    method: 'POST',
    body: JSON.stringify({
      sender_email: sender,
      recipient_email: recipient,
      ciphertext,
      iv: 'rsa-oaep-no-iv',
      sender_public_key: JSON.stringify(state.publicJwk)
    })
  });

  el.messageText.value = '';
  setStatus('Encrypted message sent', 'success');
}

function renderMessageCard(msg, plaintext) {
  const card = document.createElement('article');
  card.className = 'message-card';
  card.innerHTML = `
    <div class="meta">
      <span>From: ${msg.sender}</span>
      <span>${new Date(msg.timestamp).toLocaleString()}</span>
    </div>
    <div class="plaintext"></div>
    <div class="cipher">Ciphertext: ${msg.ciphertext.slice(0, 120)}...</div>
  `;
  card.querySelector('.plaintext').textContent = plaintext;
  return card;
}

async function fetchMessages() {
  const email = el.senderEmail.value.trim();
  if (!email) return alert('Register first');
  const messages = await api(`/api/messages/${encodeURIComponent(email)}`);
  el.messages.innerHTML = '';

  if (!messages.length) {
    el.messages.innerHTML = '<div class="message-card"><div class="plaintext">No messages yet.</div></div>';
    setStatus('Inbox empty', 'warn');
    return;
  }

  for (const msg of messages) {
    try {
      const plaintext = await decryptMessage(msg.ciphertext);
      el.messages.appendChild(renderMessageCard(msg, plaintext));
    } catch {
      el.messages.appendChild(renderMessageCard(msg, '[Decryption failed — wrong private key or tampered data]'));
    }
  }
  setStatus('Messages decrypted locally', 'success');
}

function clearOutput() {
  el.messages.innerHTML = '';
  setStatus('Idle', 'idle');
}

function initTheme() {
  let theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', theme);
  el.themeToggle.textContent = theme === 'dark' ? '☀' : '☾';
  el.themeToggle.addEventListener('click', () => {
    theme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    el.themeToggle.textContent = theme === 'dark' ? '☀' : '☾';
  });
}

async function bootstrap() {
  initTheme();
  await loadKeysFromStorage();
  const savedEmail = localStorage.getItem('securechat_email');
  if (savedEmail) {
    state.email = savedEmail;
    el.email.value = savedEmail;
    el.senderEmail.value = savedEmail;
  }

  el.requestOtp.addEventListener('click', () => requestOtp().catch(err => { alert(err.message); setStatus('OTP failed', 'error'); }));
  el.generateKeys.addEventListener('click', () => generateKeyPair().catch(err => { alert(err.message); setStatus('Keygen failed', 'error'); }));
  el.verifyRegister.addEventListener('click', () => verifyAndRegister().catch(err => { alert(err.message); setStatus('Registration failed', 'error'); }));
  el.sendMessage.addEventListener('click', () => sendMessage().catch(err => { alert(err.message); setStatus('Send failed', 'error'); }));
  el.refreshMessages.addEventListener('click', () => fetchMessages().catch(err => { alert(err.message); setStatus('Fetch failed', 'error'); }));
  el.clearConsole.addEventListener('click', clearOutput);
}

bootstrap();
