const API_BASE = window.location.protocol === 'file:' ? 'http://localhost:8000' : '';

const state = {
  email: '',
  keyPair: null,
  publicJwk: null,
  privateJwk: null,
};

const el = {
  authView: document.getElementById('auth-view'),
  chatView: document.getElementById('chat-view'),
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
  switchIdentity: document.getElementById('switch-identity'),
  themeToggle: document.querySelector('[data-theme-toggle]')
};

function setStatus(text, type = 'idle') {
  if (!el.statusBadge) return;
  el.statusBadge.textContent = text;
  const colors = {
    idle: 'rgba(1,105,111,.12)',
    success: 'rgba(67,122,34,.15)',
    error: 'rgba(161,44,123,.15)',
    warn: 'rgba(150,66,25,.15)'
  };
  el.statusBadge.style.background = colors[type] || colors.idle;
}

function showAuthView() {
  el.authView.classList.remove('is-hidden');
  el.chatView.classList.add('is-hidden');
  setStatus('Ready', 'idle');
}

function showChatView() {
  el.authView.classList.add('is-hidden');
  el.chatView.classList.remove('is-hidden');
  setStatus('Messaging ready', 'success');
  if (!el.messages.children.length) {
    el.messages.innerHTML = '<div class="message-card"><div class="plaintext">No messages loaded yet.</div></div>';
  }
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
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey']
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

  try {
    state.publicJwk = JSON.parse(pub);
    state.privateJwk = JSON.parse(priv);
    state.keyPair = {
      publicKey: await crypto.subtle.importKey('jwk', state.publicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []),
      privateKey: await crypto.subtle.importKey('jwk', state.privateJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey'])
    };
  } catch {
    localStorage.removeItem('securechat_public_jwk');
    localStorage.removeItem('securechat_private_jwk');
    localStorage.removeItem('securechat_email');
    state.publicJwk = null;
    state.privateJwk = null;
    state.keyPair = null;
    setStatus('Register again', 'warn');
  }
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
  setStatus('Sending OTP...', 'idle');
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
  if (!state.publicJwk) {
    setStatus('Generating keys...', 'idle');
    await generateKeyPair();
  }

  setStatus('Verifying identity...', 'idle');
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
  showChatView();
}

async function deriveAesKey(peerPublicKeyJson) {
  if (!state.keyPair?.privateKey) throw new Error('Private key unavailable');

  const peerPublicKey = await crypto.subtle.importKey(
    'jwk',
    typeof peerPublicKeyJson === 'string' ? JSON.parse(peerPublicKeyJson) : peerPublicKeyJson,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );

  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPublicKey },
    state.keyPair.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptForRecipient(plaintext, recipientPublicKeyJson) {
  const aesKey = await deriveAesKey(recipientPublicKeyJson);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, encoded);
  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv)
  };
}

async function decryptMessage(ciphertextBase64, ivBase64, senderPublicKeyJson) {
  const aesKey = await deriveAesKey(senderPublicKeyJson);
  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToArrayBuffer(ivBase64) },
    aesKey,
    base64ToArrayBuffer(ciphertextBase64)
  );
  return new TextDecoder().decode(plaintextBuffer);
}

async function sendMessage() {
  const sender = el.senderEmail.value.trim();
  const recipient = el.recipientEmail.value.trim();
  const message = el.messageText.value.trim();
  if (!sender || !recipient || !message) return alert('Complete sender, recipient, message');

  if (!state.publicJwk) return alert('Generate and register keys first');

  const keyLookup = await api(`/api/users/${encodeURIComponent(recipient)}/public-key`);
  const encrypted = await encryptForRecipient(message, keyLookup.public_key);

  await api('/api/messages/send', {
    method: 'POST',
    body: JSON.stringify({
      sender_email: sender,
      recipient_email: recipient,
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
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
      const plaintext = await decryptMessage(msg.ciphertext, msg.iv, msg.sender_public_key);
      el.messages.appendChild(renderMessageCard(msg, plaintext));
    } catch {
      el.messages.appendChild(renderMessageCard(msg, '[Decryption failed - wrong private key or tampered data]'));
    }
  }
  setStatus('Messages decrypted locally', 'success');
}

function clearOutput() {
  el.messages.innerHTML = '<div class="message-card"><div class="plaintext">No messages loaded yet.</div></div>';
  setStatus('Idle', 'idle');
}

function switchIdentity() {
  showAuthView();
  el.otp.value = '';
  el.email.focus();
}

function initTheme() {
  let theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', theme);
  el.themeToggle.textContent = theme === 'dark' ? 'Light' : 'Dark';
  el.themeToggle.addEventListener('click', () => {
    theme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', theme);
    el.themeToggle.textContent = theme === 'dark' ? 'Light' : 'Dark';
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
    if (state.keyPair) showChatView();
  }

  el.requestOtp.addEventListener('click', () => requestOtp().catch(err => { alert(err.message); setStatus('OTP failed', 'error'); }));
  el.generateKeys.addEventListener('click', () => generateKeyPair().catch(err => { alert(err.message); setStatus('Keygen failed', 'error'); }));
  el.verifyRegister.addEventListener('click', () => verifyAndRegister().catch(err => { alert(err.message); setStatus('Registration failed', 'error'); }));
  el.sendMessage.addEventListener('click', () => sendMessage().catch(err => { alert(err.message); setStatus('Send failed', 'error'); }));
  el.refreshMessages.addEventListener('click', () => fetchMessages().catch(err => { alert(err.message); setStatus('Fetch failed', 'error'); }));
  el.clearConsole.addEventListener('click', clearOutput);
  el.switchIdentity.addEventListener('click', switchIdentity);
}

bootstrap();
