const API_BASE = window.location.protocol === 'file:' ? 'http://localhost:8000' : '';

const state = {
  email: '',
  keyPair: null,
  publicJwk: null,
  sessionToken: '',
};

const KEY_DB_NAME = 'securechat-keys';
const KEY_DB_STORE = 'identity';
const TRUSTED_KEYS_STORAGE = 'securechat_trusted_public_keys';

const el = {
  authView: document.getElementById('auth-view'),
  chatView: document.getElementById('chat-view'),
  email: document.getElementById('email'),
  otp: document.getElementById('otp'),
  senderEmail: document.getElementById('sender-email'),
  ownFingerprint: document.getElementById('own-fingerprint'),
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
  updateOwnFingerprint();
  if (!el.messages.children.length) {
    el.messages.innerHTML = '<div class="message-card"><div class="plaintext">No messages loaded yet.</div></div>';
  }
}

async function updateOwnFingerprint() {
  if (!el.ownFingerprint || !state.publicJwk) return;
  el.ownFingerprint.textContent = await publicKeyFingerprint(state.publicJwk);
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

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEY_DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(KEY_DB_STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function storePrivateKey(privateKey) {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_DB_STORE, 'readwrite');
    tx.objectStore(KEY_DB_STORE).put(privateKey, 'privateKey');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function loadPrivateKey() {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_DB_STORE, 'readonly');
    const request = tx.objectStore(KEY_DB_STORE).get('privateKey');
    request.onsuccess = () => resolve(request.result || null);
    request.onerror = () => reject(request.error);
  });
}

async function clearPrivateKey() {
  const db = await openKeyDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_DB_STORE, 'readwrite');
    tx.objectStore(KEY_DB_STORE).delete('privateKey');
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function publicKeyFingerprint(publicKeyJson) {
  const jwk = typeof publicKeyJson === 'string' ? JSON.parse(publicKeyJson) : publicKeyJson;
  const encoded = new TextEncoder().encode(stableStringify(jwk));
  const hash = await crypto.subtle.digest('SHA-256', encoded);
  const hex = [...new Uint8Array(hash)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{1,4}/g).join(' ');
}

function getTrustedKeys() {
  return JSON.parse(localStorage.getItem(TRUSTED_KEYS_STORAGE) || '{}');
}

function saveTrustedKeys(trustedKeys) {
  localStorage.setItem(TRUSTED_KEYS_STORAGE, JSON.stringify(trustedKeys));
}

async function verifyTrustedPublicKey(email, publicKeyJson) {
  const fingerprint = await publicKeyFingerprint(publicKeyJson);
  const trustedKeys = getTrustedKeys();
  const previousFingerprint = trustedKeys[email];

  if (!previousFingerprint) {
    const trusted = confirm(
      `First secure contact with ${email}.\n\nPublic key fingerprint:\n${fingerprint}\n\nConfirm only if this matches the other user's fingerprint.`
    );
    if (!trusted) throw new Error('Public key was not trusted');
    trustedKeys[email] = fingerprint;
    saveTrustedKeys(trustedKeys);
    return fingerprint;
  }

  if (previousFingerprint !== fingerprint) {
    throw new Error(
      `Public key changed for ${email}. This could mean the user changed browser, re-registered, or a key-substitution attack is happening. Verify the fingerprint before chatting.`
    );
  }

  return fingerprint;
}

async function generateKeyPair() {
  const exportableKeyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256'
    },
    true,
    ['deriveKey']
  );

  const publicJwk = await crypto.subtle.exportKey('jwk', exportableKeyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey('jwk', exportableKeyPair.privateKey);
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    privateJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveKey']
  );
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );

  state.keyPair = { publicKey, privateKey };
  state.publicJwk = publicJwk;

  localStorage.setItem('securechat_public_jwk', JSON.stringify(publicJwk));
  localStorage.removeItem('securechat_private_jwk');
  await storePrivateKey(privateKey);
  await updateOwnFingerprint();
  setStatus('Keys generated', 'success');
}

async function loadKeysFromStorage() {
  const pub = localStorage.getItem('securechat_public_jwk');
  if (!pub) return;

  try {
    state.publicJwk = JSON.parse(pub);
    let privateKey = await loadPrivateKey();
    const legacyPrivateJwk = localStorage.getItem('securechat_private_jwk');

    if (!privateKey && legacyPrivateJwk) {
      privateKey = await crypto.subtle.importKey(
        'jwk',
        JSON.parse(legacyPrivateJwk),
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveKey']
      );
      await storePrivateKey(privateKey);
      localStorage.removeItem('securechat_private_jwk');
    }

    if (!privateKey) return;

    state.keyPair = {
      publicKey: await crypto.subtle.importKey('jwk', state.publicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []),
      privateKey
    };
  } catch {
    localStorage.removeItem('securechat_public_jwk');
    localStorage.removeItem('securechat_private_jwk');
    localStorage.removeItem('securechat_email');
    localStorage.removeItem('securechat_session_token');
    await clearPrivateKey().catch(() => {});
    state.publicJwk = null;
    state.keyPair = null;
    state.sessionToken = '';
    setStatus('Register again', 'warn');
  }
}

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (state.sessionToken) headers.Authorization = `Bearer ${state.sessionToken}`;

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers
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
  const verification = await api('/api/auth/verify-otp', {
    method: 'POST',
    body: JSON.stringify({ email, code })
  });
  state.sessionToken = verification.session_token;
  localStorage.setItem('securechat_session_token', verification.session_token);

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
  await verifyTrustedPublicKey(recipient, keyLookup.public_key);
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
      await verifyTrustedPublicKey(msg.sender, msg.sender_public_key);
      const plaintext = await decryptMessage(msg.ciphertext, msg.iv, msg.sender_public_key);
      el.messages.appendChild(renderMessageCard(msg, plaintext));
    } catch (err) {
      el.messages.appendChild(renderMessageCard(msg, `[Decryption blocked - ${err.message}]`));
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
  const savedToken = localStorage.getItem('securechat_session_token');
  if (savedToken) state.sessionToken = savedToken;
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
