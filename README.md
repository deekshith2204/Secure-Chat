# SecureChat

## Group Members

1. Thadvai Deekshith (20087999)
2. Kunal Khatwani (20079145)
3. Suraj Kumar Oad (20035415)
4. Sampath Reddy

## Objective

SecureChat is a secure web chat application designed to demonstrate end-to-end encrypted messaging. The main objective is to make sure the server can help users find each other, verify identities, and relay messages without ever seeing plaintext messages or private keys.

The application uses email-based OTP verification for identity and browser-based cryptography for message protection. Messages are encrypted before they leave the sender's browser and decrypted only inside the receiver's browser.

## Core Idea

The server is treated as a relay and storage layer, not as a trusted reader of messages. It stores:

- User email addresses
- User public keys
- OTP verification records
- Encrypted message ciphertext
- AES-GCM IV values
- Message metadata such as sender, receiver, and timestamp

The server does not store:

- Plaintext messages
- User private keys
- Decrypted message content

## Tech Stack

| Layer | Technology | Purpose |
| --- | --- | --- |
| Frontend | HTML, CSS, JavaScript | User interface for registration and messaging |
| Browser Crypto | Web Crypto API | Key generation, ECDH key agreement, AES-GCM encryption/decryption |
| Backend | Python, FastAPI | REST API for OTP, registration, public key lookup, and encrypted message relay |
| Database | SQLite locally, PostgreSQL-ready through `DATABASE_URL` | Stores users, OTPs, and encrypted messages |
| ORM | SQLAlchemy | Database models and queries |
| Email | SMTP with Gmail app password or console dev mode | Sends OTP codes for email verification |
| API Docs | FastAPI Swagger UI | Interactive backend documentation at `/api/docs` |
| Deployment Target | Render Web Service | Hosts the FastAPI backend and frontend together |

## Main Workflow

### 1. Start the Backend

From the backend folder:

```powershell
cd C:\Users\thadv\OneDrive\Desktop\securechat\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload
```

Open the application:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/api/docs
```

### 2. Register a User

1. User enters an email address.
2. User clicks **Request OTP**.
3. Backend creates a 6-digit OTP and sends it by SMTP, or prints it in the terminal during dev mode.
4. Browser generates a cryptographic key pair using the Web Crypto API.
5. User enters the OTP and clicks **Verify and continue**.
6. Backend verifies the OTP.
7. Browser uploads only the public key to the backend.
8. The private key remains in browser storage and is never sent to the server.
9. After successful registration, the UI moves to the messaging section.

### 3. Send a Message

1. Sender enters the recipient email address.
2. Browser asks the backend for the recipient's public key.
3. Sender's browser uses ECDH P-256 to derive a shared AES-GCM key.
4. Browser encrypts the message locally with AES-GCM.
5. Browser sends ciphertext, IV, sender email, recipient email, and sender public key to the backend.
6. Backend stores the encrypted message only.

### 4. Receive a Message

1. Receiver opens the messaging page.
2. Receiver clicks **Fetch messages**.
3. Backend returns encrypted messages for that receiver.
4. Receiver's browser derives the AES-GCM key using its private key and the sender's public key.
5. Receiver's browser decrypts the ciphertext locally.
6. Plaintext is displayed only in the browser.

## Database Design

### Users

Stores verified users and their public keys.

```text
users(id, email, public_key, verified, created_at)
```

### OTP Codes

Stores one-time verification codes.

```text
otp_codes(id, email, code, expires_at, used)
```

### Messages

Stores encrypted message payloads.

```text
messages(id, sender_email, recipient_email, ciphertext, iv, sender_public_key, delivered, created_at)
```

## Security Features

- Email OTP is required before public key registration.
- OTP codes expire and are marked as used after verification.
- Private keys stay in the browser.
- Public keys are stored on the server for recipient lookup.
- Messages are encrypted in the browser before reaching the backend.
- AES-GCM provides confidentiality and tamper detection.
- ECDH P-256 is used for browser-side key agreement.
- Backend validates that recipients are registered before storing messages.
- Backend validates that senders are registered before relaying messages.
- The server stores ciphertext and IV values, not plaintext.

## Vulnerabilities and Mitigations

| Vulnerability | Risk | Mitigation |
| --- | --- | --- |
| Public key substitution / MITM | A malicious server could return the attacker's public key instead of the real recipient key. | Add key fingerprint verification or safety numbers so users can compare public keys out of band. |
| Browser storage loss | If local storage is cleared, the private key is lost and old messages may not decrypt. | Add encrypted private-key backup protected by a user password, or warn users before clearing keys. |
| Device/browser change | A user registering from another browser creates a new private key. Old messages may not decrypt there. | Add account key recovery or controlled key rotation with clear user warnings. |
| OTP brute force | Attackers may try many OTP combinations. | Add rate limiting per email/IP, lockout after repeated failures, and short OTP expiry. |
| Email account compromise | If an attacker controls the user's email, they can pass OTP verification. | Encourage strong email security and 2FA; optionally add device trust or secondary verification. |
| No forward secrecy for stored messages | If a long-term private key is compromised, old messages may be decryptable. | Use session keys, ratcheting, or rotating message keys for stronger forward secrecy. |
| XSS in frontend | Malicious script could read browser keys or messages. | Use strict input handling, avoid unsafe HTML insertion, add Content Security Policy, and sanitize displayed content. |
| Open CORS in development | `allow_origins=["*"]` is convenient locally but too broad for production. | Restrict CORS to the deployed frontend domain in production. |
| SMTP credential exposure | If `.env` is committed, email credentials could leak. | Keep `.env` out of Git, use `.env.example`, and rotate app passwords if exposed. |

## How the Current Implementation Handles Gaps

- Registration cannot complete unless the OTP was verified.
- The app automatically moves from registration to messaging after successful registration.
- Returning users with saved keys open directly in the messaging section.
- Message encryption uses ECDH P-256 plus AES-GCM instead of sending plaintext or relying on server-side encryption.
- The backend acts as a ciphertext relay and does not decrypt messages.
- The README documents the main remaining trust issue: the server is still trusted as the public-key directory.

## Local Email Configuration

For local testing without email delivery, leave SMTP blank in `backend/.env`:

```env
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASS=
```

In this mode, OTP codes print in the backend terminal.

For Gmail delivery, use a Gmail app password:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_16_character_app_password
```

Do not use your normal Gmail password. Gmail requires an app password when SMTP login is used.

## Deployment

### Recommended Option: Render

Render is the simplest deployment option for this project because the FastAPI backend can also serve the frontend files. The project includes a `render.yaml` blueprint for this.

Before deploying:

1. Push this project to GitHub.
2. Make sure `.env` is not committed.
3. In Render, create a new **Blueprint** or **Web Service** from the GitHub repository.
4. Render will use:

```text
Build command: pip install -r backend/requirements.txt
Start command: uvicorn backend.main:app --host 0.0.0.0 --port $PORT
Python version: 3.12.11
```

Required Render environment variables:

```env
DATABASE_URL=sqlite:///./securechat.db
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_16_character_gmail_app_password
```

For a quick demo, SQLite is acceptable. For a more reliable deployment, use PostgreSQL and set `DATABASE_URL` to the PostgreSQL connection string provided by the hosting platform.

Important deployment note: SQLite on cloud platforms may be temporary. If the service restarts or redeploys, local SQLite data can be lost. PostgreSQL is recommended for production or final demonstration.

After deployment, Render gives a public URL similar to:

```text
https://securechat.onrender.com
```

Use that URL to open the app. The API docs will be available at:

```text
https://securechat.onrender.com/api/docs
```

### Vercel Option

Vercel is excellent for frontend-only apps and serverless functions, but this project is a better fit for Render because it uses a FastAPI backend, SMTP, and database state. Vercel can still work, but it would require adapting the backend into Vercel's Python serverless structure and using an external database.

### AWS Option

AWS is powerful but more complex. Good AWS options include:

- AWS Elastic Beanstalk for the FastAPI app
- AWS App Runner for containerized deployment
- Amazon RDS PostgreSQL for the database
- AWS SES for production email delivery

AWS is recommended only if the project needs a more advanced cloud architecture. For a student demo, Render is faster and easier.

## Demo Steps

1. Start the backend server.
2. Open `http://127.0.0.1:8000`.
3. Register user 1 with OTP.
4. Open a second browser profile or incognito window.
5. Register user 2 with OTP.
6. In user 1's browser, enter user 2's email and send a message.
7. In user 2's browser, click **Fetch messages**.
8. Confirm that the message decrypts only in the receiver's browser.

Use separate browser profiles for different users because each browser stores its own private key.

## Testing

Backend tests can be run from the project root:

```powershell
.\backend\venv\Scripts\python.exe -m pytest backend\tests -v
```

Frontend JavaScript syntax can be checked with:

```powershell
node --check frontend\app.js
```

## Future Improvements

- Add key fingerprint display and verification.
- Add message read/delivered status.
- Add rate limiting for OTP requests and OTP verification attempts.
- Add encrypted private-key backup and recovery.
- Add stronger session authentication after OTP verification.
- Add production CORS settings.
- Add Content Security Policy headers.
- Add PostgreSQL for persistent Render production storage.

## Project Link

Microsoft 365 link: https://mydbs-my.sharepoint.com/:f:/g/personal/20079145_mydbs_ie/IgA137ak4S2wTZ7uLfJyN0XlAVIDe7SKLs29QnD5spCmaoM
