# SecureChat

SecureChat is a web chat application built to demonstrate end-to-end encrypted messaging. The main idea is simple: the browser handles identity keys, encryption, and decryption, while the server only verifies users, stores public keys, and relays encrypted messages.

## Group Members

1. Thadvai Deekshith (20087999)
2. Kunal Khatwani (20079145)
3. Suraj Kumar Oad (20035415)
4. Sampath Reddy

## Objective

The objective of SecureChat is to protect message privacy even when the backend server stores and forwards messages. Plaintext messages and private keys never leave the user's browser. The backend can help with registration, OTP verification, public-key lookup, and encrypted message delivery, but it cannot decrypt user messages.

## Core Idea

SecureChat treats the backend as a relay, not as a trusted reader of messages.

The server stores:

- User email addresses
- User public keys
- OTP verification records
- Encrypted message ciphertext
- AES-GCM IV values
- Message metadata such as sender, recipient, and timestamp

The server does not store:

- Plaintext messages
- User private keys
- Decrypted message content

## Tech Stack

| Layer | Technology | Purpose |
| --- | --- | --- |
| Frontend | HTML, CSS, JavaScript | User interface for registration, OTP verification, and messaging |
| Browser Crypto | Web Crypto API | ECDH key generation, AES-GCM encryption, and AES-GCM decryption |
| Backend | Python, FastAPI | REST API for OTP, registration, public-key lookup, and message relay |
| Database | SQLite locally, PostgreSQL-ready through `DATABASE_URL` | Stores users, OTPs, and encrypted messages |
| ORM | SQLAlchemy | Defines database tables and queries |
| Email | Twilio SendGrid Mail Send API | Sends OTP codes during deployment |
| Testing | Pytest, FastAPI TestClient | Validates API behavior |
| Deployment | Render | Hosts the FastAPI backend and serves the frontend |

## Project Structure

```text
securechat/
|-- backend/
|   |-- main.py              # FastAPI app, database models, routes, OTP email, frontend serving
|   |-- requirements.txt     # Python dependencies
|   |-- Dockerfile           # Container setup for deployment
|   |-- .env.example         # Example environment variables
|   |-- README.md            # Backend-specific setup notes
|   `-- tests/
|       |-- __init__.py
|       `-- test_api.py      # API tests
|-- frontend/
|   |-- index.html           # Main browser UI
|   |-- styles.css           # Page styling
|   `-- app.js               # Client-side keys, encryption, decryption, and API calls
|-- docker-compose.yml
|-- run_local.sh
|-- .gitignore
`-- README.md
```

## Code Explanation

### Backend: `backend/main.py`

The backend is a FastAPI application. It defines the API routes, database models, OTP logic, SendGrid email delivery, and static frontend serving.

Important parts:

- `DATABASE_URL` is read from the environment. If it is not provided, the app uses local SQLite.
- SQLAlchemy models define the database tables:
  - `User` stores verified email addresses and public keys.
  - `OTPCode` stores one-time verification codes, expiry time, and used status.
  - `Message` stores encrypted messages only, including ciphertext, IV, sender email, recipient email, and sender public key.
- Pydantic request models validate API input. Email fields use `EmailStr`, so invalid email formats are rejected before an OTP is created.
- `generate_otp()` creates a 6-digit OTP using `secrets.choice`, which is better for security than normal pseudo-random generation.
- `send_otp_email()` sends OTP messages using Twilio SendGrid. It reads:

```env
SENDGRID_API_KEY
SENDGRID_FROM
```

If those variables are missing during local development, the OTP is printed in the terminal. On Render, missing email configuration returns an error instead of silently pretending the email was sent.

### Backend API Routes

| Route | Purpose |
| --- | --- |
| `POST /api/auth/request-otp` | Creates an OTP, invalidates old unused OTPs, and sends the new code by email |
| `POST /api/auth/verify-otp` | Checks the OTP, rejects invalid or expired codes, and marks valid codes as used |
| `POST /api/auth/register` | Registers or updates a user's public key only after a fresh OTP was verified |
| `GET /api/users/{email}/public-key` | Returns a verified user's public key so another browser can encrypt a message for them |
| `POST /api/messages/send` | Stores encrypted message data after checking sender and recipient are registered |
| `GET /api/messages/{email}` | Returns encrypted messages for the selected recipient |
| `GET /api/health` | Confirms the service is running and whether email is configured |

### Frontend: `frontend/app.js`

The frontend contains the main security logic. It is responsible for generating keys, storing the private key locally, encrypting outgoing messages, and decrypting incoming messages.

Important parts:

- `generateKeyPair()` creates an ECDH P-256 key pair using the Web Crypto API.
- The public key is exported as JWK and uploaded to the backend after OTP verification.
- The private key is stored in the browser and is never sent to the backend.
- `deriveAesKey()` uses the local private key and the other user's public key to derive an AES-GCM key.
- `encryptForRecipient()` encrypts the message in the sender's browser before it is sent to the backend.
- `decryptMessage()` decrypts messages in the receiver's browser using the receiver's private key and sender's public key.
- API calls connect the UI to the backend routes for OTP, registration, public-key lookup, sending messages, and fetching messages.

### Frontend Files

- `frontend/index.html` defines the registration form, OTP input, message form, and inbox area.
- `frontend/styles.css` styles the chat interface and status messages.
- `frontend/app.js` contains the actual application behavior and browser-side cryptography.

## Main Workflow

### 1. Register a User

1. The user enters an email address.
2. The user requests an OTP.
3. The backend creates a 6-digit OTP and sends it using SendGrid.
4. The browser generates an ECDH P-256 key pair.
5. The user enters the OTP.
6. The backend verifies the OTP.
7. The browser uploads only the public key.
8. The private key remains in the browser.
9. The app moves to the messaging screen.

### 2. Send a Message

1. The sender enters the recipient email.
2. The browser asks the backend for the recipient public key.
3. The browser derives an AES-GCM key using ECDH.
4. The message is encrypted locally.
5. The backend receives only ciphertext, IV, sender email, recipient email, and sender public key.
6. The backend stores the encrypted message.

### 3. Receive a Message

1. The receiver fetches messages from the backend.
2. The backend returns encrypted messages only.
3. The receiver's browser derives the AES-GCM key.
4. The browser decrypts the message locally.
5. Plaintext appears only inside the receiver's browser.

## Database Design

### `users`

```text
id, email, public_key, verified, created_at
```

Stores verified users and their public keys. Private keys are not stored.

### `otp_codes`

```text
id, email, code, expires_at, used
```

Stores short-lived OTP codes. Old unused OTPs are invalidated when a new code is requested.

### `messages`

```text
id, sender_email, recipient_email, ciphertext, iv, sender_public_key, delivered, created_at
```

Stores encrypted message payloads and metadata. It does not store plaintext.

## Environment Variables

Local development can run without real email by leaving SendGrid values blank. The OTP will print in the backend terminal.

```env
DATABASE_URL=sqlite:///./securechat.db
SENDGRID_API_KEY=
SENDGRID_FROM=dthadvai@gmail.com
```

For Render deployment, set:

```env
SENDGRID_API_KEY=your_sendgrid_api_key
SENDGRID_FROM=dthadvai@gmail.com
```

Remove old `RESEND_API_KEY`, `RESEND_FROM`, and SMTP variables if they are still present in Render.

## Run Locally

From the project root:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn main:app --reload --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/api/docs
```

## Deployment on Render

Render can run the FastAPI backend and serve the frontend from the same service.

Build command:

```text
pip install -r backend/requirements.txt
```

Start command:

```text
uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

Recommended Render variables:

```env
PYTHON_VERSION=3.12.11
DATABASE_URL=sqlite:///./securechat.db
SENDGRID_API_KEY=your_sendgrid_api_key
SENDGRID_FROM=dthadvai@gmail.com
```

SQLite is acceptable for a quick demo. PostgreSQL is recommended for production because local SQLite data on cloud services can be lost during restarts or redeploys.

## Testing

Run backend tests from the project root:

```powershell
.\backend\venv\Scripts\python.exe -m pytest backend\tests -v
```

The current backend test suite checks:

- Health endpoint response
- OTP request success in local dev mode
- Invalid email rejection
- OTP rollback when email sending fails
- Invalid OTP rejection
- Unknown user lookup rejection
- Register and public-key lookup flow
- Registration blocked until OTP is verified

## Security Features

- OTP verification is required before public-key registration.
- OTP codes expire and are marked as used after successful verification.
- Old unused OTPs are invalidated when a new OTP is requested.
- Private keys stay in the browser.
- Public keys are stored on the server only for lookup.
- Messages are encrypted before reaching the backend.
- AES-GCM provides confidentiality and tamper detection.
- ECDH P-256 is used for key agreement.
- The backend checks that both sender and recipient are registered.
- The backend stores ciphertext and IV values, not plaintext.

## Challenges Faced and How They Were Handled

| Challenge | What Happened | How It Was Handled |
| --- | --- | --- |
| Keeping messages private from the server | A normal chat backend would receive and store plaintext messages. | Encryption and decryption were moved into `frontend/app.js` using the Web Crypto API. The backend stores only ciphertext and IV values. |
| Managing user identity | The app needed a way to connect an email identity to a public key. | OTP verification was added before registration. After OTP verification, the browser uploads only the public key. |
| Preventing registration without verification | Earlier flow could allow public-key registration without strongly tying it to a fresh OTP. | Backend registration now checks for a recent verified OTP before saving the public key. |
| Handling invalid emails | Invalid email input could create unnecessary OTP records. | Backend request schemas use `EmailStr`, so invalid email formats are rejected before database records are created. |
| OTP reuse and stale codes | Multiple OTP requests could leave old valid codes active. | The backend deletes old unused OTPs before creating a new OTP and marks successful OTPs as used. |
| Email delivery on deployment | Raw SMTP and previous email-provider configuration caused deployment and delivery problems. | OTP delivery was changed to Twilio SendGrid's HTTPS Mail Send API using `SENDGRID_API_KEY` and `SENDGRID_FROM`. |
| Local development without paid/real email sending | Developers still need to test OTP flow locally even without SendGrid credentials. | If SendGrid variables are missing locally, the backend prints the OTP in the terminal. On Render, missing email configuration returns an error. |
| Sender spoofing | A user could try to send a message using another sender email. | The backend now checks that the sender email is registered before storing the message. |
| Public-key trust | The server is still the public-key directory and could theoretically return the wrong key. | This limitation is documented. A future improvement is safety-number or fingerprint comparison between users. |
| Cloud database persistence | SQLite is easy for demos but can lose data on cloud restarts. | SQLite is used for simple demos, while the code supports PostgreSQL through `DATABASE_URL` for more reliable deployment. |
| Testing after provider changes | Changing from Resend/SMTP to SendGrid could break OTP behavior. | Tests were updated to clear `SENDGRID_*` variables for dev mode, and the backend test suite was run successfully. |

## Known Limitations

| Limitation | Risk | Future Improvement |
| --- | --- | --- |
| Public-key substitution | A malicious or compromised server could return the wrong public key. | Add key fingerprints or safety numbers for out-of-band verification. |
| Browser storage loss | If the browser data is cleared, the private key is lost. | Add encrypted private-key backup protected by a user password. |
| Device change | A new browser creates a new private key and may not decrypt old messages. | Add controlled key recovery or key rotation. |
| OTP brute force | Attackers could try repeated OTP guesses. | Add rate limiting per email and IP address. |
| No advanced forward secrecy | Long-term key compromise could affect older messages. | Add session keys or a ratcheting protocol. |
| Open CORS in development | `allow_origins=["*"]` is too broad for production. | Restrict CORS to the deployed frontend domain. |
| XSS risk | Malicious script could access browser-side keys or messages. | Add a strict Content Security Policy and avoid unsafe HTML rendering. |

## Future Improvements

- Add public-key fingerprint display and safety-number verification.
- Add rate limiting for OTP request and verification endpoints.
- Add PostgreSQL for persistent production deployment.
- Add encrypted private-key backup and recovery.
- Add stronger session authentication after OTP verification.
- Add message read and delivered status.
- Add production CORS settings.
- Add Content Security Policy headers.

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

## Project Link

Microsoft 365 link: https://mydbs-my.sharepoint.com/:f:/g/personal/20079145_mydbs_ie/IgA137ak4S2wTZ7uLfJyN0XlAVIDe7SKLs29QnD5spCmaoM
