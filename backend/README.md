# SecureChat Backend

## Quick Start (Local Dev)

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # Edit with your SMTP credentials
uvicorn main:app --reload --port 8000
```

Visit: http://localhost:8000/api/docs

## Render Deployment

```bash
# Build command
pip install -r backend/requirements.txt

# Start command
uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

Set these environment variables in Render:

```env
PYTHON_VERSION=3.12.11
DATABASE_URL=sqlite:///./securechat.db
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_gmail_app_password
```

## Security Notes

- Server stores ONLY: emails, public keys (JWK), ciphertext, IVs, OTP codes
- Private keys NEVER leave the browser
- AES-GCM provides confidentiality + integrity (auth tag)
- Key distribution is the MITM attack surface (document in vulnerability analysis)
