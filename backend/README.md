# SecureChat Backend

## Quick Start (Local Dev)

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # Edit with your SendGrid credentials
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
SENDGRID_API_KEY=your_sendgrid_api_key
SENDGRID_FROM=dthadvai@gmail.com
```

Use Twilio SendGrid's HTTPS Mail Send API for deployed OTP email delivery.

## Security Notes

- Server stores ONLY: emails, public keys (JWK), ciphertext, IVs, OTP codes
- Private keys NEVER leave the browser
- AES-GCM provides confidentiality + integrity (auth tag)
- Key distribution is the MITM attack surface (document in vulnerability analysis)
