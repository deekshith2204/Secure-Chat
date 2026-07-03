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

## Azure Deployment

```bash
# 1. Create Azure App Service (Python 3.11)
az webapp create --name securechat-api --resource-group securechat-rg \
  --plan securechat-plan --runtime "PYTHON:3.11"

# 2. Set environment variables
az webapp config appsettings set --name securechat-api \
  --resource-group securechat-rg \
  --settings DATABASE_URL="postgresql://..." SMTP_HOST="..." ...

# 3. Deploy via GitHub Actions (see .github/workflows/)
git push origin main
```

## Security Notes

- Server stores ONLY: emails, public keys (JWK), ciphertext, IVs, OTP codes
- Private keys NEVER leave the browser
- AES-GCM provides confidentiality + integrity (auth tag)
- Key distribution is the MITM attack surface (document in vulnerability analysis)
