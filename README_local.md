# SecureChat — End-to-End Encrypted Web Chat

MSc CA Project | Information Systems with Computing

A web chat application where every message is encrypted in the browser before it ever touches the server. The server acts as a "dumb relay" — it stores and forwards ciphertext only and never sees plaintext or private keys.

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, Vanilla JS, Web Crypto API |
| Backend | Python 3.11, FastAPI, SQLAlchemy |
| Database | SQLite (local) / PostgreSQL (Azure) |
| OTP Email | SMTP / Gmail App Password / Mailtrap |
| Hosting | Azure App Service + Azure Static Web Apps |
| CI/CD | GitHub Actions |
| Containers | Docker + Docker Compose |

## Project Structure

```text
securechat/
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Lint + tests on push/PR
│       └── deploy-azure.yml        # Auto-deploy to Azure on main push
├── backend/
│   ├── main.py                     # FastAPI app (all routes + models)
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── .env.example
│   └── tests/
│       └── test_api.py             # Pytest test suite
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── docker-compose.yml
├── .gitignore
└── README.md
```

## Run Locally (without Docker)

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8000
```

```bash
# Frontend (separate terminal)
cd frontend
python -m http.server 5500
# Open http://localhost:5500
```

API docs: http://localhost:8000/api/docs

## Run Locally (with Docker)

```bash
docker-compose up --build
# Backend: http://localhost:8000
# Frontend: http://localhost:5500
```

## Push to GitHub

```bash
git init
git add .
git commit -m "initial: SecureChat E2E encrypted chat"
git branch -M main
git remote add origin https://github.com/<your-username>/securechat.git
git push -u origin main
```

## Deploy to Azure (GitHub Actions)

1. Create Azure resources:
```bash
# Backend — Azure App Service
az group create --name securechat-rg --location uksouth
az appservice plan create --name securechat-plan --resource-group securechat-rg --sku B1 --is-linux
az webapp create --name securechat-api --resource-group securechat-rg \
  --plan securechat-plan --runtime "PYTHON:3.11"

# Frontend — Azure Static Web Apps (via Azure Portal or CLI)
az staticwebapp create --name securechat-frontend \
  --resource-group securechat-rg --location uksouth
```

2. Add GitHub repository secrets:

| Secret | Value |
|---|---|
| `AZURE_WEBAPP_NAME` | Your App Service name |
| `AZURE_WEBAPP_PUBLISH_PROFILE` | Download from Azure Portal > App Service > Get publish profile |
| `AZURE_STATIC_WEB_APPS_API_TOKEN` | From Azure Portal > Static Web App > Manage deployment token |

3. Push to `main` — GitHub Actions will deploy automatically.

## Run Tests

```bash
cd backend
pip install pytest httpx
pytest tests/ -v
```

## Security Model

- Server stores ONLY: emails, public keys (JWK), ciphertext, IV, OTP codes
- Private keys NEVER leave the browser
- AES-GCM / RSA-OAEP encryption done client-side via Web Crypto API
- Confidentiality: server cannot decrypt any message
- Integrity: authenticated encryption detects tampering
- Authentication: email OTP proves inbox ownership
- Transport: HTTPS/TLS (Azure-provided certificate)

## Known Limitations (for Vulnerability Analysis)

1. Public key directory MITM — server could swap a public key; mitigate with key fingerprints
2. OTP brute-force — add rate limiting (5 attempts/email/hour) at Azure API Gateway
3. No forward secrecy in RSA-OAEP — upgrade to ECDH + AES-GCM for full forward secrecy
4. localStorage key storage — IndexedDB with non-extractable keys is stronger
