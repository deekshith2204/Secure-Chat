

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import string
import secrets
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# Database Setup (SQLite for local / PostgreSQL for Azure)
# ─────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./securechat.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ─────────────────────────────────────────────
# Database Models — server only stores public data
# ─────────────────────────────────────────────

class User(Base):
    """
    Identity record. Contains ONLY email + public key.
    Private key is NEVER stored here — held exclusively in browser IndexedDB.
    """
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    public_key = Column(Text, nullable=False)          # Exported JWK (JSON Web Key)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class OTPCode(Base):
    """
    Short-lived OTP for email verification.
    Security: 6-digit code, 10 min TTL, single-use flag.
    Brute-force mitigation: rate-limit endpoint to 5 attempts/email/hour.
    """
    __tablename__ = "otp_codes"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    code = Column(String(6), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)


class Message(Base):
    """
    Relay-store record. Contains ONLY ciphertext and IV.
    Server cannot decrypt — has no access to private keys.
    Confidentiality guaranteed by AES-GCM; integrity guaranteed by GCM auth tag.
    """
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_email = Column(String(255), nullable=False)
    recipient_email = Column(String(255), nullable=False, index=True)
    ciphertext = Column(Text, nullable=False)          # Base64-encoded AES-GCM output
    iv = Column(String(64), nullable=False)            # Base64-encoded 12-byte IV
    sender_public_key = Column(Text, nullable=True)    # For recipient to verify sender
    delivered = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


# ─────────────────────────────────────────────
# FastAPI App + CORS
# ─────────────────────────────────────────────
app = FastAPI(
    title="SecureChat API",
    description="End-to-End Encrypted Chat — Server never sees plaintext.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],    # Restrict to your Azure domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Dependency: DB Session
# ─────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ─────────────────────────────────────────────
# Pydantic Schemas
# ─────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    public_key: str          # JWK JSON string from Web Crypto API

class OTPRequest(BaseModel):
    email: str

class OTPVerifyRequest(BaseModel):
    email: str
    code: str

class SendMessageRequest(BaseModel):
    sender_email: str
    recipient_email: str
    ciphertext: str          # Base64 AES-GCM ciphertext
    iv: str                  # Base64 12-byte IV
    sender_public_key: str   # Sender's public key (for recipient to verify)

class PublicKeyResponse(BaseModel):
    email: str
    public_key: str


# ─────────────────────────────────────────────
# OTP Helper
# ─────────────────────────────────────────────

def generate_otp() -> str:
    """Generate a 6-digit OTP using OS-backed randomness."""
    return ''.join(secrets.choice(string.digits) for _ in range(6))


def has_recent_verified_otp(email: str, db: Session) -> bool:
    """Registration is allowed only after a fresh, successfully used OTP."""
    return db.query(OTPCode).filter(
        OTPCode.email == email,
        OTPCode.used == True,
        OTPCode.expires_at >= datetime.utcnow()
    ).first() is not None


def send_otp_email(email: str, code: str):
    """
    Send OTP via SMTP. Configure SMTP_* env vars.
    Fallback: prints to console (dev mode).
    """
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")

    subject = "SecureChat — Your verification code"
    body = f"""
Your SecureChat OTP verification code is:

  {code}

This code expires in 10 minutes. Do not share it with anyone.

If you did not request this, ignore this email.
— SecureChat Security Team
    """

    if not smtp_host:
        # Dev mode: print to terminal
        print(f"\n[DEV MODE] OTP for {email}: {code}\n")
        return

    try:
        msg = MIMEMultipart()
        msg["From"] = smtp_user
        msg["To"] = email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, email, msg.as_string())
    except Exception as e:
        print(f"[EMAIL ERROR] Failed to send OTP to {email}: {e}")
        raise HTTPException(status_code=500, detail="Failed to send OTP email.")


# ─────────────────────────────────────────────
# API Routes
# ─────────────────────────────────────────────

@app.post("/api/auth/request-otp", summary="Step 1: Request OTP for email verification")
def request_otp(req: OTPRequest, db: Session = Depends(get_db)):
    """
    Sends a 6-digit OTP to the provided email.
    Rate limiting should be applied at the reverse proxy / Azure API Gateway level.
    Security note: identical response for known/unknown emails (prevents enumeration).
    """
    code = generate_otp()
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    # Invalidate previous unused OTPs for this email
    db.query(OTPCode).filter(
        OTPCode.email == req.email,
        OTPCode.used == False
    ).delete()

    otp = OTPCode(email=req.email, code=code, expires_at=expires_at)
    db.add(otp)
    db.commit()

    send_otp_email(req.email, code)
    return {"message": "OTP sent. Check your email."}


@app.post("/api/auth/verify-otp", summary="Step 2: Verify OTP code")
def verify_otp(req: OTPVerifyRequest, db: Session = Depends(get_db)):
    """
    Validates OTP. Returns a session token placeholder.
    In production, issue a signed JWT here instead.
    """
    if not req.code.isdigit() or len(req.code) != 6:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    otp = db.query(OTPCode).filter(
        OTPCode.email == req.email,
        OTPCode.code == req.code,
        OTPCode.used == False
    ).first()

    if not otp:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")

    if otp.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="OTP has expired. Request a new one.")

    otp.used = True
    db.commit()
    return {"verified": True, "email": req.email}


@app.post("/api/auth/register", summary="Step 3: Register email + upload public key")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Associates a verified email with its browser-generated public key.
    SECURITY: Only public key is stored. Private key stays in browser IndexedDB.
    Vulnerability note: this endpoint is the key distribution point — a compromised
    server could swap public keys (MITM). Mitigation: key fingerprint verification
    (Signal-style 'safety numbers') out-of-band.
    """
    if not has_recent_verified_otp(req.email, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verify a fresh OTP before registering a public key."
        )

    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        # Update public key (key rotation)
        existing.public_key = req.public_key
        existing.verified = True
        db.commit()
        return {"message": "Public key updated.", "email": req.email}

    user = User(email=req.email, public_key=req.public_key, verified=True)
    db.add(user)
    db.commit()
    return {"message": "Registration complete.", "email": req.email}


@app.get("/api/users/{email}/public-key", response_model=PublicKeyResponse,
         summary="Lookup a user's public key by email")
def get_public_key(email: str, db: Session = Depends(get_db)):
    """
    Returns the registered public key for an email address.
    Used by sender to encrypt a message before sending.
    VULNERABILITY NOTE: This is the MITM attack surface — a malicious server
    could return a different public key. Mitigated by key fingerprint verification.
    """
    user = db.query(User).filter(User.email == email, User.verified == True).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found or not verified.")
    return {"email": user.email, "public_key": user.public_key}


@app.post("/api/messages/send", summary="Send an encrypted message (relay only)")
def send_message(req: SendMessageRequest, db: Session = Depends(get_db)):
    """
    Stores ciphertext + IV. Server cannot decrypt — it has no private keys.
    Ciphertext encrypted in the browser before this call.
    AES-GCM provides: confidentiality + integrity (auth tag detects tampering).
    """
    sender = db.query(User).filter(
        User.email == req.sender_email,
        User.verified == True
    ).first()
    if not sender:
        raise HTTPException(status_code=403, detail="Sender is not registered.")

    recipient = db.query(User).filter(
        User.email == req.recipient_email,
        User.verified == True
    ).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found.")

    msg = Message(
        sender_email=req.sender_email,
        recipient_email=req.recipient_email,
        ciphertext=req.ciphertext,
        iv=req.iv,
        sender_public_key=req.sender_public_key
    )
    db.add(msg)
    db.commit()
    return {"message": "Message stored (encrypted relay).", "id": msg.id}


@app.get("/api/messages/{email}", summary="Fetch encrypted messages for a user")
def get_messages(email: str, db: Session = Depends(get_db)):
    """
    Returns ciphertext messages for this recipient.
    Client-side JavaScript decrypts using private key from IndexedDB.
    Server never performs decryption.
    """
    messages = db.query(Message).filter(
        Message.recipient_email == email
    ).order_by(Message.created_at.asc()).all()

    return [
        {
            "id": m.id,
            "sender": m.sender_email,
            "ciphertext": m.ciphertext,
            "iv": m.iv,
            "sender_public_key": m.sender_public_key,
            "timestamp": m.created_at.isoformat()
        }
        for m in messages
    ]


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SecureChat API", "e2e_encrypted": True}


# ─────────────────────────────────────────────
# Serve Frontend (optional — for combined deployment)
# ─────────────────────────────────────────────
if os.path.exists("../frontend"):
    app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")
