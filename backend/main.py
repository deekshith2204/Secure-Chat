

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


