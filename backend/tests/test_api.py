"""
SecureChat API Tests
Run with: pytest tests/ -v
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import app, Base, get_db, OTPCode

# ─── In-memory SQLite for tests ───
TEST_DB_URL = "sqlite://"
engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

# ─── Tests ───

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["e2e_encrypted"] is True

def test_request_otp(monkeypatch):
    """OTP request should succeed for any email in dev mode."""
    monkeypatch.setenv("SMTP_HOST", "")
    res = client.post("/api/auth/request-otp", json={"email": "test@example.com"})
    assert res.status_code == 200
    assert "OTP sent" in res.json()["message"]

def test_verify_invalid_otp():
    """Invalid OTP must be rejected."""
    res = client.post("/api/auth/verify-otp", json={"email": "test@example.com", "code": "000000"})
    assert res.status_code == 400

def test_lookup_unknown_user():
    """Looking up unregistered user should return 404."""
    res = client.get("/api/users/nobody%40example.com/public-key")
    assert res.status_code == 404

def test_register_and_lookup():
    """Register a user then fetch their public key."""
    from datetime import datetime, timedelta
    db = TestingSessionLocal()
    otp = OTPCode(email="alice@example.com", code="123456",
                  expires_at=datetime.utcnow() + timedelta(minutes=5))
    db.add(otp)
    db.commit()
    db.close()

    verify_res = client.post("/api/auth/verify-otp",
                             json={"email": "alice@example.com", "code": "123456"})
    assert verify_res.status_code == 200

    reg_res = client.post("/api/auth/register",
                          json={"email": "alice@example.com", "public_key": '{"kty":"RSA"}'})
    assert reg_res.status_code == 200

    lookup_res = client.get("/api/users/alice%40example.com/public-key")
    assert lookup_res.status_code == 200
    assert lookup_res.json()["email"] == "alice@example.com"

def test_register_requires_verified_otp():
    """A public key cannot be registered before OTP verification."""
    res = client.post("/api/auth/register",
                      json={"email": "mallory@example.com", "public_key": '{"kty":"EC"}'})
    assert res.status_code == 403
