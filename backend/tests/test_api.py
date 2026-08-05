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
import main

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


@pytest.fixture(autouse=True)
def clear_rate_limits():
    main.RATE_LIMIT_BUCKETS.clear()
    yield
    main.RATE_LIMIT_BUCKETS.clear()


def auth_headers(email: str):
    return {"Authorization": f"Bearer {main.create_session_token(email)}"}

# ─── Tests ───

def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["e2e_encrypted"] is True


def test_security_headers_are_set():
    res = client.get("/api/health")
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in res.headers["content-security-policy"]

def test_request_otp(monkeypatch):
    """OTP request should succeed for any email in dev mode."""
    monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
    monkeypatch.delenv("SENDGRID_FROM", raising=False)
    res = client.post("/api/auth/request-otp", json={"email": "test@example.com"})
    assert res.status_code == 200
    assert "OTP sent" in res.json()["message"]

def test_request_otp_is_rate_limited(monkeypatch):
    """Repeated OTP requests for the same email/IP should be rate limited."""
    monkeypatch.delenv("SENDGRID_API_KEY", raising=False)
    monkeypatch.delenv("SENDGRID_FROM", raising=False)

    for _ in range(main.OTP_REQUEST_LIMIT):
        res = client.post("/api/auth/request-otp", json={"email": "limit@example.com"})
        assert res.status_code == 200

    limited = client.post("/api/auth/request-otp", json={"email": "limit@example.com"})
    assert limited.status_code == 429
    assert "Retry-After" in limited.headers

def test_request_otp_rejects_invalid_email():
    """OTP should not be created for invalid email addresses."""
    res = client.post("/api/auth/request-otp", json={"email": "not-an-email"})
    assert res.status_code == 422

def test_request_otp_rolls_back_when_email_fails(monkeypatch):
    """Failed email delivery must not leave a usable OTP behind."""
    def fail_email(email, code):
        raise main.HTTPException(status_code=403, detail="Email provider rejected recipient.")

    monkeypatch.setattr(main, "send_otp_email", fail_email)
    res = client.post("/api/auth/request-otp", json={"email": "blocked@example.com"})
    assert res.status_code == 403

    db = TestingSessionLocal()
    try:
        assert db.query(OTPCode).filter(OTPCode.email == "blocked@example.com").count() == 0
    finally:
        db.close()

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
    token = verify_res.json()["session_token"]

    reg_res = client.post("/api/auth/register",
                          json={"email": "alice@example.com", "public_key": '{"kty":"RSA"}'},
                          headers={"Authorization": f"Bearer {token}"})
    assert reg_res.status_code == 200

    lookup_res = client.get("/api/users/alice%40example.com/public-key")
    assert lookup_res.status_code == 200
    assert lookup_res.json()["email"] == "alice@example.com"

def test_register_requires_verified_otp():
    """A public key cannot be registered before OTP verification."""
    res = client.post("/api/auth/register",
                      json={"email": "mallory@example.com", "public_key": '{"kty":"EC"}'},
                      headers=auth_headers("mallory@example.com"))
    assert res.status_code == 403


def test_register_requires_matching_session():
    """A user cannot register a key for a different email session."""
    res = client.post("/api/auth/register",
                      json={"email": "victim@example.com", "public_key": '{"kty":"EC"}'},
                      headers=auth_headers("mallory@example.com"))
    assert res.status_code == 403


def test_messages_require_session():
    """Message send and inbox fetch endpoints require a verified session token."""
    send_res = client.post("/api/messages/send", json={
        "sender_email": "alice@example.com",
        "recipient_email": "bob@example.com",
        "ciphertext": "abc",
        "iv": "def",
        "sender_public_key": '{"kty":"EC"}',
    })
    assert send_res.status_code == 401

    fetch_res = client.get("/api/messages/alice%40example.com")
    assert fetch_res.status_code == 401

