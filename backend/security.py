"""
security.py – input validation, password hashing (scrypt), JWT auth, and strong-password rules.
"""
import hashlib
import hmac
import html
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, field_validator

# ─── Constants ────────────────────────────────────────────────────────────────
MAX_URL_LEN  = 2048
MAX_CHAT_LEN = 500
MAX_PWD_LEN  = 128
MIN_PWD_LEN  = 12

_CONTROL      = re.compile(r"[\x00-\x1f\x7f\s]")
_BAD_URL_CHARS = re.compile(r'[<>"\'`\\{}|^]')

# Strong-password requirements
_HAS_UPPER   = re.compile(r"[A-Z]")
_HAS_LOWER   = re.compile(r"[a-z]")
_HAS_DIGIT   = re.compile(r"\d")
_HAS_SPECIAL = re.compile(r"[!@#$%^&*()\-_=+\[\]{};:',.<>?/\\|`~]")

# Common weak passwords (partial list – extend as needed)
COMMON_PASSWORDS = {
    "password123!", "P@ssword123", "Admin@1234", "Welcome@1", "Letmein@1",
    "Qwerty@123", "Passw0rd!", "Summer@2024", "Winter@2024", "Spring@2024",
}


# ─── Request / response schemas ───────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > MAX_URL_LEN:
            raise ValueError(f"URL must be 1-{MAX_URL_LEN} characters.")
        if _CONTROL.search(v) or _BAD_URL_CHARS.search(v):
            raise ValueError("URL contains invalid characters.")
        scheme = v.split("://", 1)[0].lower() if "://" in v else "http"
        if scheme not in ("http", "https"):
            raise ValueError("Only http and https URLs are supported.")
        return v


class ChatRequest(BaseModel):
    message: str

    @field_validator("message")
    @classmethod
    def sanitize_message(cls, v: str) -> str:
        v = "".join(c for c in v if c == "\n" or c >= " ").strip()
        if not v or len(v) > MAX_CHAT_LEN:
            raise ValueError(f"Message must be 1-{MAX_CHAT_LEN} characters.")
        return html.escape(v, quote=True)


class EmailBody(BaseModel):
    """Used by /api/email-scan."""
    raw: str          # paste the raw email body (up to 10 kB)
    subject: str = ""

    @field_validator("raw")
    @classmethod
    def cap_raw(cls, v: str) -> str:
        if len(v) > 10_000:
            raise ValueError("Email body must be ≤ 10 000 characters.")
        return v.strip()


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not re.fullmatch(r"[A-Za-z0-9_\-]{3,30}", v):
            raise ValueError("Username: 3-30 chars, letters/digits/underscore/hyphen only.")
        return v

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _check_password_strength(v)


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new(cls, v: str) -> str:
        return _check_password_strength(v)


# ─── Password helpers ─────────────────────────────────────────────────────────
def _check_password_strength(password: str) -> str:
    """Raise ValueError with a clear message if the password is too weak."""
    errs = []
    if len(password) < MIN_PWD_LEN:
        errs.append(f"at least {MIN_PWD_LEN} characters")
    if len(password) > MAX_PWD_LEN:
        errs.append(f"at most {MAX_PWD_LEN} characters")
    if not _HAS_UPPER.search(password):
        errs.append("one uppercase letter")
    if not _HAS_LOWER.search(password):
        errs.append("one lowercase letter")
    if not _HAS_DIGIT.search(password):
        errs.append("one digit")
    if not _HAS_SPECIAL.search(password):
        errs.append("one special character (!@#$%… etc.)")
    if password.lower() in {p.lower() for p in COMMON_PASSWORDS}:
        errs.append("a less common password (this one is on known-breach lists)")
    if errs:
        raise ValueError("Password must contain " + ", ".join(errs) + ".")
    return password


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$")
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ─── JWT helpers ──────────────────────────────────────────────────────────────
_bearer = HTTPBearer(auto_error=False)
_DEV_FALLBACK_SECRET: Optional[str] = None


def _secret() -> str:
    global _DEV_FALLBACK_SECRET
    s = os.getenv("JWT_SECRET", "").strip()
    if len(s) >= 32 and not s.startswith("replace"):
        return s
    if _DEV_FALLBACK_SECRET is None:
        import secrets
        _DEV_FALLBACK_SECRET = secrets.token_urlsafe(48)
        import logging
        logging.getLogger("phishing.security").warning(
            "JWT_SECRET is unset or using a placeholder. Generated an ephemeral development secret."
        )
    return _DEV_FALLBACK_SECRET


def create_access_token(username: str, minutes: int = 60) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return jwt.encode({"sub": username, "exp": exp}, _secret(), algorithm="HS256")


def get_current_user(
    token: Optional[str] = None,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> str:
    raw_token = creds.credentials if creds else token
    if not raw_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated.")
    try:
        payload = jwt.decode(raw_token, _secret(), algorithms=["HS256"])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired. Please log in again.")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token.")


def get_optional_user(
    token: Optional[str] = None,
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[str]:
    """Returns username or None – for endpoints accessible both logged-in and anonymous."""
    raw_token = creds.credentials if creds else token
    if not raw_token:
        return None
    try:
        payload = jwt.decode(raw_token, _secret(), algorithms=["HS256"])
        return payload["sub"]
    except jwt.PyJWTError:
        return None
