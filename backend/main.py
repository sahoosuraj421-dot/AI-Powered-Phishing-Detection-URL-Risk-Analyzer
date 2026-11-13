"""
main.py – FastAPI application entry point.

Endpoints:
  POST /api/auth/register      – create account
  POST /api/auth/login         – get JWT
  GET  /api/auth/me            – current user info
  POST /api/auth/change-password
  POST /api/scan               – URL scan (with threat intel)
  POST /api/email-scan         – NLP email scan
  GET  /api/logs               – scan history
  GET  /api/report/pdf         – download PDF report
  GET  /api/report/csv         – download CSV report
  POST /api/chat               – AI security advisor
"""
from __future__ import annotations

import html
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlmodel import Session, select

from .database import get_session, init_db
from .email_analysis import analyze_email
from .ml_engine import PhishingFeatureExtractor
from .models import EmailScan, ScanLog, User
from .qwen_service import QwenError, ask_qwen
from .report_generator import generate_csv, generate_pdf
from .security import (
    ChangePasswordRequest,
    ChatRequest,
    EmailBody,
    LoginRequest,
    RegisterRequest,
    ScanRequest,
    create_access_token,
    get_current_user,
    get_optional_user,
    hash_password,
    verify_password,
)
from .threat_intel import enrich_url

log = logging.getLogger("phishing")
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

rate_limiting_enabled = os.getenv("RATE_LIMITING_ENABLED", "true").lower() in ("true", "1", "yes")
limiter = Limiter(key_func=get_remote_address, enabled=rate_limiting_enabled)
extractor = PhishingFeatureExtractor()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Tripwire – AI Phishing Detector", lifespan=lifespan,
              docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

origins_raw = os.getenv("ALLOWED_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000")
origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'"
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = CSP
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    return resp


# ─── Helpers ──────────────────────────────────────────────────────────────────
def _serialize(row: ScanLog) -> dict:
    if row.timestamp:
        ts = row.timestamp.replace(tzinfo=timezone.utc).isoformat() if row.timestamp.tzinfo is None else row.timestamp.isoformat()
    else:
        ts = datetime.now(timezone.utc).isoformat()
    details_parsed = {}
    if isinstance(row.details, str):
        try:
            details_parsed = json.loads(row.details)
        except Exception:
            details_parsed = {}
    elif isinstance(row.details, dict):
        details_parsed = row.details

    return {
        "id": row.id,
        "url": row.url,
        "risk_score": row.risk_score,
        "status": row.status,
        "details": details_parsed,
        "vt_positives": row.vt_positives,
        "vt_total": row.vt_total,
        "whois_age_days": row.whois_age_days,
        "brand_match": row.brand_match,
        "timestamp": ts,
    }


def _get_user_by_username(username: str, session: Session) -> Optional[User]:
    return session.exec(select(User).where(User.username == username)).first()


# ─── Auth ─────────────────────────────────────────────────────────────────────
@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, payload: RegisterRequest, session: Session = Depends(get_session)):
    if session.exec(select(User).where(User.username == payload.username)).first():
        raise HTTPException(400, "Username already taken.")
    if session.exec(select(User).where(User.email == payload.email)).first():
        raise HTTPException(400, "Email already registered.")
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    token = create_access_token(user.username)
    return {"access_token": token, "token_type": "bearer",
            "username": user.username, "email": user.email}


@app.post("/api/auth/login")
@limiter.limit("10/minute")
def login(request: Request, payload: LoginRequest, session: Session = Depends(get_session)):
    user = _get_user_by_username(payload.username, session)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid username or password.")
    if not user.is_active:
        raise HTTPException(403, "Account is disabled.")
    user.last_login = datetime.now(timezone.utc)
    session.add(user)
    session.commit()
    token = create_access_token(user.username)
    return {"access_token": token, "token_type": "bearer",
            "username": user.username, "email": user.email}


@app.get("/api/auth/me")
def me(username: str = Depends(get_current_user), session: Session = Depends(get_session)):
    user = _get_user_by_username(username, session)
    if not user:
        raise HTTPException(404, "User not found.")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "created_at": user.created_at.replace(tzinfo=timezone.utc).isoformat(),
        "last_login": user.last_login.replace(tzinfo=timezone.utc).isoformat() if user.last_login else None,
    }


@app.post("/api/auth/change-password")
@limiter.limit("5/minute")
def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    username: str = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    user = _get_user_by_username(username, session)
    if not user or not verify_password(payload.old_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect.")
    user.password_hash = hash_password(payload.new_password)
    session.add(user)
    session.commit()
    return {"detail": "Password changed successfully."}


# ─── URL Scan ─────────────────────────────────────────────────────────────────
@app.post("/api/scan")
@limiter.limit("10/minute")
def scan(
    request: Request,
    payload: ScanRequest,
    session: Session = Depends(get_session),
    username: Optional[str] = Depends(get_optional_user),
):
    result = extractor.analyze(payload.url)

    # Async-style: run threat intel (blocking but fast enough for demo)
    intel = enrich_url(payload.url)
    vt    = intel.get("virustotal", {})
    age   = intel.get("domain_age", {})
    typo  = intel.get("typosquatting", {})

    # Augment risk score with threat intel
    extra_score = 0
    signals_extra: list[str] = []
    if vt.get("available") and vt.get("positives", 0) > 0:
        extra_score += min(vt["positives"] * 5, 30)
        signals_extra.append(f"VirusTotal: {vt['positives']}/{vt['total']} vendors flagged this URL")
    if age.get("available") and age.get("very_new"):
        extra_score += 20
        signals_extra.append(f"Domain is only {age['age_days']} days old – brand new domains are high risk")
    if typo.get("available") and typo.get("suspicious"):
        extra_score += 15
        signals_extra.append(f"Domain looks like '{typo['match']}' (Levenshtein distance={typo['distance']}) – possible typosquatting")

    final_score = min(result["risk_score"] + extra_score, 100)
    details = {**result["details"], "signals": result["details"].get("signals", []) + signals_extra, "threat_intel": intel}

    user_id = None
    if username:
        u = _get_user_by_username(username, session)
        if u:
            user_id = u.id

    row = ScanLog(
        user_id=user_id,
        url=payload.url,
        risk_score=final_score,
        status="Phishing" if final_score >= 50 else "Legitimate",
        details=json.dumps(details),
        vt_positives=vt.get("positives") if vt.get("available") else None,
        vt_total=vt.get("total") if vt.get("available") else None,
        whois_age_days=age.get("age_days") if age.get("available") else None,
        brand_match=f"{typo['match']} (dist={typo['distance']})" if typo.get("suspicious") else None,
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    level = "high" if final_score >= 50 else "medium" if final_score >= 30 else "low"
    return {**_serialize(row), "risk_level": level, "threat_intel": intel}


# ─── Email Scan ───────────────────────────────────────────────────────────────
@app.post("/api/email-scan")
@limiter.limit("5/minute")
def email_scan(
    request: Request,
    payload: EmailBody,
    session: Session = Depends(get_session),
    username: Optional[str] = Depends(get_optional_user),
):
    result = analyze_email(payload.raw, payload.subject)

    user_id = None
    if username:
        u = _get_user_by_username(username, session)
        if u:
            user_id = u.id

    row = EmailScan(
        user_id=user_id,
        subject=payload.subject[:998],
        body_snippet=payload.raw[:500],
        risk_score=result["risk_score"],
        urgent_phrases=json.dumps(result["urgent_phrases"]),
        spf_pass=result["spf_pass"],
        dkim_pass=result["dkim_pass"],
        urls_found=json.dumps(result["urls_found"]),
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return {**result, "id": row.id}


# ─── History / Logs ───────────────────────────────────────────────────────────
@app.get("/api/logs")
@limiter.limit("30/minute")
def logs(
    request: Request,
    limit: int = 20,
    session: Session = Depends(get_session),
    username: Optional[str] = Depends(get_optional_user),
):
    limit = max(1, min(limit, 50))
    query = select(ScanLog).order_by(ScanLog.timestamp.desc()).limit(limit)
    # If authenticated, filter to user's own scans for non-admin
    if username:
        u = _get_user_by_username(username, session)
        if u and u.role != "admin":
            query = select(ScanLog).where(ScanLog.user_id == u.id).order_by(ScanLog.timestamp.desc()).limit(limit)
    rows = session.exec(query).all()
    return [_serialize(r) for r in rows]


# ─── Admin Control Endpoints ──────────────────────────────────────────────────
@app.get("/api/admin/users")
def admin_get_users(username: str = Depends(get_current_user), session: Session = Depends(get_session)):
    admin = _get_user_by_username(username, session)
    if not admin or admin.role != "admin":
        raise HTTPException(403, "Access restricted to administrators.")
    users = session.exec(select(User).order_by(User.id)).all()
    return [{
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.replace(tzinfo=timezone.utc).isoformat() if u.created_at else None,
        "last_login": u.last_login.replace(tzinfo=timezone.utc).isoformat() if u.last_login else None
    } for u in users]


@app.delete("/api/admin/scans/{scan_id}")
def admin_delete_scan(scan_id: int, username: str = Depends(get_current_user), session: Session = Depends(get_session)):
    admin = _get_user_by_username(username, session)
    if not admin or admin.role != "admin":
        raise HTTPException(403, "Access restricted to administrators.")
    scan = session.get(ScanLog, scan_id)
    if not scan:
        raise HTTPException(404, "Scan record not found.")
    session.delete(scan)
    session.commit()
    return {"detail": f"Scan #{scan_id} deleted by administrator."}


@app.post("/api/admin/users/{user_id}/toggle-status")
def admin_toggle_user_status(user_id: int, username: str = Depends(get_current_user), session: Session = Depends(get_session)):
    admin = _get_user_by_username(username, session)
    if not admin or admin.role != "admin":
        raise HTTPException(403, "Access restricted to administrators.")
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    if user.id == admin.id:
        raise HTTPException(400, "Administrators cannot disable their own account.")
    user.is_active = not user.is_active
    session.add(user)
    session.commit()
    return {"detail": f"User '{user.username}' status set to {'active' if user.is_active else 'disabled'}."}


# ─── Reports ──────────────────────────────────────────────────────────────────
@app.get("/api/report/csv")
@limiter.limit("5/minute")
def report_csv(
    request: Request,
    limit: int = 50,
    username: str = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    limit = max(1, min(limit, 500))
    u = _get_user_by_username(username, session)
    query = select(ScanLog).order_by(ScanLog.timestamp.desc()).limit(limit)
    if u and u.role != "admin":
        query = select(ScanLog).where(ScanLog.user_id == u.id).order_by(ScanLog.timestamp.desc()).limit(limit)
    rows = session.exec(query).all()
    data = generate_csv([_serialize(r) for r in rows])
    return Response(
        content=data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=tripwire_report.csv"},
    )


@app.get("/api/report/pdf")
@limiter.limit("5/minute")
def report_pdf(
    request: Request,
    limit: int = 50,
    username: str = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    limit = max(1, min(limit, 500))
    u = _get_user_by_username(username, session)
    query = select(ScanLog).order_by(ScanLog.timestamp.desc()).limit(limit)
    if u and u.role != "admin":
        query = select(ScanLog).where(ScanLog.user_id == u.id).order_by(ScanLog.timestamp.desc()).limit(limit)
    rows = session.exec(query).all()
    data = generate_pdf([_serialize(r) for r in rows])
    return Response(
        content=data,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=tripwire_report.pdf"},
    )


# ─── AI Chat ──────────────────────────────────────────────────────────────────
@app.post("/api/chat")
@limiter.limit("15/minute")
def chat(
    request: Request,
    payload: ChatRequest,
    session: Session = Depends(get_session),
):
    rows = session.exec(select(ScanLog).order_by(ScanLog.timestamp.desc()).limit(3)).all()
    context = [{"url": html.escape(r.url), "status": r.status, "risk_score": r.risk_score} for r in rows]
    try:
        return {"reply": ask_qwen(payload.message, context)}
    except QwenError as e:
        log.exception("Qwen request failed")
        raise HTTPException(status_code=503, detail=str(e))


# ─── Static frontend (must be last) ───────────────────────────────────────────
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
