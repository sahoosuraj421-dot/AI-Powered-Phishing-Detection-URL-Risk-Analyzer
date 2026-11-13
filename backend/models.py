from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True, max_length=50)
    email: str = Field(index=True, unique=True, max_length=254)
    password_hash: str
    role: str = Field(default="user")        # "user" | "admin"
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    last_login: Optional[datetime] = Field(default=None)


class ScanLog(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", index=True)
    url: str = Field(max_length=2048)
    risk_score: int
    status: str = Field(index=True)          # "Legitimate" | "Phishing"
    details: str = "{}"                      # JSON string of extracted features
    # Threat intel enrichment
    vt_positives: Optional[int] = Field(default=None)   # VirusTotal detections
    vt_total: Optional[int] = Field(default=None)
    whois_age_days: Optional[int] = Field(default=None)
    brand_match: Optional[str] = Field(default=None)    # e.g. "paypal (dist=2)"
    timestamp: datetime = Field(default_factory=utcnow, index=True)


class EmailScan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: Optional[int] = Field(default=None, foreign_key="user.id", index=True)
    subject: str = Field(default="", max_length=998)
    body_snippet: str = Field(default="", max_length=500)
    risk_score: int = Field(default=0)
    urgent_phrases: str = Field(default="[]")   # JSON list
    spf_pass: Optional[bool] = Field(default=None)
    dkim_pass: Optional[bool] = Field(default=None)
    urls_found: str = Field(default="[]")       # JSON list of URLs in body
    timestamp: datetime = Field(default_factory=utcnow, index=True)
