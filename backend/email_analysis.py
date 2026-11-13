"""
email_analysis.py – NLP-based phishing email analysis.

Checks for:
  - Urgent / high-pressure language patterns
  - SPF/DKIM flags in email headers (if raw email is pasted)
  - Embedded URLs
  - Overall risk scoring
"""
from __future__ import annotations

import json
import re
from typing import Optional

# ─── Urgency phrase patterns ──────────────────────────────────────────────────
URGENT_PATTERNS: list[tuple[str, int]] = [
    # (pattern, risk_points)
    (r"action\s+required", 15),
    (r"account\s+(suspended|locked|compromised|disabled|closed)", 20),
    (r"verify\s+your\s+(account|identity|email|information)", 15),
    (r"(immediately|urgent(ly)?|right\s+away|as\s+soon\s+as\s+possible)", 10),
    (r"(click\s+here|click\s+the\s+link|click\s+below)\s+to", 10),
    (r"(confirm|update|validate)\s+your\s+(details|information|password|credentials)", 15),
    (r"(limited\s+time|expires?\s+(in|on|today)|last\s+chance)", 12),
    (r"(suspicious\s+activity|unauthorized\s+(access|login|sign.?in))", 15),
    (r"(bank|financial|payment)\s+(information|details|account)", 10),
    (r"(win(ner)?|won|prize|reward|congratulations)\b", 12),
    (r"dear\s+(customer|user|member|client|valued)", 8),
    (r"(security\s+alert|warning|important\s+notice)", 10),
    (r"(password|pin|otp|verification\s+code)\s+(reset|change|update|expire)", 15),
    (r"(free\s+gift|claim\s+your|unclaimed)", 10),
    (r"(irs|tax\s+refund|government\s+grant)", 12),
    (r"(unsubscribe|opt.?out)\s+if\s+you\s+did\s+not", 5),
]

URL_REGEX = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)

SPF_PASS_PATTERN  = re.compile(r"spf=pass",  re.IGNORECASE)
SPF_FAIL_PATTERN  = re.compile(r"spf=fail",  re.IGNORECASE)
DKIM_PASS_PATTERN = re.compile(r"dkim=pass", re.IGNORECASE)
DKIM_FAIL_PATTERN = re.compile(r"dkim=fail", re.IGNORECASE)


def _find_urls(text: str) -> list[str]:
    return URL_REGEX.findall(text)


def _parse_auth_headers(text: str) -> tuple[Optional[bool], Optional[bool]]:
    """Return (spf_pass, dkim_pass) – None if header not found."""
    spf: Optional[bool]  = None
    dkim: Optional[bool] = None
    if SPF_PASS_PATTERN.search(text):
        spf = True
    elif SPF_FAIL_PATTERN.search(text):
        spf = False
    if DKIM_PASS_PATTERN.search(text):
        dkim = True
    elif DKIM_FAIL_PATTERN.search(text):
        dkim = False
    return spf, dkim


def analyze_email(raw: str, subject: str = "") -> dict:
    """
    Analyse a raw email body (and optionally the authentication headers).

    Returns a dict with:
      - risk_score   (0-100)
      - urgent_phrases  list of matched phrases
      - spf_pass / dkim_pass  (bool or None)
      - urls_found  list of URLs detected in the body
      - signals     human-readable risk signals
    """
    text = (subject + "\n\n" + raw).lower()
    urgent_phrases: list[str] = []
    score = 0
    signals: list[str] = []

    # 1) Urgency language scan
    for pattern, pts in URGENT_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            found = re.search(pattern, subject + "\n" + raw, re.IGNORECASE)
            phrase = found.group(0) if found else pattern
            urgent_phrases.append(phrase)
            score += pts
            signals.append(f'Urgency phrase detected: "{phrase}"')

    # 2) Auth header check
    spf_pass, dkim_pass = _parse_auth_headers(raw)
    if spf_pass is False:
        score += 20
        signals.append("SPF check FAILED – sender domain may be spoofed")
    elif spf_pass is True:
        score = max(0, score - 5)
    if dkim_pass is False:
        score += 20
        signals.append("DKIM signature FAILED – email may be forged")
    elif dkim_pass is True:
        score = max(0, score - 5)

    # 3) Embedded URL check
    urls = _find_urls(raw)
    if urls:
        if len(urls) > 5:
            score += 10
            signals.append(f"Many embedded URLs ({len(urls)}) – typical of phishing")
        else:
            signals.append(f"Contains {len(urls)} URL(s)")

    # 4) Subject urgency bonus
    if subject:
        subj_lower = subject.lower()
        for kw in ("urgent", "action required", "verify", "suspended", "alert", "warning"):
            if kw in subj_lower:
                score += 8
                signals.append(f'Suspicious subject keyword: "{kw}"')
                break

    score = min(score, 100)
    risk_level = "high" if score >= 50 else "medium" if score >= 25 else "low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "status": "Phishing" if score >= 50 else "Suspicious" if score >= 25 else "Likely Legitimate",
        "urgent_phrases": urgent_phrases,
        "spf_pass": spf_pass,
        "dkim_pass": dkim_pass,
        "urls_found": urls[:20],  # cap at 20
        "signals": signals,
        "url_count": len(urls),
    }
