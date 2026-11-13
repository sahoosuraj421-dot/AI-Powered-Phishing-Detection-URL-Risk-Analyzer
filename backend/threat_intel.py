"""
threat_intel.py – VirusTotal, WHOIS domain-age, and typosquatting detection.
"""
from __future__ import annotations

import logging
import os
import re
import socket
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests

log = logging.getLogger("phishing.threat_intel")


def _vt_api_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "")


def _sb_api_key() -> str:
    return os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

# ─── Popular brand list for typosquatting detection ───────────────────────────
POPULAR_BRANDS = [
    "google", "gmail", "youtube", "facebook", "instagram", "twitter", "x",
    "paypal", "amazon", "netflix", "microsoft", "apple", "icloud", "outlook",
    "linkedin", "dropbox", "github", "gitlab", "stripe", "shopify", "ebay",
    "walmart", "chase", "bankofamerica", "wellsfargo", "citibank", "barclays",
    "hsbc", "coinbase", "binance", "kraken", "robinhood", "venmo", "cashapp",
    "whatsapp", "telegram", "discord", "slack", "zoom", "teams", "office365",
    "adobe", "salesforce", "atlassian", "jira", "confluence",
]


# ─── VirusTotal ───────────────────────────────────────────────────────────────
def check_virustotal(url: str) -> dict:
    """Query VirusTotal URL report. Returns dict with positives, total, permalink."""
    key = _vt_api_key()
    if not key or key.startswith("replace"):
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY not configured"}

    headers = {"x-apikey": key, "accept": "application/json"}
    try:
        # Step 1: submit URL for scanning
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={**headers, "content-type": "application/x-www-form-urlencoded"},
            data=f"url={requests.utils.quote(url, safe='')}",
            timeout=15,
        )
        submit.raise_for_status()
        analysis_id = submit.json()["data"]["id"]

        # Step 2: fetch analysis results
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=15,
        )
        report.raise_for_status()
        stats = report.json()["data"]["attributes"]["stats"]
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values())
        return {
            "available": True,
            "positives": positives,
            "total": total,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "permalink": f"https://www.virustotal.com/gui/url/{analysis_id}",
        }
    except Exception as exc:
        log.warning("VirusTotal error: %s", exc)
        return {"available": False, "reason": str(exc)}


# ─── Google Safe Browsing ─────────────────────────────────────────────────────
def check_safe_browsing(url: str) -> dict:
    """Query Google Safe Browsing API v4."""
    key = _sb_api_key()
    if not key or key.startswith("replace"):
        return {"available": False, "reason": "GOOGLE_SAFE_BROWSING_KEY not configured"}
    try:
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=payload, timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        matches = data.get("matches", [])
        return {
            "available": True,
            "flagged": bool(matches),
            "threats": [m.get("threatType", "UNKNOWN") for m in matches],
        }
    except Exception as exc:
        log.warning("Safe Browsing error: %s", exc)
        return {"available": False, "reason": str(exc)}


# ─── WHOIS / domain age ───────────────────────────────────────────────────────
def check_domain_age(url: str) -> dict:
    """Resolve creation date via python-whois. Returns age in days (None on failure)."""
    try:
        import whois as pywhois  # python-whois
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.hostname or ""
        # Strip leading 'www.'
        domain = re.sub(r"^www\.", "", domain)
        if not domain:
            return {"available": False, "reason": "No domain extracted"}

        w = None
        if hasattr(pywhois, "whois"):
            w = pywhois.whois(domain)
        elif hasattr(pywhois, "query"):
            w = pywhois.query(domain)

        if not w:
            return {"available": False, "reason": "WHOIS lookup not supported by current environment"}

        creation = getattr(w, "creation_date", None)
        if creation is None and isinstance(w, dict):
            creation = w.get("creation_date")
        if isinstance(creation, list):
            creation = creation[0]
        if not isinstance(creation, datetime):
            return {"available": False, "reason": "No creation date in WHOIS data"}

        # Ensure timezone-aware
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation).days
        return {"available": True, "age_days": max(0, age_days), "domain": domain,
                "created": creation.strftime("%Y-%m-%d"),
                "very_new": age_days < 30}
    except Exception as exc:
        log.debug("WHOIS error for %s: %s", url, exc)
        return {"available": False, "reason": str(exc)}


# ─── Typosquatting / brand impersonation ─────────────────────────────────────
def _levenshtein(a: str, b: str) -> int:
    """Pure-python Levenshtein distance (fall back if python-Levenshtein not installed)."""
    try:
        import Levenshtein
        return Levenshtein.distance(a, b)
    except ImportError:
        pass
    # Simple DP fallback
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), curr[-1] + 1, prev[j + 1] + 1))
        prev = curr
    return prev[-1]


def check_typosquatting(url: str, threshold: int = 3) -> dict:
    """
    Check if the registered domain or subdomain is similar to any popular brand.
    Returns the best match if distance ≤ threshold.
    """
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = (parsed.hostname or "").lower()
        # Strip leading 'www.'
        host = re.sub(r"^www\.", "", host)
        labels = [l for l in host.split(".") if l]
        reg_domain = ".".join(labels[-2:]) if len(labels) >= 2 else host
        # Primary SLD (strip TLD)
        sld = labels[-2] if len(labels) >= 2 else labels[0] if labels else ""

        if not sld:
            return {"available": False, "reason": "No domain extracted"}

        # Collect candidate tokens: SLD, all subdomains/domain labels except TLD,
        # plus any hyphen-separated sub-tokens (e.g. 'paypa1' from 'paypa1-secure-login')
        candidates: set[str] = {sld}
        for lbl in (labels[:-1] if len(labels) > 1 else labels):
            candidates.add(lbl)
            for part in lbl.split("-"):
                if len(part) >= 3:
                    candidates.add(part)

        best_brand, best_dist = "", threshold + 1
        for candidate in candidates:
            for brand in POPULAR_BRANDS:
                d = _levenshtein(candidate, brand)
                # An exact match to the real brand in a deceptive domain/subdomain
                # (e.g. paypal.verify-security.com) or a close typosquat (e.g. paypa1)
                if candidate != brand and d < best_dist:
                    best_dist, best_brand = d, brand

        if best_brand and best_dist <= threshold:
            return {
                "available": True,
                "match": best_brand,
                "distance": best_dist,
                "suspicious": best_dist <= 2,
                "registered_domain": reg_domain,
            }
        return {"available": True, "match": None, "suspicious": False,
                "registered_domain": reg_domain}
    except Exception as exc:
        log.debug("Typosquatting error: %s", exc)
        return {"available": False, "reason": str(exc)}


# ─── Combined enrichment ──────────────────────────────────────────────────────
def enrich_url(url: str) -> dict:
    """Run all threat-intel checks and return a combined dict."""
    vt   = check_virustotal(url)
    sb   = check_safe_browsing(url)
    age  = check_domain_age(url)
    typo = check_typosquatting(url)
    return {"virustotal": vt, "safe_browsing": sb, "domain_age": age, "typosquatting": typo}
