import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "update", "bank",
    "confirm", "password", "wallet", "paypal", "webscr", "bonus", "suspend",
)
PHISHING_THRESHOLD = 50


class PhishingFeatureExtractor:
    """Lexical URL analysis with a transparent, weighted risk score.

    `feature_vector()` exposes the same features as numbers so a scikit-learn
    model (e.g. RandomForestClassifier) can be trained and swapped in later.
    """

    def extract(self, url: str) -> dict:
        raw = url.strip()
        has_scheme = "://" in raw
        parsed = urlparse(raw if has_scheme else "http://" + raw)
        host = (parsed.hostname or "").lower()

        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = bool(re.fullmatch(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}", host))

        labels = [lbl for lbl in host.split(".") if lbl]
        lowered = raw.lower()
        try:
            port = parsed.port
        except ValueError:
            port = -1
        return {
            "host": host,
            "url_length": len(raw),
            "has_at_symbol": "@" in raw,
            "uses_ip_address": is_ip,
            "subdomain_count": 0 if is_ip else max(len(labels) - 2, 0),
            "uses_https": parsed.scheme == "https",
            "keywords_found": [k for k in SUSPICIOUS_KEYWORDS if k in lowered],
            "hyphen_count": host.count("-"),
            "has_punycode": "xn--" in host,
            "nonstandard_port": port not in (None, 80, 443),
        }

    def score(self, f: dict) -> tuple[int, list[str]]:
        pts, signals = 0, []

        def add(n: int, why: str):
            nonlocal pts
            pts += n
            signals.append(why)

        if f["url_length"] > 120: add(15, "Very long URL")
        elif f["url_length"] > 75: add(10, "Long URL")
        elif f["url_length"] > 54: add(5, "Slightly long URL")
        if f["has_at_symbol"]: add(40, "Contains '@', which can hide the real destination")
        if f["uses_ip_address"]: add(30, "Uses an IP address instead of a domain")
        if f["subdomain_count"] >= 4: add(15, "Excessive subdomains")
        elif f["subdomain_count"] >= 3: add(10, "Many subdomains")
        if not f["uses_https"]: add(15, "Does not use HTTPS")
        if f["keywords_found"]:
            add(min(10 * len(f["keywords_found"]), 30),
                "Suspicious keywords: " + ", ".join(f["keywords_found"]))
        if f["hyphen_count"] >= 2: add(8, "Multiple hyphens in domain")
        if f["has_punycode"]: add(10, "Punycode (possible look-alike characters)")
        if f["nonstandard_port"]: add(8, "Non-standard port")
        return min(pts, 100), signals

    def analyze(self, url: str) -> dict:
        features = self.extract(url)
        score, signals = self.score(features)
        status = "Phishing" if score >= PHISHING_THRESHOLD else "Legitimate"
        level = "high" if score >= PHISHING_THRESHOLD else "medium" if score >= 30 else "low"
        return {
            "risk_score": score,
            "status": status,
            "risk_level": level,
            "details": {**features, "signals": signals},
        }

    def feature_vector(self, url: str) -> list[float]:
        f = self.extract(url)
        return [
            float(f["url_length"]),
            float(f["has_at_symbol"]),
            float(f["uses_ip_address"]),
            float(f["subdomain_count"]),
            float(f["uses_https"]),
            float(len(f["keywords_found"])),
            float(f["hyphen_count"]),
            float(f["has_punycode"]),
            float(f["nonstandard_port"]),
        ]
