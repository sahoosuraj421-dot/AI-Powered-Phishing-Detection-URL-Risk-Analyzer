"""
test_api.py – Quick smoke-test for the Tripwire API.

Run from the project root with the server already started:
    python test_api.py

Requires Python 3.10+ (uses urllib.request from stdlib only).
"""
import json
import sys
import urllib.error
import urllib.request

BASE = "http://localhost:8000"
PASS = "✅"
FAIL = "❌"


def _request(method: str, path: str, body: dict | None = None,
             token: str | None = None) -> tuple[int, dict]:
    """Send a JSON request and return (status_code, response_body)."""
    data = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body_bytes = e.read()
            return e.code, json.loads(body_bytes)
        except Exception:
            return e.code, {"detail": str(e)}


def check(label: str, condition: bool, detail: str = "") -> None:
    icon = PASS if condition else FAIL
    msg = f"  {icon} {label}"
    if detail:
        msg += f"  [{detail}]"
    print(msg)
    if not condition:
        sys.exit(1)


def main() -> None:
    print("\n── Tripwire API Smoke Test ──────────────────────────────────────")

    # ── GET /api/logs ─────────────────────────────────────────────────────────
    print("\n[1] GET /api/logs")
    code, data = _request("GET", "/api/logs")
    check("status 200", code == 200, f"got {code}")
    check("returns a list", isinstance(data, list), f"type={type(data).__name__}")
    print(f"     records returned: {len(data)}")

    # ── POST /api/scan ────────────────────────────────────────────────────────
    print("\n[2] POST /api/scan (phishing URL)")
    code, data = _request("POST", "/api/scan",
                           {"url": "http://paypa1-secure-login.example.com/verify"})
    check("status 200", code == 200, f"got {code}")
    check("risk_score present", "risk_score" in data)
    check("status field present", "status" in data)
    check("threat_intel present", "threat_intel" in data)
    score = data["risk_score"]
    status = data["status"]
    print(f"     score={score}/100  verdict={status}")

    # ── POST /api/scan – reject bad scheme ────────────────────────────────────
    print("\n[3] POST /api/scan (invalid FTP URL – should be rejected)")
    code, data = _request("POST", "/api/scan", {"url": "ftp://bad.example.com"})
    check("status 422", code == 422, f"got {code}")

    # ── POST /api/email-scan ──────────────────────────────────────────────────
    print("\n[4] POST /api/email-scan")
    email_body = (
        "Dear valued customer,\n"
        "Your account has been suspended. Click here to verify your identity immediately:\n"
        "http://secure-login.example.com/verify?token=abc123\n"
        "spf=fail dkim=fail"
    )
    code, data = _request("POST", "/api/email-scan",
                           {"raw": email_body, "subject": "URGENT: Action Required"})
    check("status 200", code == 200, f"got {code}")
    check("risk_score present", "risk_score" in data)
    check("signals present", isinstance(data.get("signals"), list))
    print(f"     email risk_score={data['risk_score']}/100  status={data.get('status')}")

    # ── POST /api/auth/register ───────────────────────────────────────────────
    import time
    username = f"smoketest_{int(time.time()) % 100000}"
    email = f"{username}@example.com"
    password = "SmokeTest@99!"

    print(f"\n[5] POST /api/auth/register  (user: {username})")
    code, data = _request("POST", "/api/auth/register",
                           {"username": username, "email": email, "password": password})
    check("status 201", code == 201, f"got {code}")
    check("access_token returned", "access_token" in data)
    token = data["access_token"]
    print(f"     token: {token[:20]}…")

    # ── POST /api/auth/login ──────────────────────────────────────────────────
    print("\n[6] POST /api/auth/login")
    code, data = _request("POST", "/api/auth/login",
                           {"username": username, "password": password})
    check("status 200", code == 200, f"got {code}")
    check("access_token returned", "access_token" in data)
    token = data["access_token"]

    # ── GET /api/auth/me ──────────────────────────────────────────────────────
    print("\n[7] GET /api/auth/me")
    code, data = _request("GET", "/api/auth/me", token=token)
    check("status 200", code == 200, f"got {code}")
    check("username matches", data.get("username") == username)

    # ── POST /api/auth/change-password ───────────────────────────────────────
    new_password = "ChangedPass@77!"
    print("\n[8] POST /api/auth/change-password")
    code, data = _request("POST", "/api/auth/change-password",
                           {"old_password": password, "new_password": new_password},
                           token=token)
    check("status 200", code == 200, f"got {code}")
    check("detail message returned", "detail" in data)

    # ── Weak-password rejection ───────────────────────────────────────────────
    print("\n[9] POST /api/auth/register (weak password – should be rejected)")
    code, data = _request("POST", "/api/auth/register",
                           {"username": "weakuser99", "email": "weak@example.com",
                            "password": "short"})
    check("status 422", code == 422, f"got {code}")

    # ── Reports ───────────────────────────────────────────────────────────────
    print("\n[10] GET /api/report/csv")
    code, data = _request("GET", "/api/report/csv", token=token)
    check("status 200", code == 200, f"got {code}")

    print("\n[11] GET /api/report/pdf")
    code, data = _request("GET", "/api/report/pdf", token=token)
    check("status 200", code == 200, f"got {code}")

    # ── AI Security Advisor ───────────────────────────────────────────────────
    print("\n[12] POST /api/chat")
    code, data = _request("POST", "/api/chat", {"message": "How do I spot phishing?"})
    check("status 200", code == 200, f"got {code}")
    check("reply field present", "reply" in data and len(data["reply"]) > 0)
    print(f"     reply snippet: {data['reply'][:60]}…")

    print("\n── All smoke tests passed! ─────────────────────────────────────\n")


if __name__ == "__main__":
    main()
