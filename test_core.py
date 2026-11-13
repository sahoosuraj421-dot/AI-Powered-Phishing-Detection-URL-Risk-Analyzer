"""
test_core.py – Offline unit tests for Tripwire Phishing Detector.

Run without needing the web server:
    python test_core.py
or:
    python -m unittest test_core.py
"""
import unittest
from backend.ml_engine import PhishingFeatureExtractor
from backend.email_analysis import analyze_email
from backend.security import _check_password_strength, hash_password, verify_password, ScanRequest
from backend.threat_intel import check_typosquatting
from backend.report_generator import generate_csv, generate_pdf
from backend.qwen_service import _offline_advisor


class TestPhishingFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = PhishingFeatureExtractor()

    def test_legitimate_url(self):
        result = self.extractor.analyze("https://google.com")
        self.assertEqual(result["status"], "Legitimate")
        self.assertLess(result["risk_score"], 50)
        self.assertTrue(result["details"]["uses_https"])
        self.assertFalse(result["details"]["uses_ip_address"])

    def test_phishing_url_ip_and_no_https(self):
        result = self.extractor.analyze("http://192.168.1.1/login/verify")
        self.assertEqual(result["status"], "Phishing")
        self.assertGreaterEqual(result["risk_score"], 50)
        self.assertTrue(result["details"]["uses_ip_address"])
        self.assertFalse(result["details"]["uses_https"])

    def test_url_with_at_symbol(self):
        features = self.extractor.extract("http://legit.com@phish-site.com/account")
        self.assertTrue(features["has_at_symbol"])
        score, signals = self.extractor.score(features)
        self.assertGreaterEqual(score, 40)

    def test_feature_vector_length(self):
        vec = self.extractor.feature_vector("https://example.com")
        self.assertEqual(len(vec), 9)
        self.assertTrue(all(isinstance(x, float) for x in vec))


class TestEmailAnalysis(unittest.TestCase):
    def test_phishing_email_detection(self):
        body = (
            "Urgent: Action required on your account. Your account has been suspended.\n"
            "Click here to verify your identity immediately: http://evil-login.example.com\n"
            "Authentication-Results: spf=fail dkim=fail"
        )
        res = analyze_email(body, subject="URGENT: Verify your account")
        self.assertEqual(res["status"], "Phishing")
        self.assertGreaterEqual(res["risk_score"], 50)
        self.assertFalse(res["spf_pass"])
        self.assertFalse(res["dkim_pass"])
        self.assertGreaterEqual(len(res["urgent_phrases"]), 2)
        self.assertEqual(len(res["urls_found"]), 1)

    def test_clean_email(self):
        body = "Hi team, please find the quarterly project status report attached. Let's sync tomorrow."
        res = analyze_email(body, subject="Project status")
        self.assertEqual(res["status"], "Likely Legitimate")
        self.assertLess(res["risk_score"], 25)


class TestSecurityValidators(unittest.TestCase):
    def test_strong_password_validation(self):
        valid = "StrongPass@2026!"
        self.assertEqual(_check_password_strength(valid), valid)

    def test_weak_password_rejection(self):
        with self.assertRaises(ValueError):
            _check_password_strength("weak")
        with self.assertRaises(ValueError):
            _check_password_strength("alllowercase123!")
        with self.assertRaises(ValueError):
            _check_password_strength("password123!")  # in common list

    def test_password_hashing_and_verification(self):
        pwd = "SecretPass#987!"
        hashed = hash_password(pwd)
        self.assertTrue(verify_password(pwd, hashed))
        self.assertFalse(verify_password("WrongPassword#987!", hashed))

    def test_scan_request_scheme_validation(self):
        req = ScanRequest(url="https://valid.example.com")
        self.assertEqual(req.url, "https://valid.example.com")
        with self.assertRaises(ValueError):
            ScanRequest(url="ftp://invalid-scheme.com")


class TestThreatIntel(unittest.TestCase):
    def test_typosquatting_subdomain_and_apex(self):
        res1 = check_typosquatting("http://paypa1.com")
        self.assertTrue(res1["available"])
        self.assertEqual(res1["match"], "paypal")
        self.assertTrue(res1["suspicious"])

        res2 = check_typosquatting("http://paypa1-secure-login.example.com/verify")
        self.assertTrue(res2["available"])
        self.assertEqual(res2["match"], "paypal")
        self.assertTrue(res2["suspicious"])

    def test_legitimate_brand_not_flagged(self):
        res = check_typosquatting("https://paypal.com")
        # Exactly paypal.com is the real brand, not a typosquat
        self.assertFalse(res["suspicious"])


class TestReportGenerator(unittest.TestCase):
    def test_csv_generation(self):
        rows = [{
            "id": 1,
            "url": "https://example.com",
            "risk_score": 10,
            "status": "Legitimate",
            "vt_positives": 0,
            "vt_total": 70,
            "whois_age_days": 500,
            "brand_match": None,
            "timestamp": "2026-11-13T10:00:00Z"
        }]
        csv_bytes = generate_csv(rows)
        self.assertIn(b"https://example.com", csv_bytes)

    def test_pdf_generation_unicode_resilience(self):
        # Must not raise FPDFUnicodeEncodingException even with non-Latin homoglyphs
        rows = [{
            "id": 2,
            "url": "http://раураl.com/verify",  # Cyrillic chars
            "risk_score": 85,
            "status": "Phishing",
            "vt_positives": 5,
            "vt_total": 70,
            "whois_age_days": 3,
            "brand_match": "paypal",
            "timestamp": "2026-11-13T10:00:00Z"
        }]
        pdf_bytes = generate_pdf(rows)
        self.assertTrue(len(pdf_bytes) > 0)


class TestOfflineAdvisor(unittest.TestCase):
    def test_offline_response(self):
        reply = _offline_advisor("How can I spot phishing emails?", [])
        self.assertIn("Phishing", reply)
        self.assertIn("Sender Spoofing", reply)


if __name__ == "__main__":
    unittest.main()

