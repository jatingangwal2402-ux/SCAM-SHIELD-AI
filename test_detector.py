"""
Test cases for ScamShield AI detection engine.
Run from the project folder:   python -m unittest discover -s tests -v
These same cases are listed in the Software Testing chapter of the report.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402

# use a throw-away database so tests never touch real data
database.DB_PATH = os.path.join(tempfile.mkdtemp(), "test.db")
database.init_db()

import detector  # noqa: E402


class SmsTests(unittest.TestCase):
    def test_01_kyc_scam_is_high(self):
        r = detector.check_sms("Dear customer your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc.xyz")
        self.assertEqual(r["level"], "High")
        self.assertEqual(r["scam_type_key"], "kyc_block")

    def test_02_hinglish_otp_request(self):
        r = detector.check_sms("Sir turant OTP bhejo warna aapka account band ho jayega")
        self.assertEqual(r["level"], "High")

    def test_03_hindi_phrase_detected(self):
        r = detector.check_sms("आपका खाता बंद हो जाएगा, केवाईसी अपडेट करें")
        self.assertGreater(r["score"], 30)
        self.assertEqual(r["scam_type_key"], "kyc_block")

    def test_04_digital_arrest(self):
        r = detector.check_sms("This is CBI officer. Arrest warrant issued, stay on the call, do not disconnect.")
        self.assertEqual(r["scam_type_key"], "digital_arrest")
        self.assertEqual(r["level"], "High")

    def test_05_genuine_otp_notice_is_low(self):
        r = detector.check_sms("123456 is your OTP for login. Do not share OTP with anyone. -Bank")
        self.assertEqual(r["level"], "Low")

    def test_06_normal_message_is_low(self):
        r = detector.check_sms("Hi, dinner at 8 tonight? Let me know.")
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["level"], "Low")


class SmsExplanationTests(unittest.TestCase):
    def test_19_safe_otp_notice_does_not_claim_suspicious_words(self):
        r = detector.check_sms("123456 is your OTP for login. Do not share OTP with anyone.")
        self.assertEqual(r["score"], 0)
        self.assertNotIn("shak wale shabd", r["explanation"])


class UrlTests(unittest.TestCase):
    def test_07_lookalike_domain_high(self):
        r = detector.check_url("http://sbi-kyc-update-secure.xyz/login")
        self.assertEqual(r["level"], "High")

    def test_08_official_domain_low(self):
        r = detector.check_url("https://www.onlinesbi.sbi")
        self.assertEqual(r["level"], "Low")

    def test_09_ip_address_url(self):
        r = detector.check_url("http://192.168.10.5/verify")
        self.assertGreaterEqual(r["score"], 45)

    def test_10_shortener_flagged(self):
        r = detector.check_url("https://bit.ly/3abcXYZ")
        self.assertTrue(any(t["category"] == "Short link" for t in r["triggers"]))


class PhoneTests(unittest.TestCase):
    def test_11_reported_number_high(self):
        r = detector.check_phone("+91 90000 00001")
        self.assertEqual(r["level"], "High")
        self.assertEqual(r["reports"], 14)

    def test_12_unknown_valid_number_low(self):
        r = detector.check_phone("9876543210")
        self.assertEqual(r["level"], "Low")

    def test_13_invalid_number_flagged(self):
        r = detector.check_phone("12345")
        self.assertTrue(any(t["category"] == "Invalid format" for t in r["triggers"]))

    def test_14_international_number_flagged(self):
        r = detector.check_phone("+44 7911 123456")
        self.assertTrue(any(t["category"] == "International number" for t in r["triggers"]))

    def test_15_report_increases_count(self):
        before = detector.check_phone("9111122223")["reports"]
        database.report_number("9111122223", "Lottery / Prize Scam")
        after = detector.check_phone("9111122223")["reports"]
        self.assertEqual(after, before + 1)


class CombinedTests(unittest.TestCase):
    def test_16_extracts_url_and_phone(self):
        msg = ("Your electricity power will be disconnected tonight 9:30. "
               "Call 9000000007 or pay at http://bijli-bill-pay.top/now")
        r = detector.combined_check(msg)
        self.assertEqual(len(r["urls"]), 1)
        self.assertEqual(len(r["phones"]), 1)
        self.assertEqual(r["level"], "High")
        self.assertEqual(r["scam_type_key"], "electricity")
        self.assertTrue(r["family_alert"])

    def test_17_safe_message_has_no_family_alert(self):
        r = detector.combined_check("See you at the library tomorrow.")
        self.assertEqual(r["level"], "Low")
        self.assertEqual(r["family_alert"], "")

    def test_18_score_never_above_100(self):
        msg = ("URGENT turant OTP bhejo KYC update account blocked digital arrest lottery "
               "anydesk http://sbi-login.xyz call 9000000001")
        self.assertLessEqual(detector.combined_check(msg)["score"], 100)


if __name__ == "__main__":
    unittest.main()
