"""
Test cases for the helper chatbot and the Scam Simulator.
Run from the project folder:   python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database  # noqa: E402

database.DB_PATH = os.path.join(tempfile.mkdtemp(), "test_chat.db")
database.init_db()

import chatbot  # noqa: E402


class HelperBotTests(unittest.TestCase):
    def test_20_otp_question(self):
        r = chatbot.chat_reply("OTP kya hota hai?")
        self.assertEqual(r["intent"], "otp")

    def test_21_digital_arrest_question(self):
        r = chatbot.chat_reply("digital arrest kya hota hai")
        self.assertEqual(r["intent"], "digital_arrest")

    def test_22_report_helpline_mentions_1930(self):
        r = chatbot.chat_reply("fraud report kahan karein")
        self.assertIn("1930", r["reply"])

    def test_23_empty_message(self):
        r = chatbot.chat_reply("   ")
        self.assertTrue(r["suggestions"])

    def test_24_unknown_question_falls_back(self):
        r = chatbot.chat_reply("asdf qwerty zxcv")
        self.assertIn("samajh nahi aaya", r["reply"])

    def test_25_pasted_scam_is_analysed(self):
        r = chatbot.chat_reply("Your account will be blocked. Update KYC at http://sbi-kyc.xyz now")
        self.assertIn("analysis", r)
        self.assertEqual(r["analysis"]["level"], "High")

    def test_26_pasted_number_is_analysed(self):
        r = chatbot.chat_reply("is number ka check karo 9000000001")
        self.assertIn("analysis", r)


class SimulatorTests(unittest.TestCase):
    def test_27_all_scenarios_have_one_safe_option_per_step(self):
        for sid, sc in chatbot.SCENARIOS.items():
            for step in sc["steps"]:
                self.assertEqual(sorted(o["risk"] for o in step["options"]), [0, 1, 2], sid)

    def test_28_start_hides_answers(self):
        out = chatbot.start_scenario("kyc")
        for opt in out["first"]["options"]:
            self.assertNotIn("risk", opt)
            self.assertNotIn("feedback", opt)

    def test_29_perfect_run_scores_100(self):
        sid = "kyc"
        answers = []
        res = None
        for i in range(len(chatbot.SCENARIOS[sid]["steps"])):
            res = chatbot.answer_step(sid, i, 0, answers)
            answers.append(0)
        self.assertTrue(res["finished"])
        self.assertEqual(res["summary"]["score"], 100)
        self.assertEqual(res["summary"]["fell_for"], [])

    def test_30_worst_run_scores_0_and_lists_mistakes(self):
        sid = "digital_arrest"
        n = len(chatbot.SCENARIOS[sid]["steps"])
        answers, res = [], None
        for i in range(n):
            res = chatbot.answer_step(sid, i, 2, answers)
            answers.append(2)
        self.assertEqual(res["summary"]["score"], 0)
        self.assertEqual(len(res["summary"]["fell_for"]), n)

    def test_31_bad_input_returns_none(self):
        self.assertIsNone(chatbot.answer_step("nope", 0, 0, []))
        self.assertIsNone(chatbot.answer_step("kyc", 99, 0, []))
        self.assertIsNone(chatbot.answer_step("kyc", 0, 7, []))


if __name__ == "__main__":
    unittest.main()
