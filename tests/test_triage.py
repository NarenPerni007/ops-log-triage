import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from log_triage import rule_based_triage, triage


class TestRuleBasedTriage(unittest.TestCase):
    def test_oom_matches(self):
        result = rule_based_triage("container OOMKilled: memory limit reached")
        self.assertEqual(result["severity"], "high")
        self.assertIn("memory", result["likely_cause"].lower())
        self.assertFalse(result["ai_used"])

    def test_connection_refused_matches(self):
        result = rule_based_triage("dial tcp 10.0.0.5:5432: connect: connection refused")
        self.assertEqual(result["severity"], "high")
        self.assertIn("not listening", result["likely_cause"])

    def test_timeout_matches(self):
        result = rule_based_triage("request failed: context deadline exceeded")
        self.assertEqual(result["severity"], "medium")

    def test_disk_full_matches(self):
        result = rule_based_triage("write failed: No space left on device")
        self.assertEqual(result["severity"], "high")

    def test_no_match_returns_low_severity(self):
        result = rule_based_triage("everything looks normal here")
        self.assertEqual(result["severity"], "low")
        self.assertIsNone(result["matched_rule"])

    def test_triage_without_key_uses_rules(self):
        os.environ.pop("LLM_API_KEY", None)
        result = triage({"logs": "pod CrashLoopBackOff, back-off restarting failed container"})
        self.assertFalse(result["ai_used"])
        self.assertEqual(result["severity"], "high")

    def test_triage_with_empty_logs(self):
        result = triage({"logs": ""})
        self.assertEqual(result["severity"], "low")
        self.assertFalse(result["ai_used"])


if __name__ == "__main__":
    unittest.main()
