"""Tests for fetch_and_analyze.py  -  ai-powered-soc-monitoring-lab, Task 13

These tests do NOT connect to the real wazuh-server and do NOT call the AI.
They check the filtering logic that decides which alert lines are worth
analyzing — the part most likely to break silently on real-world messy data.
"""

import importlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def fresh_modules(db_path):
    import os
    os.environ["AI_SOC_DB"] = str(db_path)
    for name in ("database", "fetch_and_analyze"):
        if name in sys.modules:
            del sys.modules[name]
    database = importlib.import_module("database")
    fetch = importlib.import_module("fetch_and_analyze")
    return database, fetch


ALERT_HIGH = (
    '{"id":"a1","timestamp":"2026-11-02T05:59:23.000+0000",'
    '"rule":{"id":"100100","level":14,"description":"brute force success"},'
    '"agent":{"id":"001","name":"u"},"data":{"srcip":"10.0.3.4","dstuser":"testuser"},'
    '"full_log":"Accepted password"}'
)
ALERT_LOW = (
    '{"id":"a2","timestamp":"2026-11-02T05:58:00.000+0000",'
    '"rule":{"id":"5501","level":3,"description":"PAM session opened"},'
    '"agent":{"id":"001","name":"u"},"full_log":"session opened"}'
)
ALERT_STRING_LEVEL = (
    '{"id":"a3","timestamp":"2026-11-02T05:57:00.000+0000",'
    '"rule":{"id":"19014","level":"9","description":"CIS check failed"},'
    '"agent":{"id":"000","name":"w"},"data":{"sca":{"check":{"result":"failed"}}}}'
)


class FetchAndAnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        db_path = Path(self.tmpdir.name) / "data" / "test.db"
        self.database, self.fetch = fresh_modules(db_path)
        self.conn = self.database.connect()

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_select_alerts_keeps_only_alerts_at_or_above_min_level(self):
        lines = [ALERT_HIGH, ALERT_LOW]
        stats, candidates = self.fetch.select_alerts(lines, min_level=10, conn=self.conn)
        self.assertEqual(stats["received"], 2)
        self.assertEqual(stats["below_level"], 1)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][2], "a1")

    def test_select_alerts_skips_already_stored_alerts(self):
        result = {
            "alert_id": "a1", "rule_id": "100100", "rule_level": 14,
            "analysis": {"summary": "s", "severity_assessment": "Low", "confidence": "Low",
                        "evidence": ["e"], "possible_explanation": "p", "recommended_actions": ["a"]},
            "prompt_injection_suspected": False, "requires_human_review": True,
            "model": "m", "analyzed_at": "2026-11-02T06:00:00+00:00",
        }
        self.database.save_analysis(self.conn, result, source="live")
        stats, candidates = self.fetch.select_alerts([ALERT_HIGH], min_level=10, conn=self.conn)
        self.assertEqual(stats["already_done"], 1)
        self.assertEqual(len(candidates), 0)

    def test_select_alerts_ignores_blank_lines(self):
        stats, candidates = self.fetch.select_alerts(
            ["", "   ", ALERT_HIGH, ""], min_level=10, conn=self.conn)
        self.assertEqual(stats["received"], 1)  # blank lines are not even counted

    def test_select_alerts_counts_invalid_lines_separately(self):
        stats, candidates = self.fetch.select_alerts(
            ["not json at all", "[1,2,3]", ALERT_HIGH], min_level=10, conn=self.conn)
        self.assertEqual(stats["invalid"], 2)
        self.assertEqual(len(candidates), 1)

    def test_select_alerts_deduplicates_repeated_alert_ids_in_one_batch(self):
        stats, candidates = self.fetch.select_alerts(
            [ALERT_HIGH, ALERT_HIGH], min_level=10, conn=self.conn)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(stats["already_done"], 1)

    def test_select_alerts_accepts_level_given_as_a_string(self):
        stats, candidates = self.fetch.select_alerts(
            [ALERT_STRING_LEVEL], min_level=9, conn=self.conn)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][0], 9)

    def test_select_alerts_orders_most_severe_and_newest_first(self):
        older_high = ALERT_HIGH.replace("a1", "a1b").replace(
            "2026-11-02T05:59:23.000+0000", "2026-11-01T00:00:00.000+0000")
        stats, candidates = self.fetch.select_alerts(
            [ALERT_LOW, older_high, ALERT_HIGH], min_level=0, conn=self.conn)
        # Highest level first; among equal levels, newest timestamp first.
        self.assertEqual(candidates[0][2], "a1")     # level 14, newest
        self.assertEqual(candidates[1][2], "a1b")    # level 14, older
        self.assertEqual(candidates[2][2], "a2")     # level 3

    def test_read_number_accepts_default_when_flag_absent(self):
        self.assertEqual(self.fetch.read_number([], "--max", 3, 1, 20), 3)

    def test_read_number_reads_given_value(self):
        self.assertEqual(self.fetch.read_number(["--max", "7"], "--max", 3, 1, 20), 7)

    def test_read_number_rejects_out_of_range_value(self):
        with self.assertRaises(SystemExit):
            self.fetch.read_number(["--max", "999"], "--max", 3, 1, 20)

    def test_read_number_rejects_non_numeric_value(self):
        with self.assertRaises(SystemExit):
            self.fetch.read_number(["--max", "abc"], "--max", 3, 1, 20)

    def test_explain_ssh_error_recognizes_permission_denied(self):
        msg = self.fetch.explain_ssh_error("socreader@127.0.0.1: Permission denied (publickey).")
        self.assertIn("Permission denied", msg)

    def test_explain_ssh_error_recognizes_connection_refused(self):
        msg = self.fetch.explain_ssh_error("ssh: connect to host 127.0.0.1 port 2222: Connection refused")
        self.assertIn("refused", msg.lower())

    def test_explain_ssh_error_has_a_fallback_for_unknown_errors(self):
        msg = self.fetch.explain_ssh_error("some completely unexpected error text")
        self.assertTrue(msg)  # never returns empty, so the user always sees something


if __name__ == "__main__":
    unittest.main()
