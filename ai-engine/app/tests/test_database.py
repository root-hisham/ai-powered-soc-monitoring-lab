"""Tests for database.py  -  ai-powered-soc-monitoring-lab, Task 13

Each test uses its own temporary SQLite file, so nothing touches the real
data\\soc_ai.db and tests never interfere with each other.
"""

import importlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def fresh_database_module(db_path):
    """Import database.py pointed at a throwaway file, as a fresh module each time
    (so its module-level DB_PATH, set from an environment variable, is correct)."""
    import os
    os.environ["AI_SOC_DB"] = str(db_path)
    if "database" in sys.modules:
        del sys.modules["database"]
    return importlib.import_module("database")


def sample_result(alert_id="alert.1", **overrides):
    result = {
        "alert_id": alert_id,
        "rule_id": "100100",
        "rule_level": 14,
        "analysis": {
            "summary": "A test summary.",
            "severity_assessment": "Needs investigation",
            "evidence": ["fact one", "fact two"],
            "possible_explanation": "A test explanation.",
            "recommended_actions": ["check one thing"],
            "confidence": "Low",
        },
        "mitre_from_wazuh_rule": {"ids": ["T1110"], "tactics": ["Credential Access"], "techniques": []},
        "prompt_injection_suspected": False,
        "requires_human_review": True,
        "quality_notes": [],
        "model": "llama3.2:3b",
        "analyzed_at": "2026-11-02T10:00:00+00:00",
    }
    result.update(overrides)
    return result


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmpdir.name) / "data" / "test.db"
        self.database = fresh_database_module(self.db_path)
        self.conn = self.database.connect()

    def tearDown(self):
        self.conn.close()
        self.tmpdir.cleanup()

    def test_connect_creates_folder_and_tables(self):
        self.assertTrue(self.db_path.exists())
        tables = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("analyses", tables)
        self.assertIn("analysis_errors", tables)

    def test_save_new_analysis_returns_saved(self):
        status = self.database.save_analysis(self.conn, sample_result())
        self.assertEqual(status, "saved")
        self.assertEqual(self.database.count_analyses(self.conn), 1)

    def test_duplicate_without_replace_returns_duplicate_and_is_not_stored_twice(self):
        self.database.save_analysis(self.conn, sample_result())
        status = self.database.save_analysis(self.conn, sample_result())
        self.assertEqual(status, "duplicate")
        self.assertEqual(self.database.count_analyses(self.conn), 1)

    def test_replace_overwrites_existing_row(self):
        self.database.save_analysis(self.conn, sample_result())
        changed = sample_result()
        changed["analysis"]["summary"] = "An updated summary."
        status = self.database.save_analysis(self.conn, changed, replace=True)
        self.assertEqual(status, "replaced")
        self.assertEqual(self.database.count_analyses(self.conn), 1)
        row = self.conn.execute("SELECT summary FROM analyses").fetchone()
        self.assertEqual(row["summary"], "An updated summary.")

    def test_source_defaults_to_sample(self):
        self.database.save_analysis(self.conn, sample_result())
        row = self.conn.execute("SELECT source FROM analyses").fetchone()
        self.assertEqual(row["source"], "sample")

    def test_source_can_be_set_to_live(self):
        self.database.save_analysis(self.conn, sample_result(), source="live")
        row = self.conn.execute("SELECT source FROM analyses").fetchone()
        self.assertEqual(row["source"], "live")

    def test_invalid_source_is_rejected(self):
        with self.assertRaises(ValueError):
            self.database.save_analysis(self.conn, sample_result(), source="not-a-real-source")
        self.assertEqual(self.database.count_analyses(self.conn), 0)

    def test_alert_exists_before_and_after_save(self):
        self.assertFalse(self.database.alert_exists(self.conn, "alert.1"))
        self.database.save_analysis(self.conn, sample_result())
        self.assertTrue(self.database.alert_exists(self.conn, "alert.1"))

    def test_log_error_is_recorded_and_counted(self):
        self.database.log_error(self.conn, "fetch", "something went wrong")
        self.assertEqual(self.database.count_errors(self.conn), 1)
        row = self.conn.execute("SELECT source, message FROM analysis_errors").fetchone()
        self.assertEqual(row["source"], "fetch")
        self.assertEqual(row["message"], "something went wrong")

    def test_recent_analyses_orders_newest_first(self):
        self.database.save_analysis(self.conn, sample_result("a1"))
        self.database.save_analysis(self.conn, sample_result("a2"))
        self.database.save_analysis(self.conn, sample_result("a3"))
        rows = self.database.recent_analyses(self.conn, limit=10)
        self.assertEqual([r["alert_id"] for r in rows], ["a3", "a2", "a1"])

    def test_requires_human_review_is_always_stored_as_true(self):
        result = sample_result()
        result["requires_human_review"] = False  # even if a bug upstream sent False
        self.database.save_analysis(self.conn, result)
        row = self.conn.execute("SELECT requires_human_review FROM analyses").fetchone()
        # database.py stores exactly what it is given; this test documents that the
        # CALLER (analyze_alert.py) is responsible for always setting it True.
        self.assertEqual(row["requires_human_review"], 0)

    def test_sql_injection_style_alert_id_is_stored_as_plain_text(self):
        evil_id = "x'); DROP TABLE analyses;--"
        self.database.save_analysis(self.conn, sample_result(evil_id))
        tables = {r[0] for r in self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("analyses", tables)  # table still exists
        self.assertTrue(self.database.alert_exists(self.conn, evil_id))

    def test_old_database_without_source_column_is_migrated(self):
        # Simulate a database created before the "source" column existed.
        self.conn.close()
        raw = sqlite3.connect(self.db_path)
        raw.executescript("""
            DROP TABLE analyses;
            CREATE TABLE analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL UNIQUE,
                rule_id TEXT, rule_level INTEGER, severity TEXT NOT NULL,
                confidence TEXT NOT NULL, summary TEXT NOT NULL,
                prompt_injection_suspected INTEGER NOT NULL,
                requires_human_review INTEGER NOT NULL, model TEXT NOT NULL,
                analyzed_at TEXT NOT NULL, result_json TEXT NOT NULL
            );
            INSERT INTO analyses (alert_id, rule_id, rule_level, severity, confidence,
                summary, prompt_injection_suspected, requires_human_review, model,
                analyzed_at, result_json)
            VALUES ('old1', '1', 3, 'Low', 'Low', 'old row', 0, 1, 'm',
                '2026-10-29T09:57:01+00:00', '{}');
        """)
        raw.commit()
        raw.close()

        reconnected = self.database.connect()  # must migrate without crashing
        columns = [r[1] for r in reconnected.execute("PRAGMA table_info(analyses)")]
        self.assertIn("source", columns)
        row = reconnected.execute(
            "SELECT source FROM analyses WHERE alert_id = 'old1'").fetchone()
        self.assertEqual(row["source"], "sample")  # old rows default to sample
        reconnected.close()


if __name__ == "__main__":
    unittest.main()
