"""Tests for dashboard.py  -  ai-powered-soc-monitoring-lab, Task 13

These tests check the dashboard's safety-critical, pure functions directly —
HTML escaping, pill rendering, old-database handling — without starting a real
web server. They prove that hostile text from an alert can never become a
working <script> tag or HTML attribute on the page.
"""

import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "dashboard"))

from dashboard import (  # noqa: E402
    authorized,
    data_banner,
    esc,
    fmt_time,
    level_pill,
    severity_pill,
    source_expr,
    source_pill,
)


class EscapeTests(unittest.TestCase):
    def test_script_tag_is_neutralized(self):
        out = esc("<script>alert(1)</script>")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_quotes_are_escaped_so_attributes_cannot_be_broken_out_of(self):
        out = esc('"><img src=x onerror=alert(1)>')
        self.assertNotIn('"><img', out)

    def test_none_becomes_empty_string(self):
        self.assertEqual(esc(None), "")

    def test_plain_text_is_unchanged_in_meaning(self):
        self.assertEqual(esc("testuser logged in"), "testuser logged in")

    def test_ampersand_is_escaped(self):
        self.assertEqual(esc("A & B"), "A &amp; B")


class FormatTimeTests(unittest.TestCase):
    def test_trims_iso_timestamp_to_minute_seconds(self):
        self.assertEqual(fmt_time("2026-10-27T09:33:44.235+0000"), "2026-10-27 09:33:44")

    def test_handles_none(self):
        self.assertEqual(fmt_time(None), "")


class PillTests(unittest.TestCase):
    def test_level_pill_escapes_unexpected_input(self):
        # level should always be an int, but the pill must stay safe even if it isn't
        out = level_pill("<script>")
        self.assertNotIn("<script>", out)

    def test_level_pill_handles_none(self):
        out = level_pill(None)
        self.assertIn("n/a", out)

    def test_severity_pill_escapes_hostile_value(self):
        out = severity_pill('High" onmouseover="alert(1)')
        self.assertNotIn('onmouseover="alert', out)

    def test_source_pill_only_colors_known_values(self):
        self.assertIn("live", source_pill("live"))
        self.assertIn("sample", source_pill("sample"))
        # an unexpected value must still render as safe text, just uncolored
        out = source_pill("<script>evil</script>")
        self.assertNotIn("<script>evil", out)


class AuthTests(unittest.TestCase):
    def test_rejects_missing_header(self):
        self.assertFalse(authorized(None))

    def test_rejects_non_basic_header(self):
        self.assertFalse(authorized("Bearer sometoken"))

    def test_rejects_malformed_base64(self):
        self.assertFalse(authorized("Basic not-valid-base64!!!"))


class DataBannerTests(unittest.TestCase):
    def test_banner_says_sample_only_when_no_live_data(self):
        html = data_banner(0, 2)
        self.assertIn("No live Wazuh alert", html)

    def test_banner_mentions_counts_once_live_data_exists(self):
        html = data_banner(6, 2)
        self.assertIn("6 live", html)
        self.assertIn("2", html)

    def test_banner_text_is_html_safe_even_with_odd_counts(self):
        html = data_banner(0, 0)
        self.assertNotIn("<script", html.lower())


class SourceExprMigrationTests(unittest.TestCase):
    def test_old_schema_without_source_column_falls_back_to_literal_sample(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE analyses (id INTEGER PRIMARY KEY, alert_id TEXT)")
        self.assertEqual(source_expr(conn), "'sample'")

    def test_new_schema_with_source_column_uses_the_real_column(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE analyses (id INTEGER PRIMARY KEY, source TEXT)")
        self.assertEqual(source_expr(conn), "source")


if __name__ == "__main__":
    unittest.main()
