"""database.py  -  ai-powered-soc-monitoring-lab, Task 10

Stores AI analyses (and analysis errors) in a small SQLite file.
SQLite is built into Python, so nothing needs to be installed.

Security notes:
  * Every SQL command uses "?" placeholders. Alert text is NEVER pasted into SQL,
    so a malicious log cannot change what the database does.
  * Failed analyses are recorded in their own table, so a failure is never silent.
  * The database file lives in <project>\\data\\ and must NOT be uploaded to GitHub.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "soc_ai.db"
DB_PATH = Path(os.environ.get("AI_SOC_DB", DEFAULT_DB))

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id                         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id                   TEXT    NOT NULL UNIQUE,
    rule_id                    TEXT,
    rule_level                 INTEGER,
    severity                   TEXT    NOT NULL,
    confidence                 TEXT    NOT NULL,
    summary                    TEXT    NOT NULL,
    prompt_injection_suspected INTEGER NOT NULL,
    requires_human_review      INTEGER NOT NULL,
    model                      TEXT    NOT NULL,
    analyzed_at                TEXT    NOT NULL,
    result_json                TEXT    NOT NULL,
    source                     TEXT    NOT NULL DEFAULT 'sample'
);

CREATE TABLE IF NOT EXISTS analysis_errors (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    message     TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
"""


def connect():
    """Open the database (creating the folder, file and tables if needed)."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    migrate(conn)
    return conn


def migrate(conn):
    """Older databases have no 'source' column. Add it; existing rows count as 'sample'."""
    columns = [row[1] for row in conn.execute("PRAGMA table_info(analyses)")]
    if "source" not in columns:
        with conn:
            conn.execute(
                "ALTER TABLE analyses ADD COLUMN source TEXT NOT NULL DEFAULT 'sample'"
            )


def alert_exists(conn, alert_id):
    row = conn.execute(
        "SELECT 1 FROM analyses WHERE alert_id = ?", (alert_id,)
    ).fetchone()
    return row is not None


VALID_SOURCES = ("sample", "live")


def save_analysis(conn, result, replace=False, source="sample"):
    """Save one result. Returns 'saved', 'replaced' or 'duplicate'.

    source is 'sample' (an alert file saved by hand) or 'live' (fetched from Wazuh).
    """
    if source not in VALID_SOURCES:
        raise ValueError(f"source must be one of {VALID_SOURCES}")
    analysis = result["analysis"]
    values = (
        result["alert_id"],
        result.get("rule_id"),
        result.get("rule_level"),
        analysis["severity_assessment"],
        analysis["confidence"],
        analysis["summary"],
        int(bool(result["prompt_injection_suspected"])),
        int(bool(result["requires_human_review"])),
        result["model"],
        result["analyzed_at"],
        json.dumps(result, ensure_ascii=False),
        source,
    )
    existed = alert_exists(conn, result["alert_id"])
    if existed and not replace:
        return "duplicate"

    with conn:  # one transaction: all of it happens, or none of it
        if existed:
            conn.execute("DELETE FROM analyses WHERE alert_id = ?", (result["alert_id"],))
        conn.execute(
            """INSERT INTO analyses
               (alert_id, rule_id, rule_level, severity, confidence, summary,
                prompt_injection_suspected, requires_human_review, model,
                analyzed_at, result_json, source)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
        )
    return "replaced" if existed else "saved"


def log_error(conn, source, message):
    with conn:
        conn.execute(
            "INSERT INTO analysis_errors (source, message, occurred_at) VALUES (?, ?, ?)",
            (
                str(source)[:200],
                str(message)[:500],
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
        )


def count_analyses(conn):
    return conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]


def count_errors(conn):
    return conn.execute("SELECT COUNT(*) FROM analysis_errors").fetchone()[0]


def recent_analyses(conn, limit=10):
    return conn.execute(
        """SELECT id, analyzed_at, alert_id, rule_id, rule_level, severity,
                  confidence, summary
           FROM analyses ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def recent_errors(conn, limit=3):
    return conn.execute(
        "SELECT occurred_at, source, message FROM analysis_errors ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
