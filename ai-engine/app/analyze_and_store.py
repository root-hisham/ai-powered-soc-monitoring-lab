"""analyze_and_store.py  -  ai-powered-soc-monitoring-lab, Task 10

Analyze ONE alert with the local AI and save the result in the SQLite database.

Usage (PowerShell):
    py analyze_and_store.py                      # analyze samples\\alert_100100.json
    py analyze_and_store.py path\\to\\alert.json
    py analyze_and_store.py path\\to\\alert.json --replace   # analyze again, overwrite
    py analyze_and_store.py --list               # show saved results, no AI used

Rules:
  * An alert that is already saved is SKIPPED before the AI is called
    (saves 20-30 seconds). Use --replace to analyze it again.
  * If the analysis fails, nothing is saved as a result, but the failure is
    written to the analysis_errors table, so it is never silent.
"""

import json
import sys
from contextlib import closing
from pathlib import Path

import database
from analyze_alert import AnalysisError, analyze
from parse_alert import load_alert, parse_alert


def short(text, width):
    text = str(text if text is not None else "")
    return text if len(text) <= width else text[: width - 3] + "..."


def show_list(conn):
    total = database.count_analyses(conn)
    errors = database.count_errors(conn)
    print(f"Database: {database.DB_PATH}")
    print(f"Saved analyses: {total}    Logged errors: {errors}\n")

    rows = database.recent_analyses(conn, 10)
    if rows:
        print(f"{'ID':>3}  {'Time (UTC)':<19}  {'Alert ID':<20} {'Rule':<6} {'Lvl':>3}  "
              f"{'Severity':<19} {'Conf':<6}  Summary")
        for r in rows:
            print(f"{r['id']:>3}  {str(r['analyzed_at'])[:19].replace('T', ' '):<19}  "
                  f"{short(r['alert_id'], 20):<20} {short(r['rule_id'], 6):<6} "
                  f"{r['rule_level'] if r['rule_level'] is not None else '':>3}  "
                  f"{short(r['severity'], 19):<19} {short(r['confidence'], 6):<6}  "
                  f"{short(r['summary'], 60)}")
    else:
        print("No analyses saved yet.")

    errs = database.recent_errors(conn, 3)
    if errs:
        print("\nLatest errors:")
        for e in errs:
            print(f"  {e['occurred_at']}  {short(e['source'], 24)}  {short(e['message'], 90)}")


def main(argv):
    flags = [a for a in argv if a.startswith("--")]
    paths = [a for a in argv if not a.startswith("--")]
    default_path = Path(__file__).resolve().parents[2] / "samples" / "alert_100100.json"
    path = Path(paths[0]) if paths else default_path
    replace = "--replace" in flags

    with closing(database.connect()) as conn:
        if "--list" in flags:
            show_list(conn)
            return 0

        try:
            parsed = parse_alert(load_alert(path))
        except FileNotFoundError:
            print(f"File not found: {path}")
            return 1
        except (json.JSONDecodeError, ValueError) as error:
            database.log_error(conn, path.name, f"Not a valid alert file: {error}")
            print(f"This file is not a valid alert: {error}  (logged)")
            return 1

        alert_id = parsed["alert_id"] or path.stem

        if database.alert_exists(conn, alert_id) and not replace:
            print(f"Alert {alert_id} is already analyzed. Skipped (use --replace to redo it).")
            return 0

        print(f"Analyzing {path.name} ...", file=sys.stderr)
        try:
            result = analyze(path)
        except AnalysisError as error:
            database.log_error(conn, alert_id, str(error))
            print(f"ERROR: {error}  (logged)")
            return 1

        status = database.save_analysis(conn, result, replace=replace)
        print(f"Result: {status}. Alert {result['alert_id']} | "
              f"{result['analysis']['severity_assessment']} | "
              f"confidence {result['analysis']['confidence']}")
        print(f"Summary: {result['analysis']['summary']}")
        print("Run 'py analyze_and_store.py --list' to see all saved results.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
