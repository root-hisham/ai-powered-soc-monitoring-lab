"""fetch_and_analyze.py  -  ai-powered-soc-monitoring-lab, Task 12c

Reads the most recent Wazuh alerts from the wazuh-server VM over SSH, picks the
important NEW ones, analyzes them with the local AI, and stores the results as "live".

How it stays safe:
  * It connects with the restricted key (user "socreader"). That key can only run one
    server-side command: print the last 500 alert lines. It cannot do anything else.
  * ssh is started with a fixed argument list (no shell), so nothing from the network
    can become a command.
  * Everything received is treated as untrusted text. Lines that are not valid alerts
    are counted and ignored, and text printed to the screen is cleaned first.
  * Only alerts at or above --min-level are analyzed (default 10). This also keeps out
    the low-level noise, including the alerts created by this script's own SSH logins.
  * At most --max alerts are analyzed per run (default 3), because each one takes
    about 25-35 seconds on your CPU. Run it again to continue.
  * Alerts that are already stored are skipped BEFORE the AI is called.
  * Every failure is written to the analysis_errors table. Nothing fails silently.
  * It only reads. It never changes anything on the server.

Usage (PowerShell), with wazuh-server running:
    py fetch_and_analyze.py --dry-run              # fetch and list candidates, no AI
    py fetch_and_analyze.py                        # analyze up to 3 new alerts, level 10+
    py fetch_and_analyze.py --min-level 3 --max 2  # include low-level alerts (demo)
"""

import json
import os
import shutil
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import database
from analyze_alert import AnalysisError, analyze_raw
from parse_alert import clean_text

SSH_HOST = "127.0.0.1"
SSH_PORT = int(os.environ.get("SOC_SSH_PORT", "2222"))
SSH_USER = "socreader"
SSH_KEY = Path(os.environ.get("SOC_SSH_KEY", Path.home() / ".ssh" / "soc_reader"))
SSH_TIMEOUT = 60
MAX_BYTES = 5_000_000

DEFAULT_MIN_LEVEL = 10
DEFAULT_MAX_NEW = 3


class FetchError(Exception):
    """Could not get alerts from the server. The message is safe to show."""


def explain_ssh_error(stderr_text):
    text = stderr_text.lower()
    if "permission denied" in text:
        return "The server refused the key (Permission denied). Check the socreader key setup (Task 12b)."
    if "remote host identification has changed" in text or "host key verification failed" in text:
        return ("The server's identity check failed. If you rebuilt the VM, run: "
                'ssh-keygen -R "[127.0.0.1]:2222" then connect once with ssh as vboxuser.')
    if "refused" in text:
        return "Connection refused. Is the ssh service running on wazuh-server?"
    if "timed out" in text or "no route" in text:
        return ("Connection timed out. Is wazuh-server running, and does the port forward "
                "(127.0.0.1:2222) point to its current IP?")
    return "ssh failed: " + clean_text(stderr_text, 200)


def fetch_raw():
    """Run the restricted ssh command and return its output as text."""
    ssh = shutil.which("ssh")
    if not ssh:
        raise FetchError("The 'ssh' program was not found on this computer.")
    if not SSH_KEY.exists():
        raise FetchError(f"SSH key not found: {SSH_KEY}")

    command = [
        ssh, "-T",
        "-i", str(SSH_KEY),
        "-p", str(SSH_PORT),
        "-o", "BatchMode=yes",            # never ask for a password
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        f"{SSH_USER}@{SSH_HOST}",
    ]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=SSH_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise FetchError(f"The server did not answer within {SSH_TIMEOUT} seconds.")
    except OSError as error:
        raise FetchError(f"Could not start ssh: {error}")

    if completed.returncode != 0:
        raise FetchError(explain_ssh_error(completed.stderr.decode("utf-8", "replace")))
    if len(completed.stdout) > MAX_BYTES:
        raise FetchError("The server sent far more data than expected. Nothing was used.")
    return completed.stdout.decode("utf-8", "replace")


def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def select_alerts(lines, min_level, conn):
    """Split the received lines into counts and a list of alerts worth analyzing."""
    stats = {"received": 0, "invalid": 0, "below_level": 0, "already_done": 0}
    candidates, seen = [], set()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        stats["received"] += 1
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            stats["invalid"] += 1
            continue
        if not isinstance(raw, dict):
            stats["invalid"] += 1
            continue

        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        alert_id = raw.get("id")
        level = to_int(rule.get("level"))
        if not isinstance(alert_id, str) or not alert_id or level is None:
            stats["invalid"] += 1
            continue
        if level < min_level:
            stats["below_level"] += 1
            continue
        if alert_id in seen or database.alert_exists(conn, alert_id):
            stats["already_done"] += 1
            continue
        seen.add(alert_id)
        candidates.append((level, str(raw.get("timestamp", "")), alert_id, raw))

    # Most severe first, then newest first.
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return stats, candidates


def print_summary(stats, candidates, min_level):
    print(f"Lines received:            {stats['received']}")
    print(f"  not valid alerts:        {stats['invalid']}")
    print(f"  below level {min_level}:".ljust(29) + f"{stats['below_level']}")
    print(f"  already analyzed/duplicate: {stats['already_done']}")
    print(f"New alerts to analyze:     {len(candidates)}")


def print_candidates(candidates, limit=15):
    if not candidates:
        return
    print(f"\n{'Level':>5}  {'Time':<19}  {'Rule':<7}  Description")
    for level, timestamp, alert_id, raw in candidates[:limit]:
        rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
        shown_time = clean_text(timestamp, 40)[:19].replace("T", " ")
        print(f"{level:>5}  {shown_time:<19}  "
              f"{clean_text(rule.get('id'), 7):<7}  {clean_text(rule.get('description'), 70)}")
    if len(candidates) > limit:
        print(f"... and {len(candidates) - limit} more")


def read_number(args, flag, default, low, high):
    if flag not in args:
        return default
    position = args.index(flag)
    try:
        value = int(args[position + 1])
    except (IndexError, ValueError):
        raise SystemExit(f"{flag} needs a whole number.")
    if not low <= value <= high:
        raise SystemExit(f"{flag} must be between {low} and {high}.")
    return value


def main(argv):
    dry_run = "--dry-run" in argv
    min_level = read_number(argv, "--min-level", DEFAULT_MIN_LEVEL, 0, 15)
    max_new = read_number(argv, "--max", DEFAULT_MAX_NEW, 1, 20)

    with closing(database.connect()) as conn:
        print("Fetching recent alerts from wazuh-server ...", file=sys.stderr)
        try:
            text = fetch_raw()
        except FetchError as error:
            database.log_error(conn, "fetch", str(error))
            print(f"ERROR: {error}  (logged)")
            return 1

        stats, candidates = select_alerts(text.splitlines(), min_level, conn)
        print_summary(stats, candidates, min_level)
        print_candidates(candidates)

        if dry_run:
            print("\nDry run: the AI was not used and nothing was saved.")
            return 0
        if not candidates:
            print("\nNothing new to analyze.")
            return 0

        chosen = candidates[:max_new]
        analyzed = failed = 0
        for level, _timestamp, alert_id, raw in chosen:
            print(f"\nAnalyzing {clean_text(alert_id, 40)} (level {level}) ...", file=sys.stderr)
            try:
                result = analyze_raw(raw)
            except AnalysisError as error:
                database.log_error(conn, alert_id, str(error))
                print(f"ERROR: {error}  (logged)")
                failed += 1
                if "Cannot reach Ollama" in str(error):
                    break  # the same problem would repeat for every alert
                continue
            status = database.save_analysis(conn, result, source="live")
            analyzed += 1
            analysis = result["analysis"]
            print(f"Result: {status} | {analysis['severity_assessment']} | "
                  f"confidence {analysis['confidence']}")
            print(f"Summary: {analysis['summary']}")

        left = len(candidates) - analyzed - failed
        print(f"\nDone. Analyzed: {analyzed}   Failed: {failed}   Still waiting: {max(left, 0)}")
        if left > 0:
            print("Run the command again to analyze the next ones.")
        return 0 if analyzed or not failed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
