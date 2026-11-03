"""parse_alert.py  -  ai-powered-soc-monitoring-lab, Task 8

Reads ONE Wazuh alert (a JSON file) and prints a small, cleaned version of it.
This cleaned version is what we will later give to the AI model, never the raw alert.

What it does:
  1. Accepts both alert shapes: the dashboard export (fields inside "_source")
     and the raw alerts.json line (fields at the top level).
  2. Keeps only the fields the AI needs.
  3. Cleans text: removes control characters, hides password-like values and
     email addresses, and cuts very long text.
  4. Flags log text that looks like an attempt to give instructions to an AI.
  5. Lists which important fields are missing, instead of crashing.

It does NOT call the AI, does NOT touch Wazuh, and does NOT change any file.

Usage (PowerShell):
    py parse_alert.py                      # uses samples\\alert_100100.json
    py parse_alert.py path\\to\\alert.json
"""

import json
import re
import sys
from pathlib import Path

MAX_LOG_CHARS = 500  # longest piece of log text we keep

# Things like "password=abc123" or "token: xyz" -> value is hidden
SECRET_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\b(\s*[=:]\s*)\S+"
)
EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# Phrases that suggest someone wrote instructions for an AI inside a log.
# We only FLAG them. The AI prompt (later) will also treat all log text as data.
INJECTION_HINTS = [
    "ignore previous",
    "ignore all",
    "ignore the above",
    "disregard",
    "system prompt",
    "you are now",
    "new instructions",
    "reveal your",
]

REQUIRED_FIELDS = [
    "rule_id",
    "rule_level",
    "rule_description",
    "agent_name",
]  # plus: the alert needs full_log OR details (checked below)


def load_alert(path):
    """Read one JSON object from a file and return the alert dictionary."""
    with open(path, encoding="utf-8") as f:
        data = json.loads(f.read().strip())
    if not isinstance(data, dict):
        raise ValueError("The file must contain one JSON object.")
    inner = data.get("_source")
    return inner if isinstance(inner, dict) else data


def dig(data, *path):
    """Safely read data["a"]["b"]... and return None if any step is missing."""
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def clean_text(value, limit=MAX_LOG_CHARS):
    """Make text safer: no control characters, secrets hidden, length limited."""
    if value is None:
        return None
    text = CONTROL_CHARS.sub(" ", str(value))
    text = re.sub(r"\s+", " ", text).strip()
    text = SECRET_PATTERN.sub(r"\1\2[REDACTED]", text)
    text = EMAIL_PATTERN.sub("[EMAIL]", text)
    if len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return text


def as_list(value):
    """Turn None / a single value / a list into a clean list of short strings."""
    if value is None:
        return []
    if not isinstance(value, list):
        value = [value]
    return [clean_text(item, 100) for item in value]


def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


MAX_DETAIL_ITEMS = 20
MAX_DETAIL_CHARS = 160
# Parts of "data" that are already shown as separate fields, or add only noise.
SKIP_DETAIL_KEYS = {"data.srcip", "data.srcport", "data.dstuser"}
NOISY_KEY_NAMES = {"compliance", "scan_id", "references"}


def flatten_details(raw):
    """Turn the 'data' (and 'syscheck') part of an alert into short 'key: value' lines.

    Used ONLY for alerts that have no full_log text (for example compliance scans),
    so the AI still gets the facts. Every line is cleaned like any other alert text.
    """
    items = []

    def walk(value, path, depth):
        if len(items) >= MAX_DETAIL_ITEMS or path in SKIP_DETAIL_KEYS:
            return
        if isinstance(value, dict):
            if depth >= 5:
                return
            for key, inner in value.items():
                if str(key) in NOISY_KEY_NAMES:
                    continue
                walk(inner, f"{path}.{key}", depth + 1)
        elif isinstance(value, list):
            scalars = [str(v) for v in value[:5] if isinstance(v, (str, int, float, bool))]
            if scalars:
                items.append(f"{path}: {', '.join(scalars)}")
        elif isinstance(value, (str, int, float, bool)):
            items.append(f"{path}: {value}")

    for name in ("data", "syscheck"):
        root = raw.get(name)
        if isinstance(root, dict):
            walk(root, name, 0)
    return [clean_text(item, MAX_DETAIL_CHARS) for item in items[:MAX_DETAIL_ITEMS]]


def parse_alert(raw):
    """Return the small, cleaned alert that is safe to give to the AI."""
    full_log = clean_text(dig(raw, "full_log"))
    details = [] if full_log else flatten_details(raw)
    lowered = ((full_log or "") + " " + " ".join(details)).lower()
    hints_found = [hint for hint in INJECTION_HINTS if hint in lowered]

    parsed = {
        "alert_id": clean_text(dig(raw, "id"), 100),
        "timestamp": clean_text(dig(raw, "timestamp"), 100),
        "rule_id": clean_text(dig(raw, "rule", "id"), 20),
        "rule_level": to_int(dig(raw, "rule", "level")),
        "rule_description": clean_text(dig(raw, "rule", "description"), 200),
        "rule_groups": as_list(dig(raw, "rule", "groups")),
        "mitre_ids": as_list(dig(raw, "rule", "mitre", "id")),
        "mitre_tactics": as_list(dig(raw, "rule", "mitre", "tactic")),
        "mitre_techniques": as_list(dig(raw, "rule", "mitre", "technique")),
        "agent_name": clean_text(dig(raw, "agent", "name"), 100),
        "agent_id": clean_text(dig(raw, "agent", "id"), 20),
        "source_ip": clean_text(dig(raw, "data", "srcip"), 100),
        "source_port": clean_text(dig(raw, "data", "srcport"), 20),
        "target_user": clean_text(dig(raw, "data", "dstuser"), 100),
        "full_log": full_log,
        "details": details,
        "prompt_injection_suspected": bool(hints_found),
        "injection_hints_found": hints_found,
    }
    parsed["missing_fields"] = [
        name for name in REQUIRED_FIELDS if parsed[name] in (None, "", [])
    ]
    if not parsed["full_log"] and not parsed["details"]:
        parsed["missing_fields"].append("full_log/details")
    return parsed


def main():
    # Default sample: <project>/samples/alert_100100.json
    # This file lives in <project>/ai-engine/app/, so the project root is 2 levels up.
    default_path = Path(__file__).resolve().parents[2] / "samples" / "alert_100100.json"
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else default_path

    try:
        raw = load_alert(path)
    except FileNotFoundError:
        print(f"File not found: {path}")
        return 1
    except (json.JSONDecodeError, ValueError) as error:
        print(f"This file is not a valid alert: {error}")
        return 1

    print(json.dumps(parse_alert(raw), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
