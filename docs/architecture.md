# Architecture

## Overview

```
Windows 11 host (16 GB RAM, no GPU)                 VirtualBox: "soc-lab" NAT network
┌───────────────────────────────────┐               ┌─────────────────────────────┐
│                                     │               │  wazuh-server (10.0.3.9)     │
│  Ollama                            │   SSH :2222   │   - wazuh-manager             │
│  127.0.0.1:11434                   │◄─────────────►│   - wazuh-indexer             │
│  model: llama3.2:3b (CPU, 2.6 GB)  │  restricted   │   - wazuh-dashboard :8443      │
│                                     │  key, one     │   - user: socreader           │
│  ai-engine/app/                    │  forced       │     forced command only:      │
│   fetch_and_analyze.py ──┐         │  command      │     tail -n500 alerts.json    │
│   parse_alert.py ────────┤         │               └─────────────────────────────┘
│   analyze_alert.py ──────┤                          ┌─────────────────────────────┐
│   database.py ───────────┘                          │  ubuntu1 (10.0.3.7)          │
│        │                                             │   monitored endpoint         │
│        ▼                                             │   Wazuh agent                │
│  data/soc_ai.db (SQLite)                             └─────────────────────────────┘
│        │                                             ┌─────────────────────────────┐
│        ▼                                             │  kali (10.0.3.4)             │
│  dashboard/dashboard.py                              │   attacker (lab only)        │
│  127.0.0.1:8080, password, read-only                 └─────────────────────────────┘
└───────────────────────────────────┘
```

Only `wazuh-server` needs to be running for the AI pipeline. `ubuntu1` and
`kali` are only needed when generating new attack traffic to detect.

## Data flow, step by step

1. **An event happens** on `ubuntu1` (e.g. an SSH login attempt from `kali`).
2. **The Wazuh agent on ubuntu1** forwards the log to `wazuh-server`.
3. **wazuh-manager** decodes the log and checks it against its rules,
   including the custom rule `100100` (brute-force success, MITRE T1110,
   defined in the `wazuh-home-soc-lab` repo). A match becomes an alert,
   appended as one JSON line to `/var/ossec/logs/alerts/alerts.json`.
4. **`fetch_and_analyze.py`** (on the Windows host) runs `ssh` with the
   `socreader` key. The server-side forced command
   (`tail -n 500 alerts.json`) is the *only* thing that key can ever run.
5. **`select_alerts()`** inside `fetch_and_analyze.py` parses each line as
   JSON, drops anything invalid, keeps only alerts at or above
   `--min-level` (default 10), skips alerts already in the database, and
   sorts the rest by severity then recency.
6. For each new alert (capped at `--max`, default 3, to respect the CPU
   budget), **`parse_alert.py`** builds a small, cleaned version: only the
   fields the AI needs, secrets and emails redacted, control characters
   stripped, and a check for text that looks like an instruction aimed at
   an AI (`prompt_injection_suspected`).
7. **`analyze_alert.py`** builds a prompt that puts the cleaned alert
   inside `<alert_data>` tags with an explicit system instruction that this
   is data, never instructions, and sends it to Ollama's local HTTP API
   (`127.0.0.1:11434` only — this is enforced in code, see
   `check_url_is_local()`).
8. **Ollama runs `llama3.2:3b`** fully on the CPU (no GPU available) and
   returns a JSON answer matching a fixed schema (`format` parameter).
9. **`validate_answer()`** checks every field: severity must be one of 5
   exact values, confidence one of 3, every text field non-empty and
   redacted again. An invalid answer gets one retry; two failures become a
   logged error, never a guess.
10. **`apply_consistency_rules()`** fixes contradictions the model itself
    sometimes produces — for example forcing confidence to "Low" when the
    explanation is "Unknown", or capping confidence when an injection is
    suspected.
11. **`database.py`** stores the result in SQLite, tagged `source: 'live'`
    (vs `'sample'` for a saved test file), keyed uniquely on `alert_id` so
    the same alert is never analyzed twice.
12. **`dashboard.py`** reads the database **read-only** and renders an
    overview, a filterable list (all/live/sample), and a per-alert detail
    page, with every piece of text HTML-escaped.

## Why these components

| Component | Why this one |
|---|---|
| **Ollama + llama3.2:3b** | Free, runs fully offline on CPU, no data ever leaves the laptop. 3B is the largest model that stayed responsive (~18 tokens/s) without a GPU and within the RAM budget. |
| **SSH with a forced command**, not the Wazuh API | A compromised or buggy client can only ever run one read-only command — it cannot query, modify, or even see anything else on the server. See `docs/security.md`. |
| **SQLite** | Zero setup, a single file, good enough for a single-analyst home lab. No server process to secure. |
| **Python standard library HTTP server** for the dashboard, not a framework | Fewer dependencies to keep patched; the whole security surface (auth, escaping, headers) fits in one reviewable file. |
| **`unittest`** (standard library) for tests | No extra install needed to run `run_tests.py`. |

## File reference

| File | Role |
|---|---|
| `ai-engine/app/parse_alert.py` | Clean and redact one raw alert |
| `ai-engine/app/analyze_alert.py` | Prompt construction, Ollama call, validation, consistency rules |
| `ai-engine/app/database.py` | SQLite schema, save/read, old-database migration |
| `ai-engine/app/analyze_and_store.py` | CLI: analyze one alert file and store it (used for the sample alerts) |
| `ai-engine/app/fetch_and_analyze.py` | CLI: pull live alerts over SSH, filter, analyze the new ones |
| `ai-engine/app/tests/` | 96 automated tests covering all of the above, no VM or Ollama required |
| `dashboard/dashboard.py` | Local read-only web dashboard |
| `samples/alert_100100.json` | A real captured alert (the brute-force success) |
| `samples/alert_fake_injection.json` | A synthetic alert used to test prompt-injection resistance |
| `run_tests.py` | One-command test runner from the project root |
