"""dashboard.py  -  ai-powered-soc-monitoring-lab, Task 11

A small web dashboard that shows the AI analyses stored in the SQLite database.

Security design (read this, it is part of the project's documentation):
  * Listens ONLY on 127.0.0.1 (this computer). It cannot be reached from the network.
  * Needs a password (HTTP Basic login). The password comes from the environment
    variable DASHBOARD_PASSWORD. It is never written in the code or saved in Git.
  * Opens the database READ-ONLY. The dashboard cannot change or delete results.
  * Every piece of text from the database is HTML-escaped before it is shown, and the
    page sends a Content-Security-Policy that forbids ALL scripts. A malicious log
    line therefore cannot run code in your browser.
  * Requests whose Host header is not 127.0.0.1 / localhost are refused
    (protects against DNS-rebinding tricks).
  * It shows only what is stored. Nothing is invented, and the page says clearly
    that the data comes from sample alert files until a live feed is connected.

Usage (PowerShell):
    $env:DASHBOARD_PASSWORD = "choose-a-password-of-8-or-more-characters"
    py dashboard.py
Then open http://127.0.0.1:8080  (username: analyst). Stop with Ctrl+C.
"""

import base64
import hmac
import html
import json
import os
import re
import sqlite3
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

HOST = "127.0.0.1"
PORT = int(os.environ.get("DASHBOARD_PORT", "8080"))
USERNAME = "analyst"
PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
DB_PATH = Path(
    os.environ.get("AI_SOC_DB", Path(__file__).resolve().parents[1] / "data" / "soc_ai.db")
)
OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"
MODEL = "llama3.2:3b"
HIGH_LEVEL = 12  # Wazuh rule level treated as "high severity"
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")

SEVERITY_CLASS = {
    "Informational": "s0",
    "Low": "s1",
    "Needs investigation": "s2",
    "High": "s3",
    "Critical": "s4",
}

CSS = """
:root{color-scheme:dark;--bg:#0d1117;--card:#161b22;--line:#30363d;--text:#e6edf3;--mute:#8b949e;--accent:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif}
header{padding:18px 28px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}
header h1{margin:0;font-size:20px} header span{color:var(--mute);font-size:13px}
main{padding:22px 28px;max-width:1280px;margin:auto}
a{color:var(--accent)}
.banner{background:#3a2a00;border:1px solid #6b4e00;color:#ffd277;padding:10px 14px;border-radius:8px;margin-bottom:18px;font-size:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.card b{display:block;font-size:26px} .card small{color:var(--mute)}
section{margin-bottom:26px} h2{font-size:16px;margin:0 0 10px}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:760px}
th,td{padding:8px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
th{color:var(--mute);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;border:1px solid var(--line)}
.s0,.s1{color:#7ee787;border-color:#238636}.s2{color:#ffd277;border-color:#9e6a03}
.s3,.s4,.hot{color:#ff7b72;border-color:#da3633}.warm{color:#ffd277;border-color:#9e6a03}.cool{color:#7ee787;border-color:#238636}
.ok{color:#7ee787}.bad{color:#ff7b72}.mute{color:var(--mute)}
.live{color:#79c0ff;border-color:#1f6feb}.sample{color:var(--mute)}
.box{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-bottom:14px}
.box h2{margin-top:0} ul{margin:6px 0 0 18px;padding:0}
.note{color:var(--mute);font-size:13px}
"""


def esc(value):
    """HTML-escape any value. Used for EVERY piece of dynamic text."""
    return html.escape("" if value is None else str(value), quote=True)


def fmt_time(value):
    return str(value or "")[:19].replace("T", " ")


def page(title, body):
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{esc(title)}</title><style>{CSS}</style></head><body>"
        "<header><h1>AI-Powered SOC Monitoring Lab</h1>"
        "<span>Home lab and learning project</span></header><main>"
        f"{body}</main></body></html>"
    )


def db_connect():
    """Open the database read-only. Returns None if there is no database yet."""
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(f"{DB_PATH.as_uri()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def ollama_status():
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(OLLAMA_TAGS_URL, timeout=2) as response:
            data = json.loads(response.read().decode("utf-8"))
        names = [m.get("name", "") for m in data.get("models", []) if isinstance(m, dict)]
        installed = "yes" if MODEL in names else "NO"
        return ("ok", f"Ollama is running. Model {MODEL} installed: {installed}")
    except Exception:
        return ("bad", "Ollama is not reachable (open it from the Start menu)")


def level_pill(level):
    if not isinstance(level, int):
        return f"<span class='pill mute'>{esc(level) if level is not None else 'n/a'}</span>"
    cls = "hot" if level >= HIGH_LEVEL else "warm" if level >= 7 else "cool"
    return f"<span class='pill {cls}'>{esc(level)}</span>"


def severity_pill(severity):
    cls = SEVERITY_CLASS.get(severity, "")
    return f"<span class='pill {cls}'>{esc(severity)}</span>"


def analyses_table(rows):
    if not rows:
        return "<div class='box mute'>Nothing stored yet.</div>"
    out = ["<div class='wrap'><table><tr><th>Time (UTC)</th><th>Source</th><th>Alert ID</th><th>Rule</th>"
           "<th>Wazuh level</th><th>AI severity</th><th>AI confidence</th>"
           "<th>Injection flag</th><th>AI summary</th></tr>"]
    for r in rows:
        link = "/alert?id=" + quote(str(r["alert_id"]), safe="")
        flag = "<span class='pill hot'>suspected</span>" if r["prompt_injection_suspected"] else "no"
        out.append(
            f"<tr><td>{esc(fmt_time(r['analyzed_at']))}</td>"
            f"<td>{source_pill(r['source'])}</td>"
            f"<td><a href='{esc(link)}'>{esc(r['alert_id'])}</a></td>"
            f"<td>{esc(r['rule_id'])}</td><td>{level_pill(r['rule_level'])}</td>"
            f"<td>{severity_pill(r['severity'])}</td><td>{esc(r['confidence'])}</td>"
            f"<td>{flag}</td><td>{esc(r['summary'])}</td></tr>"
        )
    out.append("</table></div>")
    return "".join(out)


BASE_COLUMNS = ("alert_id, rule_id, rule_level, severity, confidence, summary, "
                "prompt_injection_suspected, analyzed_at")
SOURCE_FILTERS = ("live", "sample")


def source_expr(conn):
    """Older databases have no 'source' column. Treat all of their rows as 'sample'."""
    has_column = any(row[1] == "source" for row in conn.execute("PRAGMA table_info(analyses)"))
    return "source" if has_column else "'sample'"


def source_pill(value):
    cls = value if value in SOURCE_FILTERS else ""
    return f"<span class='pill {cls}'>{esc(value)}</span>"


def data_banner(live_total, sample_total):
    note = "AI analysis can be wrong and always needs human review."
    if live_total == 0:
        text = ("<b>Data source:</b> stored analyses of sample alert files. No live Wazuh "
                "alert has been analyzed yet. " + note)
    else:
        text = (f"<b>Data source:</b> {live_total} live analyses (alerts fetched on demand from "
                f"wazuh-server over a read-only SSH key) and {sample_total} analyses of sample "
                "alert files. The Source column tells them apart. " + note)
    return f"<div class='banner'>{text}</div>"


def filter_links(current):
    def link(label, value):
        href = "/" if value is None else f"/?source={value}"
        shown = f"<b>{label}</b>" if value == current else label
        return f"<a href='{href}'>{shown}</a>"
    return ("<p class='note'>Show: " + link("all", None) + " &middot; " + link("live", "live")
            + " &middot; " + link("sample", "sample") + "</p>")


def overview_page(source_filter=None):
    conn = db_connect()
    if conn is None:
        return page("Overview", "<div class='box'>No database yet. Run "
                    "<code>analyze_and_store.py</code> first.</div>")
    if source_filter not in SOURCE_FILTERS:
        source_filter = None
    try:
        src = source_expr(conn)
        columns = BASE_COLUMNS + f", {src} AS source"
        where_src = f" WHERE {src} = ?" if source_filter else ""
        and_src = f" AND {src} = ?" if source_filter else ""
        src_args = (source_filter,) if source_filter else ()
        total = conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        live_total = conn.execute(f"SELECT COUNT(*) FROM analyses WHERE {src} = 'live'").fetchone()[0]
        sample_total = total - live_total
        high = conn.execute("SELECT COUNT(*) FROM analyses WHERE rule_level >= ?",
                            (HIGH_LEVEL,)).fetchone()[0]
        injected = conn.execute("SELECT COUNT(*) FROM analyses "
                                "WHERE prompt_injection_suspected = 1").fetchone()[0]
        errors = conn.execute("SELECT COUNT(*) FROM analysis_errors").fetchone()[0]
        last = conn.execute("SELECT MAX(analyzed_at) FROM analyses").fetchone()[0]
        recent = conn.execute(f"SELECT {columns} FROM analyses{where_src} "
                              "ORDER BY id DESC LIMIT 20", src_args).fetchall()
        hot = conn.execute(f"SELECT {columns} FROM analyses WHERE rule_level >= ?{and_src} "
                           "ORDER BY id DESC LIMIT 10", (HIGH_LEVEL,) + src_args).fetchall()
        err_rows = conn.execute("SELECT occurred_at, source, message FROM analysis_errors "
                                "ORDER BY id DESC LIMIT 5").fetchall()
    except sqlite3.Error:
        return page("Overview", "<div class='box bad'>The database could not be read.</div>")
    finally:
        conn.close()

    state, state_text = ollama_status()
    size_kb = DB_PATH.stat().st_size / 1024

    body = [
        data_banner(live_total, sample_total),
        "<div class='cards'>"
        f"<div class='card'><b>{total}</b><small>Analyses stored</small></div>"
        f"<div class='card'><b>{high}</b><small>High severity (Wazuh level {HIGH_LEVEL}+)</small></div>"
        f"<div class='card'><b>{injected}</b><small>Injection suspected</small></div>"
        f"<div class='card'><b>{errors}</b><small>Analysis errors</small></div>"
        f"<div class='card'><b>{total}</b><small>Need human review</small></div>"
        f"<div class='card'><b>{live_total} / {sample_total}</b><small>Live / sample</small></div></div>",
        "<section><h2>High-severity alerts</h2>" + analyses_table(hot) + "</section>",
        "<section><h2>Recent analyses</h2>" + filter_links(source_filter)
        + analyses_table(recent) + "</section>",
        "<section><h2>Analysis errors (latest 5)</h2>",
    ]
    if err_rows:
        body.append("<div class='wrap'><table><tr><th>Time (UTC)</th><th>Source</th><th>Message</th></tr>")
        for e in err_rows:
            body.append(f"<tr><td>{esc(fmt_time(e['occurred_at']))}</td><td>{esc(e['source'])}</td>"
                        f"<td>{esc(e['message'])}</td></tr>")
        body.append("</table></div>")
    else:
        body.append("<div class='box mute'>No errors logged.</div>")
    body.append("</section>")
    body.append(
        "<section><h2>System health</h2><div class='box'><ul>"
        f"<li>Model status: <span class='{state}'>{esc(state_text)}</span></li>"
        f"<li>Database: {esc(DB_PATH)} ({size_kb:.0f} KB, opened read-only)</li>"
        f"<li>Last analysis: {esc(fmt_time(last)) or 'none yet'}</li></ul></div></section>"
    )
    return page("Overview", "".join(body))


def text_list(value):
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, (str, int, float))]


def alert_page(alert_id):
    conn = db_connect()
    if conn is None:
        return None
    try:
        row = conn.execute(f"SELECT result_json, {source_expr(conn)} AS source FROM analyses "
                           "WHERE alert_id = ?", (alert_id,)).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if row is None:
        return None
    try:
        result = json.loads(row["result_json"])
    except json.JSONDecodeError:
        return page("Alert", "<div class='box bad'>Stored result is damaged.</div>")

    analysis = result.get("analysis") or {}
    mitre = result.get("mitre_from_wazuh_rule") or {}

    def items(values):
        li = "".join(f"<li>{esc(v)}</li>" for v in text_list(values))
        return f"<ul>{li}</ul>" if li else "<span class='mute'>none</span>"

    mitre_html = []
    for tid in text_list(mitre.get("ids")):
        if MITRE_ID.match(tid):
            path = tid.replace(".", "/")
            mitre_html.append(f"<a href='https://attack.mitre.org/techniques/{esc(path)}/' "
                              f"rel='noopener noreferrer'>{esc(tid)}</a>")
        else:
            mitre_html.append(esc(tid))
    mitre_line = ", ".join(mitre_html) or "<span class='mute'>none in this rule</span>"

    injected = ("<span class='pill hot'>suspected</span> The log text contains "
                "instruction-like wording. Treat it as hostile.") \
        if result.get("prompt_injection_suspected") else "No"
    body = (
        "<p><a href='/'>&larr; Back to overview</a></p>"
        f"<div class='box'><h2>Alert {esc(result.get('alert_id'))}</h2>"
        f"<p>Rule {esc(result.get('rule_id'))} &middot; Wazuh level {level_pill(result.get('rule_level'))} "
        f"&middot; AI severity {severity_pill(analysis.get('severity_assessment'))} "
        f"&middot; AI confidence {esc(analysis.get('confidence'))}</p>"
        f"<p><b>Summary:</b> {esc(analysis.get('summary'))}</p></div>"
        f"<div class='box'><h2>Evidence (from the alert)</h2>{items(analysis.get('evidence'))}</div>"
        f"<div class='box'><h2>Possible explanation (AI reasoning, may be wrong)</h2>"
        f"<p>{esc(analysis.get('possible_explanation'))}</p></div>"
        f"<div class='box'><h2>Recommended checks for a human</h2>{items(analysis.get('recommended_actions'))}</div>"
        f"<div class='box'><h2>MITRE ATT&amp;CK (from the Wazuh rule, not the AI)</h2>"
        f"<p>Techniques: {mitre_line}</p>"
        f"<p>Tactics: {esc(', '.join(text_list(mitre.get('tactics')))) or 'none'}</p></div>"
        f"<div class='box'><h2>Checks</h2><ul><li>Source: {source_pill(row['source'])}</li>"
        f"<li>Prompt injection: {injected}</li>"
        f"<li>Quality notes: {esc('; '.join(text_list(result.get('quality_notes')))) or 'none'}</li>"
        f"<li>Requires human review: {'yes' if result.get('requires_human_review') else 'NO'}</li>"
        f"<li>Model: {esc(result.get('model'))} &middot; analyzed {esc(fmt_time(result.get('analyzed_at')))} UTC</li></ul></div>"
        "<p class='note'>AI-generated analysis can be incomplete or wrong. "
        "Verify against the original alert in Wazuh before acting.</p>"
    )
    return page("Alert", body)


def authorized(header):
    if not header or not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
    except Exception:
        return False
    user, _, password = decoded.partition(":")
    ok_user = hmac.compare_digest(user.encode(), USERNAME.encode())
    ok_pass = hmac.compare_digest(password.encode(), PASSWORD.encode())
    return ok_user and ok_pass


class Handler(BaseHTTPRequestHandler):
    server_version = "SOCDashboard"
    sys_version = ""

    def log_message(self, fmt, *args):
        sys.stderr.write("[dashboard] " + (fmt % args) + "\n")

    def reply(self, status, body, headers=None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
                         "form-action 'none'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            return self.reply(400, page("Bad request", "<div class='box bad'>Bad request.</div>"))
        if not authorized(self.headers.get("Authorization")):
            return self.reply(401, page("Login required", "<div class='box'>Login required.</div>"),
                              {"WWW-Authenticate": 'Basic realm="SOC dashboard"'})

        parsed = urlparse(self.path)
        if parsed.path == "/":
            wanted = (parse_qs(parsed.query).get("source") or [""])[0]
            return self.reply(200, overview_page(wanted))
        if parsed.path == "/alert":
            alert_id = (parse_qs(parsed.query).get("id") or [""])[0]
            content = alert_page(alert_id) if alert_id else None
            if content is None:
                return self.reply(404, page("Not found", "<div class='box'>Alert not found. "
                                            "<a href='/'>Back</a></div>"))
            return self.reply(200, content)
        return self.reply(404, page("Not found", "<div class='box'>Page not found. "
                                    "<a href='/'>Back</a></div>"))

    def _not_allowed(self):
        self.reply(405, page("Not allowed", "<div class='box'>This dashboard is read-only.</div>"),
                   {"Allow": "GET"})

    do_POST = do_PUT = do_DELETE = do_PATCH = _not_allowed


def main():
    if len(PASSWORD) < 8:
        print("DASHBOARD_PASSWORD is not set (or shorter than 8 characters).")
        print('Set it for this PowerShell window only, then start again:')
        print('    $env:DASHBOARD_PASSWORD = "your-own-password"')
        print("Do not share this password and do not save it in any file.")
        return 1
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as error:
        print(f"Cannot start on port {PORT}: {error}")
        print("Another program may be using it. Try: $env:DASHBOARD_PORT = '8081'")
        return 1
    print(f"Dashboard running at http://{HOST}:{PORT}  (username: {USERNAME})")
    print(f"Database: {DB_PATH}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
