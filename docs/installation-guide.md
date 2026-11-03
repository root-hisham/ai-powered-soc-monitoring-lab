# Installation Guide

This guide sets up the AI engine and dashboard from zero, on top of an
already-working [`wazuh-home-soc-lab`](https://github.com/root-hisham/wazuh-home-soc-lab).
If that lab isn't built yet, do that first — this project reads its alerts
and does nothing on its own.

## Requirements

- Windows 11 (or any OS with Python 3.10+; commands below are PowerShell)
- A working `wazuh-home-soc-lab`: `wazuh-server` VM reachable, with the
  custom rule `100100` already installed
- About 3 GB of free RAM beyond what `wazuh-server` itself needs, for the
  AI model
- No GPU required — everything here runs on CPU

## 1. Install Python

```powershell
py --version
```

If that fails, install Python 3.12+ from https://www.python.org/downloads/,
ticking **"Add python.exe to PATH"** during setup, then open a **new**
PowerShell window and check again.

## 2. Install Ollama and the model

Download and run the installer from https://ollama.com/download/windows.

Models default to a folder under your user profile on `C:`. To keep the
~2 GB model on a different drive, set this **before** pulling any model:

```powershell
New-Item -ItemType Directory -Force -Path "D:\ollama models"
[Environment]::SetEnvironmentVariable("OLLAMA_MODELS", "D:\ollama models", "User")
```

Close and reopen PowerShell so the new variable takes effect, then:

```powershell
ollama pull llama3.2:3b
ollama list
```

Expected: `llama3.2:3b`, about 2.0 GB.

**Verify it works:**

```powershell
ollama run llama3.2:3b --verbose "In two sentences, what is an SSH brute force attack?"
```

Expect a short answer followed by stats including an `eval rate` in
tokens/second — a few to a couple dozen tokens/s is normal on a CPU-only
laptop (see `docs/ai-limitations.md` for real numbers from this build).

## 3. Get the project files

Clone or download this repo to, e.g., `D:\ai-powered-soc-monitoring-lab`.

```powershell
py run_tests.py
```

Expected: `Ran 96 tests` → `OK`. This step needs no VM and no Ollama running
— if it fails here, something is wrong with the Python install, not with
Wazuh or the network, which narrows down the problem immediately.

## 4. Test against the included sample alerts

No server connection needed for this step.

```powershell
py ai-engine\app\analyze_and_store.py
py ai-engine\app\analyze_and_store.py samples\alert_fake_injection.json
py ai-engine\app\analyze_and_store.py --list
```

Expected: 2 saved analyses, both `source: sample`.

## 5. Set up the restricted SSH connection to your Wazuh server

This is the one piece that touches the server. Full detail and the
reasoning behind it is in `docs/network-setup.md` — summary here:

**On the Windows host**, generate a key with no passphrase (it's used
unattended by a script):

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\soc_reader" -C soc-reader-lab
scp -P 2222 "$env:USERPROFILE\.ssh\soc_reader.pub" vboxuser@127.0.0.1:/tmp/soc_reader.pub
```

(This assumes a port forward `127.0.0.1:2222` → the server's `:22` already
exists in VirtualBox's NAT Network settings — see `docs/network-setup.md`
if not.)

**On `wazuh-server`**, create the restricted account and the one command it
can run:

```bash
sudo adduser --disabled-password --gecos "" socreader
sudo usermod -aG wazuh socreader

sudo tee /usr/local/bin/soc-read-alerts > /dev/null << 'EOF'
#!/bin/sh
exec /usr/bin/tail -n 500 /var/ossec/logs/alerts/alerts.json
EOF
sudo chmod 755 /usr/local/bin/soc-read-alerts

sudo mkdir -p /home/socreader/.ssh
printf 'command="/usr/local/bin/soc-read-alerts",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding %s\n' "$(cat /tmp/soc_reader.pub)" | sudo tee /home/socreader/.ssh/authorized_keys > /dev/null
sudo chown -R socreader:socreader /home/socreader/.ssh
sudo chmod 700 /home/socreader/.ssh
sudo chmod 600 /home/socreader/.ssh/authorized_keys
rm /tmp/soc_reader.pub
```

**Verify the restriction works** (back on Windows):

```powershell
ssh -i "$env:USERPROFILE\.ssh\soc_reader" -p 2222 socreader@127.0.0.1 | Measure-Object -Line
ssh -i "$env:USERPROFILE\.ssh\soc_reader" -p 2222 socreader@127.0.0.1 whoami | Measure-Object -Line
```

Both commands should print a similar line count — the second must **not**
print the word `socreader`, proving the server ran the forced command
regardless of what was asked.

## 6. Fetch and analyze real alerts

Make sure `wazuh-server` is running (`ubuntu1` and `kali` are not required
unless you're also generating new attack traffic).

```powershell
py ai-engine\app\fetch_and_analyze.py --dry-run --min-level 3
```

This previews candidates without using the AI or saving anything — a safe
way to check the connection and filtering first. When ready:

```powershell
py ai-engine\app\fetch_and_analyze.py --min-level 10 --max 2
py ai-engine\app\analyze_and_store.py --list
```

## 7. Run the dashboard

```powershell
$env:DASHBOARD_PASSWORD = "choose-your-own-password"
py dashboard\dashboard.py
```

Open `http://127.0.0.1:8080` and log in as `analyst`. Stop with `Ctrl+C`.
The password lives only in that PowerShell window's environment — it is
never written to a file.

## RAM budget: don't run everything at once

On a 16 GB laptop with no GPU, these don't all fit together comfortably.
See `docs/troubleshooting.md` for the full breakdown, but the short
version:

| Mode | What's running | Use for |
|---|---|---|
| Build | No VMs | Writing code, docs, tests |
| Live analysis | `wazuh-server` + Ollama | Fetching and analyzing real alerts |
| Attack demo | `wazuh-server` + `ubuntu1` + `kali`, **AI off** | Generating a new attack to detect |

Shut down `ubuntu1` and `kali` (`sudo poweroff`, not just closing the
window) before switching into live-analysis mode.
