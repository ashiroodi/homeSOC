#!/usr/bin/env bash
# HomeSOC agent installer for Linux and macOS.
# Usage:
#   ./install.sh                                       # interactive
#   ./install.sh --server http://IP:8080 --key KEY [--service]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SERVER=""; KEY=""; SERVICE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --server)  SERVER="$2"; shift 2;;
    --key)     KEY="$2"; shift 2;;
    --service) SERVICE=1; shift;;
    -h|--help) sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

info(){ printf '\033[36m[*]\033[0m %s\n' "$*"; }
good(){ printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn(){ printf '\033[33m[!]\033[0m %s\n' "$*"; }
bad (){ printf '\033[31m[x]\033[0m %s\n' "$*"; }

command -v python3 >/dev/null || { bad "python3 not found"; exit 1; }

PYBIN="$HERE/.venv/bin/python"
info "Creating virtualenv in $HERE/.venv"
python3 -m venv "$HERE/.venv"
info "Upgrading pip and installing dependencies"
"$PYBIN" -m pip install --quiet --upgrade pip || warn "pip self-upgrade skipped"
"$PYBIN" -m pip install --quiet -r "$HERE/requirements.txt"

if [[ -z "$SERVER" ]]; then read -rp "Server URL [http://localhost:8080]: " SERVER; SERVER="${SERVER:-http://localhost:8080}"; fi
if [[ -z "$KEY" ]];    then read -rp "Enroll key: " KEY; fi

# Normalize the server URL so a bare host/IP never produces a schemeless URL.
SERVER="${SERVER%/}"
if [[ -n "$SERVER" && ! "$SERVER" =~ ^https?:// ]]; then SERVER="http://$SERVER"; fi
[[ -n "$SERVER" && -n "$KEY" ]] || { bad "server and key are required"; exit 1; }
[[ "$SERVER" =~ :[0-9]+ ]] || warn "No port in '$SERVER' — if the server listens on 8080, use http://<host>:8080"

cat > "$HERE/config.yaml" <<EOF
server: "$SERVER"
enroll_key: "$KEY"
EOF
good "Wrote $HERE/config.yaml"
info "  server: $SERVER"

# Verify connectivity + key before declaring success.
info "Verifying connection to the server..."
if "$PYBIN" "$HERE/homesoc_agent.py" --config "$HERE/config.yaml" --check; then
  CHECK=0
else
  CHECK=$?
fi
if [[ "$CHECK" -ne 0 ]]; then
  bad "Agent is NOT live. Fix the issue above, then re-run."
  [[ "$CHECK" -eq 2 ]] && warn "Key mismatch: make config.yaml's enroll_key equal the server's HOMESOC_ENROLL_KEY."
  [[ "$CHECK" -eq 1 ]] && warn "Server unreachable: check the URL/port, that the container is up, and the server firewall."
  exit "$CHECK"
fi
good "Connection OK — server reachable and key accepted."

if [[ "$SERVICE" -eq 1 ]]; then
  OS="$(uname -s)"
  if [[ "$OS" == "Linux" ]]; then
    SUDO=""; [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"
    UNIT=/etc/systemd/system/homesoc-agent.service
    info "Installing systemd unit at $UNIT"
    $SUDO tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=HomeSOC agent
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$HERE
ExecStart=$PYBIN $HERE/homesoc_agent.py --config $HERE/config.yaml --no-prompt
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now homesoc-agent
    sleep 2
    if $SUDO systemctl is-active --quiet homesoc-agent; then
      good "Service active (runs as root = full socket + auth-log visibility)."
      good "Going live — this host should appear in the dashboard within ~30s."
    else
      bad "Service failed to start. Inspect: $SUDO journalctl -u homesoc-agent -n 50 --no-pager"
      exit 1
    fi
    info "Logs: $SUDO journalctl -u homesoc-agent -f"
  elif [[ "$OS" == "Darwin" ]]; then
    PLIST="$HOME/Library/LaunchAgents/com.homesoc.agent.plist"
    info "Installing launchd job at $PLIST"
    cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.homesoc.agent</string>
  <key>WorkingDirectory</key><string>$HERE</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYBIN</string>
    <string>$HERE/homesoc_agent.py</string>
    <string>--config</string><string>$HERE/config.yaml</string>
    <string>--no-prompt</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF
    launchctl unload "$PLIST" 2>/dev/null || true
    launchctl load "$PLIST"
    good "launchd job loaded. Going live — check the dashboard in ~30s."
    warn "For full auth-log access on macOS, run as a root LaunchDaemon instead of a user agent."
  fi
else
  good "Agent verified. To keep it running in the background, re-run with --service."
  info "Or run it now in the foreground (Ctrl-C to stop; sudo for full fidelity):"
  echo "    sudo $PYBIN $HERE/homesoc_agent.py --config $HERE/config.yaml"
fi
