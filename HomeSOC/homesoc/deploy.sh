#!/usr/bin/env bash
#
# HomeSOC one-shot deploy.
#   - checks for Docker + the compose plugin
#   - installs Docker automatically if missing (Linux; with a confirmation prompt)
#   - generates a strong enroll key if you haven't set one
#   - builds and starts the server with `docker compose up -d --build`
#
# Usage:
#   ./deploy.sh [--key <KEY>] [--port <PORT>] [--yes] [--no-build]
#
#   --key   KEY    enroll key agents must present (default: auto-generated)
#   --port  PORT   host port for the dashboard/API (default: 8080)
#   --yes, -y      don't prompt before installing Docker
#   --no-build     start without rebuilding the image
#
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSUME_YES=0
NO_BUILD=0
NO_FIREWALL=0
HOMESOC_PORT="${HOMESOC_PORT:-8080}"

usage() {
  cat <<'EOF'
HomeSOC one-shot deploy. Checks for Docker (+ compose), installs Docker on Linux
if missing, generates an enroll key if unset, then builds and starts the server.

Usage: ./deploy.sh [--key <KEY>] [--port <PORT>] [--yes] [--no-build] [--no-firewall]
  --key  KEY    enroll key agents must present (default: auto-generated)
  --port PORT   host port for the dashboard/API (default: 8080)
  --yes, -y     don't prompt before installing Docker
  --no-build    start without rebuilding the image
  --no-firewall don't touch the host firewall
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y)      ASSUME_YES=1 ;;
    --no-build)    NO_BUILD=1 ;;
    --no-firewall) NO_FIREWALL=1 ;;
    --key)         shift; HOMESOC_ENROLL_KEY="${1:-}" ;;
    --key=*)     HOMESOC_ENROLL_KEY="${1#*=}" ;;
    --port)      shift; HOMESOC_PORT="${1:-8080}" ;;
    --port=*)    HOMESOC_PORT="${1#*=}" ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "unknown option: $1"; usage; exit 1 ;;
  esac
  shift
done

log()  { printf '\033[36m[homesoc]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[homesoc]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[31m[homesoc]\033[0m %s\n' "$*" >&2; }

OS="$(uname -s)"

have() { command -v "$1" >/dev/null 2>&1; }

# ---- sudo helper: only used when not already root -------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if have sudo; then SUDO="sudo"; else SUDO=""; fi
fi

pkg_install() {
  local pkg="$1"
  if   have apt-get; then $SUDO apt-get update -y && $SUDO apt-get install -y "$pkg"
  elif have dnf;     then $SUDO dnf install -y "$pkg"
  elif have yum;     then $SUDO yum install -y "$pkg"
  elif have zypper;  then $SUDO zypper --non-interactive install "$pkg"
  elif have pacman;  then $SUDO pacman -Sy --noconfirm "$pkg"
  else return 1; fi
}

ensure_curl() {
  have curl && return 0
  log "curl not found; attempting to install it…"
  pkg_install curl || { err "Could not install curl automatically. Install curl and re-run."; exit 1; }
}

gen_key() {
  if   have openssl;        then openssl rand -hex 32
  elif [ -r /dev/urandom ]; then LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 64
  else date +%s | (sha256sum 2>/dev/null || shasum -a 256) | cut -c1-64; fi
}

install_docker_linux() {
  err "Docker is not installed."
  if [ "$ASSUME_YES" -ne 1 ]; then
    cat <<'EOF'

  Proposed action: install Docker Engine using Docker's official convenience
  script (https://get.docker.com). It will be downloaded to a file first, then
  executed with sudo. This adds Docker's package repo and installs docker-ce
  plus the compose plugin.

EOF
    printf "  Proceed with automatic install? [y/N] "
    read -r ans
    case "$ans" in
      y|Y|yes|YES) ;;
      *) err "Aborted. Install Docker yourself, then re-run this script."; exit 1 ;;
    esac
  fi
  ensure_curl
  log "downloading get.docker.com…"
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  log "running the Docker installer (sudo)…"
  $SUDO sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
  $SUDO systemctl enable --now docker 2>/dev/null || true
  if getent group docker >/dev/null 2>&1 && [ -n "${USER:-}" ]; then
    $SUDO usermod -aG docker "$USER" 2>/dev/null || true
    warn "Added $USER to the 'docker' group. Log out/in for it to take effect; this run will use sudo."
  fi
}

ensure_docker() {
  if have docker; then return 0; fi
  case "$OS" in
    Linux)  install_docker_linux ;;
    Darwin)
      err "Docker is not installed, and this script won't silently install Docker Desktop on macOS."
      if have brew; then
        echo "  Install it with:  brew install --cask docker   (then launch Docker Desktop once)"
      else
        echo "  Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
      fi
      exit 1 ;;
    *) err "Unsupported OS '$OS'. Install Docker manually."; exit 1 ;;
  esac
}

# pick a working docker invocation (may need sudo for the daemon socket)
DOCKER_PREFIX=""
docker_ready() {
  if docker info >/dev/null 2>&1; then DOCKER_PREFIX=""; return 0; fi
  if [ -n "$SUDO" ] && $SUDO docker info >/dev/null 2>&1; then DOCKER_PREFIX="$SUDO"; return 0; fi
  return 1
}

ensure_daemon() {
  docker_ready && return 0
  log "starting the Docker daemon…"
  $SUDO systemctl start docker 2>/dev/null || true
  # give Docker Desktop / the socket a moment
  for _ in 1 2 3 4 5 6 7 8 9 10; do docker_ready && return 0; sleep 1; done
  err "Docker is installed but the daemon isn't reachable. Start Docker and re-run."
  exit 1
}

compose() {
  if $DOCKER_PREFIX docker compose version >/dev/null 2>&1; then
    $DOCKER_PREFIX docker compose "$@"
  elif have docker-compose; then
    $DOCKER_PREFIX docker-compose "$@"
  else
    err "The Docker Compose plugin isn't available."
    echo "  On Linux: $SUDO apt-get install -y docker-compose-plugin   (or reinstall via get.docker.com)"
    exit 1
  fi
}

detect_ip() {
  local ip=""
  case "$OS" in
    Darwin) ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)" ;;
    *)
      if have ip; then
        ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
      fi
      if [ -z "$ip" ] && have hostname; then ip="$(hostname -I 2>/dev/null | awk '{print $1}')"; fi
      ;;
  esac
  [ -z "$ip" ] && ip="localhost"
  echo "$ip"
}

# open the dashboard/ingest port using whatever firewall the host runs
open_firewall() {
  local port="$1"
  case "$OS" in
    Linux)
      if have ufw && $SUDO ufw status 2>/dev/null | grep -qi "Status: active"; then
        log "ufw is active; allowing ${port}/tcp…"
        $SUDO ufw allow "${port}/tcp" >/dev/null 2>&1 && log "ufw: ${port}/tcp allowed." || warn "ufw rule failed."
      elif have firewall-cmd && $SUDO firewall-cmd --state >/dev/null 2>&1; then
        log "firewalld is running; allowing ${port}/tcp…"
        if $SUDO firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 && $SUDO firewall-cmd --reload >/dev/null 2>&1; then
          log "firewalld: ${port}/tcp allowed."
        else warn "firewalld rule failed."; fi
      elif have iptables; then
        if $SUDO iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1; then
          log "iptables already allows ${port}/tcp."
        else
          log "adding iptables ACCEPT for ${port}/tcp…"
          if $SUDO iptables -I INPUT -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1; then
            log "iptables: ${port}/tcp allowed (persist with: netfilter-persistent save)."
          else warn "iptables rule failed."; fi
        fi
      else
        warn "no ufw/firewalld/iptables found; open ${port}/tcp manually if a firewall is in front of this host."
      fi
      ;;
    Darwin)
      log "macOS uses a per-application firewall; Docker handles inbound for the container — no port rule needed."
      ;;
  esac
}

# ---- run ------------------------------------------------------------------
trap 'rc=$?; err "deploy.sh failed at line ${LINENO}: \`${BASH_COMMAND}\` (exit ${rc})"; exit ${rc}' ERR

log "checking dependencies…"
ensure_docker
ensure_daemon
log "Docker ready: $($DOCKER_PREFIX docker --version)"

# Resolve the enroll key (precedence: --key/env > existing .env > generate),
# then persist it to .env so it survives re-runs and Compose reads it automatically.
ENV_FILE=".env"
ENV_KEY=""
if [ -f "$ENV_FILE" ]; then
  ENV_KEY="$(grep -E '^HOMESOC_ENROLL_KEY=' "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-)"
fi

if [ -n "${HOMESOC_ENROLL_KEY:-}" ] && [ "${HOMESOC_ENROLL_KEY:-}" != "changeme" ]; then
  KEY_SOURCE="provided"
elif [ -n "$ENV_KEY" ] && [ "$ENV_KEY" != "changeme" ]; then
  HOMESOC_ENROLL_KEY="$ENV_KEY"; KEY_SOURCE="reused from .env"
else
  HOMESOC_ENROLL_KEY="$(gen_key)"; KEY_SOURCE="generated"
  log "generated a new enroll key with openssl."
fi

# write/refresh .env (keep other vars intact)
touch "$ENV_FILE"
tmp_env="$(mktemp)"
grep -vE '^(HOMESOC_ENROLL_KEY|HOMESOC_PORT)=' "$ENV_FILE" > "$tmp_env" 2>/dev/null || true
{
  cat "$tmp_env"
  printf 'HOMESOC_ENROLL_KEY=%s\n' "$HOMESOC_ENROLL_KEY"
  printf 'HOMESOC_PORT=%s\n' "$HOMESOC_PORT"
} > "$ENV_FILE"
rm -f "$tmp_env"
chmod 600 "$ENV_FILE" 2>/dev/null || true
log "saved enroll key to $(pwd)/$ENV_FILE (${KEY_SOURCE})."

export HOMESOC_ENROLL_KEY HOMESOC_PORT

log "building and starting HomeSOC (port ${HOMESOC_PORT})…"
if [ "$NO_BUILD" -eq 1 ]; then
  compose up -d
else
  compose up -d --build
fi

if [ "$NO_FIREWALL" -eq 1 ]; then
  log "skipping firewall changes (--no-firewall)."
else
  open_firewall "$HOMESOC_PORT" || warn "firewall step skipped."
fi

IP="$(detect_ip)"
echo
log "HomeSOC is up."
echo "  Dashboard : http://${IP}:${HOMESOC_PORT}/   (also http://localhost:${HOMESOC_PORT}/)"
echo
echo "  ====================================================================="
echo "   ENROLL KEY (${KEY_SOURCE}) — every agent must use this exact value:"
echo
echo "     ${HOMESOC_ENROLL_KEY}"
echo
echo "   Saved in ./.env. Install an agent with:"
echo "     sudo ./install.sh --server http://${IP}:${HOMESOC_PORT} --key ${HOMESOC_ENROLL_KEY} --service"
echo "  ====================================================================="
echo
warn "The dashboard and rule editor are unauthenticated in v1. Keep this on a trusted"
warn "network or put it behind a reverse proxy with auth before exposing it."
warn "Treat .env as a secret — it's listed in .gitignore so it won't be committed."
echo
echo "  Logs : ${DOCKER_PREFIX:+$DOCKER_PREFIX }docker compose logs -f"
echo "  Stop : ${DOCKER_PREFIX:+$DOCKER_PREFIX }docker compose down"
