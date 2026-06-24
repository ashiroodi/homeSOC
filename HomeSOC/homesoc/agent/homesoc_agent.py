#!/usr/bin/env python3
"""HomeSOC endpoint agent — Linux / Windows / macOS.

Collects four telemetry streams and ships them to the HomeSOC server:
  process  — new process executions (psutil snapshot diff)
  file     — create/modify/delete/move under watched paths (watchdog)
  network  — new outbound/established connections (psutil snapshot diff)
  auth     — login/sudo events (platform-specific log readers)

Userland and polling-based: it samples the process and socket tables on an
interval, so very short-lived activity between samples can be missed. For
kernel-grade capture, pair it with eBPF/auditd (Linux), Sysmon/ETW (Windows), or
EndpointSecurity (macOS). Several collectors need elevated privileges to see all
processes, sockets, and logs; each degrades gracefully and logs a warning when
it can't.

Config resolution order (first found wins):
  CLI flags  ->  env (HOMESOC_SERVER / HOMESOC_KEY)  ->  config.yaml  ->  prompt
"""
import argparse
import json
import os
import platform as _plat
import queue
import re
import socket
import subprocess
import sys
import threading
import time

try:
    import psutil
except ImportError:
    sys.exit("psutil is required: pip install psutil")
try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

AGENT_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# platform identity
# ---------------------------------------------------------------------------
def os_family():
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p == "darwin":
        return "darwin"
    if p.startswith("win"):
        return "windows"
    return p

PLATFORM = os_family()
HOSTNAME = socket.gethostname()


def log(msg, level="INFO"):
    fr = sys._getframe(1)
    loc = f"{fr.f_code.co_name}:{fr.f_lineno}"
    ts = time.strftime("%H:%M:%S")
    print(f"{ts} [homesoc-agent] {level:<5} [{loc}] {msg}", flush=True)


def primary_ip(server_host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((server_host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------
def default_paths():
    home = os.path.expanduser("~")
    if PLATFORM == "linux":
        return [p for p in ["/etc", "/tmp", "/dev/shm", "/var/spool/cron",
                            os.path.join(home, ".ssh"), os.path.join(home, "Downloads")]]
    if PLATFORM == "darwin":
        return [p for p in ["/tmp", os.path.join(home, "Downloads"),
                            os.path.join(home, "Library/LaunchAgents"),
                            "/Library/LaunchAgents", "/Library/LaunchDaemons"]]
    if PLATFORM == "windows":
        return [p for p in [os.environ.get("TEMP", r"C:\Windows\Temp"),
                            os.path.join(home, "Downloads"),
                            os.environ.get("APPDATA", "")] if p]
    return [home]


def load_config():
    ap = argparse.ArgumentParser(description="HomeSOC agent")
    ap.add_argument("--server", help="server base URL, e.g. http://192.168.1.10:8080")
    ap.add_argument("--key", help="enroll key (matches HOMESOC_ENROLL_KEY on server)")
    ap.add_argument("--config", default=os.environ.get("HOMESOC_CONFIG", "config.yaml"))
    ap.add_argument("--no-prompt", action="store_true", help="never prompt interactively")
    ap.add_argument("--check", action="store_true",
                    help="verify connectivity + enroll key against the server, then exit")
    args = ap.parse_args()

    cfg = {}
    if os.path.exists(args.config):
        try:
            import yaml
            with open(args.config) as f:
                cfg = yaml.safe_load(f) or {}
        except ImportError:
            log("PyYAML not installed; ignoring config file")
        except Exception as e:
            log(f"could not read {args.config}: {e}")

    server = args.server or os.environ.get("HOMESOC_SERVER") or cfg.get("server")
    key = args.key or os.environ.get("HOMESOC_KEY") or cfg.get("enroll_key")

    if (not server or not key) and not args.no_prompt and sys.stdin.isatty():
        log("First-run setup (values are saved to config.yaml).")
        if not server:
            server = input("  Server URL [http://localhost:8080]: ").strip() or "http://localhost:8080"
        if not key:
            key = input("  Enroll key: ").strip()
        _write_config(args.config, _normalize_server(server), key, cfg)

    if not server or not key:
        sys.exit("Missing server/key. Provide --server and --key, set HOMESOC_SERVER/"
                 "HOMESOC_KEY, or fill config.yaml.")

    server = _normalize_server(server)

    cfg.update({
        "server": server,
        "enroll_key": key,
        "watch_paths": cfg.get("watch_paths") or default_paths(),
        "process_interval": cfg.get("process_interval", 1.5),
        "network_interval": cfg.get("network_interval", 3.0),
        "ship_interval": cfg.get("ship_interval", 3.0),
        "state_file": cfg.get("state_file",
                              os.path.join(os.path.dirname(os.path.abspath(args.config)) or ".",
                                           "homesoc_state.json")),
        "config_path": args.config,
        "check": args.check,
    })
    return cfg


def _normalize_server(url):
    """Accept bare hosts/IPs and add a scheme so requests never sees a schemeless URL."""
    u = (url or "").strip().rstrip("/")
    if u and not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return u


def _write_config(path, server, key, existing):
    try:
        import yaml
        existing = dict(existing or {})
        existing["server"] = server
        existing["enroll_key"] = key
        with open(path, "w") as f:
            yaml.safe_dump(existing, f, default_flow_style=False)
        log(f"saved config to {path}")
    except Exception as e:
        log(f"could not save config: {e}")


# ---------------------------------------------------------------------------
# enrollment / state
# ---------------------------------------------------------------------------
def load_state(path):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_state(path, state):
    try:
        with open(path, "w") as f:
            json.dump(state, f)
    except OSError as e:
        log(f"could not write state: {e}")


def enroll(cfg, ip):
    state = load_state(cfg["state_file"])
    if state.get("device_id"):
        return state["device_id"]
    r = requests.post(
        cfg["server"] + "/api/enroll",
        headers={"Authorization": "Bearer " + cfg["enroll_key"]},
        json={"hostname": HOSTNAME, "platform": PLATFORM,
              "agent_version": AGENT_VERSION, "ip": ip},
        timeout=10,
    )
    r.raise_for_status()
    device_id = r.json()["device_id"]
    save_state(cfg["state_file"], {"device_id": device_id})
    log(f"enrolled as {device_id}")
    return device_id


# ---------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------
class Collectors:
    def __init__(self, cfg, device_id, q: queue.Queue):
        self.cfg = cfg
        self.device_id = device_id
        self.q = q
        self.stop = threading.Event()

    def emit(self, category, action, **fields):
        ev = {
            "ts": time.time(),
            "device_id": self.device_id,
            "hostname": HOSTNAME,
            "platform": PLATFORM,
            "category": category,
            "action": action,
        }
        ev.update(fields)
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            pass

    # ----- process ------------------------------------------------------
    def run_process(self):
        seen = {}
        try:
            for p in psutil.process_iter(["pid", "create_time"]):
                seen[p.info["pid"]] = p.info.get("create_time")
        except psutil.Error:
            pass
        while not self.stop.is_set():
            try:
                current = {}
                for p in psutil.process_iter(["pid", "create_time"]):
                    current[p.info["pid"]] = p.info.get("create_time")
                new_pids = [pid for pid, ct in current.items()
                            if pid not in seen or seen.get(pid) != ct]
                for pid in new_pids:
                    self._emit_process(pid)
                seen = current
            except psutil.Error:
                pass
            self.stop.wait(self.cfg["process_interval"])

    def _emit_process(self, pid):
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                name = _safe(lambda: p.name())
                exe = _safe(lambda: p.exe())
                cmd = _safe(lambda: " ".join(p.cmdline()))
                ppid = _safe(lambda: p.ppid())
                user = _safe(lambda: p.username())
                pname = None
                if ppid:
                    pname = _safe(lambda: psutil.Process(ppid).name())
        except psutil.Error:
            return
        self.emit("process", "exec", process={
            "pid": pid, "ppid": ppid, "name": name, "exe": exe,
            "cmdline": cmd or "", "username": user, "parent_name": pname,
        })

    # ----- network ------------------------------------------------------
    def run_network(self):
        seen = set()
        first = True
        while not self.stop.is_set():
            try:
                conns = psutil.net_connections(kind="inet")
            except (psutil.AccessDenied, psutil.Error):
                if first:
                    log("network: insufficient privileges for full socket visibility")
                conns = []
            current = set()
            for c in conns:
                if not c.raddr or c.status not in ("ESTABLISHED", "SYN_SENT"):
                    continue
                raddr, rport = c.raddr.ip, c.raddr.port
                laddr = c.laddr.ip if c.laddr else None
                lport = c.laddr.port if c.laddr else None
                key = (laddr, lport, raddr, rport, c.status, c.pid)
                current.add(key)
                if key in seen or first:
                    continue
                pname = None
                if c.pid:
                    pname = _safe(lambda: psutil.Process(c.pid).name())
                self.emit("network", "connect", network={
                    "laddr": laddr, "lport": lport, "raddr": raddr, "rport": rport,
                    "proto": "tcp" if c.type == socket.SOCK_STREAM else "udp",
                    "status": c.status, "pid": c.pid, "process_name": pname,
                })
            seen = current
            first = False
            self.stop.wait(self.cfg["network_interval"])

    # ----- file ---------------------------------------------------------
    def run_file(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            log("file: watchdog not installed; file monitoring disabled")
            return

        emit = self.emit
        last_modify = {}

        class Handler(FileSystemEventHandler):
            def _emit(self, action, path):
                if action == "modify":
                    now = time.time()
                    if now - last_modify.get(path, 0) < 2.0:
                        return
                    last_modify[path] = now
                emit("file", action, file={"path": path, "name": os.path.basename(path)})

            def on_created(self, e):
                if not e.is_directory:
                    self._emit("create", e.src_path)

            def on_modified(self, e):
                if not e.is_directory:
                    self._emit("modify", e.src_path)

            def on_deleted(self, e):
                if not e.is_directory:
                    self._emit("delete", e.src_path)

            def on_moved(self, e):
                self._emit("move", getattr(e, "dest_path", e.src_path))

        obs = Observer()
        scheduled = 0
        for path in self.cfg["watch_paths"]:
            if not os.path.isdir(path):
                continue
            try:
                obs.schedule(Handler(), path, recursive=True)
                scheduled += 1
            except (OSError, PermissionError) as e:
                log(f"file: cannot watch {path}: {e}")
        if not scheduled:
            log("file: no watchable paths; file monitoring disabled")
            return
        obs.start()
        log(f"file: watching {scheduled} path(s)")
        try:
            while not self.stop.is_set():
                self.stop.wait(1.0)
        finally:
            obs.stop()
            obs.join(timeout=3)

    # ----- auth ---------------------------------------------------------
    def run_auth(self):
        try:
            if PLATFORM == "linux":
                self._auth_linux()
            elif PLATFORM == "darwin":
                self._auth_macos()
            elif PLATFORM == "windows":
                self._auth_windows()
        except Exception as e:
            log(f"auth: collector stopped ({e})")

    def _auth_linux(self):
        path = None
        for cand in ("/var/log/auth.log", "/var/log/secure"):
            if os.path.exists(cand):
                path = cand
                break
        if not path:
            log("auth: no auth.log/secure found (journald-only?); auth disabled. "
                "See README for the journalctl option.")
            return
        for line in _tail(path, self.stop):
            self._parse_unix_auth(line)

    def _auth_macos(self):
        # Best-effort: stream the unified log for sshd/sudo/authorization events.
        cmd = ["log", "stream", "--style", "syslog", "--predicate",
               'process == "sshd" OR process == "sudo" OR process == "authd"']
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, bufsize=1)
        except (FileNotFoundError, OSError) as e:
            log(f"auth: could not start 'log stream' ({e}); auth disabled")
            return
        try:
            for line in proc.stdout:
                if self.stop.is_set():
                    break
                self._parse_unix_auth(line)
        finally:
            proc.terminate()

    def _parse_unix_auth(self, line):
        import re
        low = line.lower()
        if "sshd" in low and ("accepted" in low or "failed password" in low):
            result = "success" if "accepted" in low else "failure"
            m_user = re.search(r"for (?:invalid user )?(\S+)", line)
            m_ip = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)
            self.emit("auth", "login", auth={
                "method": "ssh", "result": result,
                "user": m_user.group(1) if m_user else None,
                "source_ip": m_ip.group(1) if m_ip else None,
                "raw": line.strip()[:400],
            })
        elif "sudo" in low and ("authentication failure" in low or "incorrect password" in low):
            m_user = re.search(r"user=(\S+)", line) or re.search(r"USER=(\S+)", line)
            self.emit("auth", "sudo", auth={
                "method": "sudo", "result": "failure",
                "user": m_user.group(1) if m_user else None,
                "raw": line.strip()[:400],
            })

    def _auth_windows(self):
        # Poll the Security log for 4624 (success), 4625 (failure), 4672 (priv).
        last = time.time()
        ps_template = (
            "$ErrorActionPreference='Stop';"
            "Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4624,4625,4672;"
            "StartTime=(Get-Date).AddSeconds(-{secs})}} -ErrorAction SilentlyContinue |"
            "ForEach-Object {{ $x=[xml]$_.ToXml(); $d=@{{}};"
            "$x.Event.EventData.Data | ForEach-Object {{ $d[$_.Name]=$_.'#text' }};"
            "[pscustomobject]@{{Id=$_.Id;Time=$_.TimeCreated.ToString('o');"
            "User=$d['TargetUserName'];Domain=$d['TargetDomainName'];"
            "LogonType=$d['LogonType'];Ip=$d['IpAddress']}} }} |"
            "ConvertTo-Json -Compress"
        )
        denied_logged = False
        while not self.stop.is_set():
            interval = max(5.0, time.time() - last)
            last = time.time()
            ps = ps_template.format(secs=int(interval) + 2)
            try:
                out = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                    capture_output=True, text=True, timeout=30,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                log(f"auth: powershell query failed ({e})")
                self.stop.wait(15)
                continue
            data = (out.stdout or "").strip()
            if not data:
                if out.returncode != 0 and not denied_logged:
                    log("auth: cannot read Security log (run agent as Administrator)")
                    denied_logged = True
                self.stop.wait(8)
                continue
            try:
                parsed = json.loads(data)
            except json.JSONDecodeError:
                self.stop.wait(8)
                continue
            for rec in (parsed if isinstance(parsed, list) else [parsed]):
                eid = int(rec.get("Id", 0))
                result = "failure" if eid == 4625 else "success"
                self.emit("auth", "login", auth={
                    "method": "windows", "result": result,
                    "user": rec.get("User"), "source_ip": rec.get("Ip"),
                    "logon_type": rec.get("LogonType"),
                    "raw": f"EventID {eid}",
                })
            self.stop.wait(8)


def _safe(fn, default=None):
    try:
        return fn()
    except (psutil.Error, Exception):
        return default


def _tail(path, stop_event):
    """Yield new lines appended to a file (handles truncation/rotation)."""
    with open(path, "r", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while not stop_event.is_set():
            line = f.readline()
            if not line:
                # detect rotation
                try:
                    if os.stat(path).st_size < f.tell():
                        f.seek(0)
                except OSError:
                    pass
                stop_event.wait(0.5)
                continue
            yield line


# ---------------------------------------------------------------------------
# shipper
# ---------------------------------------------------------------------------
class Shipper(threading.Thread):
    def __init__(self, cfg, device_id, q, ip):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.device_id = device_id
        self.q = q
        self.ip = ip
        self.stop = threading.Event()
        self.buffer = []
        self.last_send = 0

    def run(self):
        url = self.cfg["server"] + "/api/events"
        hb = self.cfg["server"] + "/api/heartbeat"
        headers = {"Authorization": "Bearer " + self.cfg["enroll_key"]}
        while not self.stop.is_set():
            # drain queue
            try:
                while len(self.buffer) < 500:
                    self.buffer.append(self.q.get_nowait())
            except queue.Empty:
                pass

            now = time.time()
            if self.buffer:
                try:
                    r = requests.post(url, headers=headers, timeout=10, json={
                        "device_id": self.device_id, "ip": self.ip,
                        "events": self.buffer[:500],
                    })
                    r.raise_for_status()
                    self.buffer = self.buffer[500:]
                    self.last_send = now
                except requests.RequestException as e:
                    status = getattr(getattr(e, "response", None), "status_code", "n/a")
                    log(f"send to {url} failed (HTTP {status}: {e}); buffering {len(self.buffer)} event(s)", "ERROR")
                    if len(self.buffer) > 5000:
                        dropped = len(self.buffer) - 5000
                        self.buffer = self.buffer[-5000:]
                        log(f"offline backlog full; dropped {dropped} oldest event(s)", "WARN")
            elif now - self.last_send > 30:
                try:
                    requests.post(hb, headers=headers, timeout=10,
                                  json={"device_id": self.device_id, "ip": self.ip})
                    self.last_send = now
                except requests.RequestException as e:
                    log(f"heartbeat to {hb} failed ({e})", "WARN")
            self.stop.wait(self.cfg["ship_interval"])


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def run_check(cfg):
    """One-shot connectivity + key check used by the installers. Exit code:
    0 = live, 2 = key rejected, 1/3 = unreachable / unexpected."""
    log(f"checking {cfg['server']} (host={HOSTNAME} platform={PLATFORM})")
    try:
        r = requests.get(cfg["server"] + "/api/ping",
                         headers={"Authorization": "Bearer " + cfg["enroll_key"]},
                         timeout=10)
    except requests.RequestException as e:
        log(f"NOT LIVE: cannot reach {cfg['server']} ({e})", "ERROR")
        return 1
    if r.status_code == 200:
        log("LIVE: server reachable and enroll key accepted.")
        return 0
    if r.status_code in (401, 403):
        log(f"NOT LIVE: enroll key rejected (HTTP {r.status_code}) — the key in "
            f"config.yaml does not match the server's HOMESOC_ENROLL_KEY.", "ERROR")
        return 2
    log(f"NOT LIVE: unexpected HTTP {r.status_code} from {cfg['server']}", "ERROR")
    return 3


def main():
    cfg = load_config()
    if cfg.get("check"):
        sys.exit(run_check(cfg))
    ip = primary_ip(cfg["server"].split("//")[-1].split(":")[0].split("/")[0])
    log(f"host={HOSTNAME} platform={PLATFORM} server={cfg['server']}")

    # enroll with retry (server may not be up yet)
    device_id = None
    while device_id is None:
        try:
            device_id = enroll(cfg, ip)
        except requests.RequestException as e:
            log(f"enroll failed ({e}); retrying in 10s")
            time.sleep(10)

    q = queue.Queue(maxsize=20000)
    collectors = Collectors(cfg, device_id, q)
    shipper = Shipper(cfg, device_id, q, ip)
    shipper.start()

    threads = []
    for target, name in [
        (collectors.run_process, "process"),
        (collectors.run_network, "network"),
        (collectors.run_file, "file"),
        (collectors.run_auth, "auth"),
    ]:
        t = threading.Thread(target=target, name=name, daemon=True)
        t.start()
        threads.append(t)
    log("collectors running: process, network, file, auth")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("shutting down")
        collectors.stop.set()
        shipper.stop.set()


if __name__ == "__main__":
    main()
