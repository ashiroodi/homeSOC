"""SQLite storage layer — single file, WAL mode.

Sized for a home/lab fleet (tens of endpoints, modest event volume). Swap this
module for ClickHouse if you outgrow it; the app talks to these helpers, not to
SQL directly.
"""
import json
import os
import sqlite3
import threading
import time
import uuid

DB_PATH = os.environ.get("HOMESOC_DB", "/data/homesoc.db")

_conn = None
_lock = threading.Lock()


def _now() -> float:
    return time.time()


def init(db_path: str = None):
    global _conn
    if db_path:
        globals()["DB_PATH"] = db_path
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)) or ".", exist_ok=True)
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")
    _conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            device_id   TEXT PRIMARY KEY,
            hostname    TEXT,
            platform    TEXT,
            ip          TEXT,
            agent_version TEXT,
            first_seen  REAL,
            last_seen   REAL
        );

        CREATE TABLE IF NOT EXISTS events (
            id          TEXT PRIMARY KEY,
            ts          REAL,
            device_id   TEXT,
            hostname    TEXT,
            platform    TEXT,
            category    TEXT,
            action      TEXT,
            pid         INTEGER,
            ppid        INTEGER,
            process_name TEXT,
            raw         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_dev_ts ON events(device_id, ts);
        CREATE INDEX IF NOT EXISTS idx_events_cat    ON events(category);
        CREATE INDEX IF NOT EXISTS idx_events_pid    ON events(device_id, pid);

        CREATE TABLE IF NOT EXISTS alerts (
            id          TEXT PRIMARY KEY,
            ts          REAL,
            created_at  REAL,
            rule_id     TEXT,
            title       TEXT,
            severity    TEXT,
            category    TEXT,
            mitre       TEXT,
            device_id   TEXT,
            hostname    TEXT,
            event_id    TEXT,
            event       TEXT,
            status      TEXT,
            behavioral  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(ts);
        CREATE INDEX IF NOT EXISTS idx_alerts_dev ON alerts(device_id);

        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS custom_rules (
            id          TEXT PRIMARY KEY,
            definition  TEXT,
            enabled     INTEGER DEFAULT 1,
            created_at  REAL,
            updated_at  REAL
        );
        """
    )
    _conn.commit()


# ----- devices -------------------------------------------------------------

def upsert_device(device_id, hostname, platform, ip=None, agent_version=None):
    with _lock:
        row = _conn.execute(
            "SELECT first_seen FROM devices WHERE device_id=?", (device_id,)
        ).fetchone()
        now = _now()
        first = row["first_seen"] if row else now
        _conn.execute(
            """INSERT INTO devices(device_id,hostname,platform,ip,agent_version,first_seen,last_seen)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(device_id) DO UPDATE SET
                 hostname=excluded.hostname, platform=excluded.platform,
                 ip=COALESCE(excluded.ip, devices.ip),
                 agent_version=COALESCE(excluded.agent_version, devices.agent_version),
                 last_seen=excluded.last_seen""",
            (device_id, hostname, platform, ip, agent_version, first, now),
        )
        _conn.commit()


def touch_device(device_id, ip=None):
    with _lock:
        _conn.execute(
            "UPDATE devices SET last_seen=?, ip=COALESCE(?, ip) WHERE device_id=?",
            (_now(), ip, device_id),
        )
        _conn.commit()


def list_devices():
    with _lock:
        rows = _conn.execute("SELECT * FROM devices ORDER BY hostname").fetchall()
    out = []
    now = _now()
    for r in rows:
        d = dict(r)
        d["online"] = (now - (d.get("last_seen") or 0)) < 120
        out.append(d)
    return out


# ----- events --------------------------------------------------------------

def insert_event(ev: dict) -> str:
    eid = str(uuid.uuid4())
    proc = ev.get("process") or {}
    with _lock:
        _conn.execute(
            """INSERT INTO events(id,ts,device_id,hostname,platform,category,action,
                                  pid,ppid,process_name,raw)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                eid,
                float(ev.get("ts") or _now()),
                ev.get("device_id"),
                ev.get("hostname"),
                ev.get("platform"),
                ev.get("category"),
                ev.get("action"),
                _int(proc.get("pid")),
                _int(proc.get("ppid")),
                proc.get("name"),
                json.dumps(ev),
            ),
        )
        _conn.commit()
    return eid


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def events_for_device(device_id, start, end, limit=300):
    with _lock:
        rows = _conn.execute(
            """SELECT * FROM events WHERE device_id=? AND ts BETWEEN ? AND ?
               ORDER BY ts ASC LIMIT ?""",
            (device_id, start, end, limit),
        ).fetchall()
    return [_event_row(r) for r in rows]


def process_events_for_device(device_id, before_ts, lookback=3600):
    """Process exec events for tree reconstruction, newest first."""
    with _lock:
        rows = _conn.execute(
            """SELECT * FROM events WHERE device_id=? AND category='process'
               AND ts BETWEEN ? AND ? ORDER BY ts DESC LIMIT 2000""",
            (device_id, before_ts - lookback, before_ts + 60),
        ).fetchall()
    return [_event_row(r) for r in rows]


def _event_row(r):
    d = dict(r)
    try:
        d["raw"] = json.loads(d["raw"]) if d.get("raw") else {}
    except (json.JSONDecodeError, TypeError):
        d["raw"] = {}
    return d


def prune_events(retention_days=14):
    cutoff = _now() - retention_days * 86400
    with _lock:
        _conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        _conn.commit()


# ----- alerts --------------------------------------------------------------

def insert_alert(alert: dict) -> str:
    aid = str(uuid.uuid4())
    with _lock:
        _conn.execute(
            """INSERT INTO alerts(id,ts,created_at,rule_id,title,severity,category,
                                  mitre,device_id,hostname,event_id,event,status,behavioral)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                aid,
                alert["ts"],
                _now(),
                alert["rule_id"],
                alert["title"],
                alert["severity"],
                alert.get("category"),
                json.dumps(alert.get("mitre") or []),
                alert["device_id"],
                alert.get("hostname"),
                alert.get("event_id"),
                json.dumps(alert.get("event") or {}),
                "new",
                None,
            ),
        )
        _conn.commit()
    return aid


def list_alerts(status=None, severity=None, limit=500):
    q = "SELECT * FROM alerts"
    clauses, params = [], []
    if status:
        clauses.append("status=?"); params.append(status)
    if severity:
        clauses.append("severity=?"); params.append(severity)
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    q += " ORDER BY ts DESC LIMIT ?"; params.append(limit)
    with _lock:
        rows = _conn.execute(q, params).fetchall()
    return [_alert_row(r) for r in rows]


def get_alert(aid):
    with _lock:
        r = _conn.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
    return _alert_row(r) if r else None


def set_alert_status(aid, status):
    with _lock:
        _conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, aid))
        _conn.commit()


def delete_alert(aid):
    with _lock:
        cur = _conn.execute("DELETE FROM alerts WHERE id=?", (aid,))
        _conn.commit()
    return cur.rowcount > 0


def set_alert_behavioral(aid, text):
    with _lock:
        _conn.execute("UPDATE alerts SET behavioral=? WHERE id=?", (text, aid))
        _conn.commit()


def alert_counts():
    with _lock:
        rows = _conn.execute(
            "SELECT severity, COUNT(*) c FROM alerts WHERE status!='resolved' GROUP BY severity"
        ).fetchall()
    return {r["severity"]: r["c"] for r in rows}


def _alert_row(r):
    d = dict(r)
    for k in ("mitre", "event"):
        try:
            d[k] = json.loads(d[k]) if d.get(k) else ([] if k == "mitre" else {})
        except (json.JSONDecodeError, TypeError):
            d[k] = [] if k == "mitre" else {}
    return d


# ----- settings ------------------------------------------------------------

def get_setting(key, default=None):
    with _lock:
        r = _conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(key, value):
    with _lock:
        _conn.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        _conn.commit()


# ----- custom rules --------------------------------------------------------

def list_custom_rules(only_enabled=False):
    q = "SELECT * FROM custom_rules"
    if only_enabled:
        q += " WHERE enabled=1"
    q += " ORDER BY updated_at DESC"
    with _lock:
        rows = _conn.execute(q).fetchall()
    return [dict(r) for r in rows]


def get_custom_rule(rule_id):
    with _lock:
        r = _conn.execute("SELECT * FROM custom_rules WHERE id=?", (rule_id,)).fetchone()
    return dict(r) if r else None


def upsert_custom_rule(rule_id, definition_json, enabled=True):
    now = _now()
    with _lock:
        row = _conn.execute("SELECT created_at FROM custom_rules WHERE id=?", (rule_id,)).fetchone()
        created = row["created_at"] if row else now
        _conn.execute(
            """INSERT INTO custom_rules(id,definition,enabled,created_at,updated_at)
               VALUES(?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 definition=excluded.definition, enabled=excluded.enabled,
                 updated_at=excluded.updated_at""",
            (rule_id, definition_json, 1 if enabled else 0, created, now),
        )
        _conn.commit()


def set_custom_rule_enabled(rule_id, enabled):
    with _lock:
        _conn.execute("UPDATE custom_rules SET enabled=?, updated_at=? WHERE id=?",
                      (1 if enabled else 0, _now(), rule_id))
        _conn.commit()


def delete_custom_rule(rule_id):
    with _lock:
        cur = _conn.execute("DELETE FROM custom_rules WHERE id=?", (rule_id,))
        _conn.commit()
    return cur.rowcount > 0
