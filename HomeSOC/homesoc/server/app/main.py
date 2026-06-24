"""HomeSOC server — ingestion, detection, dashboard API.

Endpoints
  POST /api/enroll                 device registration (shared enroll key)
  POST /api/events                 batch event ingest -> runs detection
  POST /api/heartbeat              keep-alive
  GET  /api/devices                fleet list
  GET  /api/alerts                 alert queue (filterable)
  GET  /api/alerts/{id}            full alert "story"
  POST /api/alerts/{id}/status     triage state change
  POST /api/alerts/{id}/analyze    optional Claude behavioral analysis
  GET  /api/rules                  loaded signature rules
  POST /api/rules/reload           hot-reload rules from disk
  GET/POST /api/settings           Claude token/model (token stored, masked on read)
  GET  /api/stats                  header counters
  GET  /                           dashboard SPA

AuthN (v1): a single shared enroll key (HOMESOC_ENROLL_KEY) sent by agents as
  Authorization: Bearer <key>.  Adequate for a trusted LAN lab; per-device
  secrets + TLS are the documented hardening path, not implemented here.
"""
import datetime as dt
import hmac
import json
import logging
import os
import re
import traceback

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import claude, db
from .detection import Engine, validate_definition

logger = logging.getLogger("homesoc")

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.environ.get("HOMESOC_RULES", os.path.join(os.path.dirname(HERE), "rules"))
STATIC_DIR = os.path.join(os.path.dirname(HERE), "static")
ENROLL_KEY = os.environ.get("HOMESOC_ENROLL_KEY", "changeme")

app = FastAPI(title="HomeSOC")
engine: Engine = None


def _custom_rules_provider():
    out = []
    for row in db.list_custom_rules(only_enabled=True):
        try:
            out.append((row["id"], json.loads(row["definition"])))
        except (json.JSONDecodeError, TypeError):
            continue
    return out


def _slugify(s):
    s = re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")
    return s or "rule"


@app.on_event("startup")
def _startup():
    global engine
    logging.basicConfig(
        level=os.environ.get("HOMESOC_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s [%(funcName)s:%(lineno)d] %(message)s",
    )
    db.init()
    engine = Engine(RULES_DIR, custom_provider=_custom_rules_provider)
    if ENROLL_KEY == "changeme":
        logger.warning("HOMESOC_ENROLL_KEY is the default 'changeme'. "
                       "Set a strong value before exposing the server.")
    logger.info("loaded %d rules; %d rule errors", len(engine.rules), len(engine.errors))
    for e in engine.errors:
        logger.warning("rule error: %s", e)


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    """Return the precise failure site (file:line:function) and log the traceback.

    HTTPException is handled by Starlette and never reaches here, so this only
    fires for genuinely unexpected errors.
    """
    where = "unknown"
    for frame, lineno in traceback.walk_tb(exc.__traceback__):
        fn = frame.f_code.co_filename
        if "site-packages" not in fn and "lib/python" not in fn:
            where = f"{os.path.basename(fn)}:{lineno} in {frame.f_code.co_name}()"
    logger.error("unhandled %s on %s %s -> %s\n%s",
                 type(exc).__name__, request.method, request.url.path, where,
                 "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    return JSONResponse(status_code=500, content={
        "error": type(exc).__name__,
        "detail": str(exc),
        "where": where,
        "path": request.url.path,
        "method": request.method,
    })


# ----- auth ----------------------------------------------------------------

def require_key(authorization: str = Header(None)):
    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not hmac.compare_digest(token, ENROLL_KEY):
        raise HTTPException(status_code=401, detail="bad enroll key")
    return True


@app.get("/api/ping")
def ping(_=Depends(require_key)):
    # cheap connectivity + key check (no side effects); used by the installers
    return {"ok": True}


# ----- models --------------------------------------------------------------

class EnrollReq(BaseModel):
    hostname: str
    platform: str
    agent_version: str = "0"
    ip: str | None = None


class EventBatch(BaseModel):
    device_id: str
    events: list[dict]
    ip: str | None = None


class Heartbeat(BaseModel):
    device_id: str
    ip: str | None = None


class StatusReq(BaseModel):
    status: str


class SettingsReq(BaseModel):
    claude_token: str | None = None
    claude_model: str | None = None
    claude_enabled: bool | None = None


class RuleSaveReq(BaseModel):
    definition: dict
    enabled: bool = True


class RuleValidateReq(BaseModel):
    definition: dict
    sample_event: dict | None = None


class ToggleReq(BaseModel):
    enabled: bool


# ----- ingestion -----------------------------------------------------------

@app.post("/api/enroll")
def enroll(req: EnrollReq, _=Depends(require_key)):
    import uuid
    device_id = str(uuid.uuid4())
    db.upsert_device(device_id, req.hostname, req.platform, req.ip, req.agent_version)
    return {"device_id": device_id}


@app.post("/api/heartbeat")
def heartbeat(req: Heartbeat, _=Depends(require_key)):
    db.touch_device(req.device_id, req.ip)
    return {"ok": True}


@app.post("/api/events")
def ingest(batch: EventBatch, _=Depends(require_key)):
    if len(batch.events) > 5000:
        raise HTTPException(413, f"event batch too large ({len(batch.events)}); max 5000 per request")
    db.touch_device(batch.device_id, batch.ip)
    fired = 0
    errors = []
    for i, ev in enumerate(batch.events):
        try:
            ev.setdefault("device_id", batch.device_id)
            eid = db.insert_event(ev)
            for rule in engine.match(ev):
                db.insert_alert({
                    "ts": float(ev.get("ts") or _now()),
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity,
                    "category": ev.get("category"),
                    "mitre": rule.mitre,
                    "device_id": batch.device_id,
                    "hostname": ev.get("hostname"),
                    "event_id": eid,
                    "event": ev,
                })
                fired += 1
        except Exception as e:  # one bad event must not drop the whole batch
            logger.exception("ingest failed for event index %d (device=%s)", i, batch.device_id)
            errors.append({"index": i, "error": type(e).__name__, "detail": str(e)})
    out = {"ingested": len(batch.events), "alerts": fired}
    if errors:
        out["errors"] = errors
    return out


def _now():
    import time
    return time.time()


# ----- read APIs -----------------------------------------------------------

@app.get("/api/devices")
def devices():
    return db.list_devices()


@app.get("/api/stats")
def stats():
    return {
        "alerts": db.alert_counts(),
        "devices": len(db.list_devices()),
        "rules": len(engine.rules),
    }


@app.get("/api/alerts")
def alerts(status: str = None, severity: str = None):
    return db.list_alerts(status=status, severity=severity)


@app.get("/api/alerts/{aid}")
def alert_story(aid: str):
    a = db.get_alert(aid)
    if not a:
        raise HTTPException(404, "alert not found")
    story = build_story(a)
    return {"alert": a, **story}


@app.post("/api/alerts/{aid}/status")
def set_status(aid: str, req: StatusReq):
    if req.status not in ("new", "investigating", "resolved"):
        raise HTTPException(400, "invalid status")
    if not db.get_alert(aid):
        raise HTTPException(404, "alert not found")
    # resolving clears the alert from the dashboard entirely
    if req.status == "resolved":
        db.delete_alert(aid)
        return {"ok": True, "deleted": True}
    db.set_alert_status(aid, req.status)
    return {"ok": True, "deleted": False}


@app.post("/api/alerts/{aid}/analyze")
def analyze(aid: str):
    a = db.get_alert(aid)
    if not a:
        raise HTTPException(404, "alert not found")
    if not claude.is_enabled():
        raise HTTPException(400, "Claude analysis disabled — set a token in Settings.")
    story = build_story(a)
    try:
        text = claude.analyze(a, {"alert": a, **story})
    except RuntimeError as e:
        raise HTTPException(502, str(e))
    db.set_alert_behavioral(aid, text)
    return {"behavioral": text}


@app.get("/api/rules")
def rules():
    summary = engine.summary()
    # engine.rules only holds enabled rules; surface disabled custom rules too so
    # the dashboard can still display and re-enable them.
    present = {r["id"] for r in summary["rules"]}
    for row in db.list_custom_rules():
        if row["id"] in present:
            continue
        try:
            defn = json.loads(row["definition"])
        except (json.JSONDecodeError, TypeError):
            continue
        summary["rules"].append({
            "id": row["id"], "title": defn.get("title", row["id"]),
            "severity": (defn.get("severity") or "medium").lower(),
            "category": defn.get("category"), "platform": defn.get("platform") or [],
            "mitre": defn.get("mitre") or [], "description": defn.get("description", ""),
            "references": defn.get("references") or [],
            "match": defn.get("detection", {}).get("match", []),
            "source": "custom", "enabled": False,
        })
    return summary


@app.post("/api/rules/reload")
def reload_rules():
    engine.load()
    return engine.summary()


@app.post("/api/rules/validate")
def validate_rule(req: RuleValidateReq):
    """Check a rule definition (and optionally test it against a sample event)
    without saving it. Powers the editor's Validate / Test-match buttons."""
    return validate_definition(req.definition, req.sample_event)


@app.post("/api/rules/custom")
def create_custom_rule(req: RuleSaveReq):
    defn = dict(req.definition)
    rid = _slugify(defn.get("id") or defn.get("title") or "")
    if not rid.startswith("custom-"):
        rid = "custom-" + rid
    defn["id"] = rid
    existing = engine.builtin_ids() | {r["id"] for r in db.list_custom_rules()}
    if rid in existing:
        raise HTTPException(409, f"a rule with id '{rid}' already exists")
    v = validate_definition(defn)
    if not v["valid"]:
        raise HTTPException(400, v["error"])
    db.upsert_custom_rule(rid, json.dumps(defn), enabled=req.enabled)
    engine.load()
    return {"id": rid, "summary": engine.summary()}


@app.put("/api/rules/custom/{rule_id}")
def update_custom_rule(rule_id: str, req: RuleSaveReq):
    if not db.get_custom_rule(rule_id):
        raise HTTPException(404, "custom rule not found")
    defn = dict(req.definition)
    defn["id"] = rule_id  # id is immutable once created
    v = validate_definition(defn)
    if not v["valid"]:
        raise HTTPException(400, v["error"])
    db.upsert_custom_rule(rule_id, json.dumps(defn), enabled=req.enabled)
    engine.load()
    return {"id": rule_id, "summary": engine.summary()}


@app.post("/api/rules/custom/{rule_id}/toggle")
def toggle_custom_rule(rule_id: str, req: ToggleReq):
    if not db.get_custom_rule(rule_id):
        raise HTTPException(404, "custom rule not found")
    db.set_custom_rule_enabled(rule_id, req.enabled)
    engine.load()
    return {"id": rule_id, "enabled": req.enabled}


@app.delete("/api/rules/custom/{rule_id}")
def remove_custom_rule(rule_id: str):
    if not db.delete_custom_rule(rule_id):
        raise HTTPException(404, "custom rule not found")
    engine.load()
    return {"ok": True}


@app.get("/api/settings")
def get_settings():
    token = db.get_setting("claude_token") or ""
    return {
        "claude_enabled": db.get_setting("claude_enabled") == "1",
        "claude_model": db.get_setting("claude_model") or claude.DEFAULT_MODEL,
        "claude_token_set": bool(token),
        "claude_token_masked": ("sk-…" + token[-4:]) if len(token) >= 4 else "",
    }


@app.post("/api/settings")
def post_settings(req: SettingsReq):
    if req.claude_token is not None:
        # empty string clears the token
        db.set_setting("claude_token", req.claude_token.strip())
    if req.claude_model is not None:
        db.set_setting("claude_model", req.claude_model.strip())
    if req.claude_enabled is not None:
        db.set_setting("claude_enabled", "1" if req.claude_enabled else "0")
    return get_settings()


# ----- alert story builder -------------------------------------------------

def _iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event_summary(ev: dict) -> str:
    cat = ev.get("category")
    p = ev.get("process") or {}
    if cat == "process":
        return f"{p.get('name','?')} :: {p.get('cmdline','')}".strip()
    if cat == "file":
        f = ev.get("file") or {}
        return f"{ev.get('action','')} {f.get('path','')}".strip()
    if cat == "network":
        n = ev.get("network") or {}
        return (f"{n.get('process_name','?')} -> {n.get('raddr','')}:{n.get('rport','')} "
                f"{n.get('proto','')} {n.get('status','')}").strip()
    if cat == "auth":
        au = ev.get("auth") or {}
        return (f"{au.get('result','')} {au.get('method','')} user={au.get('user','')} "
                f"from={au.get('source_ip','')}").strip()
    return ev.get("action", "")


def build_story(alert: dict) -> dict:
    ev = alert.get("event") or {}
    device_id = alert["device_id"]
    ts = alert["ts"]

    device = next((d for d in db.list_devices() if d["device_id"] == device_id), {})

    rule = next((r for r in engine.rules if r.id == alert["rule_id"]), None)
    rule_info = {
        "id": alert["rule_id"],
        "title": alert["title"],
        "severity": alert["severity"],
        "description": rule.description if rule else "",
        "mitre": alert.get("mitre") or [],
        "references": rule.references if rule else [],
        "match": rule.match if rule else [],
    }

    tree = _process_tree(device_id, ev, ts)

    window = 300
    raw_tl = db.events_for_device(device_id, ts - window, ts + window, limit=300)
    timeline = []
    for r in raw_tl:
        e = r["raw"]
        timeline.append({
            "id": r["id"],
            "ts": r["ts"],
            "ts_iso": _iso(r["ts"]),
            "category": e.get("category"),
            "action": e.get("action"),
            "summary": _event_summary(e),
            "is_trigger": r["id"] == alert.get("event_id"),
        })

    return {
        "device": device,
        "rule": rule_info,
        "process_tree": tree,
        "timeline": timeline,
        "behavioral": alert.get("behavioral"),
        "story_note": ("Lineage and timeline are reconstructed from polled "
                       "telemetry and may be partial; short-lived activity "
                       "between samples can be missing."),
    }


def _process_tree(device_id, ev, ts):
    """Reconstruct ancestor chain + immediate children from sampled process events."""
    procs = db.process_events_for_device(device_id, ts)
    by_pid = {}
    for r in procs:
        pid = r.get("pid")
        if pid is not None and pid not in by_pid:
            by_pid[pid] = r  # newest occurrence wins (rows are DESC by ts)

    trig = ev.get("process") or {}
    trig_pid = _toint(trig.get("pid"))

    chain = []  # root -> ... -> trigger
    seen = set()
    cur_pid, cur_ppid = trig_pid, _toint(trig.get("ppid"))
    cur_node = _node_from_event(ev) if ev.get("category") == "process" else (
        _node_from_row(by_pid.get(trig_pid)) if trig_pid in by_pid else None)
    if cur_node is None and trig_pid is not None:
        cur_node = {"pid": trig_pid, "ppid": cur_ppid, "process_name": trig.get("name"),
                    "cmdline": trig.get("cmdline", "")}
    if cur_node:
        chain.append(cur_node)
        seen.add(trig_pid)

    walk_ppid = cur_ppid
    hops = 0
    while walk_ppid is not None and walk_ppid not in seen and hops < 12:
        row = by_pid.get(walk_ppid)
        if not row:
            break
        node = _node_from_row(row)
        chain.append(node)
        seen.add(walk_ppid)
        walk_ppid = node.get("ppid")
        hops += 1

    chain.reverse()
    for depth, n in enumerate(chain):
        n["depth"] = depth
        n["is_trigger"] = (n.get("pid") == trig_pid)

    # immediate children of the trigger pid
    if trig_pid is not None:
        child_depth = chain[-1]["depth"] + 1 if chain else 0
        for r in procs:
            if r.get("ppid") == trig_pid and r.get("pid") != trig_pid:
                node = _node_from_row(r)
                node["depth"] = child_depth
                node["is_trigger"] = False
                chain.append(node)
    return chain


def _node_from_row(r):
    if not r:
        return {}
    e = r.get("raw") or {}
    p = e.get("process") or {}
    return {"pid": r.get("pid"), "ppid": r.get("ppid"),
            "process_name": r.get("process_name") or p.get("name"),
            "cmdline": p.get("cmdline", ""), "ts": r.get("ts")}


def _node_from_event(e):
    p = e.get("process") or {}
    return {"pid": _toint(p.get("pid")), "ppid": _toint(p.get("ppid")),
            "process_name": p.get("name"), "cmdline": p.get("cmdline", ""),
            "ts": e.get("ts")}


def _toint(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


# ----- static dashboard ----------------------------------------------------

@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
