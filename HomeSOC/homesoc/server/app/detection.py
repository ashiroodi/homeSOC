"""Signature detection engine.

Stateless, per-event matching against YAML rules: one event in, zero or more
alerts out. Windowed and aggregate detections (rate-based brute force, beaconing)
are out of scope here; correlated reasoning lives in the optional Claude path.
"""
import ipaddress
import logging
import os
import re

import yaml

log = logging.getLogger("homesoc.detection")


class Rule:
    def __init__(self, d: dict):
        self.id = d.get("id")
        self.title = d.get("title", self.id)
        self.severity = (d.get("severity") or "medium").lower()
        self.category = d.get("category")            # optional event-category filter
        self.platform = _as_list(d.get("platform"))  # optional ["linux",...]
        self.description = d.get("description", "")
        self.mitre = _as_list(d.get("mitre"))
        self.references = _as_list(d.get("references"))
        self.match = d.get("detection", {}).get("match", [])
        self.source = "builtin"   # set to "custom" by the engine for DB rules
        self.enabled = True
        if not self.id:
            raise ValueError("rule missing id")
        if not self.match:
            raise ValueError(f"rule {self.id} has empty detection.match")

    def to_definition(self) -> dict:
        d = {"id": self.id, "title": self.title, "severity": self.severity,
             "description": self.description, "detection": {"match": self.match}}
        if self.category:
            d["category"] = self.category
        if self.platform:
            d["platform"] = self.platform
        if self.mitre:
            d["mitre"] = self.mitre
        if self.references:
            d["references"] = self.references
        return d

    def applies_to(self, ev):
        if self.category and ev.get("category") != self.category:
            return False
        if self.platform and ev.get("platform") not in self.platform:
            return False
        return True

    def evaluate(self, ev) -> bool:
        # all conditions AND-ed
        return all(_eval_condition(c, ev) for c in self.match)


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ----- field access --------------------------------------------------------

def get_field(ev: dict, dotted: str):
    cur = ev
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


# ----- operators -----------------------------------------------------------

def _norm(v, cs):
    s = "" if v is None else str(v)
    return s if cs else s.lower()


def _eval_condition(cond: dict, ev: dict) -> bool:
    field = cond.get("field")
    op = (cond.get("op") or "equals").lower()
    cs = bool(cond.get("case_sensitive", False))
    val = cond.get("value")
    vals = cond.get("values") or ([] if val is None else [val])
    actual = get_field(ev, field)

    if op == "exists":
        return actual is not None
    if op == "not_exists":
        return actual is None

    if op in ("equals", "eq"):
        return _norm(actual, cs) == _norm(val, cs)
    if op in ("not_equals", "neq"):
        return _norm(actual, cs) != _norm(val, cs)
    if op == "in":
        return _norm(actual, cs) in [_norm(x, cs) for x in vals]
    if op == "not_in":
        return _norm(actual, cs) not in [_norm(x, cs) for x in vals]

    a = _norm(actual, cs)
    if op == "contains":
        return _norm(val, cs) in a
    if op == "contains_any":
        return any(_norm(x, cs) in a for x in vals)
    if op == "contains_all":
        return all(_norm(x, cs) in a for x in vals)
    if op == "startswith":
        return any(a.startswith(_norm(x, cs)) for x in vals)
    if op == "endswith":
        return any(a.endswith(_norm(x, cs)) for x in vals)
    if op == "regex":
        flags = 0 if cs else re.IGNORECASE
        return any(re.search(p, str(actual or ""), flags) for p in vals)

    if op in ("gt", "lt", "gte", "lte"):
        try:
            an = float(actual); vn = float(val)
        except (TypeError, ValueError):
            return False
        return {"gt": an > vn, "lt": an < vn, "gte": an >= vn, "lte": an <= vn}[op]

    # IP helpers
    if op == "ip_public":
        return _ip_is_public(actual)
    if op == "ip_private":
        return _ip_is_private(actual)
    if op == "ip_in":
        return _ip_in_any(actual, vals)
    if op == "ip_not_in":
        return not _ip_in_any(actual, vals)

    raise ValueError(f"unknown operator: {op}")


def _ip(v):
    try:
        return ipaddress.ip_address(str(v))
    except ValueError:
        return None


def _ip_is_private(v):
    ip = _ip(v)
    return bool(ip and (ip.is_private or ip.is_loopback or ip.is_link_local))


def _ip_is_public(v):
    ip = _ip(v)
    return bool(ip and not (ip.is_private or ip.is_loopback or ip.is_link_local
                            or ip.is_multicast or ip.is_reserved or ip.is_unspecified))


def _ip_in_any(v, cidrs):
    ip = _ip(v)
    if not ip:
        return False
    for c in cidrs:
        try:
            if ip in ipaddress.ip_network(str(c), strict=False):
                return True
        except ValueError:
            continue
    return False


# ----- engine --------------------------------------------------------------

class Engine:
    def __init__(self, rules_dir: str, custom_provider=None):
        self.rules_dir = rules_dir
        # custom_provider() -> list of (rule_id, definition_dict); injected by the
        # kept out of this module so detection has no DB dependency.
        self.custom_provider = custom_provider
        self.rules = []
        self.errors = []
        self.load()

    def load(self):
        rules, errors = [], []
        seen = set()
        for fn in sorted(os.listdir(self.rules_dir)):
            if not fn.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(self.rules_dir, fn)
            try:
                with open(path) as f:
                    docs = list(yaml.safe_load_all(f))
            except yaml.YAMLError as e:
                errors.append(f"{fn}: {e}")
                continue
            for doc in docs:
                if not doc:
                    continue
                try:
                    r = Rule(doc)
                except ValueError as e:
                    errors.append(f"{fn}: {e}")
                    continue
                if r.id in seen:
                    errors.append(f"{fn}: duplicate rule id {r.id}")
                    continue
                seen.add(r.id)
                rules.append(r)

        # custom rules from the dashboard (enabled only, provided by the app)
        if self.custom_provider:
            try:
                custom = self.custom_provider()
            except Exception as e:  # provider failure must not break detection
                custom = []
                errors.append(f"custom rules: {e}")
            for rid, defn in custom:
                try:
                    r = Rule(defn)
                except ValueError as e:
                    errors.append(f"custom {rid}: {e}")
                    continue
                r.source = "custom"
                if r.id in seen:
                    errors.append(f"custom {rid}: id collides with an existing rule")
                    continue
                seen.add(r.id)
                rules.append(r)

        self.rules, self.errors = rules, errors
        return self

    def builtin_ids(self):
        return {r.id for r in self.rules if r.source == "builtin"}

    def match(self, ev: dict):
        """Return list of rule objects that fire on this event."""
        hits = []
        for r in self.rules:
            if not r.applies_to(ev):
                continue
            try:
                if r.evaluate(ev):
                    hits.append(r)
            except (ValueError, re.error) as e:
                log.warning("rule %r failed to evaluate (%s: %s); skipping",
                            r.id, type(e).__name__, e)
                continue
        return hits

    def summary(self):
        by_sev = {}
        for r in self.rules:
            by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
        return {
            "count": len(self.rules),
            "by_severity": by_sev,
            "errors": self.errors,
            "rules": [
                {"id": r.id, "title": r.title, "severity": r.severity,
                 "category": r.category, "platform": r.platform, "mitre": r.mitre,
                 "description": r.description, "references": r.references,
                 "match": r.match, "source": r.source, "enabled": r.enabled}
                for r in self.rules
            ],
        }


def validate_definition(defn: dict, sample_event: dict = None) -> dict:
    """Validate a rule definition; optionally test it against a sample event.

    Returns {"valid": bool, "error": str|None, "matched": bool|None}.
    """
    try:
        rule = Rule(defn)
    except (ValueError, AttributeError, TypeError) as e:
        return {"valid": False, "error": str(e), "matched": None}

    # surface bad regex now rather than silently at match time
    for cond in rule.match:
        if (cond.get("op") or "").lower() == "regex":
            vals = cond.get("values") or ([cond.get("value")] if cond.get("value") is not None else [])
            for pat in vals:
                try:
                    re.compile(str(pat))
                except re.error as e:
                    return {"valid": False, "error": f"invalid regex {pat!r}: {e}", "matched": None}
        if not cond.get("field") and (cond.get("op") or "").lower() not in ("exists", "not_exists"):
            return {"valid": False, "error": "every condition needs a 'field'", "matched": None}

    matched = None
    if sample_event is not None:
        try:
            matched = bool(rule.applies_to(sample_event) and rule.evaluate(sample_event))
        except (ValueError, re.error) as e:
            return {"valid": False, "error": f"evaluation error: {e}", "matched": None}
    return {"valid": True, "error": None, "matched": matched}
