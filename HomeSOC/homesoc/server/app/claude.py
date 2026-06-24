"""Optional behavioral analysis via the Anthropic API.

Off until a token is configured in Settings; signature detection runs without
it. Takes an alert plus its local event context and returns an analyst-style
assessment. It never isolates hosts, resolves alerts, or overrides verdicts.
The model is configurable and defaults to a current model.
"""
from . import db

DEFAULT_MODEL = "claude-sonnet-4-6"

SYSTEM_PROMPT = (
    "You are assisting a CIRT analyst triaging an endpoint alert in a home SOC. "
    "You are given a signature-rule hit and surrounding host telemetry. "
    "Reason like an incident responder:\n"
    "- Separate confirmed facts (present in the telemetry) from inference.\n"
    "- Do not assert a verdict the evidence does not support. 'Insufficient "
    "evidence' is a valid conclusion.\n"
    "- Note benign explanations as well as malicious ones.\n"
    "- Map to MITRE ATT&CK only where the telemetry justifies it.\n"
    "- Recommend concrete next collection/triage steps, not blanket containment.\n"
    "Output sections: Assessment, Confirmed facts, Inference / hypotheses, "
    "Benign explanations, Suggested next steps, Confidence (low/medium/high) "
    "with one-line justification."
)


def is_enabled() -> bool:
    return db.get_setting("claude_enabled") == "1" and bool(db.get_setting("claude_token"))


def analyze(alert: dict, story: dict) -> str:
    token = db.get_setting("claude_token")
    if not token:
        raise RuntimeError("No Claude token configured (Settings panel).")
    model = db.get_setting("claude_model") or DEFAULT_MODEL

    try:
        from anthropic import Anthropic
    except ImportError as e:
        raise RuntimeError(
            "anthropic SDK not installed in the server image; rebuild with it "
            "to enable behavioral analysis."
        ) from e

    client = Anthropic(api_key=token)
    user_content = _render(alert, story)
    msg = client.messages.create(
        model=model,
        max_tokens=1200,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")


def _render(alert, story) -> str:
    import json
    rule = story.get("rule", {})
    lines = [
        f"ALERT: {alert.get('title')}  (severity={alert.get('severity')})",
        f"Rule: {rule.get('id')} — {rule.get('description','')}",
        f"MITRE: {', '.join(alert.get('mitre') or []) or 'n/a'}",
        f"Host: {alert.get('hostname')} ({story.get('device',{}).get('platform')})",
        "",
        "TRIGGERING EVENT:",
        json.dumps(alert.get("event", {}), indent=2)[:4000],
        "",
        "PROCESS LINEAGE (reconstructed from sampled process telemetry, may be partial):",
    ]
    for n in story.get("process_tree", []):
        lines.append(f"  {'  ' * n.get('depth',0)}{n.get('process_name')}  "
                     f"(pid={n.get('pid')}, ppid={n.get('ppid')}) "
                     f"{n.get('cmdline','')[:200]}")
    lines.append("")
    lines.append("NEARBY TIMELINE (same host, +/- 5 min):")
    for e in story.get("timeline", [])[:60]:
        lines.append(f"  {e.get('ts_iso')}  {e.get('category')}/{e.get('action')}  "
                     f"{e.get('summary','')[:200]}")
    return "\n".join(lines)
