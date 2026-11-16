"""What the web console SAYS, checked by running its own ``truth.js`` under Node.

``console/static/js/truth.js`` holds every sentence that states whether a device is blocked,
and the posture band, the watch-only bar and the commit-confirm bar take their words from
it. It imports nothing and touches no DOM, so Node can import the very file the browser
loads. No browser and no network are needed; without a ``node`` program these tests skip.

The rule held here (docs/API.md, the watch-only contract): in a watch-only process the
console must make it impossible to believe that something is blocked, and only an
enforcement outcome of ``applied`` may ever read "Blocked" or "Read-only". A process that is
not watch-only reads exactly as before, including a lockdown that blocks in monitor mode.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

STATIC = Path(__file__).resolve().parents[2] / "src" / "portlock" / "console" / "static"
TRUTH = STATIC / "js" / "truth.js"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    NODE is None, reason="no `node` program on the path: the console's JavaScript cannot run"
)

REASON = (
    "PortLock cannot change this computer: it is not running as administrator, and its "
    "files are in this user's own folders."
)

# The scenarios, built and evaluated in Node; the results come back as JSON. Device text is
# synthetic. The script imports truth.js by file URL, so nothing is copied or bundled.
SCRIPT = r"""
const T = await import(process.argv[2]);
const REASON = process.argv[3];

const lockIdle = { state: "idle", active: false, external_timer_armed: false };
const lockActive = {
  state: "active", active: true, external_timer_armed: true, pending_change_id: null,
};

function status({ effective = "monitor", chosen = effective, watchOnly = false,
                  lockdown = lockIdle }) {
  const can = !watchOnly;
  return {
    mode: {
      mode: chosen, effective_mode: effective, source: "config", killswitch: false, notes: [],
      can_enforce: can, watch_only: watchOnly, watch_only_reason: watchOnly ? REASON : null,
    },
    lockdown,
    enforcer: {
      name: watchOnly ? "watch-only" : "fake",
      block: can, read_only: can, eject: can, default_deny: can,
    },
  };
}

function conn({ state = "denied", access = "deny", enforcement, provisional = false }) {
  return {
    connection_id: 7, state, provisional, protected: false, protection_codes: [],
    decision: { access, source: "policy", rule_id: null, reasons: ["synthetic reason"] },
    enforcement,
  };
}

function would(what) {
  return { outcome: "would_apply", would: what, os_state: "open", tier: "none",
           mechanism: null, detail: null };
}

function applied(osState) {
  return { outcome: "applied", would: null, os_state: osState, tier: "reactive",
           mechanism: "fake.mechanism", detail: null };
}

function failed(error, outcome = "failed") {
  return { outcome, would: null, os_state: "open", tier: "none", mechanism: null,
           detail: null, error };
}

const wouldBlock = would("blocked");
const wouldReadOnly = would("read_only");
const appliedBlock = applied("blocked");
const appliedReadOnly = applied("read_only");
const preview = [{ instance_id: "test/1-1", name: "Example stick", vid_pid: "1209:0001",
                   outcome: "block", reason: "removable storage" }];

function everything(st, { would = 0, blockedNow = 0, device = null, approved = null,
                          change = null, simulation = false } = {}) {
  const watchOnly = T.isWatchOnly(st);
  return {
    isWatchOnly: watchOnly,
    reason: T.watchOnlyReason(st),
    posture: T.posture(st),
    blocksForReal: T.blocksForReal(st),
    copy: T.postureCopy(st, { would, blockedNow }),
    banner: T.shellBanner({ simulation, status: st }),
    truth: device ? T.enforcementTruth(device, { watchOnly }) : null,
    approval: approved ? T.approvalMessage(approved, st) : null,
    denial: device ? T.denialMessage({ connection: device, eject: null }, st) : null,
    provisional: device ? T.provisionalNote(device, st) : null,
    pendingNote: T.pendingWaitNote(st),
    intendedNote: T.intendedNote(st),
    change: change ? T.changeCopy(change, st) : null,
  };
}

const watchOnly = status({ watchOnly: true });
const results = {
  watch_only: everything(watchOnly),
  watch_only_simulated: everything(watchOnly, { simulation: true }),
  watch_only_enforce_in_config: everything(status({ watchOnly: true, chosen: "enforce" })),
  watch_only_would_apply: everything(watchOnly, {
    would: 1,
    device: conn({ enforcement: wouldBlock, provisional: true }),
    approved: conn({ state: "read_only", access: "read_only", enforcement: wouldReadOnly }),
    change: { kind: "widen_scope", preview },
  }),
  watch_only_stale_lockdown: everything(status({ watchOnly: true, lockdown: lockActive }), {
    change: { kind: "lockdown", preview },
  }),
  enforcing_applied: everything(status({ effective: "enforce" }), {
    blockedNow: 1,
    device: conn({ enforcement: appliedBlock }),
    approved: conn({ state: "read_only", access: "read_only", enforcement: appliedReadOnly }),
    change: { kind: "enforce_mode", preview },
  }),
  elevated_monitor_lockdown: everything(status({ effective: "monitor", lockdown: lockActive }), {
    change: { kind: "lockdown", preview },
  }),
  elevated_monitor: everything(status({ effective: "monitor" }), {
    would: 2,
    device: conn({ enforcement: wouldBlock }),
    approved: conn({ state: "read_only", access: "read_only", enforcement: wouldReadOnly }),
    change: { kind: "widen_scope", preview },
  }),
  provisional_applied: T.provisionalNote(
    conn({ state: "read_only", enforcement: appliedReadOnly, provisional: true }),
    status({ effective: "enforce" }),
  ),
  mode_object_alone: T.isWatchOnly(watchOnly.mode),
  missing_field: T.isWatchOnly({ mode: { mode: "monitor", effective_mode: "monitor" } }),
  string_true: T.isWatchOnly({ mode: { watch_only: "true" } }),
  no_reason_sent: T.watchOnlyReason({ mode: { watch_only: true } }),
};

// K1: the key to the chip styles, and which rows are intended only.
const enforcing = status({ effective: "enforce" });
const monitorLockdown = status({ effective: "monitor", lockdown: lockActive });
const plainMonitor = status({ effective: "monitor" });
results.legend = {
  watch_only: T.chipLegend?.(watchOnly) ?? null,
  monitor: T.chipLegend?.(plainMonitor) ?? null,
};
results.intended_only = {
  would: T.intendedOnly?.(conn({ enforcement: wouldBlock }), watchOnly) ?? null,
  applied: T.intendedOnly?.(conn({ enforcement: appliedBlock }), enforcing) ?? null,
  failed: T.intendedOnly?.(conn({ enforcement: failed("access denied") }), enforcing) ?? null,
};

// K2: the bar's sentence, and mode notes that repeat the reason.
const notedWatchOnly = status({ watchOnly: true });
notedWatchOnly.mode.notes = [REASON, "Antivirus engines are not used in watch-only."];
results.mode_notes = T.modeNotes?.(notedWatchOnly.mode) ?? null;
results.control_note = T.WATCH_ONLY_CONTROL_NOTE ?? null;

// K3: enforce mode, enforcement failed or unsupported.
const failedPlain = failed(null);
const failedDetail = failed("access denied");
const unsupported = failed(null, "unsupported");
const held = (enforcement, state = "read_only") => conn({ state, enforcement, provisional: true });
const denyOf = (enforcement) => T.denialMessage({ connection: conn({ enforcement }), eject: null },
                                                enforcing);
results.enforce_failed = {
  approval: T.approvalMessage(
    conn({ state: "allowed", access: "allow", enforcement: failedDetail }), enforcing),
  approval_still: T.approvalMessage(conn({ state: "denied", enforcement: failedPlain }), enforcing),
  denial: denyOf(failedPlain),
  denial_unsupported: denyOf(unsupported),
  provisional_plain: T.provisionalNote(held(failedPlain), enforcing),
  provisional_detail: T.provisionalNote(held(failedDetail), enforcing),
  provisional_unsupported: T.provisionalNote(held(unsupported), enforcing),
  provisional_would_block: T.provisionalNote(held(wouldBlock, "denied"), plainMonitor),
  still_applied: T.approvalMessage(conn({ state: "denied", enforcement: appliedBlock }), enforcing),
};

// K5: a wider scope while a real lockdown is active in monitor mode, and the held ports.
results.scope_during_monitor_lockdown = T.changeCopy({ kind: "widen_scope", preview },
                                                     monitorLockdown);
results.default_deny_during_monitor_lockdown = T.changeCopy({ kind: "default_deny", preview },
                                                            monitorLockdown);
results.port_hold = {
  enforce: T.portHoldText?.(enforcing) ?? null,
  monitor: T.portHoldText?.(plainMonitor) ?? null,
  monitor_lockdown: T.portHoldText?.(monitorLockdown) ?? null,
  watch_only: T.portHoldText?.(watchOnly) ?? null,
};

// D4: the default-deny control shows the stored choice, and says when it is not in force.
const MONITOR_NOTE = "Default-deny is stored on but not in force: it applies only in "
  + "enforce mode, and PortLock is in monitor mode now. The choice is kept.";
const IGNORED_NOTE = "A default-deny setting stored by an earlier run is ignored: this "
  + "process is watch-only and denies nothing.";
const control = (reply, st) => T.defaultDenyControl?.(reply, st) ?? null;
results.default_deny = {
  monitor_stored: control({ enabled: false, stored: true, note: MONITOR_NOTE }, plainMonitor),
  monitor_off: control({ enabled: false, stored: false, note: null }, plainMonitor),
  enforcing_on: control({ enabled: true, stored: true, note: null }, enforcing),
  watch_only_stored: control({ enabled: false, stored: true, note: IGNORED_NOTE }, watchOnly),
  watch_only_off: control({ enabled: false, stored: false, note: null }, watchOnly),
  older_service: control({ enabled: true }, enforcing),
  toast_enforcing: T.defaultDenyToast?.(true, enforcing) ?? null,
  toast_monitor: T.defaultDenyToast?.(true, plainMonitor) ?? null,
  toast_monitor_lockdown: T.defaultDenyToast?.(true, monitorLockdown) ?? null,
  toast_off: T.defaultDenyToast?.(false, plainMonitor) ?? null,
};
process.stdout.write(JSON.stringify(results));
"""

# The console's DOM-building modules, run under Node with a minimal document stub: what the
# device table, the device dialog, the watch-only bar and the legend really draw. fmt.js keeps
# a page-wide timer, so the script exits by itself once it has written its answer.
DOM_SCRIPT = r"""
class Node {}
class Text extends Node {
  constructor(text) { super(); this.textContent = String(text); this.parentNode = null; }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
}
class Element extends Node {
  constructor(tag) {
    super();
    this.tagName = tag; this.attrs = {}; this.children = []; this.dataset = {};
    this.parentNode = null;
    this.style = { setProperty() {} };
  }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  getAttribute(key) { return key in this.attrs ? this.attrs[key] : null; }
  removeAttribute(key) { delete this.attrs[key]; }
  appendChild(child) {
    if (child instanceof Element && child.tagName === "#fragment") {
      for (const inner of [...child.children]) this.appendChild(inner);
      return child;
    }
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.children.push(child);
    return child;
  }
  removeChild(child) {
    this.children = this.children.filter((c) => c !== child);
    child.parentNode = null;
  }
  insertBefore(child, ref) {
    this.appendChild(child);
    if (ref) {
      this.children = this.children.filter((c) => c !== child);
      this.children.splice(this.children.indexOf(ref), 0, child);
    }
    return child;
  }
  replaceChildren(...children) {
    // As in a browser: anything that is not a node becomes text, null included ("null").
    for (const child of this.children) child.parentNode = null;
    this.children = [];
    for (const child of children) {
      this.appendChild(child instanceof Node ? child : new Text(String(child)));
    }
  }
  replaceWith(other) {
    const parent = this.parentNode;
    if (!parent) return;
    parent.insertBefore(other, this);
    parent.removeChild(this);
  }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  get firstChild() { return this.children[0] || null; }
  get isConnected() { return true; }
  addEventListener() {}
  showModal() {}
  close() {}
  scrollIntoView() {}
  set className(value) { this.attrs.class = value; }
  get className() { return this.attrs.class || ""; }
  get textContent() { return this.children.map((c) => c.textContent).join(""); }
  set textContent(value) { this.replaceChildren(new Text(value)); }
}
globalThis.Node = Node;
const body = new Element("body");
globalThis.document = {
  body,
  createElement: (tag) => new Element(tag),
  createTextNode: (text) => new Text(text),
  createDocumentFragment: () => new Element("#fragment"),
  getElementById: () => null,
};
globalThis.location = { href: "http://127.0.0.1/" };

const base = process.argv[2];
const REASON = process.argv[3];
const ui = await import(base + "/ui.js");
const store = await import(base + "/store.js");
const table = await import(base + "/devicetable.js");
const T = await import(base + "/truth.js");

function statusOf({ effective = "monitor", watchOnly = false }) {
  return {
    mode: { mode: effective, effective_mode: effective, source: "config", killswitch: false,
            notes: [], can_enforce: !watchOnly, watch_only: watchOnly,
            watch_only_reason: watchOnly ? REASON : null },
    lockdown: { state: "idle", active: false, external_timer_armed: false },
    enforcer: { name: watchOnly ? "watch-only" : "fake", block: !watchOnly,
                read_only: !watchOnly, eject: !watchOnly, default_deny: !watchOnly },
  };
}

function connOf(stateName, access, enforcement) {
  return {
    connection_id: 7, display_name: "Example stick", fingerprint: "fp:example",
    state: stateName, provisional: false, protected: false, protection_codes: [],
    confidence: "high", basis: ["vid", "pid", "serial"], removed_at: null,
    connected_at: "2026-01-01T00:00:00Z", scan: null,
    device: { vid: 4617, pid: 1, serial: "SYNTHETIC-1", manufacturer: "Example",
              product: "Stick", bcd_device: 256, device_class: 0, bus_path: "1-1",
              removable: true, categories: ["storage"], interfaces: [], volumes: [] },
    decision: { access, source: "policy", rule_id: null, reasons: ["synthetic reason"],
                alert: false },
    enforcement,
  };
}
const would = (what) => ({ outcome: "would_apply", would: what, os_state: "open", tier: "none",
                           mechanism: null, detail: null });
const applied = (what) => ({ outcome: "applied", would: null, os_state: what, tier: "reactive",
                             mechanism: "fake.mechanism", detail: null });

function chips(node, out = []) {
  if (node instanceof Element) {
    const cls = (node.getAttribute("class") || "").split(" ");
    if (cls.includes("chip")) out.push({ text: node.textContent, dashed: cls.includes("dashed") });
    for (const child of node.children) chips(child, out);
  }
  return out;
}

function find(node, test) {
  if (!(node instanceof Element)) return null;
  if (test(node)) return node;
  for (const child of node.children) {
    const hit = find(child, test);
    if (hit) return hit;
  }
  return null;
}

// The State and Decision cells of each row of the device table.
function rowCells(conns) {
  const drawn = table.deviceTable(conns, { onOpen() {} });
  const tbody = find(drawn, (el) => el.tagName === "tbody");
  return tbody.children.map((tr) => ({
    state: chips(tr.children[1]),
    decision: chips(tr.children[2]),
  }));
}

const out = {};
store.state.status = statusOf({ watchOnly: true });
out.watch_only_rows = rowCells([
  connOf("denied", "deny", would("blocked")),
  connOf("read_only", "read_only", would("read_only")),
]);

// The device dialog, with the service's two answers stubbed.
let live = connOf("denied", "deny", would("blocked"));
globalThis.fetch = async (url) => {
  const payload = url.includes("/connections/")
    ? { connection: live, decisions: [], scans: [] }
    : { connection_count: 1, first_seen: "2026-01-01T00:00:00Z", grants: [] };
  return { status: 200, ok: true, json: async () => payload };
};
async function dialogChips() {
  body.replaceChildren();
  table.openDeviceDetail(live);
  for (let i = 0; i < 50; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
  const dialog = find(body, (el) => el.tagName === "dialog");
  const row = find(dialog, (el) => (el.getAttribute("class") || "") === "row");
  return { chips: chips(row), shows_null: /\bnull\b/.test(dialog.textContent) };
}
out.watch_only_dialog = await dialogChips();

store.state.status = statusOf({ effective: "enforce" });
out.enforcing_rows = rowCells([connOf("denied", "deny", applied("blocked"))]);
live = connOf("denied", "deny", applied("blocked"));
out.enforcing_dialog = await dialogChips();

function collapsedText(node) {
  // Everything the bar shows while "Why" is closed: the details' own content is hidden.
  if (!(node instanceof Element)) return node.textContent;
  if (node.tagName === "details") {
    return node.children.filter((c) => c.tagName === "summary").map((c) => c.textContent).join("");
  }
  return node.children.map(collapsedText).join(" ");
}
const bar = ui.shellBar
  ? ui.shellBar(T.shellBanner({ simulation: false, status: statusOf({ watchOnly: true }) }))
  : null;
out.bar = bar
  ? {
      collapsed: collapsedText(bar).replace(/\s+/g, " ").trim(),
      summary: find(bar, (el) => el.tagName === "summary")?.textContent ?? null,
      hidden: find(bar, (el) => el.tagName === "details")?.children
        .filter((c) => c.tagName !== "summary").map((c) => c.textContent).join(" ") ?? null,
      label: bar.getAttribute("aria-label"),
    }
  : null;

out.legend_line = ui.chipLegendLine && T.chipLegend
  ? (() => {
      const line = ui.chipLegendLine(T.chipLegend(statusOf({ watchOnly: true })));
      return { text: line.textContent, chips: chips(line) };
    })()
  : null;

process.stdout.write(JSON.stringify(out), () => process.exit(0));
"""


def text_of(copy: dict[str, Any]) -> str:
    """Every word a posture band shows, in one string."""
    parts = [copy["headline"]]
    parts += [part if isinstance(part, str) else part["strong"] for part in copy["sub"]]
    parts += [note["text"] for note in copy["notes"]]
    parts += [rung["label"] for rung in copy["ladder"]]
    return " ".join(parts)


@pytest.fixture(scope="module")
def said(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    assert NODE is not None
    script = tmp_path_factory.mktemp("node") / "scenarios.mjs"
    script.write_text(SCRIPT, encoding="utf-8")
    done = subprocess.run(
        [NODE, str(script), TRUTH.as_uri(), REASON],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    result: dict[str, Any] = json.loads(done.stdout)
    return result


@pytest.fixture(scope="module")
def drawn(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """What the DOM-building modules draw, under a minimal document stub."""
    assert NODE is not None
    script = tmp_path_factory.mktemp("node-dom") / "drawn.mjs"
    script.write_text(DOM_SCRIPT, encoding="utf-8")
    done = subprocess.run(
        [NODE, str(script), (STATIC / "js").as_uri(), REASON],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    result: dict[str, Any] = json.loads(done.stdout)
    return result


def js_source(relative: str) -> str:
    return (STATIC / "js" / relative).read_text(encoding="utf-8")


# --- truth.js stays importable without a browser -----------------------------------------


def test_truth_js_is_pure() -> None:
    source = TRUTH.read_text(encoding="utf-8")
    assert not re.search(r"(?m)^\s*import\b", source), "truth.js must import nothing"
    for pattern in (
        r"\bdocument\.",
        r"\bwindow\.",
        r"\blocalStorage\b",
        r"\bfetch\(",
        r"\bsetTimeout\(",
    ):
        assert not re.search(pattern, source), f"truth.js must not use {pattern}"


def test_every_console_module_parses_as_an_es_module(tmp_path: Path) -> None:
    """No browser here: a syntax error in a view would otherwise go unseen."""
    assert NODE is not None
    for path in sorted((STATIC / "js").rglob("*.js")):
        copy = tmp_path / (path.relative_to(STATIC).as_posix().replace("/", "_") + ".mjs")
        copy.write_bytes(path.read_bytes())
        done = subprocess.run(
            [NODE, "--check", str(copy)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
        assert done.returncode == 0, f"{path.name}: {done.stderr}"


# --- a watch-only status ------------------------------------------------------------------


def test_watch_only_is_its_own_posture(said: dict[str, Any]) -> None:
    case = said["watch_only"]
    assert case["isWatchOnly"] is True
    assert case["posture"] == "watch_only"
    assert case["blocksForReal"] is False
    assert case["reason"] == REASON
    copy = case["copy"]
    assert copy["kind"] == "watch_only"
    assert copy["headline"] == "Watch-only: nothing is being blocked."
    assert {"tone": "", "text": f"Why: {REASON}"} in copy["notes"]
    words = text_of(copy)
    assert "outside its own folder" in words
    assert "yet" not in words  # never "cannot enforce yet": this process never will
    assert "Lockdown" not in words and "Enforce" not in words


def test_watch_only_ladder_offers_no_next_rung(said: dict[str, Any]) -> None:
    ladder = said["watch_only"]["copy"]["ladder"]
    assert ladder == [{"name": "watch_only", "label": "Watch-only", "current": True}]


def test_watch_only_bar_states_what_it_is_and_why(said: dict[str, Any]) -> None:
    banner = said["watch_only"]["banner"]
    assert banner["kind"] == "watch_only"
    assert banner["lead"] == "Watch-only"
    assert banner["text"] == (
        "Nothing is blocked: PortLock changes nothing on this computer outside its own folder."
    )
    assert banner["why"] == "Why"
    assert banner["reason"] == REASON


def test_the_simulation_bar_and_the_watch_only_bar_never_show_together(
    said: dict[str, Any],
) -> None:
    banner = said["watch_only_simulated"]["banner"]
    assert banner["kind"] == "simulation"
    assert "SIMULATION" in banner["text"] and "real PortLock" not in banner["text"]


def test_enforce_in_the_configuration_is_explained_not_promised(said: dict[str, Any]) -> None:
    copy = said["watch_only_enforce_in_config"]["copy"]
    assert copy["kind"] == "watch_only"
    warn = [note["text"] for note in copy["notes"] if note["tone"] == "warn"]
    assert warn == [
        "The configuration asks for enforce mode, but this process is watch-only and "
        "never enforces. Nothing is blocked."
    ]


def test_a_lockdown_record_never_reads_as_blocking_in_watch_only(said: dict[str, Any]) -> None:
    case = said["watch_only_stale_lockdown"]
    assert case["posture"] == "watch_only"
    assert case["blocksForReal"] is False
    copy = case["copy"]
    assert copy["headline"] == "Watch-only: nothing is being blocked."
    assert "all removable storage is blocked" not in text_of(copy)
    bad = [note["text"] for note in copy["notes"] if note["tone"] == "bad"]
    assert bad == [
        "A lockdown is recorded as active, but nothing is blocked: this process is watch-only."
    ]
    change = case["change"]
    assert change["real"] is False
    assert change["items"] == [{"label": "Would be blocked", "tone": "c-watch", "dashed": True}]
    assert "blocked now" not in change["explain"]


# --- a watch-only status with a would_apply device ----------------------------------------


def test_a_would_apply_device_reads_would_in_watch_only(said: dict[str, Any]) -> None:
    case = said["watch_only_would_apply"]
    truth = case["truth"]
    assert truth["kind"] == "intended"
    assert truth["headline"] == "Would be blocked"
    assert truth["detail"] == "Watch-only: nothing was changed."
    assert truth["title"].startswith("Watch-only")
    # The words follow what the service says it would do (`would`: blocked here).
    assert case["provisional"] == "Would be held blocked until its scan is clean"
    assert "If it could enforce, 1 connected device would be blocked" in text_of(case["copy"])


def test_toasts_in_watch_only_never_claim_the_device_changed(said: dict[str, Any]) -> None:
    case = said["watch_only_would_apply"]
    approval = case["approval"]["text"]
    assert "now read-only" not in approval
    assert approval.startswith("Approved: the decision is read-only. Nothing on the device")
    assert "changes nothing on this computer" in approval
    denial = case["denial"]["text"]
    assert denial.startswith("Denied for this connection, but it is not blocked:")
    assert "watch-only" in denial
    assert case["pendingNote"].startswith("Watch-only: this device is NOT blocked")
    assert "yet" not in case["pendingNote"]
    assert case["intendedNote"].startswith("PortLock is watch-only on this computer.")


def test_a_waiting_change_in_watch_only_says_would(said: dict[str, Any]) -> None:
    change = said["watch_only_would_apply"]["change"]
    assert change["real"] is False
    assert change["summary"] == "1 of 1 connected device would be blocked by this change"
    assert change["items"][0]["label"] == "Would be blocked"
    assert change["explain"].startswith("Nothing is blocked: PortLock is watch-only here")


# --- an enforcing status with an applied block --------------------------------------------


def test_an_applied_block_reads_blocked_when_enforcing(said: dict[str, Any]) -> None:
    case = said["enforcing_applied"]
    assert case["isWatchOnly"] is False
    assert case["reason"] is None
    assert case["banner"] is None
    assert case["posture"] == "enforce"
    assert case["blocksForReal"] is True
    assert case["truth"]["kind"] == "real"
    assert case["truth"]["headline"] == "Blocked"
    assert case["truth"]["tier"] == "reactive"
    copy = case["copy"]
    assert copy["headline"] == "Enforcing: devices policy has not approved are blocked."
    assert "1 connected device is blocked now." in text_of(copy)
    assert [rung["current"] for rung in copy["ladder"]] == [False, True, False]
    assert case["approval"] == {"text": "Approved: now read-only.", "tone": "good"}
    assert case["denial"]["text"] == (
        "Denied for this connection. It will be pending again if it is plugged in again."
    )
    assert said["provisional_applied"] == "Held read-only until its scan is clean"


def test_a_waiting_change_while_enforcing_reads_as_before(said: dict[str, Any]) -> None:
    change = said["enforcing_applied"]["change"]
    assert change["real"] is True
    assert change["explain"] == "PortLock is now blocking, not just watching."
    assert change["summary"] == "1 of 1 connected device blocked by this change"
    assert change["items"] == [{"label": "Blocked", "tone": "c-deny", "dashed": False}]


# --- an elevated monitor status with a real active lockdown --------------------------------


def test_a_real_lockdown_in_monitor_mode_reads_as_blocking(said: dict[str, Any]) -> None:
    case = said["elevated_monitor_lockdown"]
    assert case["isWatchOnly"] is False
    assert case["banner"] is None
    assert case["posture"] == "lockdown"
    assert case["blocksForReal"] is True
    copy = case["copy"]
    assert copy["headline"] == "Lockdown: all removable storage is blocked."
    assert "New devices are denied." in text_of(copy)
    assert copy["notes"] == []  # its operating-system timer is armed
    assert [rung["name"] for rung in copy["ladder"]] == ["monitor", "enforce", "lockdown"]
    change = case["change"]
    assert change["real"] is True
    assert change["explain"] == "Removable storage is blocked and new devices are denied now."
    assert change["items"][0]["label"] == "Blocked"


def test_the_lockdown_panel_still_says_it_works_in_monitor_mode() -> None:
    protection = (STATIC / "js" / "views" / "protection.js").read_text(encoding="utf-8")
    assert "denies new devices at once, even in monitor mode" in protection


def test_plain_monitor_mode_reads_as_before(said: dict[str, Any]) -> None:
    case = said["elevated_monitor"]
    assert case["posture"] == "monitor"
    copy = case["copy"]
    assert copy["headline"] == "Nothing is being blocked."
    assert "In enforce mode 2 connected devices would be blocked or made read-only." in text_of(
        copy
    )
    assert case["truth"]["detail"] == "Monitor mode: nothing was changed."
    assert case["pendingNote"] == (
        "Monitor mode: this device is NOT blocked while it waits. Approving it changes nothing yet."
    )
    assert "now read-only" not in case["approval"]["text"]
    assert case["change"]["summary"] == "1 of 1 connected device would be blocked by this change"


# --- what counts as watch-only ------------------------------------------------------------


def test_only_an_explicit_true_is_watch_only(said: dict[str, Any]) -> None:
    assert said["mode_object_alone"] is True
    assert said["missing_field"] is False
    assert said["string_true"] is False
    assert said["no_reason_sent"].startswith("PortLock is not running as an administrator")


# --- K1: a row whose enforcement is only intended is drawn dashed -------------------------


def test_watch_only_rows_draw_state_and_decision_dashed(drawn: dict[str, Any]) -> None:
    rows = drawn["watch_only_rows"]
    assert [[c["text"] for c in row["state"]] for row in rows] == [["Denied"], ["Read-only"]]
    assert [[c["text"] for c in row["decision"]] for row in rows] == [["Denied"], ["Read-only"]]
    for row in rows:
        assert all(c["dashed"] for c in row["state"] + row["decision"]), row


def test_the_device_dialog_draws_intended_chips_dashed(drawn: dict[str, Any]) -> None:
    dialog = drawn["watch_only_dialog"]
    assert [c["text"] for c in dialog["chips"]] == ["Denied", "Denied"]
    assert all(c["dashed"] for c in dialog["chips"])
    assert dialog["shows_null"] is False  # a null child once became the text "null"


def test_an_applied_block_stays_solid(drawn: dict[str, Any]) -> None:
    (row,) = drawn["enforcing_rows"]
    assert row["state"] == [{"text": "Denied", "dashed": False}]
    assert row["decision"] == [{"text": "Denied", "dashed": False}]
    assert drawn["enforcing_dialog"]["chips"] == [
        {"text": "Denied", "dashed": False},
        {"text": "Denied", "dashed": False},
    ]


def test_intended_only_is_decided_by_the_enforcement_truth(said: dict[str, Any]) -> None:
    assert said["intended_only"] == {"would": True, "applied": False, "failed": False}


def test_the_chip_legend_reads_correctly_in_watch_only(said: dict[str, Any]) -> None:
    legend = said["legend"]["watch_only"]
    assert legend is not None, "truth.js must word the legend"
    by_label = {item["label"]: item for item in legend}
    assert by_label["Dashed"]["text"] == "means intended only (watch-only): nothing was changed."
    assert "monitor mode" not in " ".join(item["text"] for item in legend)
    # Nothing is ever changed in watch-only, so solid cannot be "really was changed" there.
    assert "changed" not in by_label["Solid"]["text"]
    assert by_label["Solid"]["short"] == "Solid = as it is"
    monitor = {item["label"]: item for item in said["legend"]["monitor"]}
    assert monitor["Dashed"]["text"] == "means intended only (monitor mode): nothing was changed."
    assert monitor["Solid"]["short"] == "Solid = in force"


def test_the_legend_line_is_drawn_from_truth_js(drawn: dict[str, Any]) -> None:
    line = drawn["legend_line"]
    assert line is not None
    assert [c["text"] for c in line["chips"]] == ["Solid", "Dashed", "Not enforced"]
    assert [c["dashed"] for c in line["chips"]] == [False, True, False]
    assert "(watch-only)" in line["text"]
    for view in ("views/devices.js", "views/overview.js"):
        source = js_source(view)
        assert "chipLegend(" in source, view
        assert "intended only (monitor mode)" not in source, view
        assert "Solid = in force" not in source, view


def test_every_state_and_decision_chip_of_a_connection_goes_through_truth_chips() -> None:
    for name in ("devicetable.js", "views/devices.js"):
        source = js_source(name)
        assert not re.search(r"stateChip\((?:conn|live|c)\.state\)", source), name
        assert not re.search(r"accessChip\((?:conn|live|c)\.decision\.access\)", source), name
        assert not re.search(r"accessChip\(decision\.access\)", source), name


# --- K2: a short bar, the reason behind "Why", and no repeats on Protection --------------


def test_the_watch_only_bar_is_one_sentence_with_the_reason_behind_why(
    drawn: dict[str, Any],
) -> None:
    bar = drawn["bar"]
    assert bar is not None, "ui.js must draw the bar"
    assert bar["label"] == "Watch-only"
    assert bar["summary"] == "Why"
    assert bar["hidden"] == REASON
    assert REASON not in bar["collapsed"]
    assert bar["collapsed"] == (
        "Watch-only Nothing is blocked: PortLock changes nothing on this computer outside "
        "its own folder. Why"
    )
    # About two lines of 13 px text at 400 px; it was nine lines with the reason shown.
    assert len(bar["collapsed"]) <= 110


def test_mode_notes_drop_the_reason_the_bar_already_gives(said: dict[str, Any]) -> None:
    assert said["mode_notes"] == ["Antivirus engines are not used in watch-only."]


def test_disabled_controls_point_at_the_reason_instead_of_repeating_it(
    said: dict[str, Any],
) -> None:
    note = said["control_note"]
    assert note == "Not available in watch-only. See Why at the top of the page."
    protection = js_source("views/protection.js")
    assert "return WATCH_ONLY_CONTROL_NOTE;" in protection
    assert "Not available: ${watchOnlyReason" not in protection
    assert "modeNotes(mode)" in protection and "mode.notes.map" not in protection
    # One short note beside each of the three disabled controls, and each is that note.
    assert len(re.findall(r"reasonFor\([^,]+, notHere\(\)\)", protection)) == 3
    assert protection.count("reasonFor(") == 3


# --- K3: enforce mode, enforcement that failed --------------------------------------------


def test_failed_enforcement_never_reads_as_success(said: dict[str, Any]) -> None:
    case = said["enforce_failed"]
    assert case["approval"] == {
        "text": "Approved: the decision is allowed, but enforcement failed: access denied.",
        "tone": "bad",
    }
    assert case["approval_still"] == {
        "text": "Grant recorded, but the decision is still denied: synthetic reason. "
        "It is not blocked either: enforcement failed.",
        "tone": "bad",
    }
    assert case["denial"] == {
        "text": "Denied for this connection, but it is not blocked: enforcement failed. "
        "It will be pending again if it is plugged in again.",
        "tone": "bad",
    }
    assert case["denial_unsupported"]["tone"] == "bad"
    assert "it cannot be enforced here" in case["denial_unsupported"]["text"]
    for toast in (case["approval"], case["approval_still"], case["denial"]):
        assert "monitor mode" not in toast["text"] and "Would" not in toast["text"]


def test_a_failed_provisional_hold_says_not_held(said: dict[str, Any]) -> None:
    case = said["enforce_failed"]
    assert case["provisional_plain"] == "Not held: enforcement failed"
    assert case["provisional_detail"] == "Not held: enforcement failed: access denied"
    assert case["provisional_unsupported"] == "Not held: it cannot be enforced here"
    assert case["provisional_would_block"] == "Would be held blocked until its scan is clean"


def test_every_toast_ends_with_a_full_stop(said: dict[str, Any]) -> None:
    assert said["enforce_failed"]["still_applied"] == {
        "text": "Grant recorded, but the device is still denied: synthetic reason.",
        "tone": "bad",
    }
    for case in ("watch_only_would_apply", "enforcing_applied", "elevated_monitor"):
        for key in ("approval", "denial"):
            assert said[case][key]["text"].endswith("."), (case, key)


# --- K4: watch-only never claims to change nothing at all ---------------------------------


def test_watch_only_strings_say_outside_its_own_folder(said: dict[str, Any]) -> None:
    case = said["watch_only_would_apply"]
    for text in (
        case["change"]["explain"],
        case["approval"]["text"],
        case["denial"]["text"],
        case["pendingNote"],
    ):
        assert "outside its own folder" in text, text


def test_no_console_string_says_it_changes_nothing_on_this_computer_unqualified() -> None:
    bare = re.compile(r"(?:changes|changed) nothing on this computer(?! outside its own folder)")
    for path in sorted((STATIC / "js").rglob("*.js")):
        source = path.read_text(encoding="utf-8")
        assert not bare.search(source), path.name
        assert "nothing was changed on this computer" not in source, path.name


# --- K5: monitor mode never claims a block that only enforce mode makes ------------------


def test_a_wider_scope_during_a_monitor_mode_lockdown_says_would(said: dict[str, Any]) -> None:
    for key in ("scope_during_monitor_lockdown", "default_deny_during_monitor_lockdown"):
        change = said[key]
        assert change["real"] is False, key
        assert change["items"] == [{"label": "Would be blocked", "tone": "c-watch", "dashed": True}]
        assert change["explain"] == "This change blocks nothing yet: PortLock is in monitor mode."
    # The lockdown itself still blocks for real in monitor mode.
    assert said["elevated_monitor_lockdown"]["change"]["real"] is True


def test_the_port_cool_down_is_blocked_only_when_portlock_blocks(said: dict[str, Any]) -> None:
    hold = said["port_hold"]
    assert hold["enforce"] == (
        "A port that sees too many arrivals in a short time is held blocked for a cool-down. "
        "If you are sure it is safe, release it early."
    )
    assert hold["monitor_lockdown"] == hold["enforce"]
    assert hold["monitor"] == (
        "A port that sees too many arrivals in a short time is held for a cool-down. "
        "PortLock is in monitor mode, so the port is not really blocked. "
        "If you are sure it is safe, release it early."
    )
    assert "watch-only" in hold["watch_only"] and "not really blocked" in hold["watch_only"]
    assert "portHoldText(state.status)" in js_source("views/enrolment.js")


# --- D4: default-deny stored but not in force -----------------------------------------------


def test_the_default_deny_control_shows_the_stored_choice_with_its_note(
    said: dict[str, Any],
) -> None:
    case = said["default_deny"]
    # Monitor mode in an elevated, system-wide process: stored on, not in force. The box
    # stays ticked, so the choice does not look lost, and the note says why it is not in
    # force.
    monitor = case["monitor_stored"]
    assert monitor is not None, "truth.js has no defaultDenyControl"
    assert monitor["checked"] is True and monitor["inForce"] is False
    assert monitor["locked"] is False
    assert monitor["note"].startswith("Default-deny is stored on but not in force")
    assert "monitor mode" in monitor["note"]
    assert case["monitor_off"]["checked"] is False and case["monitor_off"]["note"] is None
    on = case["enforcing_on"]
    assert (on["checked"], on["inForce"], on["note"]) == (True, True, None)
    assert on["hint"] == (
        "Applies only in enforce mode. Turning it on is applied under commit-confirm."
    )
    # An older service without "stored" reads as before.
    assert case["older_service"]["checked"] is True and case["older_service"]["note"] is None


def test_the_default_deny_control_keeps_its_watch_only_behaviour(said: dict[str, Any]) -> None:
    case = said["default_deny"]
    # Off in watch-only: it cannot be turned on, and no hint promises enforce mode.
    off = case["watch_only_off"]
    assert off["locked"] is True and off["checked"] is False and off["hint"] is None
    # Stored on by an earlier, enforcing run: shown ticked with the note, and turning it
    # off stays allowed.
    stored = case["watch_only_stored"]
    assert stored["checked"] is True and stored["locked"] is False and stored["inForce"] is False
    assert "is ignored" in stored["note"]


def test_the_default_deny_toast_says_on_only_where_it_denies(said: dict[str, Any]) -> None:
    case = said["default_deny"]
    assert case["toast_enforcing"] == "Default-deny is on. Confirm it in the bar at the top."
    stored = (
        "Default-deny is stored on. It applies only in enforce mode. Confirm it in the bar "
        "at the top."
    )
    assert case["toast_monitor"] == stored
    assert case["toast_monitor_lockdown"] == stored
    assert case["toast_off"] == "Default-deny is off."
    protection = js_source("views/protection.js")
    assert "defaultDenyControl(reply, state.status)" in protection
    assert "defaultDenyToast(result.enabled, state.status)" in protection
    assert "checked: reply.enabled" not in protection
    # The note describes the checkbox, so a ticked box that is not in force is not read as on.
    assert 'toggle.input.setAttribute("aria-describedby", note.id)' in protection
