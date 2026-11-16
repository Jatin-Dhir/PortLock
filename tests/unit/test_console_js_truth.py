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
process.stdout.write(JSON.stringify(results));
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
    assert "real PortLock" in banner["text"]
    assert "changes nothing on this computer outside its own folder" in banner["text"]
    assert "Nothing is blocked." in banner["text"]
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
    assert truth["detail"] == "Watch-only: nothing was changed on this computer."
    assert truth["title"].startswith("Watch-only")
    assert case["provisional"] == "Would be held read-only until its scan is clean"
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
