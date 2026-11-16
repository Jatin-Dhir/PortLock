// Turning API values into plain statements, and deciding what is TRUE about a device.
//
// The rule behind every line here: a decision is not an enforcement. "Denied" says what
// policy wants; only an enforcement outcome of `applied` says the operating system was made
// to do it. Where it was not, the console says "not enforced" or "would", in words.
//
// This module touches no DOM and imports nothing, so the tests can run it under Node
// (tests/unit/test_console_js_truth.py). Keep it that way: put the words here, and let the
// views only arrange them.

export const POSTURE_TEXT = {
  watch_only: "Watch-only",
  monitor: "Monitor",
  enforce: "Enforce",
  lockdown: "Lockdown",
};

export const SIMULATION_TEXT =
  "SIMULATION: nothing real is read, blocked, ejected or changed on this machine. Every device here is synthetic.";

// Used only if a service too old to send its reason says it is watch-only.
const WATCH_ONLY_FALLBACK_REASON =
  "PortLock is not running as an administrator with its files in system-wide folders, so it cannot be trusted to change this computer.";

/**
 * True when the service says this process is watch-only (`mode.watch_only`, docs/API.md):
 * it can never change the computer, whatever is clicked. Takes a status or a mode object.
 * Only an explicit `true` counts, so a missing field never hides the watch-only bar's
 * opposite: a process is called watch-only only when the service says so.
 */
export function isWatchOnly(statusOrMode) {
  const mode = statusOrMode && typeof statusOrMode.mode === "object" ? statusOrMode.mode : statusOrMode;
  return mode?.watch_only === true;
}

/** The service's plain reason for watch-only, or null when the process is not watch-only. */
export function watchOnlyReason(statusOrMode) {
  if (!isWatchOnly(statusOrMode)) return null;
  const mode = typeof statusOrMode.mode === "object" ? statusOrMode.mode : statusOrMode;
  const reason = typeof mode.watch_only_reason === "string" ? mode.watch_only_reason.trim() : "";
  return reason || WATCH_ONLY_FALLBACK_REASON;
}

function lockdownEngaged(lock) {
  return Boolean(lock && (lock.active || lock.state === "engaging" || lock.state === "active" || lock.state === "lifting"));
}

/**
 * watch_only, monitor, enforce or lockdown: the states that must never be confused.
 * Watch-only wins over everything: such a process blocks nothing, so even a lockdown record
 * (which the service refuses to create there) must not make the console say "Lockdown".
 */
export function posture(status) {
  if (isWatchOnly(status)) return "watch_only";
  if (lockdownEngaged(status?.lockdown)) return "lockdown";
  return status?.mode?.effective_mode === "enforce" ? "enforce" : "monitor";
}

/** True only while the operating system is really being asked to block (enforce or lockdown). */
export function blocksForReal(status) {
  const kind = posture(status);
  return kind === "enforce" || kind === "lockdown";
}

export const ACCESS_TEXT = {
  allow: ["Allowed", "c-allow"],
  read_only: ["Read-only", "c-readonly"],
  deny: ["Denied", "c-deny"],
  pending: ["Pending", "c-pending"],
};

export const STATE_TEXT = {
  new: ["New", "c-neutral"],
  protected: ["Protected", "c-watch"],
  allowed: ["Allowed", "c-allow"],
  read_only: ["Read-only", "c-readonly"],
  pending: ["Pending", "c-pending"],
  denied: ["Denied", "c-deny"],
};

export const SOURCE_TEXT = {
  safety: "safety check",
  lockdown: "lockdown",
  policy: "policy rule",
  grant: "grant",
  scan: "scan result",
  default: "policy default",
};

export const PROTECTION_TEXT = {
  hub: "a USB hub",
  built_in: "built into this machine",
  system_volume: "holds the system volume",
  protected_fingerprint: "an enrolled input device on its enrolled port",
  input_device: "an input device",
  out_of_scope: "outside the enforcement scope",
  safety_check_failed: "the safety check could not run, so it is left alone",
};

export const SCAN_TEXT = {
  none: ["No scan", "c-neutral"],
  waiting: ["Scan waiting", "c-pending"],
  queued: ["Scan queued", "c-pending"],
  running: ["Scanning", "c-watch"],
  clean: ["Clean", "c-allow"],
  suspicious: ["Suspicious", "c-pending"],
  malicious: ["Malicious", "c-deny"],
  incomplete: ["Scan incomplete", "c-pending"],
  error: ["Scan error", "c-deny"],
};

export const TIER_TEXT = {
  preventive: ["Preventive", "The operating system refuses the device before it is first usable."],
  reactive: ["Reactive", "PortLock saw the device first, then blocked it: there was a short window of use."],
  none: ["No tier", "No operating-system mechanism was used."],
};

export const DEGRADED_TEXT = {
  backend: "device detection is not healthy",
  store: "the database cannot be read or written",
  audit: "audit records are not being stored or exported",
  audit_chain: "the audit chain failed verification",
  journal: "the enforcement journal has unreadable entries",
  scan: "the scanner is not working",
};

/**
 * What is actually true about one connected device, in four kinds:
 *  - `real`: the operating system was changed (blocked, read-only) or deliberately left open;
 *  - `intended`: monitor mode or watch-only, nothing was changed; shown dashed;
 *  - `none`: enforcement did NOT happen where it should have (failed, unsupported, outside scope);
 *  - `protected`: PortLock refuses to touch it.
 * Only `applied` ever yields "Blocked" or "Read-only"; `would_apply` always reads "Would be".
 * `watchOnly` changes only the words of the `intended` kind, never the kind.
 */
export function enforcementTruth(conn, { watchOnly = false } = {}) {
  const decision = conn.decision;
  const enf = conn.enforcement;
  if (conn.protected) {
    const codes = conn.protection_codes || [];
    if (codes.length > 0 && codes.every((code) => code === "out_of_scope")) {
      return { kind: "none", headline: "Not enforced", detail: "Outside the enforcement scope.", tier: null };
    }
    const why = codes.map((code) => PROTECTION_TEXT[code] || code).join("; ");
    return { kind: "protected", headline: "Never touched", detail: why ? `Protected: ${why}.` : "Protected.", tier: null };
  }
  if (!decision) {
    return { kind: "none", headline: "Awaiting decision", detail: "", tier: null };
  }
  if (!enf) {
    return { kind: "none", headline: "Not enforced", detail: "No enforcement result yet.", tier: null };
  }
  const tier = enf.tier && enf.tier !== "none" ? enf.tier : null;
  const how = [enf.mechanism, enf.detail].filter(Boolean).join(" - ");
  switch (enf.outcome) {
    case "applied": {
      const word = { blocked: "Blocked", read_only: "Read-only", open: "Open" }[enf.os_state] || "Applied";
      return { kind: "real", headline: word, detail: how, tier };
    }
    case "not_needed":
      return { kind: "real", headline: "Open", detail: "Nothing to enforce.", tier: null };
    case "would_apply": {
      const would = { blocked: "blocked", read_only: "read-only" }[enf.would];
      return {
        kind: "intended",
        headline: would ? `Would be ${would}` : "Would stay open",
        detail: watchOnly ? "Watch-only: nothing was changed." : "Monitor mode: nothing was changed.",
        title: watchOnly
          ? "Watch-only: this is what PortLock would do if it could enforce"
          : "Monitor mode: this is what enforce mode would do",
        tier: null,
      };
    }
    case "failed":
      return { kind: "none", headline: "Not enforced", detail: enf.error || enf.detail || "Enforcement failed.", tier: null };
    case "unsupported":
      return {
        kind: "none",
        headline: "Not enforced",
        detail: enf.error || enf.detail || "This machine cannot enforce that.",
        tier: null,
      };
    case "refused":
      return {
        kind: "none",
        headline: "Not enforced",
        detail: `Refused by the safety check. ${enf.detail || enf.error || ""}`.trim(),
        tier: null,
      };
    default:
      return { kind: "none", headline: "Not determined", detail: "Enforcement has not been decided yet.", tier: null };
  }
}

/**
 * True when what a row shows is intended only: its State and Decision chips are then drawn
 * dashed, like its enforcement chip, so no solid "Denied" or "Read-only" stands for a device
 * the operating system was never asked to change.
 */
export function intendedOnly(conn, status) {
  return Boolean(conn) && enforcementTruth(conn, { watchOnly: isWatchOnly(status) }).kind === "intended";
}

/**
 * The key to the chip styles, worded for this process. `short` is the compact form for a
 * panel header. In watch-only nothing is ever changed, so solid there cannot mean "changed".
 */
export function chipLegend(status) {
  const watchOnly = isWatchOnly(status);
  return [
    {
      label: "Solid",
      short: watchOnly ? "Solid = as it is" : "Solid = in force",
      tone: "c-neutral",
      dashed: false,
      hatch: false,
      text: watchOnly
        ? "means it is so now: watch-only blocks nothing and makes nothing read-only."
        : "means it is in force: the operating system really was changed, or left open as decided.",
    },
    {
      label: "Dashed",
      short: "Dashed = intended only",
      tone: "c-watch",
      dashed: true,
      hatch: false,
      text: watchOnly
        ? "means intended only (watch-only): nothing was changed."
        : "means intended only (monitor mode): nothing was changed.",
    },
    {
      label: "Not enforced",
      short: null,
      tone: "c-pending",
      dashed: false,
      hatch: true,
      text: "means PortLock wanted to act and could not.",
    },
  ];
}

/** The one-line reading of a decision: "Pending, by policy default". */
export function decisionLine(decision) {
  if (!decision) return "";
  const rule = decision.rule_id ? ` ${decision.rule_id}` : "";
  return `${SOURCE_TEXT[decision.source] || decision.source}${rule}`;
}

export const KIND_TEXT = {
  lockdown: "Lockdown",
  enforce_mode: "Enforce mode",
  widen_scope: "Wider enforcement scope",
  default_deny: "Default-deny for new devices",
};

function simplePlural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

// ---- the bar on every page ---------------------------------------------------------------

// The bar stays short (a label and one sentence) because it heads every page; the reason sits
// behind its "Why" disclosure, and every other place that needs it points there.
export const WATCH_ONLY_LEAD = "Watch-only";
export const WATCH_ONLY_TEXT = "Nothing is blocked: PortLock changes nothing on this computer outside its own folder.";
export const WATCH_ONLY_WHY = "Why";

/** Beside a control a watch-only process refuses: short, and pointing at the bar's reason. */
export const WATCH_ONLY_CONTROL_NOTE = "Not available in watch-only. See Why at the top of the page.";

/**
 * Which bar heads every page: the simulation's, the watch-only one, or none. Never both: a
 * simulation is not the real PortLock, and saying both would contradict itself.
 */
export function shellBanner({ simulation = false, status = null } = {}) {
  if (simulation) return { kind: "simulation", text: SIMULATION_TEXT };
  if (isWatchOnly(status)) {
    return { kind: "watch_only", lead: WATCH_ONLY_LEAD, text: WATCH_ONLY_TEXT, why: WATCH_ONLY_WHY, reason: watchOnlyReason(status) };
  }
  return null;
}

/**
 * The service's mode notes worth showing beside the mode. The watch-only reason is one of
 * them, but it already sits behind the bar's "Why", so it is not repeated.
 */
export function modeNotes(mode) {
  const notes = Array.isArray(mode?.notes) ? mode.notes : [];
  const reason = watchOnlyReason(mode);
  return notes.filter((note) => typeof note === "string" && note.trim() !== "" && note.trim() !== reason);
}

// ---- the overview's posture band ---------------------------------------------------------

const LADDER = ["monitor", "enforce", "lockdown"];

/**
 * The words of the overview's posture band. `sub` is a list of segments: a string, or
 * `{strong: text}` for the one phrase that must stand out. `notes` are `{tone, text}` with
 * tone "" (plain), "warn" or "bad". `ladder` lists the rungs to draw; in watch-only there is
 * one, because no other rung can be reached in this process.
 * `would`: connected devices with a `would` outcome; `blockedNow`: devices really blocked.
 */
export function postureCopy(status, { would = 0, blockedNow = 0, plural = simplePlural } = {}) {
  const kind = posture(status);
  const mode = status?.mode || {};
  const lock = status?.lockdown || {};
  const enforcer = status?.enforcer;
  const notes = [];
  let headline;
  let sub;

  if (kind === "watch_only") {
    headline = "Watch-only: nothing is being blocked.";
    sub = [
      "This is the real PortLock. It watches the USB devices on this computer and records what it sees and what it would decide. ",
      { strong: "It changes nothing on this computer outside its own folder." },
      would > 0 ? ` If it could enforce, ${plural(would, "connected device", "connected devices")} would be blocked or made read-only.` : "",
    ];
    notes.push({ tone: "", text: `Why: ${watchOnlyReason(status)}` });
    if (mode.mode === "enforce") {
      notes.push({ tone: "warn", text: "The configuration asks for enforce mode, but this process is watch-only and never enforces. Nothing is blocked." });
    }
    if (lockdownEngaged(status?.lockdown)) {
      notes.push({ tone: "bad", text: `A lockdown is recorded as ${lock.state || "active"}, but nothing is blocked: this process is watch-only.` });
    }
    return { kind, headline, sub, notes, ladder: [{ name: "watch_only", label: POSTURE_TEXT.watch_only, current: true }] };
  }

  if (kind === "monitor") {
    headline = "Nothing is being blocked.";
    sub = [
      "PortLock is watching and recording what it would do. ",
      { strong: "It changes nothing on this machine." },
      would > 0 ? ` In enforce mode ${plural(would, "connected device", "connected devices")} would be blocked or made read-only.` : "",
    ];
    const modeNotes = Array.isArray(mode.notes) ? mode.notes : [];
    if (mode.mode === "enforce") {
      notes.push({
        tone: "warn",
        text: `Enforce mode is chosen but is not in force${mode.killswitch ? ": the kill switch is on" : modeNotes.length ? `: ${modeNotes.join(" ")}` : ""}.`,
      });
    }
    if (mode.mode === "monitor" && !mode.can_enforce) {
      notes.push({ tone: "warn", text: `This machine cannot enforce yet${modeNotes.length ? `: ${modeNotes.join(" ")}` : "."}` });
    }
  } else if (kind === "enforce") {
    headline = "Enforcing: devices policy has not approved are blocked.";
    sub = [
      "Keyboards, mice, hubs, built-in devices and enrolled input devices are ",
      { strong: "never touched" },
      ". ",
      `${plural(blockedNow, "connected device is", "connected devices are")} blocked now.`,
    ];
    if (enforcer && !enforcer.block) {
      notes.push({ tone: "warn", text: "This machine reports that it cannot block devices. Decisions will show as not enforced." });
    }
  } else {
    headline = "Lockdown: all removable storage is blocked.";
    sub = [
      "New devices are denied. Protected devices are never touched. ",
      lock.pending_change_id ? { strong: "Not confirmed yet: it rolls back unless you confirm it (bar above). " } : "",
      lock.state === "lifting" ? "It is being lifted now." : "It lifts itself when the timer ends.",
    ];
    if (!lock.external_timer_armed) {
      notes.push({ tone: "warn", text: "The operating-system timer that lifts this lockdown even if PortLock stops is not armed." });
    }
  }
  const ladder = LADDER.map((name) => ({ name, label: POSTURE_TEXT[name], current: name === kind }));
  return { kind, headline, sub, notes, ladder };
}

// ---- the commit-confirm bar --------------------------------------------------------------

const CHANGE_EXPLAIN = {
  lockdown: "Removable storage is blocked and new devices are denied now.",
  enforce_mode: "PortLock is now blocking, not just watching.",
  widen_scope: "More kinds of device are now enforced against.",
  default_deny: "The operating system now refuses unknown new devices by default.",
};

/**
 * The words of one waiting change. A lockdown blocks for real in a process that can
 * enforce, monitor mode included; anything else blocks only while PortLock enforces, so it
 * is "real" only in enforce mode: an active lockdown blocks storage, but it does not make a
 * wider scope or default-deny block in monitor mode. Where nothing is really blocked, every
 * sentence says "would".
 */
export function changeCopy(change, status) {
  const watchOnly = isWatchOnly(status);
  const real = !watchOnly && (change.kind === "lockdown" || status?.mode?.effective_mode === "enforce");
  const items = change.preview || [];
  const blocked = items.filter((item) => item.outcome === "block").length;
  const devices = `${items.length} connected device${items.length === 1 ? "" : "s"}`;
  const explain = real
    ? CHANGE_EXPLAIN[change.kind] || ""
    : watchOnly
      ? "Nothing is blocked: PortLock is watch-only here and changes nothing on this computer outside its own folder."
      : "This change blocks nothing yet: PortLock is in monitor mode.";
  return {
    real,
    explain,
    summary: real ? `${blocked} of ${devices} blocked by this change` : `${blocked} of ${devices} would be blocked by this change`,
    items: items.map((item) => {
      if (item.outcome === "block") {
        return real ? { label: "Blocked", tone: "c-deny", dashed: false } : { label: "Would be blocked", tone: "c-watch", dashed: true };
      }
      if (item.outcome === "protected") return { label: "Protected", tone: "c-watch", dashed: false };
      if (item.outcome === "exempt") return { label: "Exempt", tone: "c-watch", dashed: false };
      return { label: "Not enforced", tone: "c-pending", dashed: false };
    }),
  };
}

// ---- what a device's own words may claim -------------------------------------------------

/** `text` as a sentence: trimmed, and ending with a full stop unless it already ends one. */
function sentence(text) {
  const trimmed = String(text ?? "").trim();
  if (!trimmed) return "";
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

/** `text` to follow a colon: no closing full stop, and a capital lowered unless it starts a name. */
function clause(text) {
  const trimmed = String(text ?? "").trim().replace(/\.$/, "");
  return /^[A-Z][a-z]/.test(trimmed) ? trimmed[0].toLowerCase() + trimmed.slice(1) : trimmed;
}

/**
 * What went wrong, for a truth of the `none` kind, as a clause to follow "but" or a colon:
 * "enforcement failed: access denied", "it cannot be enforced here".
 */
function failure(conn, truth) {
  const enf = conn.enforcement;
  const specific = clause(enf?.error || enf?.detail);
  const withDetail = (text) => (specific ? `${text}: ${specific}` : text);
  if (truth.detail === "Outside the enforcement scope.") return "it is outside the enforcement scope";
  if (!conn.decision || !enf) return "it has not been enforced yet";
  if (enf.outcome === "unsupported") return withDetail("it cannot be enforced here");
  if (enf.outcome === "refused") return withDetail("the safety check refused it");
  if (enf.outcome === "failed") return withDetail("enforcement failed");
  return "it has not been enforced yet";
}

// Why an intended outcome changed nothing. Only for the `intended` kind: an enforcement that
// failed is reported as a failure, never as "monitor mode".
function notChangedBecause(watchOnly) {
  return watchOnly
    ? "PortLock is watch-only here and changes nothing on this computer outside its own folder."
    : "monitor mode changes nothing on this machine.";
}

/**
 * The toast after an approval. "now read-only" is said only when that was applied, and the
 * tone is "bad" whenever enforcement should have happened and did not (failed, unsupported).
 */
export function approvalMessage(connection, status) {
  const watchOnly = isWatchOnly(status);
  const truth = enforcementTruth(connection, { watchOnly });
  const stateName = connection.state;
  const shown = String(stateName).replace("_", "-");
  const still = stateName === "denied" || stateName === "pending";
  const reason = sentence(connection.decision?.reasons?.[0] || "a policy rule applies");
  if (truth.kind === "real" || truth.kind === "protected") {
    return still
      ? { text: `Grant recorded, but the device is still ${shown}: ${reason}`, tone: "bad" }
      : { text: `Approved: now ${shown}.`, tone: "good" };
  }
  if (truth.kind === "intended") {
    const why = notChangedBecause(watchOnly);
    return still
      ? { text: `Grant recorded, but the decision is still ${shown}: ${reason} Nothing was blocked: ${why}`, tone: "bad" }
      : { text: `Approved: the decision is ${shown}. Nothing on the device was changed: ${why}`, tone: "good" };
  }
  const wrong = failure(connection, truth);
  return still
    ? { text: `Grant recorded, but the decision is still ${shown}: ${reason} It is not blocked either: ${wrong}.`, tone: "bad" }
    : { text: `Approved: the decision is ${shown}, but ${wrong}.`, tone: "bad" };
}

/** The toast after a denial. "Denied" alone may only stand when the block was applied. */
export function denialMessage(reply, status) {
  if (reply.eject && !reply.eject.ok) return { text: `Denied, but the eject failed: ${sentence(reply.eject.error)}`, tone: "bad" };
  const watchOnly = isWatchOnly(status);
  const truth = enforcementTruth(reply.connection, { watchOnly });
  const again = "It will be pending again if it is plugged in again.";
  // The original words make no claim about the operating system, so they stand whenever
  // something real was done (or the device is protected and never touched).
  if (truth.kind === "real" || truth.kind === "protected") {
    return { text: `Denied for this connection. ${again}`, tone: "good" };
  }
  if (truth.kind === "intended") {
    return { text: `Denied for this connection, but it is not blocked: ${notChangedBecause(watchOnly)} ${again}`, tone: "good" };
  }
  return { text: `Denied for this connection, but it is not blocked: ${failure(reply.connection, truth)}. ${again}`, tone: "bad" };
}

/**
 * The line under a device held provisionally while its scan runs. "Held" only when the
 * operating system holds it, "Would be held" only for an intended outcome, and "Not held"
 * with the reason when enforcement failed or could not run.
 */
export function provisionalNote(conn, status) {
  const truth = enforcementTruth(conn, { watchOnly: isWatchOnly(status) });
  const enf = conn.enforcement;
  if (truth.kind === "real" && enf?.os_state === "read_only") return "Held read-only until its scan is clean";
  if (truth.kind === "real" && enf?.os_state === "blocked") return "Held blocked until its scan is clean";
  if (truth.kind === "intended") {
    return enf?.would === "blocked" ? "Would be held blocked until its scan is clean" : "Would be held read-only until its scan is clean";
  }
  if (truth.kind === "protected") return "Not held: PortLock never touches this device";
  if (truth.kind === "real") return "Not held: nothing needed enforcing";
  return `Not held: ${failure(conn, truth)}`;
}

/** The text of the Held ports panel. A held port is blocked only while PortLock blocks for real. */
export function portHoldText(status) {
  const lead = "A port that sees too many arrivals in a short time is held";
  const tail = "If you are sure it is safe, release it early.";
  if (blocksForReal(status)) return `${lead} blocked for a cool-down. ${tail}`;
  const why = isWatchOnly(status) ? "PortLock is watch-only on this computer" : "PortLock is in monitor mode";
  return `${lead} for a cool-down. ${why}, so the port is not really blocked. ${tail}`;
}

/** The note in a device's detail when nothing was done to it because PortLock only watches. */
export function intendedNote(status) {
  return isWatchOnly(status)
    ? "PortLock is watch-only on this computer. Nothing was blocked, ejected or changed for this device."
    : "PortLock is in monitor mode. Nothing was blocked, ejected or changed for this device.";
}

/** The note on a pending card whose device is not blocked while it waits. */
export function pendingWaitNote(status) {
  return isWatchOnly(status)
    ? "Watch-only: this device is NOT blocked while it waits. Approving or denying it records your decision and changes nothing on this computer outside its own folder."
    : "Monitor mode: this device is NOT blocked while it waits. Approving it changes nothing yet.";
}
