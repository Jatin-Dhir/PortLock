// Turning API values into plain statements, and deciding what is TRUE about a device.
//
// The rule behind every line here: a decision is not an enforcement. "Denied" says what
// policy wants; only an enforcement outcome of `applied` says the operating system was made
// to do it. Where it was not, the console says "not enforced", in words.

export const POSTURE_TEXT = {
  monitor: "Monitor",
  enforce: "Enforce",
  lockdown: "Lockdown",
};

/** monitor, enforce or lockdown: the three states that must never be confused. */
export function posture(status) {
  const lock = status?.lockdown;
  if (lock && (lock.active || lock.state === "engaging" || lock.state === "active" || lock.state === "lifting")) {
    return "lockdown";
  }
  return status?.mode?.effective_mode === "enforce" ? "enforce" : "monitor";
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
 *  - `intended`: monitor mode, nothing was changed; shown dashed;
 *  - `none`: enforcement did NOT happen where it should have (failed, unsupported, outside scope);
 *  - `protected`: PortLock refuses to touch it.
 */
export function enforcementTruth(conn) {
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
        detail: "Monitor mode: nothing was changed.",
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
