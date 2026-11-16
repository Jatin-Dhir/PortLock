// Overview: which of the three states PortLock is in, what needs a decision, what is
// connected, what to look at. The posture band is the one loud element on the page.

import { h, replace } from "../dom.js";
import { count, countdown, liveAgo, plural, timeEl } from "../fmt.js";
import { deviceTable, openDeviceDetail } from "../devicetable.js";
import { mountPending } from "../pending.js";
import { scope, state } from "../store.js";
import { DEGRADED_TEXT, POSTURE_TEXT, enforcementTruth, posture } from "../truth.js";
import { chip, empty, pageHead, panel, severityChip } from "../ui.js";

const LADDER = ["monitor", "enforce", "lockdown"];

function wouldChange() {
  return [...state.devices.values()].filter((conn) => !conn.protected && conn.enforcement && conn.enforcement.would).length;
}

function blockedNow() {
  return [...state.devices.values()].filter(
    (conn) => enforcementTruth(conn).kind === "real" && conn.enforcement.os_state === "blocked",
  ).length;
}

function band() {
  const status = state.status;
  const kind = posture(status);
  const lock = status.lockdown;
  const mode = status.mode;
  const enforcer = status.enforcer;
  let headline;
  let sub;
  let clock = null;
  const facts = [];
  const notes = [];

  if (kind === "monitor") {
    const would = wouldChange();
    headline = "Nothing is being blocked.";
    sub = h(
      "span",
      {},
      "PortLock is watching and recording what it would do. ",
      h("strong", {}, "It changes nothing on this machine."),
      would > 0 ? ` In enforce mode ${plural(would, "connected device", "connected devices")} would be blocked or made read-only.` : "",
    );
    if (mode.mode === "enforce") {
      notes.push(
        `Enforce mode is chosen but is not in force${mode.killswitch ? ": the kill switch is on" : mode.notes.length ? `: ${mode.notes.join(" ")}` : ""}.`,
      );
    }
    if (mode.mode === "monitor" && !mode.can_enforce) {
      notes.push(`This machine cannot enforce yet${mode.notes.length ? `: ${mode.notes.join(" ")}` : "."}`);
    }
  } else if (kind === "enforce") {
    headline = "Enforcing: devices policy has not approved are blocked.";
    sub = h(
      "span",
      {},
      "Keyboards, mice, hubs, built-in devices and enrolled input devices are ",
      h("strong", {}, "never touched"),
      ". ",
      `${plural(blockedNow(), "connected device is", "connected devices are")} blocked now.`,
    );
    if (enforcer && !enforcer.block) notes.push("This machine reports that it cannot block devices. Decisions will show as not enforced.");
  } else {
    headline = "Lockdown: all removable storage is blocked.";
    sub = h(
      "span",
      {},
      "New devices are denied. Protected devices are never touched. ",
      lock.pending_change_id ? h("strong", {}, "Not confirmed yet: it rolls back unless you confirm it (bar above). ") : null,
      lock.state === "lifting" ? "It is being lifted now." : "It lifts itself when the timer ends.",
    );
    if (lock._deadlineMs) {
      clock = h("div", { class: "posture-clock" }, h("span", { class: "t" }, countdown(lock._deadlineMs)), h("span", { class: "l" }, "until it lifts by itself"));
    }
    facts.push(
      ["Engaged by", lock.engaged_by],
      ["At", lock.engaged_at ? timeEl(lock.engaged_at) : null],
      ["Reason", lock.reason],
      ["Renewed", lock.renew_count ? `${lock.renew_count} time${lock.renew_count === 1 ? "" : "s"}` : null],
      ["Mode underneath", POSTURE_TEXT[mode.effective_mode]],
    );
    if (!lock.external_timer_armed) {
      notes.push("The operating-system timer that lifts this lockdown even if PortLock stops is not armed.");
    }
  }

  facts.push(["Policy", `${status.policy.name} (${plural(status.policy.rules, "rule", "rules")}, ${status.policy.source})`]);
  if (kind !== "lockdown") facts.push(["Detection", status.backend.name], ["Can block devices", enforcer ? (enforcer.block ? "yes" : "no") : "unknown"]);

  return h(
    "section",
    { class: "posture", "data-state": kind, "aria-label": "Protection state" },
    h(
      "ol",
      { class: "ladder", "aria-label": "Monitor, then Enforce, then Lockdown" },
      LADDER.map((name) => h("li", { "aria-current": name === kind ? "true" : null }, POSTURE_TEXT[name])),
    ),
    h("div", { class: "posture-grid" }, h("div", {}, h("h2", { class: "posture-headline" }, headline), h("p", { class: "posture-sub" }, sub)), clock),
    notes.map((text) => h("p", { class: "note warn" }, text)),
    h(
      "dl",
      { class: "posture-facts" },
      facts
        .filter(([, value]) => value)
        .map(([key, value]) => h("div", {}, `${key}: `, h("b", {}, value))),
    ),
  );
}

const STAT_ORDER = [
  ["connected", "Connected", ""],
  ["protected", "Protected", "enforce"],
  ["allowed", "Allowed", "allow"],
  ["read_only", "Read-only", "readonly"],
  ["pending", "Pending", "pending"],
  ["denied", "Denied", "deny"],
  ["not_enforced", "Not enforced", "warn"],
];

function stats() {
  const counts = state.status.counts;
  return h(
    "ul",
    { class: "stats", "aria-label": "Device counts" },
    STAT_ORDER.map(([key, label, tone]) => {
      const n = counts[key] ?? 0;
      const live = key === "pending" || key === "not_enforced" ? (n > 0 ? tone : "") : tone;
      return h(
        "li",
        { class: "stat", "data-tone": live },
        h("span", { class: "n" }, count(n)),
        h("span", { class: "l" }, label),
      );
    }),
  );
}

function health() {
  const status = state.status;
  const items = [];
  for (const flag of status.degraded) items.push(`Degraded: ${DEGRADED_TEXT[flag] || flag}.`);
  if (!status.backend.healthy) items.push(`Device detection is unhealthy${status.backend.last_error ? `: ${status.backend.last_error}` : "."}`);
  if (status.audit.sink_failures > 0) items.push(`${plural(status.audit.sink_failures, "audit export has", "audit exports have")} failed.`);
  if (items.length === 0) return null;
  return h("div", { class: "stack" }, items.map((text) => h("p", { class: "note bad", role: "alert" }, text)));
}

function alerts() {
  if (state.alerts.length === 0) {
    return empty("No alerts since this page was opened.", "Earlier alerts are in the audit log.");
  }
  return h(
    "ul",
    { class: "alerts" },
    state.alerts.map((a) =>
      h(
        "li",
        {},
        severityChip(a.severity),
        h("span", { class: "msg" }, h("strong", {}, a.title), " ", a.message),
        liveAgo(a.receivedAt),
      ),
    ),
  );
}

export function mount(root) {
  const s = scope();
  const announce = h("p", { class: "sr-only", role: "status" });
  const bandHost = h("div", {});
  const healthHost = h("div", {});
  const statsHost = h("div", {});
  const pendingHost = h("div", {});
  const devicesHost = h("div", { class: "panel-flush" });
  const alertsHost = h("div", {});
  let lastPosture = null;

  replace(
    root,
    pageHead("Overview"),
    announce,
    bandHost,
    healthHost,
    statsHost,
    panel("Needs a decision", pendingHost),
    panel("Connected devices", devicesHost, chip("Solid = in force", "c-neutral"), chip("Dashed = intended only", "c-watch", { dashed: true })),
    panel("Alerts", alertsHost),
  );

  const stopPending = mountPending(pendingHost);

  function renderTop() {
    if (!state.status) return;
    replace(bandHost, band());
    replace(statsHost, stats());
    replace(healthHost, health());
    const kind = posture(state.status);
    if (kind !== lastPosture) {
      announce.textContent = `Protection state: ${POSTURE_TEXT[kind]}.`;
      lastPosture = kind;
    }
  }

  function renderDevices() {
    const conns = [...state.devices.values()].sort((a, b) => a.connection_id - b.connection_id);
    replace(
      devicesHost,
      deviceTable(conns, { onOpen: openDeviceDetail }) || empty("No USB device is connected.", "Plug one in and it appears here at once."),
    );
  }

  s.on(["status", "lockdown", "mode"], renderTop);
  s.on("devices", () => {
    renderDevices();
    renderTop();
  });
  s.on("alerts", () => replace(alertsHost, alerts()));
  renderTop();
  renderDevices();
  replace(alertsHost, alerts());

  return () => {
    stopPending();
    s.dispose();
  };
}
