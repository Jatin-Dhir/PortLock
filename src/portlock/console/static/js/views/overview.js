// Overview: which of the three states PortLock is in, what needs a decision, what is
// connected, what to look at. The posture band is the one loud element on the page.

import { h, replace } from "../dom.js";
import { count, countdown, liveAgo, plural, timeEl } from "../fmt.js";
import { deviceTable, openDeviceDetail } from "../devicetable.js";
import { mountPending } from "../pending.js";
import { scope, state } from "../store.js";
import { DEGRADED_TEXT, POSTURE_TEXT, chipLegend, enforcementTruth, posture, postureCopy } from "../truth.js";
import { chip, empty, pageHead, panel, severityChip } from "../ui.js";

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
  const lock = status.lockdown;
  const mode = status.mode;
  const enforcer = status.enforcer;
  // The words, and which rungs to draw, are decided in truth.js (tested under Node).
  const copy = postureCopy(status, { would: wouldChange(), blockedNow: blockedNow(), plural });
  const kind = copy.kind;
  let clock = null;
  const facts = [];
  const sub = h(
    "span",
    {},
    copy.sub.map((part) => (typeof part === "string" ? part : h("strong", {}, part.strong))),
  );

  if (kind === "lockdown") {
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
  }

  facts.push(["Policy", `${status.policy.name} (${plural(status.policy.rules, "rule", "rules")}, ${status.policy.source})`]);
  if (kind === "watch_only") {
    facts.push(["Detection", status.backend.name], ["Can block devices", "no, never in this process"]);
  } else if (kind !== "lockdown") {
    facts.push(["Detection", status.backend.name], ["Can block devices", enforcer ? (enforcer.block ? "yes" : "no") : "unknown"]);
  }

  return h(
    "section",
    { class: "posture", "data-state": kind, "aria-label": "Protection state" },
    h(
      "ol",
      { class: "ladder", "aria-label": kind === "watch_only" ? "Watch-only: no other state can be reached here" : "Monitor, then Enforce, then Lockdown" },
      copy.ladder.map((rung) => h("li", { "aria-current": rung.current ? "true" : null }, rung.label)),
    ),
    h("div", { class: "posture-grid" }, h("div", {}, h("h2", { class: "posture-headline" }, copy.headline), h("p", { class: "posture-sub" }, sub)), clock),
    copy.notes.map((note) => h("p", { class: note.tone ? `note ${note.tone}` : "note" }, note.text)),
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
    panel(
      "Connected devices",
      devicesHost,
      chipLegend(state.status)
        .filter((item) => item.short)
        .map((item) => chip(item.short, item.tone, { dashed: item.dashed })),
    ),
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
