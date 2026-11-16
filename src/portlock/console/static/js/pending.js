// Devices waiting for a decision. Each card has a live half (what the device is, re-drawn on
// every event) and a form half that is built once and kept, so a note typed while another
// device arrives is not lost.

import { api } from "./api.js";
import { deviceIdentity, confidenceChip, openDeviceDetail } from "./devicetable.js";
import { h, replace, uid } from "./dom.js";
import { bytes, liveAgo } from "./fmt.js";
import { applyEvent, can, scope, state } from "./store.js";
import { decisionLine, enforcementTruth } from "./truth.js";
import { button, checkbox, chip, empty, enforcementCell, field, select, tags, textInput, toast } from "./ui.js";

const DURATIONS = [
  ["30m", "30 minutes"],
  ["1h", "1 hour"],
  ["2h", "2 hours"],
  ["4h", "4 hours"],
  ["8h", "8 hours"],
  ["24h", "24 hours"],
];

function volumeSummary(device) {
  if (!device.volumes.length) return null;
  const v = device.volumes[0];
  const more = device.volumes.length > 1 ? ` and ${device.volumes.length - 1} more` : "";
  return `${v.label || v.device_node}${v.size_bytes != null ? `, ${bytes(v.size_bytes)}` : ""}${v.fs_type ? `, ${v.fs_type}` : ""}${more}`;
}

function buildForms(conn) {
  const id = conn.connection_id;
  const group = uid("kind");
  const low = conn.confidence === "low";

  if (!can("approve_device")) {
    return h("p", { class: "note" }, "Your role can view this device but not decide on it.");
  }

  const kinds = [
    ["once", "Once", "Only for this plug-in", true],
    ["temporary", "For a while", "Until the time is up", can("issue_temporary_grant")],
    [
      "trust",
      "Always trust",
      low ? "Not possible: no unique serial number" : "Until you remove it",
      can("manage_trust") && !low,
    ],
  ];
  let kind = "once";
  const duration = select(DURATIONS.concat(can("manage_users") ? [["7d", "7 days"]] : []), "2h");
  const durationField = field("For how long", duration);
  durationField.hidden = true;
  const readOnly = checkbox("Read-only", { hint: "It can be read from but not written to" });
  const note = textInput({ maxlength: "512", placeholder: "Optional: why" });
  const radios = h(
    "div",
    { class: "radios" },
    kinds.map(([value, label, hint, enabled]) => {
      const input = h("input", {
        type: "radio",
        name: group,
        value,
        checked: value === "once",
        disabled: !enabled,
        onchange: () => {
          kind = value;
          durationField.hidden = kind !== "temporary";
        },
      });
      return h("label", { class: "check" }, input, h("span", {}, label, h("span", { class: "hint" }, hint)));
    }),
  );

  const approve = button("Approve", {
    tone: "enforce",
    onClick: async () => {
      const body = { kind, read_only: readOnly.input.checked };
      if (kind === "temporary") body.expires_in = duration.value;
      if (note.value.trim()) body.note = note.value.trim();
      const reply = await api.post(`/connections/${id}/approve`, body);
      applyEvent("decision.made", { connection: reply.connection });
      const outcome = reply.connection.decision;
      const stillBlocked = reply.connection.state === "denied" || reply.connection.state === "pending";
      toast(
        stillBlocked
          ? `Grant recorded, but the device is still ${reply.connection.state}: ${outcome.reasons[0] || "a policy rule applies"}`
          : `Approved: now ${reply.connection.state.replace("_", "-")}.`,
        stillBlocked ? "bad" : "good",
      );
    },
  });

  const eject = checkbox("Also ask the system to eject it", { hint: "Does not delete or change anything on the device" });
  const denyNote = textInput({ maxlength: "512", placeholder: "Optional: why" });
  const deny = button("Deny", {
    tone: "danger",
    onClick: async () => {
      const body = { eject: eject.input.checked };
      if (denyNote.value.trim()) body.note = denyNote.value.trim();
      const reply = await api.post(`/connections/${id}/deny`, body);
      applyEvent("decision.made", { connection: reply.connection });
      if (reply.eject && !reply.eject.ok) toast(`Denied, but the eject failed: ${reply.eject.error}`, "bad");
      else toast("Denied for this connection. It will be pending again if it is plugged in again.", "good");
    },
  });

  return h(
    "div",
    { class: "pcard-forms" },
    h("fieldset", {}, h("legend", {}, "Allow it"), radios, durationField, readOnly.el, field("Note", note), h("div", { class: "row" }, approve)),
    h("div", { class: "deny-box stack" }, h("div", { class: "label muted" }, "Or refuse it"), eject.el, field("Note", denyNote), h("div", { class: "row" }, deny)),
  );
}

function describe(conn) {
  const device = conn.device;
  const truth = enforcementTruth(conn);
  const volumes = volumeSummary(device);
  return h(
    "div",
    { class: "pcard-info" },
    h("div", {}, h("button", { class: "linkish pcard-title", type: "button", onclick: () => openDeviceDetail(conn) }, conn.display_name || "Unnamed device")),
    h("div", { class: "cell-sub mono" }, deviceIdentity(device)),
    h("div", { class: "row" }, chip("Pending", "c-pending"), confidenceChip(conn), conn.decision && conn.decision.alert ? chip("Alert", "c-deny") : null),
    device.categories.length ? tags(device.categories) : null,
    volumes ? h("div", { class: "cell-sub" }, `Volume: ${volumes}`) : null,
    h("div", { class: "cell-sub" }, "Plugged in ", liveAgo(conn.connected_at)),
    conn.decision ? h("div", { class: "cell-sub" }, `Why pending: ${conn.decision.reasons[0] || decisionLine(conn.decision)}`) : null,
    enforcementCell(conn),
    truth.kind === "intended"
      ? h("p", { class: "note warn" }, "Monitor mode: this device is NOT blocked while it waits. Approving it changes nothing yet.")
      : null,
    truth.kind === "none"
      ? h("p", { class: "note bad" }, "This device is waiting, but PortLock did not block it. See the enforcement note above.")
      : null,
  );
}

/** Render the pending devices into `container`, live. Returns a function that stops it. */
export function mountPending(container) {
  const cards = new Map();
  const s = scope();
  const list = h("div", { class: "pcards" });
  const none = empty("Nothing is waiting for a decision.", "A device that policy cannot decide appears here as soon as it is plugged in.");
  replace(container, list);

  function render() {
    const pending = [...state.devices.values()]
      .filter((conn) => conn.state === "pending")
      .sort((a, b) => a.connection_id - b.connection_id);
    const shown = pending;
    for (const [id, card] of cards) {
      if (!shown.some((conn) => conn.connection_id === id)) {
        card.el.remove();
        cards.delete(id);
      }
    }
    none.remove();
    if (shown.length === 0) {
      list.appendChild(none);
      return;
    }
    shown.forEach((conn, index) => {
      let card = cards.get(conn.connection_id);
      if (!card) {
        const info = h("div", { class: "pcard-info" });
        const el = h("article", { class: "pcard", "aria-label": `Pending device ${conn.display_name || ""}` }, info, buildForms(conn));
        card = { el, info };
        cards.set(conn.connection_id, card);
      }
      card.info.replaceWith(describe(conn));
      card.info = card.el.firstChild;
      if (list.children[index] !== card.el) list.insertBefore(card.el, list.children[index] || null);
    });
  }

  s.on(["devices", "status"], render);
  render();
  return () => s.dispose();
}
