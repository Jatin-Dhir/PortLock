// The table of connected devices, and the detail dialog behind each row. Every string that
// came from a device goes through h() as a text node.

import { api, seg } from "./api.js";
import { frag, h } from "./dom.js";
import { bytes, hex, liveAgo, timeEl, vidPid } from "./fmt.js";
import { state, can } from "./store.js";
import { decisionLine, enforcementTruth, SOURCE_TEXT } from "./truth.js";
import {
  accessChip,
  button,
  chip,
  copyButton,
  describeError,
  empty,
  enforcementCell,
  infoDialog,
  kv,
  loading,
  scanChip,
  verdictChip,
  stateChip,
  table,
  tags,
  toast,
} from "./ui.js";

export function deviceIdentity(device) {
  return `${vidPid(device)} · ${device.serial ? `serial ${device.serial}` : "no serial number"}`;
}

export function confidenceChip(conn) {
  // A protected device is never enforced against, so how well it is identified is moot.
  return conn.confidence === "low" && !conn.protected
    ? chip("Low confidence", "c-pending", { title: "No unique serial number: every unit of this model looks identical to PortLock." })
    : null;
}

/** Connected devices, one row each. `onOpen(conn)` opens the detail. */
export function deviceTable(conns, { onOpen, caption = "Connected devices" }) {
  if (conns.length === 0) return null;
  return table({
    caption,
    rows: conns,
    rowProps: (conn) => ({ class: state.fresh.has(conn.connection_id) ? "fresh" : null }),
    columns: [
      {
        label: "Device",
        cell: (conn) =>
          frag(
            h("button", { class: "linkish cell-main", type: "button", onclick: () => onOpen(conn) }, conn.display_name || "Unnamed device"),
            h("div", { class: "cell-sub mono" }, deviceIdentity(conn.device)),
            confidenceChip(conn),
          ),
      },
      {
        label: "State",
        cell: (conn) =>
          frag(
            stateChip(conn.state),
            conn.provisional ? h("div", { class: "cell-sub" }, "Held read-only until its scan is clean") : null,
          ),
      },
      {
        label: "Decision",
        cell: (conn) =>
          conn.decision
            ? frag(
                accessChip(conn.decision.access),
                conn.decision.alert ? chip("Alert", "c-deny") : null,
                h("div", { class: "cell-sub" }, `by ${decisionLine(conn.decision)}`),
              )
            : h("span", { class: "faint" }, "none yet"),
      },
      { label: "Enforcement", cell: (conn) => enforcementCell(conn) },
      { label: "Scan", cell: (conn) => scanChip(conn.scan) },
      { label: "Connected", cell: (conn) => liveAgo(conn.connected_at) },
    ],
  });
}

function interfaceTag(iface) {
  return `class ${hex(iface.cls, 2)} / ${hex(iface.subcls, 2)} / ${hex(iface.protocol, 2)}`;
}

function volumeLine(volume) {
  const parts = [volume.label || volume.device_node, volume.fs_type, volume.size_bytes != null ? bytes(volume.size_bytes) : null];
  if (volume.read_only === true) parts.push("read-only");
  if (volume.mount_point) parts.push(`mounted at ${volume.mount_point}`);
  return parts.filter(Boolean).join(" · ");
}

/** The whole story of one connection: identity, what it says it is, what was decided and done. */
export async function openDeviceDetail(conn) {
  const content = h("div", { class: "stack" }, loading("Loading device"));
  const shown = infoDialog(conn.display_name || "Device", content);
  try {
    const [detail, known] = await Promise.all([
      api.get(`/connections/${conn.connection_id}`),
      api.get(`/devices/${seg(conn.fingerprint)}`),
    ]);
    const live = detail.connection;
    const device = live.device;
    const truth = enforcementTruth(live);
    const decision = live.decision;
    content.replaceChildren(
      h(
        "div",
        { class: "row" },
        stateChip(live.state),
        decision ? accessChip(decision.access) : null,
        confidenceChip(live),
        scanChip(live.scan),
        live.removed_at ? chip("Unplugged", "c-neutral") : null,
      ),
      kv([
        ["Fingerprint", h("span", {}, h("code", {}, live.fingerprint), " ", copyButton(live.fingerprint))],
        ["Fingerprint built from", tags(live.basis)],
        ["Seen", `${known.connection_count} time${known.connection_count === 1 ? "" : "s"}, first ${known.first_seen}`],
        ["Connected", timeEl(live.connected_at)],
        ["Unplugged", live.removed_at ? timeEl(live.removed_at) : null],
      ]),
      h("h3", {}, "What the device says about itself"),
      h("p", { class: "hint" }, "Supplied by the device, so it can be wrong or hostile. It is shown as plain text only."),
      kv([
        ["Manufacturer", device.manufacturer],
        ["Product", device.product],
        ["Serial", device.serial || "none"],
        ["Vendor : product", vidPid(device)],
        ["Device release", device.bcd_device == null ? null : `0x${hex(device.bcd_device)}`],
        ["Device class", `0x${hex(device.device_class, 2)}`],
        ["Port", device.bus_path],
        ["Removable", device.removable == null ? "unknown" : device.removable ? "yes" : "no"],
        ["Categories", tags(device.categories || [])],
        ["Interfaces", device.interfaces.length ? tags(device.interfaces.map(interfaceTag)) : "none"],
        ["Volumes", device.volumes.length ? h("div", {}, device.volumes.map((v) => h("div", {}, volumeLine(v)))) : "none mounted"],
      ]),
      h("h3", {}, "What was decided, and what was done"),
      decision
        ? h(
            "div",
            { class: "stack" },
            h("div", { class: "row" }, accessChip(decision.access), h("span", {}, `by ${decisionLine(decision)}`)),
            h("ul", {}, decision.reasons.map((reason) => h("li", {}, reason))),
          )
        : h("p", { class: "muted" }, "No decision yet."),
      h("div", {}, enforcementCell(live)),
      live.enforcement && live.enforcement.error ? h("p", { class: "note bad" }, live.enforcement.error) : null,
      truth.kind === "intended"
        ? h("p", { class: "note" }, "PortLock is in monitor mode. Nothing was blocked, ejected or changed for this device.")
        : null,
      h("h3", {}, "Decision history for this connection"),
      detail.decisions.length === 0
        ? empty("No decisions recorded")
        : table({
            caption: "Decisions",
            rows: detail.decisions,
            columns: [
              { label: "When", cell: (d) => timeEl(d.decided_at) },
              { label: "Access", cell: (d) => accessChip(d.access) },
              { label: "By", cell: (d) => SOURCE_TEXT[d.source] || d.source },
              { label: "Because", cell: (d) => d.trigger },
              { label: "Mode", cell: (d) => d.mode },
            ],
          }),
      detail.scans.length
        ? h(
            "div",
            { class: "stack" },
            h("h3", {}, "Scans"),
            table({
              caption: "Scans",
              rows: detail.scans,
              columns: [
                { label: "#", cell: (s) => String(s.id) },
                { label: "Volume", cell: (s) => s.mount_point },
                { label: "State", cell: (s) => s.state },
                { label: "Verdict", cell: (s) => (s.verdict ? verdictChip(s.verdict) : "pending") },
              ],
            }),
          )
        : null,
      known.grants.length
        ? h(
            "div",
            { class: "stack" },
            h("h3", {}, "Grants for this device"),
            table({
              caption: "Grants",
              rows: known.grants,
              columns: [
                { label: "Kind", cell: (g) => `${g.kind}${g.read_only ? ", read-only" : ""}` },
                { label: "By", cell: (g) => g.granted_by },
                { label: "Until", cell: (g) => (g.expires_at ? timeEl(g.expires_at) : "no expiry") },
                { label: "Status", cell: (g) => (g.ended_at ? `ended: ${g.end_reason}` : "active") },
              ],
            }),
          )
        : null,
      live.state === "pending" && can("approve_device")
        ? h("p", { class: "note warn" }, "This device is waiting for a decision. Approve or deny it on the Pending page.")
        : null,
      live.removed_at === null && device.volumes.length > 0 && can("run_scan")
        ? h(
            "div",
            { class: "row" },
            button("Scan its volumes", {
              onClick: async () => {
                await api.post("/scans", { connection_id: live.connection_id });
                toast("Scan queued. Results appear on the Scans page.", "good");
              },
            }),
          )
        : null,
    );
  } catch (error) {
    content.replaceChildren(h("div", { class: "form-error", role: "alert" }, describeError(error)));
  }
  return shown;
}

