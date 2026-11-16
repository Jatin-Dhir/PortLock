// Devices: connected now, the history of connections, and every device ever seen.

import { api, seg } from "../api.js";
import { deviceIdentity, deviceTable, openDeviceDetail, confidenceChip } from "../devicetable.js";
import { h, replace } from "../dom.js";
import { count, liveAgo, shortFp, timeEl } from "../fmt.js";
import { scope, state } from "../store.js";
import { accessChip, button, chip, empty, enforcementCell, errorState, infoDialog, kv, loading, pageHead, stateChip, table, textInput, field } from "../ui.js";

const TABS = [
  ["connected", "Connected now"],
  ["history", "History"],
  ["known", "Every device seen"],
];

function legend() {
  return h(
    "p",
    { class: "legend" },
    chip("Solid", "c-neutral"),
    "means the operating system was really changed.",
    chip("Dashed", "c-watch", { dashed: true }),
    "means intended only (monitor mode): nothing was changed.",
    chip("Not enforced", "c-pending", { hatch: true }),
    "means PortLock wanted to act and could not.",
  );
}

/** A list read page by page. `fetchPage(cursor)` returns `{items, next}`. */
function pager({ fetchPage, render, emptyState }) {
  const host = h("div", {});
  let items = [];
  let next = null;
  let busy = false;

  async function load(reset) {
    if (busy) return;
    busy = true;
    try {
      if (reset) {
        items = [];
        next = null;
        replace(host, loading());
      }
      const page = await fetchPage(reset ? null : next);
      items = items.concat(page.items);
      next = page.next;
      draw();
    } catch (error) {
      replace(host, errorState(error, () => load(true)));
    } finally {
      busy = false;
    }
  }

  function draw() {
    if (items.length === 0) {
      replace(host, emptyState);
      return;
    }
    replace(
      host,
      h("div", { class: "panel-flush" }, render(items)),
      next !== null
        ? h("div", { class: "panel-body" }, button("Load older", { onClick: () => load(false) }))
        : h("p", { class: "hint panel-body" }, `${count(items.length)} shown. That is all of them.`),
    );
  }

  return { host, reload: () => load(true) };
}

async function openKnown(device) {
  const body = h("div", { class: "stack" }, loading());
  const shown = infoDialog(device.display_name || "Device", body);
  try {
    const detail = await api.get(`/devices/${seg(device.fingerprint)}`);
    replace(
      body,
      kv([
        ["Fingerprint", h("code", {}, detail.fingerprint)],
        ["Identity", deviceIdentity(detail.device)],
        ["Trust", detail.trust ? `trusted (${detail.trust === "read_only" ? "read-only" : "full access"})` : "not trusted"],
        ["First seen", timeEl(detail.first_seen)],
        ["Last seen", timeEl(detail.last_seen)],
        ["Connections", count(detail.connection_count)],
      ]),
      h("h3", {}, "Recent connections"),
      detail.connections.length === 0
        ? empty("No connections recorded")
        : table({
            caption: "Recent connections",
            rows: detail.connections,
            columns: [
              { label: "#", cell: (c) => h("button", { class: "linkish", type: "button", onclick: () => openDeviceDetail(c) }, String(c.connection_id)) },
              { label: "State", cell: (c) => stateChip(c.state) },
              { label: "Connected", cell: (c) => timeEl(c.connected_at) },
              { label: "Unplugged", cell: (c) => (c.removed_at ? timeEl(c.removed_at) : "still connected") },
            ],
          }),
    );
  } catch (error) {
    replace(body, errorState(error));
  }
  return shown;
}

export function mount(root) {
  const s = scope();
  let tab = "connected";
  const content = h("div", {});
  const tabs = h(
    "div",
    { class: "seg", role: "group", "aria-label": "Which devices" },
    TABS.map(([id, label]) => h("button", { type: "button", "aria-pressed": id === tab ? "true" : "false", "data-tab": id, onclick: () => select(id) }, label)),
  );
  replace(root, pageHead("Devices", null, tabs), legend(), content);

  let connectedHost = null;
  const history = pager({
    fetchPage: async (cursor) => {
      const reply = await api.get("/devices/history", { limit: 50, before_id: cursor });
      return { items: reply.connections, next: reply.next };
    },
    emptyState: empty("No connection has been recorded yet."),
    render: (rows) =>
      table({
        caption: "Connection history",
        rows,
        columns: [
          {
            label: "Device",
            cell: (c) => [
              h("button", { class: "linkish cell-main", type: "button", onclick: () => openDeviceDetail(c) }, c.display_name || "Unnamed device"),
              h("div", { class: "cell-sub mono" }, deviceIdentity(c.device)),
              confidenceChip(c),
            ],
          },
          { label: "State", cell: (c) => stateChip(c.state) },
          { label: "Decision", cell: (c) => (c.decision ? accessChip(c.decision.access) : "none") },
          { label: "Enforcement", cell: (c) => enforcementCell(c) },
          { label: "Connected", cell: (c) => timeEl(c.connected_at) },
          { label: "Left", cell: (c) => (c.removed_at ? [timeEl(c.removed_at), h("div", { class: "cell-sub" }, c.close_reason || "")] : "still connected") },
        ],
      }),
  });

  let text = "";
  const known = pager({
    fetchPage: async (cursor) => {
      const reply = await api.get("/devices/known", { limit: 50, before: cursor, text });
      return { items: reply.devices, next: reply.next };
    },
    emptyState: empty("No device matches.", "Devices appear here the first time they are plugged in."),
    render: (rows) =>
      table({
        caption: "Every device seen",
        rows,
        columns: [
          {
            label: "Device",
            cell: (d) => [
              h("button", { class: "linkish cell-main", type: "button", onclick: () => openKnown(d) }, d.display_name || "Unnamed device"),
              h("div", { class: "cell-sub mono" }, deviceIdentity(d.device)),
              h("div", { class: "cell-sub mono" }, shortFp(d.fingerprint)),
            ],
          },
          { label: "Confidence", cell: (d) => (d.confidence === "low" ? chip("Low", "c-pending") : chip("High", "c-allow")) },
          { label: "Trust", cell: (d) => (d.trust ? chip(d.trust === "read_only" ? "Trusted read-only" : "Trusted", "c-allow") : h("span", { class: "faint" }, "none")) },
          { label: "Now", cell: (d) => (d.connected ? chip("Connected", "c-watch") : h("span", { class: "faint" }, "away")) },
          { label: "Times seen", num: true, cell: (d) => count(d.connection_count) },
          { label: "Last seen", cell: (d) => liveAgo(d.last_seen) },
        ],
      }),
  });
  const search = textInput({ type: "search", placeholder: "Manufacturer, product, serial or fingerprint" });
  const searchForm = h(
    "form",
    {
      class: "row panel-body",
      onsubmit: (event) => {
        event.preventDefault();
        text = search.value.trim();
        known.reload();
      },
    },
    field("Search", search),
    button("Search", { type: "submit" }),
  );

  function renderConnected() {
    const conns = [...state.devices.values()].sort((a, b) => a.connection_id - b.connection_id);
    replace(
      connectedHost,
      h("div", { class: "panel-flush" }, deviceTable(conns, { onOpen: openDeviceDetail }) || empty("No USB device is connected.", "Plug one in and it appears here at once.")),
    );
  }

  function select(id) {
    tab = id;
    for (const b of tabs.children) b.setAttribute("aria-pressed", b.dataset.tab === id ? "true" : "false");
    if (id === "connected") {
      connectedHost = h("div", { class: "panel" });
      replace(content, connectedHost);
      renderConnected();
    } else if (id === "history") {
      replace(content, h("div", { class: "panel" }, history.host));
      history.reload();
    } else {
      replace(content, h("div", { class: "panel" }, searchForm, known.host));
      known.reload();
    }
  }

  s.on("devices", () => {
    if (tab === "connected") renderConnected();
  });
  select("connected");
  return () => s.dispose();
}
