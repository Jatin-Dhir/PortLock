// The audit log: search it, page through it, and verify its hash chain.

import { api } from "../api.js";
import { h, replace } from "../dom.js";
import { count, plural, shortFp, timeEl } from "../fmt.js";
import { scope, state } from "../store.js";
import { button, empty, errorBox, errorState, field, loading, pageHead, panel, select, severityChip, table, textInput } from "../ui.js";

const SEVERITIES = [["", "Any severity"], ["debug", "Debug and up"], ["info", "Info and up"], ["notice", "Notice and up"], ["warning", "Warning and up"], ["error", "Error and up"], ["critical", "Critical only"]];

function isoSeconds(local) {
  if (!local) return null;
  const date = new Date(local);
  return Number.isNaN(date.getTime()) ? null : date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function dataCell(data) {
  const text = JSON.stringify(data);
  if (!text || text === "{}") return h("span", { class: "faint" }, "none");
  return h("details", { class: "audit-data" }, h("summary", {}, text), h("pre", { class: "json" }, JSON.stringify(data, null, 2)));
}

export function mount(root) {
  const s = scope();
  const resultsHost = h("div", {});
  const newNote = h("div", {});
  const headHost = h("span", { class: "muted mono" });
  let records = [];
  let next = null;
  let query = {};
  let order = "desc";
  let busy = false;

  // ---- search ----
  const text = textInput({ placeholder: "Anything in the record's data" });
  const type = textInput({ placeholder: "For example grant.created or auth.*" });
  const severity = select(SEVERITIES, "");
  const actor = textInput();
  const device = textInput({ placeholder: "plk1:..." });
  const since = h("input", { type: "datetime-local" });
  const until = h("input", { type: "datetime-local" });
  const orderSel = select([["desc", "Newest first"], ["asc", "Oldest first"]], "desc");

  function readForm() {
    const types = type.value.split(/[\s,]+/).filter(Boolean);
    return {
      text: text.value.trim(),
      type: types.length ? types : null,
      min_severity: severity.value,
      actor: actor.value.trim(),
      device_fp: device.value.trim(),
      since: isoSeconds(since.value),
      until: isoSeconds(until.value),
    };
  }

  async function run(reset) {
    if (busy) return;
    busy = true;
    try {
      if (reset) {
        query = readForm();
        order = orderSel.value;
        records = [];
        next = null;
        state.newAudit = 0;
        replace(newNote);
        replace(resultsHost, loading("Searching"));
      }
      const cursor = next === null ? {} : order === "desc" ? { until_seq: next } : { since_seq: next };
      const reply = await api.get("/audit", { ...query, ...cursor, order, limit: 100 });
      records = records.concat(reply.records);
      next = reply.next;
      headHost.textContent = `Head: record ${reply.head.seq}, hash ${shortFp(reply.head.hash)}`;
      headHost.title = reply.head.hash;
      draw();
    } catch (error) {
      replace(resultsHost, errorState(error, () => run(true)));
    } finally {
      busy = false;
    }
  }

  function draw() {
    if (records.length === 0) {
      replace(resultsHost, empty("No record matches.", "Loosen a filter, or widen the time range."));
      return;
    }
    replace(
      resultsHost,
      h(
        "div",
        { class: "panel-flush" },
        table({
          caption: "Audit records",
          rows: records,
          columns: [
            { label: "#", num: true, cell: (r) => String(r.seq) },
            { label: "Time", cell: (r) => timeEl(r.ts) },
            { label: "Severity", cell: (r) => severityChip(r.severity) },
            { label: "Event", cell: (r) => h("code", {}, r.event_type) },
            { label: "By", cell: (r) => r.actor || h("span", { class: "faint" }, "system") },
            { label: "Device", cell: (r) => (r.device_fp ? h("code", { title: r.device_fp }, shortFp(r.device_fp)) : "") },
            { label: "Data", cell: (r) => dataCell(r.data) },
          ],
        }),
      ),
      h(
        "div",
        { class: "panel-body" },
        next !== null ? button("Load more", { onClick: () => run(false) }) : h("p", { class: "hint" }, `${plural(records.length, "record", "records")} shown. That is all that matches.`),
      ),
    );
  }

  const searchForm = h(
    "form",
    {
      class: "panel-body",
      onsubmit: (event) => {
        event.preventDefault();
        run(true);
      },
    },
    h("div", { class: "form-grid" }, field("Text", text), field("Event type", type, "Several allowed, separated by spaces. auth.* matches an area."), field("Severity", severity), field("Actor", actor), field("Device fingerprint", device), field("Order", orderSel), field("From", since), field("To", until)),
    h("div", { class: "row" }, button("Search", { tone: "primary", type: "submit" })),
  );

  // ---- verify ----
  const verifyHost = h("div", {});
  const startSeq = textInput({ inputmode: "numeric", placeholder: "1" });
  const headSeq = textInput({ inputmode: "numeric", placeholder: "Sequence number of a saved head" });
  const headHash = textInput({ placeholder: "64 hex characters" });

  const verify = button("Verify the chain", {
    tone: "primary",
    onClick: async () => {
      const body = {};
      try {
        if (startSeq.value.trim()) body.start_seq = Number.parseInt(startSeq.value, 10);
        if (headSeq.value.trim() || headHash.value.trim()) {
          body.expected_head = { seq: Number.parseInt(headSeq.value, 10), hash: headHash.value.trim() };
        }
        replace(verifyHost, loading("Verifying"));
        const result = await api.post("/audit/verify", body);
        replace(verifyHost, verdict(result));
      } catch (error) {
        replace(verifyHost, errorBox(error));
      }
    },
  });

  function verdict(result) {
    const notes = [];
    if (result.ok && result.macs_checked === 0) {
      notes.push("No MAC key was available. This shows that no record was edited, removed or reordered, but a chain rebuilt from scratch would not be noticed. Compare the head with a copy kept somewhere the administrator cannot rewrite.");
    }
    if (result.ok && !result.keyed) notes.push("This log carries no MACs.");
    notes.push(result.head_checked ? "The head matched the separate head file." : "The head was not compared with the separate head file.");
    return h(
      "div",
      { class: `verify-result${result.ok ? "" : " bad"}`, role: "status" },
      h("div", { class: "verdict" }, result.ok ? "Chain intact" : "Chain broken"),
      h("div", {}, `${plural(result.checked, "record", "records")} checked${result.macs_checked ? `, ${count(result.macs_checked)} MACs checked` : ""}.`),
      !result.ok ? h("div", {}, `First bad record: ${result.first_bad_seq === null ? "unknown" : `#${result.first_bad_seq}`}. ${result.reason || ""}`) : null,
      result.head ? h("div", { class: "muted mono" }, `Last good record ${result.head.seq}, hash ${result.head.hash}`) : null,
      notes.map((note) => h("p", { class: result.ok ? "hint" : "note bad" }, note)),
      !result.ok ? h("p", { class: "note bad" }, "The service now reports the audit chain as degraded until a later verification succeeds.") : null,
    );
  }

  function renderNew() {
    if (state.newAudit === 0) {
      replace(newNote);
      return;
    }
    replace(
      newNote,
      h("div", { class: "note panel-body" }, `${plural(state.newAudit, "new record has", "new records have")} been written since this list was loaded. `, button("Refresh the list", { small: true, onClick: () => run(true) })),
    );
  }

  replace(
    root,
    pageHead("Audit log", "Every decision and change, in a hash chain: editing, deleting or reordering a past record breaks it."),
    panel(
      "Verify the chain",
      h(
        "div",
        { class: "panel-body" },
        h("p", { class: "muted" }, "Walks every record and recomputes its hash. The result is itself recorded in the log."),
        h("details", {}, h("summary", {}, "Check against a head you saved earlier (detects truncation or replacement)"), h("div", { class: "form-grid" }, field("Start at record", startSeq), field("Saved head: sequence", headSeq), field("Saved head: hash", headHash))),
        h("div", { class: "row" }, verify),
        verifyHost,
      ),
    ),
    panel("Search", searchForm, headHost),
    h("section", { class: "panel" }, newNote, resultsHost),
  );
  run(true);
  s.on("audit", renderNew);
  s.on("reload", () => run(true));
  return () => s.dispose();
}
