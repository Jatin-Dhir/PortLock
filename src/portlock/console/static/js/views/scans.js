// Scans: queue one, watch it run, read the report. PortLock only reads what the operating
// system has mounted and never changes anything on the volume.

import { api } from "../api.js";
import { h, replace } from "../dom.js";
import { bytes, count, liveAgo, plural, shortFp } from "../fmt.js";
import { can, scope, state } from "../store.js";
import { button, chip, empty, errorState, field, infoDialog, kv, loading, pageHead, panel, select, table, toast, verdictChip } from "../ui.js";

function deviceName(scan) {
  const conn = state.devices.get(scan.connection_id);
  return conn ? conn.display_name || "Unnamed device" : `connection ${scan.connection_id}`;
}

async function openReport(id) {
  const body = h("div", { class: "stack" }, loading("Loading report"));
  const shown = infoDialog(`Scan ${id}`, body);
  try {
    const { scan } = await api.get(`/scans/${id}`);
    const report = scan.report || {};
    const findings = report.findings || [];
    const errors = report.errors || [];
    const engines = report.engines || [];
    replace(
      body,
      h("div", { class: "row" }, scan.verdict ? verdictChip(scan.verdict) : chip(scan.state, "c-neutral")),
      kv([
        ["Fingerprint", h("code", {}, shortFp(scan.fingerprint))],
        ["Volume", scan.mount_point],
        ["Asked by", `${scan.requested_by} (${scan.trigger})`],
        ["Files seen", report.files_seen == null ? null : count(report.files_seen)],
        ["Stopped early", scan.summary && scan.summary.truncated_reason ? scan.summary.truncated_reason : null],
      ]),
      scan.verdict && scan.verdict !== "clean"
        ? h("p", { class: "note warn" }, scan.verdict === "incomplete" || scan.verdict === "error" ? "Not everything was examined, so this is not a clean result." : "Findings below need a person to look at them. Nothing was deleted or changed.")
        : null,
      h("h3", {}, "Findings"),
      findings.length === 0
        ? empty("No findings.")
        : table({
            caption: "Findings",
            rows: findings,
            columns: [
              { label: "Severity", cell: (f) => verdictChip(f.severity) },
              { label: "Path", cell: (f) => h("code", {}, f.path) },
              { label: "Engine", cell: (f) => `${f.engine}: ${f.rule}` },
              { label: "Detail", cell: (f) => f.detail || "" },
            ],
          }),
      errors.length ? h("div", { class: "stack" }, h("h3", {}, "Errors"), h("ul", {}, errors.map((e) => h("li", {}, typeof e === "string" ? e : JSON.stringify(e))))) : null,
      engines.length ? h("div", { class: "stack" }, h("h3", {}, "Engines"), h("ul", {}, engines.map((e) => h("li", {}, `${e.name}: ${e.available ? "available" : "not available"}${e.version ? `, version ${e.version}` : ""}`)))) : null,
    );
  } catch (error) {
    replace(body, errorState(error));
  }
  return shown;
}

export function mount(root) {
  const s = scope();
  const scans = new Map();
  const listHost = h("div", { class: "panel-flush" }, loading());
  const formHost = h("div", { class: "panel-body" });
  const progressEls = new Map();

  function progressText(scan) {
    const p = state.scanProgress.get(scan.id);
    if (p) return `${plural(p.files_seen, "file", "files")}, ${bytes(p.bytes_hashed)} read so far`;
    return scan.state === "queued" ? "waiting for its turn" : "starting";
  }

  function draw() {
    progressEls.clear();
    const rows = [...scans.values()].sort((a, b) => b.id - a.id);
    replace(
      listHost,
      rows.length === 0
        ? empty("No scan has been run.", "Policy can ask for a scan when a device is mounted, and you can start one yourself below.")
        : table({
            caption: "Scans",
            rows,
            columns: [
              { label: "#", num: true, cell: (r) => String(r.id) },
              { label: "Device", cell: (r) => [h("div", { class: "cell-main" }, deviceName(r)), h("div", { class: "cell-sub mono" }, r.mount_point)] },
              { label: "Asked by", cell: (r) => `${r.requested_by} (${r.trigger})` },
              {
                label: "State",
                cell: (r) => {
                  if (r.state === "running" || r.state === "queued") {
                    const el = h("div", { class: "cell-sub" }, progressText(r));
                    progressEls.set(r.id, { el, scan: r });
                    return [chip(r.state, "c-watch"), el];
                  }
                  return chip(r.state, "c-neutral");
                },
              },
              { label: "Verdict", cell: (r) => (r.verdict ? verdictChip(r.verdict) : h("span", { class: "faint" }, "pending")) },
              {
                label: "Result",
                cell: (r) =>
                  r.summary
                    ? `${plural(r.summary.files_seen, "file", "files")}, ${r.summary.findings.malicious} malicious, ${r.summary.findings.suspicious} suspicious${r.summary.errors ? `, ${plural(r.summary.errors, "error", "errors")}` : ""}`
                    : "",
              },
              { label: "Queued", cell: (r) => liveAgo(r.queued_at) },
              { label: "", cell: (r) => (r.state === "done" ? button("Report", { small: true, tone: "quiet", onClick: () => openReport(r.id) }) : null) },
            ],
          }),
    );
  }

  async function load() {
    try {
      const reply = await api.get("/scans", { limit: 100 });
      scans.clear();
      for (const scan of reply.scans) scans.set(scan.id, scan);
      draw();
    } catch (error) {
      replace(listHost, errorState(error, load));
    }
  }

  let picked = "";
  function renderForm() {
    const withVolumes = [...state.devices.values()].filter((conn) => conn.device.volumes.length > 0);
    if (withVolumes.length === 0) {
      replace(formHost, empty("No connected device has a mounted volume.", "A scan reads what the operating system has mounted, so there is nothing to scan yet."));
      return;
    }
    if (!withVolumes.some((conn) => String(conn.connection_id) === picked)) picked = String(withVolumes[0].connection_id);
    const device = select(withVolumes.map((conn) => [String(conn.connection_id), conn.display_name || "Unnamed device"]), picked);
    const volume = select([], "");
    function syncVolumes() {
      picked = device.value;
      const conn = state.devices.get(Number.parseInt(device.value, 10));
      const vols = conn ? conn.device.volumes.filter((v) => v.mount_point) : [];
      replace(volume, [h("option", { value: "" }, `All mounted volumes (${vols.length})`), vols.map((v) => h("option", { value: v.mount_point }, v.mount_point))]);
    }
    device.addEventListener("change", syncVolumes);
    replace(
      formHost,
      h("div", { class: "form-grid" }, field("Device", device), field("Volume", volume)),
      h(
        "div",
        { class: "row" },
        button("Start a scan", {
          tone: "primary",
          disabled: !can("run_scan"),
          title: can("run_scan") ? null : "Your role cannot start scans",
          onClick: async () => {
            const body = { connection_id: Number.parseInt(device.value, 10) };
            if (volume.value) body.mount_point = volume.value;
            const reply = await api.post("/scans", body);
            for (const scan of reply.scans) scans.set(scan.id, scan);
            draw();
            toast(`${plural(reply.scans.length, "scan", "scans")} queued.`, "good");
          },
        }),
      ),
    );
    syncVolumes();
  }

  replace(
    root,
    pageHead("Scans", "A scan reports; it never deletes or changes a file. A clean result means everything was examined. Incomplete and error results are not clean."),
    panel("Start a scan", formHost),
    panel("Scans", listHost),
  );
  renderForm();
  load();
  s.on("scans", (payload) => {
    if (payload && payload.scan) {
      scans.set(payload.scan.id, payload.scan);
      draw();
    } else if (payload && payload.progress) {
      const entry = progressEls.get(payload.progress.scan_id);
      if (entry) entry.el.textContent = progressText(entry.scan);
    }
  });
  s.on("devices", () => {
    renderForm();
    draw();
  });
  s.on("reload", load);
  return () => s.dispose();
}
