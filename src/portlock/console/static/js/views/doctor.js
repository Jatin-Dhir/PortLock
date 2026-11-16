// Doctor: what this machine can really do right now, with the reason for every "no".

import { api } from "../api.js";
import { h, replace } from "../dom.js";
import { timeEl } from "../fmt.js";
import { scope } from "../store.js";
import { button, chip, empty, errorState, kv, loading, pageHead, panel, table } from "../ui.js";

const STATUS = {
  ok: ["OK", "c-allow"],
  warn: ["Warning", "c-pending"],
  fail: ["Failed", "c-deny"],
  info: ["Info", "c-watch"],
};

function capabilities(caps, title) {
  if (!caps) return h("p", { class: "muted" }, `${title}: not reported.`);
  const flags = Object.entries(caps).filter(([, value]) => typeof value === "boolean");
  return h(
    "div",
    { class: "stack" },
    kv([["Name", caps.name], ...flags.map(([key, value]) => [key.replace(/_/g, " "), value ? "yes" : "no"])]),
    caps.notes && caps.notes.length ? h("ul", {}, caps.notes.map((note) => h("li", { class: "muted" }, note))) : null,
  );
}

export function mount(root) {
  const s = scope();
  const host = h("div", { class: "view-body stack" }, loading("Running the checks"));

  async function load() {
    replace(host, loading("Running the checks"));
    try {
      const report = await api.get("/doctor");
      const [worstLabel, worstTone] = STATUS[report.worst] || [report.worst, "c-neutral"];
      replace(
        host,
        h("div", { class: "row" }, chip(worstLabel, worstTone, { hatch: report.worst === "fail" }), h("span", { class: "muted" }, `${report.platform}, PortLock ${report.version}, checked `), timeEl(report.generated_at)),
        panel(
          "Checks",
          report.checks.length === 0
            ? empty("The report has no checks.")
            : h(
                "ul",
                { class: "checks" },
                report.checks.map((check) => {
                  const [label, tone] = STATUS[check.status] || [check.status, "c-neutral"];
                  return h("li", {}, chip(label, tone), h("div", {}, h("div", {}, check.summary), check.detail ? h("div", { class: "cell-sub" }, check.detail) : null, h("div", { class: "cell-sub mono" }, check.id)));
                }),
              ),
        ),
        panel(
          "Enforcement mechanisms",
          report.mechanisms.length === 0
            ? empty("No mechanism was reported.")
            : h(
                "div",
                { class: "panel-flush" },
                table({
                  caption: "Enforcement mechanisms",
                  rows: report.mechanisms,
                  columns: [
                    { label: "For", cell: (m) => m.role.replace(/_/g, " ") },
                    { label: "Mechanism", cell: (m) => h("code", {}, m.mechanism) },
                    { label: "Usable now", cell: (m) => (m.available ? chip("Yes", "c-allow") : chip("No", "c-deny")) },
                    { label: "What it guarantees", cell: (m) => m.tier },
                    { label: "Why not", cell: (m) => m.reason || "" },
                  ],
                }),
              ),
        ),
        h("div", { class: "grid-2" }, panel("Detection backend", h("div", { class: "panel-body" }, capabilities(report.backend, "Backend"))), panel("Enforcer", h("div", { class: "panel-body" }, capabilities(report.enforcer, "Enforcer")))),
        h("p", { class: "hint" }, "This report holds device counts only: never a serial number, a product name or an instance id."),
      );
    } catch (error) {
      replace(host, errorState(error, load));
    }
  }

  replace(root, pageHead("Doctor", "A read-only check of what PortLock can and cannot do on this machine.", button("Run the checks again", { onClick: load })), host);
  load();
  return () => s.dispose();
}
