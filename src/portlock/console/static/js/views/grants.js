// Grants and trust. A grant only ever acts on a device policy left pending: it never
// widens what a rule decided (DESIGN 5). Trust is a grant with no expiry.

import { api } from "../api.js";
import { h, replace } from "../dom.js";
import { shortFp, timeEl, vidPid } from "../fmt.js";
import { can, scope } from "../store.js";
import {
  button,
  checkbox,
  chip,
  confirmDialog,
  empty,
  errorState,
  field,
  loading,
  pageHead,
  panel,
  select,
  table,
  textInput,
  toast,
} from "../ui.js";

const DURATIONS = [
  ["30m", "30 minutes"],
  ["2h", "2 hours"],
  ["8h", "8 hours"],
  ["24h", "24 hours"],
  ["7d", "7 days"],
  ["30d", "30 days"],
];

export function mount(root) {
  const s = scope();
  const names = new Map(); // fingerprint -> device, for readable rows
  const trustHost = h("div", { class: "panel-flush" }, loading());
  const grantsHost = h("div", { class: "panel-flush" }, loading());
  const formHost = h("div", { class: "panel-body" });
  let includeEnded = false;
  let known = [];
  let formKey = null;

  const nameOf = (fp) => {
    const d = names.get(fp);
    return d ? [h("div", { class: "cell-main" }, d.display_name || "Unnamed device"), h("div", { class: "cell-sub mono" }, shortFp(fp))] : h("code", {}, shortFp(fp));
  };

  const access = (g) => (g.read_only ? chip("Read-only", "c-readonly") : chip("Full access", "c-allow"));

  async function revoke(grant) {
    const ok = await confirmDialog({
      title: "Revoke this grant?",
      message: "A connected device that depended on it is re-evaluated at once, and blocked if nothing else allows it.",
      confirmLabel: "Revoke",
      tone: "danger",
    });
    if (!ok) return;
    const reply = grant.kind === "trust" ? await api.del(`/trust/${grant.id}`) : await api.del(`/grants/${grant.id}`);
    toast(`Revoked. ${reply.reevaluated.length ? `${reply.reevaluated.length} connected device(s) re-evaluated.` : ""}`.trim(), "good");
    await load();
  }

  const canRevoke = (g) => (g.kind === "trust" ? can("manage_trust") : can("issue_temporary_grant"));

  async function load() {
    try {
      const [trust, grants, devices] = await Promise.all([
        api.get("/trust"),
        api.get("/grants", { include_inactive: includeEnded ? "true" : null }),
        api.get("/devices/known", { limit: 500 }),
      ]);
      known = devices.devices;
      names.clear();
      for (const d of known) names.set(d.fingerprint, d);
      replace(
        trustHost,
        trust.trust.length === 0
          ? empty("No device is trusted.", "Trusting a device lets it in without asking, every time, until you remove the trust.")
          : table({
              caption: "Trusted devices",
              rows: trust.trust,
              columns: [
                { label: "Device", cell: (g) => nameOf(g.fingerprint) },
                { label: "Access", cell: access },
                { label: "Granted", cell: (g) => [timeEl(g.created_at), h("div", { class: "cell-sub" }, `by ${g.granted_by}`)] },
                { label: "Note", cell: (g) => g.note || "" },
                { label: "", cell: (g) => (canRevoke(g) ? button("Revoke", { small: true, tone: "quiet", onClick: () => revoke(g) }) : null) },
              ],
            }),
      );
      replace(
        grantsHost,
        grants.grants.length === 0
          ? empty(includeEnded ? "No grant has ever been issued." : "No active grant.", "Approving a pending device creates one.")
          : table({
              caption: "Grants",
              rows: grants.grants,
              columns: [
                { label: "Device", cell: (g) => nameOf(g.fingerprint) },
                { label: "Kind", cell: (g) => g.kind },
                { label: "Access", cell: access },
                {
                  label: "Until",
                  cell: (g) => [
                    g.expires_at ? timeEl(g.expires_at) : g.kind === "once" ? "this plug-in only" : "no expiry",
                    g.bound_port ? h("div", { class: "cell-sub" }, `bound to port ${g.bound_port}`) : null,
                  ],
                },
                { label: "By", cell: (g) => g.granted_by },
                { label: "Status", cell: (g) => (g.ended_at ? chip(`Ended: ${g.end_reason}`, "c-neutral") : chip("Active", "c-allow")) },
                { label: "", cell: (g) => (!g.ended_at && canRevoke(g) ? button("Revoke", { small: true, tone: "quiet", onClick: () => revoke(g) }) : null) },
              ],
            }),
      );
      // The form keeps what was typed unless the list of devices it offers has changed.
      const key = known.map((d) => d.fingerprint).join(",");
      if (key !== formKey) {
        formKey = key;
        renderForm();
      }
    } catch (error) {
      replace(trustHost, errorState(error, load));
      replace(grantsHost);
    }
  }

  let formState = { fingerprint: "", kind: "once" };
  function renderForm() {
    if (known.length === 0) {
      replace(formHost, empty("No device has been seen yet.", "A grant needs a device PortLock has seen at least once."));
      return;
    }
    if (!known.some((d) => d.fingerprint === formState.fingerprint)) formState.fingerprint = known[0].fingerprint;
    const device = select(known.map((d) => [d.fingerprint, `${d.display_name || "Unnamed device"} (${vidPid(d.device)}, ${shortFp(d.fingerprint)})`]), formState.fingerprint);
    const kind = select(
      [
        ["once", "Once: this plug-in only"],
        ["temporary", "For a while", !can("issue_temporary_grant")],
        ["trust", "Trust: no expiry", !can("manage_trust")],
      ],
      formState.kind,
    );
    const duration = select(DURATIONS, "2h");
    const durationField = field("For how long", duration);
    const readOnly = checkbox("Read-only");
    const low = checkbox("This device has no unique serial number", {
      hint: "Every unit of its model looks the same. The grant is bound to its port, and a temporary one lasts at most 24 hours.",
    });
    const lowField = low.el;
    const note = textInput({ maxlength: "512", placeholder: "Optional: why" });
    const hint = h("p", { class: "hint" });

    function sync() {
      formState = { fingerprint: device.value, kind: kind.value };
      const d = known.find((item) => item.fingerprint === device.value);
      const isLow = d && d.confidence === "low";
      durationField.hidden = kind.value !== "temporary";
      lowField.hidden = !(isLow && kind.value !== "trust");
      hint.textContent =
        isLow && kind.value === "trust"
          ? "A device without a unique serial number can never be trusted. Use a one-time or temporary grant."
          : kind.value === "trust"
            ? "Trust lasts until you remove it. Only trust a device you can identify as yours."
            : "";
    }
    device.addEventListener("change", sync);
    kind.addEventListener("change", sync);

    replace(
      formHost,
      h("div", { class: "form-grid" }, field("Device", device), field("Kind", kind), durationField),
      readOnly.el,
      lowField,
      field("Note", note),
      hint,
      h(
        "div",
        { class: "row" },
        button("Grant", {
          tone: "primary",
          disabled: !(can("issue_temporary_grant") || can("manage_trust")),
          onClick: async () => {
            const base = { fingerprint: device.value, read_only: readOnly.input.checked };
            if (note.value.trim()) base.note = note.value.trim();
            if (kind.value === "trust") {
              await api.post("/trust", base);
            } else {
              const body = { ...base, kind: kind.value };
              if (kind.value === "temporary") body.expires_in = duration.value;
              if (low.input.checked) body.allow_low_confidence = true;
              await api.post("/grants", body);
            }
            note.value = "";
            toast("Grant created.", "good");
            await load();
          },
        }),
      ),
    );
    sync();
  }

  const showEnded = checkbox("Show ended grants");
  showEnded.input.addEventListener("change", () => {
    includeEnded = showEnded.input.checked;
    load();
  });

  replace(
    root,
    pageHead("Grants and trust", "What lets a pending device in. A grant never overrides a policy rule that denies the device: to allow that, change the policy."),
    panel("Trusted devices", trustHost),
    panel("Grants", grantsHost, showEnded.el),
    panel("Grant access to a device that has been seen", formHost),
  );
  load();
  s.on(["grants", "reload"], load);
  return () => s.dispose();
}
