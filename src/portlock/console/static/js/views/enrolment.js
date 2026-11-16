// Enrolment of the operator's own input devices (DESIGN 14.1): an enrolled keyboard stays
// protected on the port it was enrolled on, and only there. Being plugged in at start-up
// confers nothing.

import { api, seg } from "../api.js";
import { h, replace } from "../dom.js";
import { shortFp, timeEl, vidPid } from "../fmt.js";
import { can, scope, state } from "../store.js";
import { isWatchOnly, portHoldText } from "../truth.js";
import { button, confirmDialog, empty, errorState, field, loading, pageHead, panel, select, table, textInput, toast } from "../ui.js";

const INPUT = new Set(["keyboard", "mouse", "hid"]);

// Only a device whose every function is input (a hub may sit beside it) is offered. One that
// puts storage or anything else beside a keyboard is the shape of a BadUSB stick: it is
// never offered for protection (DESIGN 14.2).
function inputDevices() {
  return [...state.devices.values()].filter((conn) => {
    const categories = (conn.device.categories || []).filter((category) => category !== "hub");
    return !conn.removed_at && categories.length > 0 && categories.every((category) => INPUT.has(category));
  });
}

export function mount(root) {
  const s = scope();
  const listHost = h("div", { class: "panel-flush" }, loading());
  const enrolHost = h("div", { class: "panel-body" });
  const writer = can("manage_trust");

  async function loadList() {
    try {
      const reply = await api.get("/enrolments");
      replace(
        listHost,
        reply.enrolments.length === 0
          ? empty("No input device is enrolled.", "Until you enrol one, no keyboard is protected on the strength of being enrolled.")
          : table({
              caption: "Enrolled input devices",
              rows: reply.enrolments,
              columns: [
                { label: "Label", cell: (e) => e.label || h("span", { class: "faint" }, "no label") },
                { label: "Fingerprint", cell: (e) => h("code", { title: e.fingerprint }, shortFp(e.fingerprint)) },
                { label: "Port", cell: (e) => h("code", {}, e.bus_path) },
                { label: "Enrolled", cell: (e) => [timeEl(e.enrolled_at), h("div", { class: "cell-sub" }, `by ${e.enrolled_by}`)] },
                {
                  label: "",
                  cell: (e) =>
                    writer
                      ? button("Remove", {
                          small: true,
                          tone: "quiet",
                          onClick: async () => {
                            const ok = await confirmDialog({
                              title: "Remove this enrolment?",
                              message: isWatchOnly(state.status)
                                ? `${e.label || "This device"} will no longer be protected on port ${e.bus_path}. Policy will treat it like any other device. PortLock is watch-only on this computer, so nothing is blocked.`
                                : `${e.label || "This device"} will no longer be protected on port ${e.bus_path}. Policy will treat it like any other device, so it can be blocked.`,
                              confirmLabel: "Remove enrolment",
                              tone: "danger",
                            });
                            if (!ok) return;
                            await api.del(`/enrolments/${seg(e.fingerprint)}`, { bus_path: e.bus_path });
                            toast("Enrolment removed.", "good");
                            await loadList();
                          },
                        })
                      : null,
                },
              ],
            }),
      );
    } catch (error) {
      replace(listHost, errorState(error, loadList));
    }
  }

  let picked = "";
  const label = textInput({ maxlength: "128", placeholder: "Optional, for example: desk keyboard" });

  function renderEnrol() {
    const devices = inputDevices();
    if (devices.length === 0) {
      replace(enrolHost, empty("No input device is connected.", "Plug in the keyboard or mouse you rely on, then enrol it here."));
      return;
    }
    const options = devices.map((conn) => [String(conn.connection_id), `${conn.display_name || "Unnamed device"} (${vidPid(conn.device)}, port ${conn.device.bus_path || "unknown"})`]);
    if (!devices.some((conn) => String(conn.connection_id) === picked)) picked = options[0][0];
    const choose = select(options, picked);
    choose.addEventListener("change", () => {
      picked = choose.value;
    });
    replace(
      enrolHost,
      h("div", { class: "form-grid" }, field("Connected input device", choose), field("Label", label)),
      h(
        "div",
        { class: "row" },
        button("Enrol this device on its port", {
          tone: "primary",
          disabled: !writer,
          title: writer ? null : "Your role cannot manage enrolments",
          onClick: async () => {
            const body = { connection_id: Number.parseInt(choose.value, 10) };
            if (label.value.trim()) body.label = label.value.trim();
            await api.post("/enrolments", body);
            label.value = "";
            toast("Enrolled. It stays protected on this port, and only on this port.", "good");
            await loadList();
          },
        }),
      ),
    );
  }

  const port = textInput({ placeholder: "For example 1-4" });
  const release = h(
    "div",
    { class: "panel-body" },
    // "held blocked" only while PortLock really blocks (truth.portHoldText).
    h("p", { class: "muted" }, portHoldText(state.status)),
    h("div", { class: "row" }, field("Port", port), button("Release port", {
      disabled: !writer,
      onClick: async () => {
        if (!port.value.trim()) throw new Error("Enter the port to release.");
        await api.post("/ports/release", { port: port.value.trim() });
        port.value = "";
        toast("Port released.", "good");
      },
    })),
  );

  replace(
    root,
    pageHead("Input devices", "Enrol the keyboards and mice you depend on, so PortLock can never lock you out of them. Enrolment is bound to the port: the same device on another port is not protected."),
    panel("Enrolled", listHost),
    panel("Enrol a connected input device", enrolHost),
    panel("Held ports", release),
  );
  renderEnrol();
  loadList();
  s.on("devices", renderEnrol);
  return () => s.dispose();
}
