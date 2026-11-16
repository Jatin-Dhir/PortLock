// The bar that appears on EVERY page while a change is waiting for confirmation.
//
// Enforce mode, a wider scope, default-deny and a lockdown are applied at once and rolled
// back unless confirmed in time (DESIGN 14.15). That is a safety net for an operator who
// might have locked themselves out, so the prompt must be impossible to miss and must show
// the time left, whatever page is open.

import { api } from "./api.js";
import { h, replace } from "./dom.js";
import { countdown } from "./fmt.js";
import { can, refreshChanges, scope, state } from "./store.js";
import { KIND_TEXT } from "./truth.js";
import { button, chip, toast } from "./ui.js";

const EXPLAIN = {
  lockdown: "Removable storage is blocked and new devices are denied now.",
  enforce_mode: "PortLock is now blocking, not just watching.",
  widen_scope: "More kinds of device are now enforced against.",
  default_deny: "The operating system now refuses unknown new devices by default.",
};

function needed(change) {
  return change.kind === "lockdown" ? "engage_lockdown" : "change_mode";
}

function previewList(change) {
  const items = change.preview || [];
  if (items.length === 0) return h("p", { class: "hint" }, "No connected device is affected.");
  const blocked = items.filter((item) => item.outcome === "block").length;
  return h(
    "details",
    {},
    h("summary", {}, `${blocked} of ${items.length} connected device${items.length === 1 ? "" : "s"} blocked by this change`),
    h(
      "ul",
      { class: "preview" },
      items.map((item) =>
        h(
          "li",
          {},
          chip(item.outcome === "block" ? "Blocked" : item.outcome === "protected" ? "Protected" : item.outcome === "exempt" ? "Exempt" : "Not enforced",
            item.outcome === "block" ? "c-deny" : item.outcome === "not_enforced" ? "c-pending" : "c-watch"),
          h("span", {}, `${item.name} (${item.vid_pid})`),
          h("span", { class: "muted" }, item.reason),
        ),
      ),
    ),
  );
}

export function mountChangeBar(container) {
  const s = scope();

  function render() {
    if (state.changes.length === 0) {
      replace(container);
      container.className = "";
      return;
    }
    container.className = "changebar";
    replace(
      container,
      state.changes.map((change) =>
        h(
          "section",
          { "aria-label": `${KIND_TEXT[change.kind] || change.kind} waiting for confirmation`, role: "alert" },
          h(
            "div",
            { class: "changebar-main" },
            h("strong", {}, `${KIND_TEXT[change.kind] || change.kind} is on, and will be undone unless you confirm.`),
            h("span", {}, "Rolls back in ", countdown(change._deadlineMs, "count")),
            button("Confirm and keep it", {
              tone: "primary",
              disabled: !can(needed(change)),
              title: can(needed(change)) ? null : "Your role cannot confirm this change",
              onClick: async () => {
                await api.post(`/changes/${change.id}/confirm`);
                toast(`${KIND_TEXT[change.kind] || "The change"} confirmed.`, "good");
                refreshChanges();
              },
            }),
            button("Roll back now", {
              tone: "quiet",
              disabled: !can(needed(change)),
              onClick: async () => {
                await api.post(`/changes/${change.id}/cancel`);
                toast("Rolled back.", "good");
                refreshChanges();
              },
            }),
          ),
          h("p", { class: "hint" }, `${EXPLAIN[change.kind] || ""} Made by ${change.actor}. If you cannot reach this page any more, it undoes itself.`),
          previewList(change),
        ),
      ),
    );
  }

  s.on("changes", render);
  render();
  return () => s.dispose();
}
