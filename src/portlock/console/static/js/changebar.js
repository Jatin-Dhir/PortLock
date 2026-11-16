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
import { KIND_TEXT, changeCopy } from "./truth.js";
import { button, chip, toast } from "./ui.js";

function needed(change) {
  return change.kind === "lockdown" ? "engage_lockdown" : "change_mode";
}

// The words, "Blocked" or "Would be blocked", come from truth.js: only a change that really
// blocks may say a device is blocked.
function previewList(change, copy) {
  const items = change.preview || [];
  if (items.length === 0) return h("p", { class: "hint" }, "No connected device is affected.");
  return h(
    "details",
    {},
    h("summary", {}, copy.summary),
    h(
      "ul",
      { class: "preview" },
      items.map((item, index) =>
        h(
          "li",
          {},
          chip(copy.items[index].label, copy.items[index].tone, { dashed: copy.items[index].dashed }),
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
      state.changes.map((change) => {
        const copy = changeCopy(change, state.status);
        return h(
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
          h("p", { class: "hint" }, `${copy.explain} Made by ${change.actor}. If you cannot reach this page any more, it undoes itself.`.trim()),
          previewList(change, copy),
        );
      }),
    );
  }

  // Not on "status": re-drawing would take focus off the Confirm button. A mode or lockdown
  // change is followed by a fresh list of changes (store.refreshChanges), which re-draws this.
  s.on("changes", render);
  render();
  return () => s.dispose();
}
