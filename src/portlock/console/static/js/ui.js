// Shared interface parts: chips, buttons, fields, dialogs, tables, and the honest
// empty / loading / error states.

import { ApiError } from "./api.js";
import { frag, h, replace, uid } from "./dom.js";
import { count } from "./fmt.js";
import { state } from "./store.js";
import {
  ACCESS_TEXT,
  SCAN_TEXT,
  STATE_TEXT,
  TIER_TEXT,
  enforcementTruth,
  isWatchOnly,
} from "./truth.js";

// ---- chips ------------------------------------------------------------------------------

/** `dashed` means intended only; `hatch` means a warning that something is NOT in force. */
export function chip(label, tone = "c-neutral", { dashed = false, hatch = false, title = null } = {}) {
  return h("span", { class: `chip ${tone}${dashed ? " dashed" : ""}${hatch ? " hatch" : ""}`, title }, label);
}

export function accessChip(access) {
  const [label, tone] = ACCESS_TEXT[access] || [access, "c-neutral"];
  return chip(label, tone);
}

export function stateChip(stateName) {
  const [label, tone] = STATE_TEXT[stateName] || [stateName, "c-neutral"];
  return chip(label, tone);
}

export function scanChip(scan) {
  if (!scan) return null;
  const [label, tone] = SCAN_TEXT[scan.state] || [scan.state, "c-neutral"];
  return chip(label, tone);
}

const SEVERITY_TONE = {
  debug: "c-neutral",
  info: "c-neutral",
  notice: "c-watch",
  warning: "c-pending",
  error: "c-deny",
  critical: "c-deny",
};

export function severityChip(severity) {
  return chip(severity, SEVERITY_TONE[severity] || "c-neutral", { hatch: severity === "critical" });
}

const VERDICT_TONE = {
  clean: "c-allow",
  suspicious: "c-pending",
  malicious: "c-deny",
  incomplete: "c-pending",
  error: "c-deny",
};

/** A scan verdict. Only "clean" is reassuring: incomplete and error mean not everything was examined. */
export function verdictChip(verdict) {
  return chip(verdict, VERDICT_TONE[verdict] || "c-neutral", { hatch: verdict === "incomplete" || verdict === "error" });
}

/** The enforcement column: what the operating system was really made to do. */
export function enforcementCell(conn) {
  const truth = enforcementTruth(conn, { watchOnly: isWatchOnly(state.status) });
  let badge;
  if (truth.kind === "real") {
    const tone = truth.headline === "Blocked" ? "c-deny" : truth.headline === "Read-only" ? "c-readonly" : "c-allow";
    badge = chip(truth.headline, tone);
  } else if (truth.kind === "intended") {
    badge = chip(truth.headline, "c-watch", { dashed: true, title: truth.title });
  } else if (truth.kind === "protected") {
    badge = chip(truth.headline, "c-watch");
  } else {
    badge = chip(truth.headline, "c-pending", { hatch: truth.headline === "Not enforced" });
  }
  const tier = truth.tier ? TIER_TEXT[truth.tier] : null;
  return h(
    "div",
    {},
    badge,
    truth.detail ? h("div", { class: "cell-sub" }, truth.detail) : null,
    tier ? h("div", { class: "cell-sub", title: tier[1] }, `${tier[0]} tier`) : null,
  );
}

// ---- buttons and fields -----------------------------------------------------------------

/**
 * A button whose handler may be async. While it runs the button is disabled and marked
 * busy; a thrown error is shown as a toast unless the handler handled it itself.
 */
export function button(label, { tone = "", small = false, onClick, disabled = false, title = null, type = "button" } = {}) {
  const classes = ["btn"];
  if (tone) classes.push(`btn-${tone}`);
  if (small) classes.push("btn-small");
  const el = h("button", { class: classes.join(" "), type, disabled, title }, label);
  if (onClick) {
    el.addEventListener("click", async (event) => {
      if (el.getAttribute("aria-busy") === "true") return;
      el.setAttribute("aria-busy", "true");
      el.disabled = true;
      try {
        await onClick(event);
      } catch (error) {
        toastError(error);
      } finally {
        el.removeAttribute("aria-busy");
        if (el.isConnected) el.disabled = disabled;
      }
    });
  }
  return el;
}

/**
 * The plain reason a control cannot be used, shown beside it and tied to it with
 * `aria-describedby`, so nobody has to hover over a disabled button to learn why.
 * Returns null when there is no reason, so it can sit in a children list.
 */
export function reasonFor(control, text) {
  if (!text) return null;
  const id = uid("why");
  const described = control.getAttribute("aria-describedby");
  control.setAttribute("aria-describedby", described ? `${described} ${id}` : id);
  return h("p", { class: "hint why-not", id }, text);
}

/** A labelled control. `control` must be one element; it gets the label's `for`. */
export function field(labelText, control, hint = null) {
  const id = control.id || uid("in");
  control.id = id;
  const hintId = hint ? `${id}-hint` : null;
  if (hintId) control.setAttribute("aria-describedby", hintId);
  return h(
    "div",
    { class: "field" },
    h("label", { for: id }, labelText),
    control,
    hint ? h("div", { class: "hint", id: hintId }, hint) : null,
  );
}

export function textInput(props = {}) {
  return h("input", { type: "text", autocomplete: "off", spellcheck: "false", ...props });
}

export function select(options, value) {
  return h(
    "select",
    { value },
    options.map(([val, label, disabled]) => h("option", { value: val, disabled: disabled === true }, label)),
  );
}

export function checkbox(labelText, { checked = false, hint = null, name = null } = {}) {
  const input = h("input", { type: "checkbox", checked, name });
  const wrap = h("label", { class: "check" }, input, h("span", {}, labelText, hint ? h("span", { class: "hint" }, hint) : null));
  return { input, el: wrap };
}

// ---- states -----------------------------------------------------------------------------

export function empty(title, text) {
  return h("div", { class: "state" }, h("strong", {}, title), text ? h("p", {}, text) : null);
}

export function loading(text = "Loading") {
  return h(
    "div",
    { class: "state", role: "status" },
    h("span", { class: "skeleton" }),
    h("span", { class: "sr-only" }, text),
  );
}

export function errorState(error, retry) {
  const unreachable = error instanceof ApiError && error.code === "unreachable";
  return h(
    "div",
    { class: "state is-error", role: "alert" },
    h("strong", {}, unreachable ? "The service did not answer" : "This could not be loaded"),
    h("p", {}, describeError(error)),
    retry ? button("Try again", { small: true, onClick: retry }) : null,
  );
}

/** Words for an error, including every problem the service listed. */
export function describeError(error) {
  if (error instanceof ApiError) {
    return error.code === "locked_out" || error.code === "rate_limited" || error.code === "busy"
      ? `${error.message}${retryHint(error)}`
      : error.message;
  }
  return error && error.message ? error.message : "Something went wrong.";
}

function retryHint(error) {
  const seconds = error.details && error.details.retry_after_seconds;
  return Number.isInteger(seconds) ? ` Try again in ${seconds} s.` : "";
}

/** An inline error block for forms and dialogs; lists every problem the service reported. */
export function errorBox(error) {
  const problems = error instanceof ApiError && error.details && Array.isArray(error.details.problems) ? error.details.problems : [];
  return h(
    "div",
    { class: "form-error", role: "alert" },
    describeError(error),
    problems.length
      ? h(
          "ul",
          {},
          problems.map((problem) =>
            h("li", {}, typeof problem === "string" ? problem : `${problem.path}: ${problem.message}`),
          ),
        )
      : null,
  );
}

// ---- toasts -----------------------------------------------------------------------------

export function toast(message, kind = "info", { seconds = 6 } = {}) {
  const host = document.getElementById("toasts");
  if (!host) return;
  const el = h(
    "div",
    { class: `toast ${kind}` },
    h("p", {}, message),
    h("button", { class: "btn btn-quiet btn-small", type: "button", "aria-label": "Dismiss", onclick: () => el.remove() }, "Dismiss"),
  );
  host.appendChild(el);
  if (kind !== "bad") setTimeout(() => el.remove(), seconds * 1000);
}

export function toastError(error) {
  toast(describeError(error), "bad");
}

// ---- dialogs ----------------------------------------------------------------------------

function openDialog({ title, content, footer }) {
  const dialog = h("dialog", { class: "dlg", "aria-labelledby": uid("dlg-title") });
  const heading = h("h2", { id: dialog.getAttribute("aria-labelledby") }, title);
  const closeButton = h("button", { class: "btn btn-quiet btn-small", type: "button", onclick: () => dialog.close("dismiss") }, "Close");
  replace(dialog, h("header", {}, heading, closeButton), h("div", { class: "dlg-body" }, content), footer ? footer : null);
  document.body.appendChild(dialog);
  const done = new Promise((resolve) => {
    dialog.addEventListener("close", () => {
      dialog.remove();
      resolve(dialog.returnValue);
    });
  });
  dialog.showModal();
  return { dialog, done };
}

/** A read-only dialog. */
export function infoDialog(title, content) {
  const { dialog, done } = openDialog({ title, content, footer: null });
  void dialog;
  return done;
}

/** Ask before doing something that matters. Resolves true only on the confirm button. */
export function confirmDialog({ title, message, confirmLabel = "Confirm", tone = "primary" }) {
  const cancel = h("button", { class: "btn btn-quiet", type: "button", onclick: () => dialog.close("cancel"), autofocus: true }, "Cancel");
  const ok = h("button", { class: `btn btn-${tone}`, type: "button", onclick: () => dialog.close("ok") }, confirmLabel);
  const { dialog, done } = openDialog({
    title,
    content: typeof message === "string" ? h("p", {}, message) : message,
    footer: h("footer", {}, cancel, ok),
  });
  return done.then((value) => value === "ok");
}

/**
 * A dialog with a form. `onSubmit` runs on submit; if it throws, the error is shown inside
 * the dialog and the dialog stays open. Resolves with what `onSubmit` returned, or
 * undefined if the dialog was dismissed.
 */
export function formDialog({ title, content, submitLabel = "Save", tone = "primary", onSubmit }) {
  let result;
  const errorSlot = h("div", {});
  const submit = h("button", { class: `btn btn-${tone}`, type: "submit" }, submitLabel);
  const cancel = h("button", { class: "btn btn-quiet", type: "button", onclick: () => dialog.close("cancel") }, "Cancel");
  const form = h(
    "form",
    {
      class: "dlg-body",
      novalidate: true,
      onsubmit: async (event) => {
        event.preventDefault();
        submit.disabled = true;
        submit.setAttribute("aria-busy", "true");
        replace(errorSlot);
        try {
          result = await onSubmit();
          dialog.close("ok");
        } catch (error) {
          replace(errorSlot, errorBox(error));
          errorSlot.scrollIntoView({ block: "nearest" });
        } finally {
          submit.disabled = false;
          submit.removeAttribute("aria-busy");
        }
      },
    },
    content,
    errorSlot,
    h("footer", { class: "row" }, cancel, submit),
  );
  const { dialog, done } = openDialog({ title, content: form, footer: null });
  return done.then((value) => (value === "ok" ? result : undefined));
}

// ---- tables and lists -------------------------------------------------------------------

/**
 * A table. `columns`: `{label, cell(row), num}`. `cell` returns text or nodes, never HTML.
 * `rowProps(row)` may add a class or dataset to a row.
 */
export function table({ columns, rows, caption, rowProps }) {
  return h(
    "table",
    { class: "tbl" },
    caption ? h("caption", { class: "sr-only" }, caption) : null,
    h("thead", {}, h("tr", {}, columns.map((col) => h("th", { scope: "col", class: col.num ? "num" : null }, col.label)))),
    h(
      "tbody",
      {},
      rows.map((row) =>
        h(
          "tr",
          rowProps ? rowProps(row) : {},
          columns.map((col) => h("td", { class: col.num ? "num" : null }, col.cell(row))),
        ),
      ),
    ),
  );
}

export function kv(pairs) {
  return h(
    "dl",
    { class: "kv" },
    pairs
      .filter(([, value]) => value !== null && value !== undefined && value !== "")
      .map(([key, value]) => frag(h("dt", {}, key), h("dd", {}, value))),
  );
}

export function tags(items) {
  return h("span", { class: "tags" }, items.map((item) => h("span", { class: "tag" }, item)));
}

export function jsonBlock(value) {
  return h("pre", { class: "json" }, JSON.stringify(value, null, 2));
}

export function copyButton(text, label = "Copy") {
  return button(label, {
    small: true,
    tone: "quiet",
    onClick: async () => {
      try {
        await navigator.clipboard.writeText(text);
        toast("Copied.", "good", { seconds: 2 });
      } catch {
        toast("The browser would not copy. Select the text and copy it by hand.", "bad");
      }
    },
  });
}

export function pageHead(title, intro, ...actions) {
  return h("div", { class: "page-head" }, h("h1", {}, title), actions, intro ? h("p", {}, intro) : null);
}

export function panel(title, body, ...headerExtras) {
  return h("section", { class: "panel" }, h("header", {}, h("h2", {}, title), headerExtras), body);
}

export { count };
