// Policy: read it, check a draft, save it, and ask "what would this do to that device?".

import { api } from "../api.js";
import { h, replace } from "../dom.js";
import { plural, shortFp, timeEl, vidPid } from "../fmt.js";
import { can, scope, state } from "../store.js";
import { SOURCE_TEXT, blocksForReal, isWatchOnly } from "../truth.js";
import {
  accessChip,
  button,
  checkbox,
  chip,
  confirmDialog,
  empty,
  errorBox,
  errorState,
  field,
  kv,
  loading,
  pageHead,
  panel,
  select,
  tags,
} from "../ui.js";

const OUTCOME = {
  matched: ["Matched", "c-allow"],
  shadowed: ["Shadowed by an earlier rule", "c-neutral"],
  no_match: ["No match", "c-neutral"],
  disabled: ["Disabled", "c-neutral"],
  expired: ["Expired", "c-neutral"],
};

function matchTags(match) {
  const entries = Object.entries(match || {});
  if (entries.length === 0) return h("span", { class: "faint" }, "matches every device");
  return tags(entries.map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`));
}

function actionLine(action) {
  return h(
    "span",
    { class: "row" },
    accessChip(action.access),
    action.scan && action.scan !== "none" ? chip(`scan: ${action.scan.replace("_", " ")}`, "c-watch") : null,
    action.alert ? chip("alert", "c-deny") : null,
  );
}

function rulesList(policy) {
  const rules = policy.rules || [];
  return h(
    "div",
    { class: "rules" },
    rules.map((rule, index) =>
      h(
        "div",
        { class: `rule${rule.enabled === false ? " off" : ""}` },
        h("span", { class: "idx" }, String(index + 1)),
        h(
          "div",
          { class: "stack" },
          h("div", {}, h("strong", {}, rule.id), rule.enabled === false ? chip("disabled", "c-neutral") : null, rule.expires ? chip(`expires ${rule.expires}`, "c-pending") : null),
          rule.description ? h("div", { class: "muted" }, rule.description) : null,
          matchTags(rule.match),
        ),
        actionLine(rule.action || {}),
      ),
    ),
    h(
      "div",
      { class: "rule" },
      h("span", { class: "idx" }, "end"),
      h("div", {}, h("strong", {}, "Default"), h("div", { class: "muted" }, "Anything no rule matched.")),
      actionLine(policy.default || {}),
    ),
  );
}

export function mount(root) {
  const s = scope();
  let info = null;
  let activeText = "";
  const summaryHost = h("div", { class: "panel-body" }, loading());
  const rulesHost = h("div", { class: "panel-flush" });
  const editor = h("textarea", { rows: "18", spellcheck: "false", "aria-label": "Policy document, JSON", autocapitalize: "none" });
  const editResult = h("div", { class: "stack" });
  const staleNote = h("div", {});
  const testHost = h("div", { class: "stack" });
  const writer = can("edit_policy");

  const dirty = () => editor.value !== activeText;

  function show(policyInfo) {
    info = policyInfo;
    const hadEdits = dirty() && editor.value !== "";
    activeText = JSON.stringify(info.policy, null, 2);
    if (!hadEdits) editor.value = activeText;
    replace(
      summaryHost,
      kv([
        ["Name", info.name],
        ["Rules", String(info.rules)],
        ["Loaded from", info.source === "file" ? "the policy file" : info.source === "default" ? "the built-in default (no policy file yet)" : "the last good copy (the file could not be used)"],
        ["Loaded", timeEl(info.loaded_at)],
        ["Hash", h("code", {}, info.hash)],
      ]),
    );
    replace(rulesHost, rulesList(info.policy));
    replace(staleNote);
  }

  async function load() {
    try {
      show(await api.get("/policy"));
    } catch (error) {
      replace(summaryHost, errorState(error, load));
    }
  }

  function draft() {
    try {
      return { value: JSON.parse(editor.value) };
    } catch (error) {
      return { error: new Error(`The editor does not hold valid JSON: ${error.message}`) };
    }
  }

  const validate = button("Check the draft", {
    onClick: async () => {
      const parsed = draft();
      if (parsed.error) {
        replace(editResult, errorBox(parsed.error));
        return;
      }
      const reply = await api.post("/policy/validate", { policy: parsed.value });
      replace(
        editResult,
        reply.valid
          ? h("p", { class: "note" }, `The draft is valid. If saved its hash would be ${reply.hash}.`)
          : h("div", { class: "form-error", role: "alert" }, `The draft has ${plural(reply.problems.length, "problem", "problems")}:`, h("ul", {}, reply.problems.map((p) => h("li", {}, p)))),
      );
    },
  });

  const save = button("Save and apply", {
    tone: "primary",
    disabled: !writer,
    title: writer ? null : "Your role cannot edit the policy",
    onClick: async () => {
      const parsed = draft();
      if (parsed.error) {
        replace(editResult, errorBox(parsed.error));
        return;
      }
      const enforcing = blocksForReal(state.status);
      const ok = await confirmDialog({
        title: "Apply this policy?",
        message: enforcing
          ? "It takes effect at once and every connected device is re-evaluated. Devices the new policy denies are blocked now."
          : isWatchOnly(state.status)
            ? "It takes effect at once and every connected device is re-evaluated. PortLock is watch-only on this computer, so nothing is blocked; the decisions change."
            : "It takes effect at once and every connected device is re-evaluated. PortLock is in monitor mode, so nothing is blocked; the decisions change.",
        confirmLabel: "Apply policy",
      });
      if (!ok) return;
      try {
        const reply = await api.put("/policy", { policy: parsed.value, expected_hash: info ? info.hash : undefined });
        editor.value = JSON.stringify(reply.policy, null, 2);
        show(reply);
        const sum = reply.summary;
        replace(
          editResult,
          h("p", { class: "note" }, `Applied. ${plural(sum.evaluated, "device", "devices")} re-evaluated: ${sum.changed} changed, ${sum.blocked} blocked, ${sum.read_only} read-only, ${sum.released} released, ${sum.failed} failed.`),
        );
      } catch (error) {
        replace(editResult, errorBox(error));
        if (error.code === "policy_conflict") await load();
      }
    },
  });

  const revert = button("Discard my edits", {
    tone: "quiet",
    onClick: () => {
      editor.value = activeText;
      replace(editResult);
      replace(staleNote);
    },
  });

  // ---- test a device ----
  let known = [];
  const subject = select([["", "Loading devices"]], "");
  const useDraft = checkbox("Test against the draft in the editor, not the active policy");

  async function loadSubjects() {
    try {
      const reply = await api.get("/devices/known", { limit: 500 });
      known = reply.devices;
      const options = [];
      for (const conn of state.devices.values()) {
        options.push([`c:${conn.connection_id}`, `Connected: ${conn.display_name || "Unnamed device"} (${vidPid(conn.device)})`]);
      }
      for (const device of known) {
        options.push([`f:${device.fingerprint}`, `Seen before: ${device.display_name || "Unnamed device"} (${shortFp(device.fingerprint)})`]);
      }
      if (options.length === 0) options.push(["", "No device has been seen yet"]);
      replace(subject, options.map(([value, label]) => h("option", { value }, label)));
    } catch (error) {
      replace(testHost, errorState(error, loadSubjects));
    }
  }

  function explain(reply) {
    const decision = reply.decision;
    return h(
      "div",
      { class: "stack" },
      h(
        "div",
        { class: "row" },
        accessChip(decision.access),
        h("span", {}, `by ${SOURCE_TEXT[decision.source] || decision.source}`),
        decision.alert ? chip("alert", "c-deny") : null,
        decision.scan !== "none" ? chip(`scan: ${decision.scan.replace("_", " ")}`, "c-watch") : null,
      ),
      h("ul", {}, decision.reasons.map((reason) => h("li", {}, reason))),
      kv([
        ["Deciding rule", reply.matched_rule || (reply.matched_default ? "the policy default" : "none")],
        ["Policy tested", h("code", {}, shortFp(reply.policy_hash))],
        ["Answer holds until", reply.valid_until ? timeEl(reply.valid_until) : "no expiry"],
        ["Rules skipped", reply.skipped.length ? reply.skipped.map((entry) => entry.join(": ")).join("; ") : "none"],
      ]),
      h(
        "ol",
        { class: "explain", "aria-label": "Every rule, in order" },
        reply.explain.map((rule) => {
          const [label, tone] = OUTCOME[rule.outcome] || [rule.outcome, "c-neutral"];
          return h(
            "li",
            { "data-outcome": rule.outcome },
            h("div", { class: "row" }, h("strong", {}, rule.rule_id), chip(label, tone), h("span", { class: "muted" }, rule.summary)),
            rule.criteria.length
              ? h("ul", {}, rule.criteria.map((c) => h("li", {}, `${c.criterion}: ${c.matched ? "matched" : "did not match"}. ${c.detail}`)))
              : null,
          );
        }),
      ),
    );
  }

  const runTest = button("Test", {
    tone: "primary",
    onClick: async () => {
      if (!subject.value) throw new Error("Pick a device to test.");
      const body = subject.value.startsWith("c:")
        ? { connection_id: Number.parseInt(subject.value.slice(2), 10) }
        : { fingerprint: subject.value.slice(2) };
      if (useDraft.input.checked) {
        const parsed = draft();
        if (parsed.error) throw parsed.error;
        body.policy = parsed.value;
      }
      replace(testHost, explain(await api.post("/policy/test", body)));
    },
  });

  replace(
    root,
    pageHead("Policy", "The first matching rule decides. A grant never widens a rule; it only settles a device the policy left pending."),
    panel("Active policy", summaryHost),
    panel("Rules, in the order they are tried", rulesHost),
    panel(
      "Edit",
      h(
        "div",
        { class: "panel-body" },
        staleNote,
        field("Policy document", editor, "JSON, as documented in docs/POLICY.md. Nothing changes until you save."),
        h("div", { class: "row" }, validate, save, revert),
        editResult,
      ),
    ),
    panel("What would the policy do with this device?", h("div", { class: "panel-body" }, field("Device", subject), useDraft.el, h("div", { class: "row" }, runTest), testHost)),
  );

  load();
  loadSubjects();
  s.on("policy", async (event) => {
    if (!dirty()) {
      await load();
      return;
    }
    replace(
      staleNote,
      h(
        "div",
        { class: "note warn", role: "alert" },
        `The active policy changed to "${event.name}" while you were editing. Saving will be refused until you reload it. `,
        button("Load the new version and drop my edits", {
          small: true,
          onClick: async () => {
            editor.value = "";
            await load();
          },
        }),
      ),
    );
  });
  s.on("reload", load);
  return () => s.dispose();
}
