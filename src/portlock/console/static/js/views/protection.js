// Protection: the mode (monitor or enforce), what is enforced against, default-deny, and the
// emergency lockdown. Every change that could lock the operator out is applied under
// commit-confirm: it is rolled back unless confirmed from this browser in time.

import { ApiError, api } from "../api.js";
import { h, replace } from "../dom.js";
import { countdown, plural, timeEl } from "../fmt.js";
import { can, refreshChanges, scope, setChanges, setLockdown, setMode, state } from "../store.js";
import { POSTURE_TEXT, WATCH_ONLY_CONTROL_NOTE, isWatchOnly, modeNotes, posture, watchOnlyReason } from "../truth.js";
import { button, checkbox, chip, confirmDialog, errorState, field, formDialog, kv, loading, pageHead, panel, reasonFor, select, textInput, toast } from "../ui.js";

const SCOPES = {
  storage: "Storage only: mass storage, phones and cameras in file mode, and devices that hide another function beside an input device",
  storage_and_unknown: "Storage and unknown devices",
  all_except_protected: "Everything except protected devices",
};

const POSTURE_TONE = { watch_only: "c-watch", monitor: "c-watch", enforce: "c-enforce", lockdown: "c-lock" };

// Enforce mode, default-deny and the lockdown are refused by a watch-only service (409
// `watch_only`). The controls are disabled there with a short note beside them that points
// at the reason behind the bar's "Why", instead of repeating it three times; should one be
// used anyway, the service's own reason is shown, never a generic error.
function notHere() {
  return WATCH_ONLY_CONTROL_NOTE;
}

async function unlessWatchOnly(action) {
  if (isWatchOnly(state.status)) {
    toast(watchOnlyReason(state.status), "bad");
    return;
  }
  try {
    await action();
  } catch (error) {
    if (error instanceof ApiError && error.code === "watch_only") {
      toast(error.message, "bad");
      refreshChanges(); // brings the mode, and with it the disabled controls, up to date
      return;
    }
    throw error;
  }
}

function addChange(change) {
  if (!change) return;
  setChanges([...state.changes.filter((c) => c.id !== change.id), change]);
  refreshChanges();
}

function parseMinutes(input, max) {
  const text = input.value.trim();
  if (!/^\d+$/.test(text)) throw new Error("Minutes must be a whole number.");
  const n = Number.parseInt(text, 10);
  if (n < 1 || n > max) throw new Error(`Minutes must be from 1 to ${max}.`);
  return n;
}

export function mount(root) {
  const s = scope();
  const modeHost = h("div", { class: "panel-body" });
  const scopeHost = h("div", { class: "panel-body" }, loading());
  const denyHost = h("div", { class: "panel-body" }, loading());
  const lockHost = h("div", { class: "panel-body" });
  const settingsHost = h("div", { class: "panel-body" }, loading());
  const nowHost = h("div", { class: "row" });

  // ---- mode ----
  function renderMode() {
    const mode = state.mode;
    if (!mode) return;
    const watchOnly = isWatchOnly(mode);
    const enforcing = !watchOnly && mode.effective_mode === "enforce";
    const writer = can("change_mode");
    const kind = posture(state.status);
    replace(nowHost, h("span", {}, "Right now: "), chip(POSTURE_TEXT[kind], POSTURE_TONE[kind], { dashed: kind === "watch_only" }));
    const enforceButton = enforcing
      ? null
      : button("Switch to enforce mode…", {
          tone: "enforce",
          disabled: !writer || !mode.can_enforce || watchOnly,
          title: watchOnly ? null : !writer ? "Your role cannot change the mode" : !mode.can_enforce ? "This machine cannot enforce yet" : null,
          onClick: () =>
            unlessWatchOnly(async () => {
              const ok = await confirmDialog({
                title: "Switch to enforce mode?",
                message: h(
                  "div",
                  { class: "stack" },
                  h("p", {}, "PortLock starts blocking devices policy has not approved, at once."),
                  h("p", { class: "note warn" }, "It is applied under commit-confirm: unless you press Confirm in this browser within 60 seconds, PortLock goes back to monitor mode by itself. Keep this page open."),
                ),
                confirmLabel: "Enforce now",
                tone: "enforce",
              });
              if (!ok) return;
              const reply = await api.put("/mode", { mode: "enforce" });
              setMode(reply.mode);
              addChange(reply.change);
              toast("Enforce mode is on. Confirm it in the bar at the top of the page.", "good");
            }),
        });
    replace(
      modeHost,
      kv([
        ["Chosen mode", POSTURE_TEXT[mode.mode]],
        ["In force", watchOnly ? "Watch-only: nothing is blocked" : POSTURE_TEXT[mode.effective_mode]],
        ["Chosen by", { config: "the configuration file", setting: "an administrator in the console", killswitch: "the kill switch" }[mode.source] || mode.source],
      ]),
      mode.killswitch ? h("p", { class: "note bad" }, "The kill switch file is present, so enforcement is off and PortLock stays in monitor mode until it is removed.") : null,
      // The watch-only reason is one of the notes; it is behind the bar's "Why" already.
      modeNotes(mode).map((note) => h("p", { class: "note warn" }, note)),
      // In watch-only the page heading already says what this line would.
      watchOnly
        ? null
        : h(
            "p",
            { class: "muted" },
            enforcing ? "PortLock blocks devices policy has not approved." : "PortLock only records what it would block. Nothing on this machine is changed.",
          ),
      h(
        "div",
        { class: "row" },
        enforceButton,
        watchOnly && enforceButton ? reasonFor(enforceButton, notHere()) : null,
        enforcing
          ? button("Switch to monitor", {
              disabled: !writer,
              onClick: async () => {
                const ok = await confirmDialog({
                  title: "Switch to monitor mode?",
                  message: "PortLock puts back everything it changed. Devices are no longer blocked. An active lockdown stays on.",
                  confirmLabel: "Switch to monitor",
                });
                if (!ok) return;
                const reply = await api.put("/mode", { mode: "monitor" });
                setMode(reply.mode);
                toast("Monitor mode. Nothing is being blocked.", "good");
              },
            })
          : null,
      ),
    );
  }

  // ---- scope ----
  async function loadScope() {
    try {
      const reply = await api.get("/scope");
      const choose = select(reply.scopes.map((name) => [name, SCOPES[name] || name]), reply.scope);
      replace(
        scopeHost,
        h("p", { class: "muted" }, "Which devices PortLock may enforce against. Anything outside it is reported as not enforced, never as protected. Widening it is applied under commit-confirm."),
        field("Scope", choose),
        h(
          "div",
          { class: "row" },
          button("Apply scope", {
            disabled: !can("change_mode"),
            onClick: async () => {
              if (choose.value === reply.scope) return;
              const result = await api.put("/scope", { scope: choose.value });
              addChange(result.change);
              toast(result.change ? "Scope widened. Confirm it in the bar at the top." : "Scope narrowed.", "good");
              await loadScope();
            },
          }),
        ),
      );
    } catch (error) {
      replace(scopeHost, errorState(error, loadScope));
    }
  }

  // ---- default-deny ----
  async function loadDeny() {
    try {
      const reply = await api.get("/default-deny");
      // Watch-only refuses turning it on; turning it off stays allowed.
      const locked = isWatchOnly(state.status) && !reply.enabled;
      const toggle = checkbox("Ask the operating system to refuse new devices by default", {
        checked: reply.enabled,
        hint: locked ? null : "Only in enforce mode. Turning it on is applied under commit-confirm.",
      });
      toggle.input.disabled = locked;
      const apply = button("Apply", {
        disabled: !can("change_mode") || locked,
        onClick: async () => {
          if (toggle.input.checked === reply.enabled) return;
          const turnOn = toggle.input.checked;
          const send = async () => {
            const result = await api.put("/default-deny", { enabled: turnOn });
            addChange(result.change);
            toast(result.enabled ? "Default-deny is on. Confirm it in the bar at the top." : "Default-deny is off.", "good");
          };
          if (turnOn) await unlessWatchOnly(send);
          else await send();
          await loadDeny();
        },
      });
      replace(denyHost, toggle.el, h("div", { class: "row" }, apply, locked ? reasonFor(toggle.input, notHere()) : null));
      if (locked) apply.setAttribute("aria-describedby", toggle.input.getAttribute("aria-describedby"));
    } catch (error) {
      replace(denyHost, errorState(error, loadDeny));
    }
  }

  // ---- lockdown ----
  function renderLockdown() {
    const lock = state.lockdown;
    if (!lock) return;
    const writerEngage = can("engage_lockdown");
    const watchOnly = isWatchOnly(state.status);
    if (watchOnly && !lock.active && lock.state === "idle") {
      // No minutes or reason fields: nothing here could use them.
      const engage = button("Engage lockdown…", { tone: "danger", disabled: true });
      replace(
        lockHost,
        h("p", { class: "muted" }, "A lockdown blocks all removable storage and denies new devices at once."),
        h("div", { class: "row" }, engage, reasonFor(engage, notHere())),
      );
      return;
    }
    if (!lock.active && lock.state === "idle") {
      const minutes = textInput({ inputmode: "numeric", value: String(lock.default_minutes) });
      const reason = textInput({ maxlength: "256", placeholder: "Optional: why" });
      replace(
        lockHost,
        h("p", { class: "muted" }, "Blocks all removable storage and denies new devices at once, even in monitor mode. Protected devices are never touched. It lifts itself when the timer ends, so it cannot stay on by accident."),
        h("div", { class: "form-grid" }, field("Lift itself after (minutes)", minutes, `Up to ${plural(lock.max_minutes, "minute", "minutes")}.`), field("Reason", reason)),
        h(
          "div",
          { class: "row" },
          button("Engage lockdown…", {
            tone: "danger",
            disabled: !writerEngage,
            title: writerEngage ? null : "Your role cannot engage a lockdown",
            onClick: () => unlessWatchOnly(async () => {
              const n = parseMinutes(minutes, lock.max_minutes);
              const ok = await confirmDialog({
                title: "Engage lockdown?",
                message: h(
                  "div",
                  { class: "stack" },
                  h("p", {}, `All removable storage is blocked now and new devices are denied, for ${plural(n, "minute", "minutes")} unless you lift it earlier.`),
                  h("p", { class: "note warn" }, "It is applied under commit-confirm: press Confirm in this browser within 60 seconds or it is undone by itself. The bar at the top lists exactly which devices it blocks."),
                ),
                confirmLabel: "Engage lockdown",
                tone: "danger",
              });
              if (!ok) return;
              const body = { minutes: n };
              if (reason.value.trim()) body.reason = reason.value.trim();
              const reply = await api.post("/lockdown/engage", body);
              setLockdown(reply.lockdown);
              addChange(reply.change);
              toast("Lockdown engaged. Confirm it in the bar at the top of the page.", "good");
            }),
          }),
        ),
      );
      return;
    }
    const renew = textInput({ inputmode: "numeric", placeholder: String(lock.default_minutes) });
    replace(
      lockHost,
      h(
        "div",
        { class: "row" },
        // A watch-only service refuses to engage one, so this is only a stale record there.
        watchOnly
          ? chip("Recorded only: nothing is blocked", "c-watch", { dashed: true })
          : chip(lock.pending_change_id ? "Engaged, not confirmed" : "Lockdown active", "c-lock", { hatch: true }),
      ),
      h(
        "div",
        { class: "posture-clock" },
        lock._deadlineMs ? h("span", { class: "t" }, countdown(lock._deadlineMs)) : null,
        h("span", { class: "l" }, "until it lifts by itself"),
      ),
      kv([
        ["Engaged by", lock.engaged_by],
        ["At", lock.engaged_at ? timeEl(lock.engaged_at) : null],
        ["Reason", lock.reason],
        ["Renewed", lock.renew_count ? plural(lock.renew_count, "time", "times") : "never"],
        ["Outside timer", lock.external_timer_armed ? "armed: the operating system lifts it even if PortLock stops" : "not armed"],
      ]),
      h(
        "div",
        { class: "form-grid" },
        field("Restart the timer (minutes)", renew, "Leave empty for the default."),
      ),
      h(
        "div",
        { class: "row" },
        button("Renew", {
          disabled: !writerEngage,
          onClick: async () => {
            const body = renew.value.trim() ? { minutes: parseMinutes(renew, lock.max_minutes) } : {};
            const reply = await api.post("/lockdown/renew", body);
            setLockdown(reply.lockdown);
            toast("Timer restarted.", "good");
          },
        }),
        button("Lift lockdown…", { tone: "primary", disabled: !can("lift_lockdown"), title: can("lift_lockdown") ? null : "Your role cannot lift a lockdown", onClick: liftDialog }),
      ),
      h("p", { class: "hint" }, "Lifting asks for your password or a recovery code again. If the service is not running, `portlock recover` lifts it from the command line."),
    );
  }

  async function liftDialog() {
    const kind = select([["password", "My password"], ["recovery_code", "A recovery code"]], "password");
    const secret = h("input", { type: "password", autocomplete: "current-password" });
    const secretField = field("Secret", secret);
    kind.addEventListener("change", () => {
      secret.value = "";
      secret.type = kind.value === "password" ? "password" : "text";
      secret.autocomplete = kind.value === "password" ? "current-password" : "off";
    });
    const lifted = await formDialog({
      title: "Lift the lockdown",
      submitLabel: "Lift lockdown",
      content: h("div", { class: "stack" }, h("p", { class: "muted" }, "Prove it is you before devices are released."), field("Use", kind), secretField),
      onSubmit: async () => {
        if (!secret.value) throw new Error("Enter your password or a recovery code.");
        const reply = await api.post("/lockdown/lift", { [kind.value]: secret.value });
        secret.value = "";
        setLockdown(reply.lockdown);
        return reply;
      },
    });
    if (lifted) {
      const sum = lifted.summary;
      toast(sum ? `Lockdown lifted. ${sum.released} released, ${sum.blocked} still blocked by policy.` : "Lockdown lifted.", "good");
    }
  }

  // ---- settings ----
  async function loadSettings() {
    try {
      const reply = await api.get("/settings");
      const scanOn = checkbox("Scan mounted volumes when policy asks for it", { checked: reply.runtime["scan.enabled"] });
      const minutes = textInput({ inputmode: "numeric", value: String(reply.runtime["lockdown.default_minutes"]) });
      replace(
        settingsHost,
        scanOn.el,
        h("div", { class: "form-grid" }, field("Default lockdown length (minutes)", minutes)),
        kv([
          ["Enrolled and protected fingerprints", String(reply.runtime.protected_fingerprints.length)],
          ["Input-device enforcement", reply.effective.hid_enforcement_enabled ? "on" : "off (the default)"],
          ["Fail closed", reply.effective.fail_closed ? "yes" : "no"],
          ["Read-only baseline", reply.effective.baseline_read_only ? "on" : "off"],
        ]),
        h("p", { class: "hint" }, "Everything else, including input-device enforcement and the API address, can only be changed in the configuration file by someone with operating-system rights. That is deliberate."),
        h(
          "div",
          { class: "row" },
          button("Save settings", {
            disabled: !can("edit_policy"),
            onClick: async () => {
              const body = {};
              if (scanOn.input.checked !== reply.runtime["scan.enabled"]) body["scan.enabled"] = scanOn.input.checked;
              const n = parseMinutes(minutes, state.lockdown ? state.lockdown.max_minutes : 1440);
              if (n !== reply.runtime["lockdown.default_minutes"]) body["lockdown.default_minutes"] = n;
              if (Object.keys(body).length === 0) {
                toast("Nothing to change.", "info");
                return;
              }
              await api.patch("/settings", body);
              toast("Settings saved.", "good");
              await loadSettings();
            },
          }),
        ),
      );
    } catch (error) {
      replace(settingsHost, errorState(error, loadSettings));
    }
  }

  replace(
    root,
    pageHead(
      "Protection",
      isWatchOnly(state.status)
        ? "PortLock is watch-only on this computer: it shows and records, and blocks nothing. Enforce mode, default-deny and the emergency lockdown are not available."
        : "Monitor only watches. Enforce blocks. Lockdown blocks all removable storage in an emergency. Changes that could lock you out are undone unless you confirm them.",
    ),
    nowHost,
    panel("Mode", modeHost),
    h("div", { class: "grid-2" }, panel("Enforcement scope", scopeHost), panel("Default-deny for new devices", denyHost)),
    panel("Emergency lockdown", lockHost),
    panel("Settings", settingsHost),
  );
  renderMode();
  renderLockdown();
  loadScope();
  loadDeny();
  loadSettings();
  s.on(["mode", "status"], renderMode);
  s.on("lockdown", renderLockdown);
  s.on("settings", loadSettings);
  s.on("reload", () => {
    loadScope();
    loadDeny();
    loadSettings();
  });
  return () => s.dispose();
}
