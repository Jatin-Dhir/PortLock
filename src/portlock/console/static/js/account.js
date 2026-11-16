// The signed-in person's own account: password change and recovery codes.

import { api, seg, setToken } from "./api.js";
import { h } from "./dom.js";
import { timeEl } from "./fmt.js";
import { state } from "./store.js";
import { button, copyButton, field, formDialog, infoDialog, kv, toast } from "./ui.js";

/** Show freshly issued recovery codes. They are returned once and kept only as digests. */
export function showRecoveryCodes(reply) {
  const codes = reply.codes;
  return infoDialog(
    `Recovery codes for ${reply.username}`,
    h(
      "div",
      { class: "stack" },
      h("p", { class: "note warn" }, "These are shown once and cannot be shown again. Each works a single time. Any older set no longer works."),
      h("div", { class: "codes" }, codes.map((code) => h("div", {}, code))),
      h("div", { class: "row" }, copyButton(codes.join("\n"), "Copy all"), h("span", { class: "hint" }, "Store them somewhere other than this computer.")),
    ),
  );
}

/**
 * Issue a new set of recovery codes for `username` and show it. The signed-in person types
 * their own current password first: a recovery code can lift a lockdown and reset a
 * password, so an open session alone is not enough to create one.
 */
export async function issueRecoveryCodes(username, consequence) {
  const current = h("input", { type: "password", autocomplete: "current-password" });
  let reply = null;
  const done = await formDialog({
    title: `New recovery codes for ${username}`,
    submitLabel: "Issue new codes",
    content: h(
      "div",
      { class: "stack" },
      h("p", { class: "muted" }, consequence),
      field("Your current password", current, "Asked again because a recovery code can lift a lockdown or reset a password."),
    ),
    onSubmit: async () => {
      reply = await api.post(`/users/${seg(username)}/recovery-codes`, { current_password: current.value });
      current.value = "";
      return true;
    },
  });
  if (done && reply !== null) showRecoveryCodes(reply);
}

export function openAccount({ onPasswordChanged }) {
  const me = state.me;
  const body = h(
    "div",
    { class: "stack" },
    kv([
      ["User", me.username],
      ["Role", state.role],
      ["Signed in", timeEl(state.session.created_at)],
      ["Session ends at the latest", timeEl(state.session.expires_at)],
    ]),
    h(
      "div",
      { class: "row" },
      button("Change password", { onClick: () => changePassword(onPasswordChanged) }),
      button("Issue new recovery codes", {
        onClick: () => issueRecoveryCodes(me.username, "The eight codes you have now stop working. The new ones are shown once."),
      }),
    ),
  );
  return infoDialog("Your account", body);
}

async function changePassword(onChanged) {
  const current = h("input", { type: "password", autocomplete: "current-password" });
  const next = h("input", { type: "password", autocomplete: "new-password" });
  const again = h("input", { type: "password", autocomplete: "new-password" });
  const done = await formDialog({
    title: "Change password",
    submitLabel: "Change password",
    content: h(
      "div",
      { class: "stack" },
      h("p", { class: "muted" }, "Changing it ends every other session of your account."),
      field("Current password", current),
      field("New password", next, "At least 12 characters."),
      field("New password again", again),
    ),
    onSubmit: async () => {
      if (next.value !== again.value) throw new Error("The two new passwords are not the same.");
      const reply = await api.post("/auth/password", { current_password: current.value, new_password: next.value });
      setToken(reply.token);
      state.session = reply.session;
      current.value = "";
      next.value = "";
      again.value = "";
      return true;
    },
  });
  if (done) {
    toast("Password changed. This session continues with a new token.", "good");
    await onChanged();
  }
}
