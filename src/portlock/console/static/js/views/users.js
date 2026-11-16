// Users and recovery codes. Administrators only. Any change to an account's password, role
// or enabled state ends every session of that account.

import { showRecoveryCodes } from "../account.js";
import { api, seg } from "../api.js";
import { h, replace } from "../dom.js";
import { timeEl } from "../fmt.js";
import { me, scope } from "../store.js";
import { button, chip, confirmDialog, empty, errorState, field, formDialog, loading, pageHead, panel, select, table, textInput, toast } from "../ui.js";

const ROLES = [
  ["admin", "Administrator: everything"],
  ["operator", "Operator: approve devices, scans, lockdown"],
  ["auditor", "Auditor: read-only, may read and export the audit log"],
];

export function mount(root) {
  const s = scope();
  const listHost = h("div", { class: "panel-flush" }, loading());

  async function load() {
    try {
      const reply = await api.get("/users");
      replace(
        listHost,
        reply.users.length === 0
          ? empty("No user exists.")
          : table({
              caption: "Users",
              rows: reply.users,
              columns: [
                { label: "User", cell: (u) => [h("span", { class: "cell-main" }, u.username), u.username.toLowerCase() === me().toLowerCase() ? h("span", { class: "cell-sub" }, " (you)") : null] },
                { label: "Role", cell: (u) => roleSelect(u) },
                { label: "Status", cell: (u) => (u.enabled ? chip("Enabled", "c-allow") : chip("Disabled", "c-neutral")) },
                { label: "Last sign-in", cell: (u) => timeEl(u.last_login_at) },
                { label: "Recovery codes left", num: true, cell: (u) => String(u.recovery_codes_remaining) },
                {
                  label: "Password lock",
                  cell: (u) =>
                    u.locked_out_seconds > 0
                      ? [chip(`Locked ${u.locked_out_seconds} s`, "c-pending"), " ", button("Unlock", { small: true, tone: "quiet", onClick: () => act(() => api.post(`/users/${seg(u.username)}/unlock`), "Unlocked.") })]
                      : h("span", { class: "faint" }, "not locked"),
                },
                { label: "", cell: (u) => actions(u) },
              ],
            }),
      );
    } catch (error) {
      replace(listHost, errorState(error, load));
    }
  }

  async function act(call, message) {
    await call();
    toast(message, "good");
    await load();
  }

  function roleSelect(user) {
    const control = select(ROLES.map(([value, label]) => [value, label]), user.role);
    control.setAttribute("aria-label", `Role of ${user.username}`);
    control.addEventListener("change", async () => {
      const role = control.value;
      const ok = await confirmDialog({
        title: `Change the role of ${user.username} to ${role}?`,
        message: "Every session of this account ends, so they sign in again.",
        confirmLabel: "Change role",
      });
      try {
        if (ok) {
          await api.put(`/users/${seg(user.username)}/role`, { role });
          toast("Role changed.", "good");
        }
      } catch (error) {
        toast(error.message, "bad");
      }
      await load();
    });
    return control;
  }

  function actions(user) {
    const name = seg(user.username);
    return h(
      "div",
      { class: "row" },
      user.enabled
        ? button("Disable", { small: true, tone: "quiet", onClick: () => act(() => api.post(`/users/${name}/disable`), "Disabled.") })
        : button("Enable", { small: true, tone: "quiet", onClick: () => act(() => api.post(`/users/${name}/enable`), "Enabled.") }),
      button("Reset password…", { small: true, tone: "quiet", onClick: () => resetPassword(user) }),
      button("New recovery codes…", {
        small: true,
        tone: "quiet",
        onClick: async () => {
          const ok = await confirmDialog({
            title: `New recovery codes for ${user.username}?`,
            message: "Their current codes stop working. The new ones are shown once, here.",
            confirmLabel: "Issue new codes",
          });
          if (!ok) return;
          showRecoveryCodes(await api.post(`/users/${name}/recovery-codes`));
          await load();
        },
      }),
      button("Delete…", {
        small: true,
        tone: "quiet",
        onClick: async () => {
          const ok = await confirmDialog({
            title: `Delete ${user.username}?`,
            message: "The account and its sessions are removed. This cannot be undone. The last enabled administrator cannot be deleted.",
            confirmLabel: "Delete user",
            tone: "danger",
          });
          if (!ok) return;
          await api.del(`/users/${name}`);
          toast("User deleted.", "good");
          await load();
        },
      }),
    );
  }

  async function resetPassword(user) {
    const next = h("input", { type: "password", autocomplete: "new-password" });
    const done = await formDialog({
      title: `Reset the password of ${user.username}`,
      submitLabel: "Set password",
      content: h("div", { class: "stack" }, h("p", { class: "muted" }, "Clears any lockout and ends their sessions. Tell them the new password in person."), field("New password", next, "At least 12 characters.")),
      onSubmit: async () => {
        await api.post(`/users/${seg(user.username)}/password`, { new_password: next.value });
        next.value = "";
        return true;
      },
    });
    if (done) {
      toast("Password set.", "good");
      await load();
    }
  }

  // ---- create ----
  const username = textInput({ autocapitalize: "none", placeholder: "3 to 32 characters: a-z 0-9 . _ -" });
  const password = h("input", { type: "password", autocomplete: "new-password" });
  const role = select(ROLES, "operator");
  const create = button("Create user", {
    tone: "primary",
    onClick: async () => {
      await api.post("/users", { username: username.value.trim(), password: password.value, role: role.value });
      username.value = "";
      password.value = "";
      toast("User created. Issue their recovery codes when they first sign in.", "good");
      await load();
    },
  });

  replace(
    root,
    pageHead("Users", "Who can sign in, and what each role may do. The first administrator is created on the machine with `portlock init`, never here."),
    panel("Accounts", listHost),
    panel("Add a user", h("div", { class: "panel-body" }, h("div", { class: "form-grid" }, field("User name", username), field("Password", password, "At least 12 characters."), field("Role", role)), h("div", { class: "row" }, create))),
  );
  load();
  s.on("reload", load);
  return () => s.dispose();
}
