// Sign in, and sign in with a recovery code. The password goes to the service in the body of
// one POST and is never stored by this page: the token that comes back stays in memory.

import { api } from "./api.js";
import { h, replace } from "./dom.js";
import { button, errorBox, errorState, field, textInput } from "./ui.js";

export function mountSignin({ ping, problem, notice, onSignedIn, retry }) {
  if (problem) {
    return h("div", { class: "signin" }, h("div", { class: "signin-card" }, h("h1", {}, "PortLock"), errorState(problem, retry)));
  }

  const slot = h("div", { class: "stack" });
  const card = h("div", { class: "signin-card" }, h("h1", {}, "PortLock"));
  const root = h("main", { class: "signin" }, card);

  function passwordForm() {
    const user = textInput({ name: "username", autocomplete: "username", autocapitalize: "none", required: true });
    const pass = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true });
    const errorSlot = h("div", {});
    const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Sign in");
    const form = h(
      "form",
      {
        class: "stack",
        novalidate: true,
        onsubmit: async (event) => {
          event.preventDefault();
          if (!user.value.trim() || !pass.value) {
            replace(errorSlot, errorBox(new Error("Enter your user name and password.")));
            return;
          }
          submit.disabled = true;
          submit.setAttribute("aria-busy", "true");
          replace(errorSlot);
          try {
            const reply = await api.post("/auth/login", { username: user.value.trim(), password: pass.value });
            pass.value = "";
            await onSignedIn(reply);
          } catch (error) {
            replace(errorSlot, errorBox(error));
            pass.value = "";
            pass.focus();
          } finally {
            submit.disabled = false;
            submit.removeAttribute("aria-busy");
          }
        },
      },
      field("User name", user),
      field("Password", pass),
      errorSlot,
      submit,
    );
    queueMicrotask(() => user.focus());
    return form;
  }

  function recoveryForm() {
    const user = textInput({ name: "username", autocomplete: "username", autocapitalize: "none" });
    const code = textInput({ name: "recovery_code", autocapitalize: "characters", placeholder: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345" });
    const pass = h("input", { type: "password", name: "new_password", autocomplete: "new-password" });
    const again = h("input", { type: "password", name: "confirm", autocomplete: "new-password" });
    const errorSlot = h("div", {});
    const submit = h("button", { class: "btn btn-primary", type: "submit" }, "Set a new password and sign in");
    return h(
      "form",
      {
        class: "stack",
        novalidate: true,
        onsubmit: async (event) => {
          event.preventDefault();
          replace(errorSlot);
          if (pass.value !== again.value) {
            replace(errorSlot, errorBox(new Error("The two new passwords are not the same.")));
            return;
          }
          submit.disabled = true;
          try {
            const reply = await api.post("/auth/recovery", {
              username: user.value.trim(),
              recovery_code: code.value.trim(),
              new_password: pass.value,
            });
            pass.value = "";
            again.value = "";
            await onSignedIn(reply);
          } catch (error) {
            replace(errorSlot, errorBox(error));
          } finally {
            submit.disabled = false;
          }
        },
      },
      h("p", { class: "muted" }, "Each recovery code works once. Using one ends every other session of that account."),
      field("User name", user),
      field("Recovery code", code),
      field("New password", pass, "At least 12 characters."),
      field("New password again", again),
      errorSlot,
      submit,
    );
  }

  function show(mode) {
    const toggle = h(
      "button",
      { class: "linkish", type: "button", onclick: () => show(mode === "password" ? "recovery" : "password") },
      mode === "password" ? "Lost your password? Use a recovery code" : "Back to sign in",
    );
    replace(slot, mode === "password" ? passwordForm() : recoveryForm(), toggle);
  }

  replace(
    card,
    h("h1", {}, "PortLock"),
    h("p", { class: "muted" }, "Sign in to the console on this machine."),
    notice ? h("p", { class: "note warn", role: "status" }, notice) : null,
    ping && ping.setup_required
      ? h(
          "div",
          { class: "note bad stack" },
          h("p", {}, "PortLock has no administrator account yet, so nobody can sign in. Create one on this computer first:"),
          h("p", {}, h("code", {}, "portlock init"), " if PortLock is installed, or ", h("code", {}, "python -m portlock init"), " from PortLock's ", h("code", {}, "src"), " folder."),
          h("p", {}, "Use the same kind of window that started this service: an ordinary one for the watch-only PortLock, an administrator one for a system-wide installation."),
        )
      : null,
    slot,
    h("p", { class: "hint" }, ping ? `Service ${ping.version}, API ${ping.api}. This page loads nothing from any other host.` : ""),
  );
  show("password");
  return root;
}
