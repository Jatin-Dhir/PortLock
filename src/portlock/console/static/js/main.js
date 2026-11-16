// Page shell: sign-in or the console, the navigation, the pending-change bar and the
// session. Views live in ./views/ and are loaded when first opened.

import { openAccount } from "./account.js";
import { ApiError, api, hasToken, onActivity, onSessionLost, setToken } from "./api.js";
import { h, replace } from "./dom.js";
import { startStream, stopStream, onStreamSessionEnded } from "./events.js";
import { count } from "./fmt.js";
import { mountChangeBar } from "./changebar.js";
import { mountSignin } from "./signin.js";
import { loadAll, resetState, state, can, scope } from "./store.js";
import { errorState, toast } from "./ui.js";

const SIMULATION_TEXT = "SIMULATION: nothing real is read, blocked, ejected or changed on this machine. Every device here is synthetic.";

const VIEWS = [
  { path: "overview", label: "Overview", module: "./views/overview.js" },
  { path: "pending", label: "Pending", module: "./views/pendingview.js", badge: "pending" },
  { path: "devices", label: "Devices", module: "./views/devices.js" },
  { path: "enrolment", label: "Input devices", module: "./views/enrolment.js" },
  { path: "grants", label: "Grants and trust", module: "./views/grants.js" },
  { path: "policy", label: "Policy", module: "./views/policy.js" },
  { path: "audit", label: "Audit log", module: "./views/audit.js", permission: "view_audit" },
  { path: "scans", label: "Scans", module: "./views/scans.js" },
  { path: "protection", label: "Protection", module: "./views/protection.js" },
  { path: "users", label: "Users", module: "./views/users.js", permission: "manage_users" },
  { path: "doctor", label: "Doctor", module: "./views/doctor.js" },
];

const app = document.getElementById("app");
let shell = null; // { main, nav, scope, dispose }
let current = null; // { path, dispose, token }
let navToken = 0;
let ending = false;

// ---- sign in ----------------------------------------------------------------------------

async function showSignin(notice) {
  teardown();
  let ping = null;
  let problem = null;
  try {
    ping = await api.get("/ping");
    state.simulation = Boolean(ping.simulation);
    state.setupRequired = Boolean(ping.setup_required);
  } catch (error) {
    problem = error;
  }
  document.title = "Sign in - PortLock";
  replace(app, simulationBar(), mountSignin({ ping, problem, notice, onSignedIn: signedIn, retry: () => showSignin(notice) }));
}

function simulationBar() {
  return state.simulation ? h("div", { class: "simbar", role: "status" }, h("span", {}, SIMULATION_TEXT)) : null;
}

async function signedIn(reply) {
  setToken(reply.token);
  ending = false;
  state.me = reply.user;
  state.role = reply.user.role;
  state.session = reply.session;
  await refreshSession();
  buildShell();
  startStream();
  try {
    await loadAll();
  } catch (error) {
    replace(shell.main, h("div", { class: "view" }, errorState(error, () => location.reload())));
    return;
  }
  navigate();
}

// A new password ends the old session, and with it the old event stream: open a new one.
async function passwordChanged() {
  stopStream();
  startStream();
  await refreshSession();
}

async function refreshSession() {
  const reply = await api.get("/auth/session");
  state.me = reply.user;
  state.role = reply.user.role;
  state.session = reply.session;
  state.permissions = new Set(reply.permissions);
  const idle = Date.parse(reply.session.idle_expires_at) - Date.parse(reply.session.last_seen_at);
  if (Number.isFinite(idle) && idle > 0) state.idleMs = idle;
  state.idleDeadline = Date.now() + state.idleMs;
}

function teardown() {
  stopStream();
  setToken(null);
  resetState();
  if (current) current.dispose();
  current = null;
  if (shell) shell.scope.dispose();
  shell = null;
  replace(app);
}

function endSession(notice) {
  if (ending) return;
  ending = true;
  showSignin(notice);
}

onSessionLost(() => endSession("Your session ended. Sign in again."));
onStreamSessionEnded((reason) =>
  endSession(reason === "expired" ? "Your session timed out. Sign in again." : "Your session was ended. Sign in again."),
);

async function signOut() {
  try {
    await api.post("/auth/logout");
  } catch {
    // Ending it here is what matters; the token is dropped either way.
  }
  endSession("You are signed out.");
}

// ---- shell ------------------------------------------------------------------------------

function buildShell() {
  const s = scope();
  const live = h("span", { class: "livedot", "data-live": "down", role: "status" }, h("i", { "aria-hidden": "true" }), h("span", {}, "Offline"));
  const idle = h("div", { class: "note warn", hidden: true });
  const nav = h("ul", {});
  const main = h("main", { class: "main", id: "main", tabindex: "-1" });
  const changebar = h("div", { id: "changebar" });

  const links = VIEWS.filter((v) => !v.permission || can(v.permission)).map((view) => {
    const badge = h("span", { class: "badge", hidden: true });
    const link = h("a", { href: `#/${view.path}`, "data-view": view.path }, h("span", {}, view.label), badge);
    return { view, link, badge };
  });
  replace(nav, links.map(({ link }) => h("li", {}, link)));

  replace(
    app,
    h("a", { class: "skip-link", href: "#main" }, "Skip to content"),
    h(
      "div",
      { class: "app" },
      simulationBar(),
      h(
        "header",
        { class: "topbar" },
        h("div", { class: "brand" }, "PortLock", h("small", {}, state.hostLabel)),
        h("div", { class: "grow" }),
        live,
        h("button", { class: "btn btn-quiet btn-small", type: "button", onclick: () => openAccount({ onPasswordChanged: passwordChanged }) }, `${state.me.username} (${state.role})`),
        h("button", { class: "btn btn-quiet btn-small", type: "button", onclick: signOut }, "Sign out"),
      ),
      changebar,
      idle,
      h("div", { class: "shell" }, h("nav", { class: "rail", "aria-label": "Console sections" }, nav), main),
    ),
  );
  s.on("live", () => {
    const text = { up: "Live", connecting: "Reconnecting", down: "Offline" }[state.live];
    live.dataset.live = state.live;
    live.lastChild.textContent = text;
  });
  s.on(["devices", "changes", "status"], () => {
    const pending = [...state.devices.values()].filter((c) => c.state === "pending").length;
    for (const { view, badge } of links) {
      if (view.badge === "pending") {
        badge.hidden = pending === 0;
        badge.textContent = count(pending);
        badge.setAttribute("aria-label", `${pending} waiting`);
      }
    }
    const waiting = state.changes.length > 0;
    document.title = `${pending > 0 ? `(${pending}) ` : ""}${waiting ? "Confirm needed - " : ""}${currentLabel()} - PortLock`;
  });
  const disposeChangeBar = mountChangeBar(changebar);

  const tick = setInterval(() => {
    if (!hasToken()) return;
    const left = state.idleDeadline - Date.now();
    idle.hidden = left > 60000;
    if (!idle.hidden) {
      idle.textContent =
        left > 0
          ? "This session ends in under a minute because nothing has been done. Press any key or click to stay signed in."
          : "This session may have ended. Press any key or click to find out.";
    }
  }, 1000);
  let pinging = false;
  const interact = async () => {
    if (!hasToken() || pinging || state.idleMs - (state.idleDeadline - Date.now()) < 120000) return;
    pinging = true;
    try {
      await refreshSession();
    } catch {
      // A 401 is handled by onSessionLost; anything else will show on the next action.
    } finally {
      pinging = false;
    }
  };
  document.addEventListener("pointerdown", interact);
  document.addEventListener("keydown", interact);

  shell = {
    main,
    nav,
    links,
    scope: {
      dispose() {
        s.dispose();
        disposeChangeBar();
        clearInterval(tick);
        document.removeEventListener("pointerdown", interact);
        document.removeEventListener("keydown", interact);
      },
    },
  };
}

onActivity(() => {
  state.idleDeadline = Date.now() + state.idleMs;
});

function currentLabel() {
  const path = routeName();
  return VIEWS.find((v) => v.path === path)?.label ?? "Overview";
}

function routeName() {
  const name = location.hash.replace(/^#\//, "").split("?")[0];
  return VIEWS.some((v) => v.path === name) ? name : "overview";
}

async function navigate() {
  if (!shell) return;
  const path = routeName();
  const view = VIEWS.find((v) => v.path === path);
  if (view.permission && !can(view.permission)) {
    location.hash = "#/overview";
    return;
  }
  if (current && current.path === path) return;
  const mine = ++navToken;
  for (const { link, view: v } of shell.links) {
    if (v.path === path) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  if (current) current.dispose();
  current = null;
  const root = h("div", { class: "view" });
  replace(shell.main, root);
  document.title = `${view.label} - PortLock`;
  try {
    const module = await import(view.module);
    if (mine !== navToken) return;
    const dispose = await module.mount(root);
    if (mine !== navToken) {
      dispose?.();
      return;
    }
    current = { path, dispose: dispose || (() => {}) };
    shell.main.focus({ preventScroll: true });
  } catch (error) {
    if (mine === navToken) replace(root, errorState(error instanceof ApiError ? error : new Error("This section could not be opened."), () => navigate()));
  }
}

window.addEventListener("hashchange", () => {
  if (shell) navigate();
});

// Keep the "nothing else loaded" promise honest: report anything that breaks.
window.addEventListener("unhandledrejection", (event) => {
  if (event.reason instanceof ApiError) return;
  console.error(event.reason);
});

showSignin().catch((error) => {
  console.error(error);
  toast("The console could not start.", "bad");
});
