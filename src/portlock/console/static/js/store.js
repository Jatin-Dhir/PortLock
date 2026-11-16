// What the console knows, and how live events change it. The server pushes whole
// Connection objects, so an event replaces the copy held here: nothing is merged and nothing
// is counted by hand (docs/API.md 7.3).

import { api } from "./api.js";

export const state = {
  me: null,
  role: null,
  permissions: new Set(),
  session: null,
  idleMs: 15 * 60 * 1000,
  idleDeadline: 0,
  simulation: false,
  setupRequired: false,
  hostLabel: "",
  status: null,
  mode: null,
  lockdown: null,
  changes: [],
  devices: new Map(),
  alerts: [],
  live: "down",
  fresh: new Set(),
  scanProgress: new Map(),
  newAudit: 0,
  loadedAt: 0,
};

const listeners = new Map();

/** Subscribe to one topic or several; returns the function that unsubscribes. */
export function on(topics, fn) {
  const names = Array.isArray(topics) ? topics : [topics];
  for (const name of names) {
    if (!listeners.has(name)) listeners.set(name, new Set());
    listeners.get(name).add(fn);
  }
  return () => {
    for (const name of names) listeners.get(name)?.delete(fn);
  };
}

export function emit(topic, payload) {
  for (const fn of [...(listeners.get(topic) ?? [])]) {
    try {
      fn(payload);
    } catch (error) {
      // A broken view must not stop the others from hearing the event.
      console.error(`listener for ${topic} failed`, error);
    }
  }
}

/** Subscriptions owned by one view; `dispose` drops them all when the view goes away. */
export function scope() {
  const offs = [];
  return {
    on(topics, fn) {
      offs.push(on(topics, fn));
    },
    dispose() {
      for (const off of offs.splice(0)) off();
    },
  };
}

export function can(permission) {
  return state.permissions.has(permission);
}

export function me() {
  return state.me ? state.me.username : "";
}

export function resetState() {
  Object.assign(state, {
    me: null,
    role: null,
    permissions: new Set(),
    session: null,
    status: null,
    mode: null,
    lockdown: null,
    changes: [],
    devices: new Map(),
    alerts: [],
    fresh: new Set(),
    scanProgress: new Map(),
    newAudit: 0,
    loadedAt: 0,
  });
}

// ---- derived values ---------------------------------------------------------------------

function stampLockdown(lockdown) {
  if (!lockdown) return lockdown;
  const now = Date.now();
  lockdown._deadlineMs = lockdown.remaining_seconds == null ? null : now + lockdown.remaining_seconds * 1000;
  lockdown._confirmMs =
    lockdown.confirm_remaining_seconds == null ? null : now + lockdown.confirm_remaining_seconds * 1000;
  return lockdown;
}

function stampChange(change) {
  const now = Date.now();
  const seconds = change.remaining_seconds ?? change.timeout_seconds ?? 60;
  change._deadlineMs = now + seconds * 1000;
  return change;
}

export function setLockdown(lockdown) {
  state.lockdown = stampLockdown(lockdown);
  if (state.status) state.status.lockdown = state.lockdown;
  emit("lockdown");
  emit("status");
}

export function setMode(mode) {
  state.mode = mode;
  if (state.status) state.status.mode = mode;
  emit("mode");
  emit("status");
}

let changeTimer = null;

export function setChanges(list) {
  state.changes = list.map(stampChange);
  emit("changes");
  // The service rolls an unconfirmed change back at its deadline. One look just after it
  // keeps this page honest even if the rollback event is missed; it is not polling.
  clearTimeout(changeTimer);
  if (state.changes.length > 0) {
    const next = Math.min(...state.changes.map((c) => c._deadlineMs));
    changeTimer = setTimeout(refreshChanges, Math.max(1500, next - Date.now() + 2000));
  }
}

let refreshTimer = null;

/**
 * Ask the service which changes are waiting for confirmation, and what the lockdown and the
 * mode are now (debounced). Confirming or rolling back a change raises no event of its own,
 * so the page asks.
 */
export function refreshChanges() {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(async () => {
    try {
      const [changes, lockdown, mode] = await Promise.all([
        api.get("/changes", undefined, { quiet: true }),
        api.get("/lockdown", undefined, { quiet: true }),
        api.get("/mode", undefined, { quiet: true }),
      ]);
      setLockdown(lockdown);
      setMode(mode);
      setChanges(changes.changes);
    } catch {
      // The next event or action asks again; a stale bar is corrected by the 401 handler.
    }
  }, 150);
}

// ---- loading ----------------------------------------------------------------------------

/** Load everything the overview shows. Throws the first error. */
export async function loadAll({ quiet = false } = {}) {
  const options = { quiet };
  const [status, devices, lockdown, changes, mode] = await Promise.all([
    api.get("/status", undefined, options),
    api.get("/devices", undefined, options),
    api.get("/lockdown", undefined, options),
    api.get("/changes", undefined, options),
    api.get("/mode", undefined, options),
  ]);
  state.status = status;
  state.hostLabel = status.host_label || "";
  state.simulation = Boolean(status.simulation);
  state.devices = new Map(devices.devices.map((conn) => [conn.connection_id, conn]));
  state.mode = mode;
  state.status.mode = mode;
  state.status.lockdown = stampLockdown(lockdown);
  state.lockdown = state.status.lockdown;
  state.loadedAt = Date.now();
  state.changes = [];
  emit("status");
  emit("devices");
  emit("lockdown");
  emit("mode");
  setChanges(changes.changes);
}

let reloadTimer = null;

export function reloadSoon() {
  clearTimeout(reloadTimer);
  reloadTimer = setTimeout(() => {
    loadAll({ quiet: true }).catch(() => {});
    emit("reload");
  }, 400);
}

// ---- events -----------------------------------------------------------------------------

function upsertConnection(connection, isNew) {
  if (!connection) return;
  if (connection.removed_at) {
    state.devices.delete(connection.connection_id);
  } else {
    if (isNew && !state.devices.has(connection.connection_id)) {
      state.fresh.add(connection.connection_id);
      setTimeout(() => state.fresh.delete(connection.connection_id), 1500);
    }
    state.devices.set(connection.connection_id, connection);
  }
  emit("devices");
}

/** Apply one event of docs/API.md 7.3. Unknown events are ignored. */
export function applyEvent(name, data) {
  switch (name) {
    case "device.connected":
      upsertConnection(data.connection, true);
      break;
    case "decision.made":
    case "device.changed":
      upsertConnection(data.connection, false);
      break;
    case "device.removed":
      state.devices.delete(data.connection_id);
      emit("devices");
      break;
    case "enforcement.result": {
      const conn = data.connection_id == null ? null : state.devices.get(data.connection_id);
      if (conn) {
        conn.enforcement = data.enforcement;
        emit("devices");
      }
      break;
    }
    case "grant.changed":
      emit("grants", data);
      break;
    case "policy.changed":
      emit("policy", data);
      break;
    case "scan.started":
    case "scan.finished":
      if (name === "scan.finished" && data.scan) state.scanProgress.delete(data.scan.id);
      emit("scans", { scan: data.scan });
      break;
    case "scan.progress":
      state.scanProgress.set(data.scan_id, data);
      emit("scans", { progress: data });
      break;
    case "lockdown.changed":
      setLockdown(data.lockdown);
      refreshChanges();
      break;
    case "mode.changed":
      setMode(data.mode);
      refreshChanges();
      break;
    case "settings.changed":
      emit("settings", data);
      break;
    case "status.changed":
      if (state.status) {
        state.status.degraded = data.degraded;
        state.status.counts = data.counts;
        emit("status");
      }
      break;
    case "alert":
      state.alerts.unshift({ ...data, receivedAt: new Date().toISOString() });
      state.alerts.length = Math.min(state.alerts.length, 50);
      emit("alerts");
      break;
    case "audit.appended":
      state.newAudit += 1;
      emit("audit", data);
      break;
    default:
      break;
  }
}
