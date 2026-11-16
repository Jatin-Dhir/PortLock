// The one place that talks to the service. The bearer token lives in this module's memory
// and nowhere else: not in a cookie, not in a URL, not in web storage. A reload asks for the
// password again, as docs/API.md 5.1 recommends.

const BASE = "/api/v1";

let token = null;
let sessionLost = () => {};
let activity = () => {};

export class ApiError extends Error {
  constructor(status, code, message, details, requestId) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details ?? null;
    this.requestId = requestId ?? null;
  }
}

export function setToken(value) {
  token = value;
}

export function hasToken() {
  return token !== null;
}

/** Called when a request that carried a token is answered 401 `unauthenticated`. */
export function onSessionLost(fn) {
  sessionLost = fn;
}

/** Called after every successful authenticated request (it refreshes the idle clock). */
export function onActivity(fn) {
  activity = fn;
}

export function authHeaders() {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function queryString(query) {
  if (!query) return "";
  const parts = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    // A repeatable field (the audit `type` filter) is sent once per value.
    for (const item of Array.isArray(value) ? value : [value]) parts.append(key, String(item));
  }
  const text = parts.toString();
  return text ? `?${text}` : "";
}

async function request(method, path, { body, query, signal, quiet } = {}) {
  const headers = { Accept: "application/json", ...authHeaders() };
  const init = { method, headers, signal, cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(BASE + path + queryString(query), init);
  } catch (cause) {
    if (cause && cause.name === "AbortError") throw cause;
    throw new ApiError(0, "unreachable", "The PortLock service cannot be reached. Is it still running?");
  }
  if (response.status === 204) {
    if (token && !quiet) activity();
    return null;
  }
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const err = payload && payload.error ? payload.error : {};
    const error = new ApiError(
      response.status,
      err.code || "error",
      err.message || `The service answered ${response.status}.`,
      err.details,
      err.request_id,
    );
    if (response.status === 401 && error.code === "unauthenticated" && token) sessionLost(error);
    throw error;
  }
  if (token && !quiet) activity();
  return payload;
}

export const api = {
  get: (path, query, options) => request("GET", path, { query, ...options }),
  post: (path, body, options) => request("POST", path, { body: body ?? undefined, ...options }),
  put: (path, body, options) => request("PUT", path, { body, ...options }),
  patch: (path, body, options) => request("PATCH", path, { body, ...options }),
  del: (path, query, options) => request("DELETE", path, { query, ...options }),
};

/** Path segments from device or user data are encoded; the fingerprint's colon is kept readable. */
export function seg(value) {
  return encodeURIComponent(String(value)).replace(/%3A/gi, ":");
}
