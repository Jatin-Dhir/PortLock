// The live event stream. A browser's EventSource cannot send an Authorization header, and
// the token must not travel in a URL, so the stream is read with fetch and parsed here
// (docs/API.md section 7). It resumes with Last-Event-ID and reloads when the server says
// the history is gone.

import { authHeaders } from "./api.js";
import { applyEvent, emit, reloadSoon, state } from "./store.js";

const SILENCE_MS = 45000; // the server sends a keep-alive every 15 s
const MAX_BACKOFF_MS = 15000;

let controller = null;
let lastId = null;
let stopped = true;
let backoff = 1000;
let sessionEnded = () => {};

export function onStreamSessionEnded(fn) {
  sessionEnded = fn;
}

function setLive(value) {
  if (state.live !== value) {
    state.live = value;
    emit("live");
  }
}

function parseFrame(raw) {
  let id = null;
  let event = "message";
  const data = [];
  for (const line of raw.split("\n")) {
    if (line === "" || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    const value = colon === -1 ? "" : line.slice(colon + 1).replace(/^ /, "");
    if (field === "id") id = value;
    else if (field === "event") event = value;
    else if (field === "data") data.push(value);
    else if (field === "retry") {
      const n = Number.parseInt(value, 10);
      if (Number.isInteger(n) && n > 0) backoff = Math.min(Math.max(n, 1000), MAX_BACKOFF_MS);
    }
  }
  if (data.length === 0) return null;
  try {
    return { id, event, data: JSON.parse(data.join("\n")) };
  } catch {
    return null;
  }
}

function handleFrame(frame) {
  if (frame.id) lastId = frame.id;
  switch (frame.event) {
    case "hello":
      backoff = 1000;
      setLive("up");
      if (!frame.data.resumed) reloadSoon();
      break;
    case "reset":
      lastId = null;
      reloadSoon();
      break;
    case "session.ended":
      stopped = true;
      sessionEnded(frame.data.reason);
      break;
    default:
      applyEvent(frame.event, frame.data);
  }
}

async function connect() {
  if (stopped) return;
  controller = new AbortController();
  const mine = controller;
  setLive("connecting");
  let silence = null;
  const arm = () => {
    clearTimeout(silence);
    silence = setTimeout(() => mine.abort(), SILENCE_MS);
  };
  try {
    const headers = { Accept: "text/event-stream", ...authHeaders() };
    if (lastId) headers["Last-Event-ID"] = lastId;
    const response = await fetch("/api/v1/events", {
      headers,
      signal: mine.signal,
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (response.status === 401) {
      stopped = true;
      sessionEnded("revoked");
      return;
    }
    if (!response.ok || !response.body) throw new Error(`stream refused (${response.status})`);
    arm();
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      arm();
      buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
      let end = buffer.indexOf("\n\n");
      while (end !== -1) {
        const frame = parseFrame(buffer.slice(0, end));
        buffer = buffer.slice(end + 2);
        if (frame) handleFrame(frame);
        end = buffer.indexOf("\n\n");
      }
    }
  } catch {
    // Dropped, refused or silent for too long: fall through to the reconnect below.
  } finally {
    clearTimeout(silence);
  }
  if (stopped || mine !== controller) return;
  setLive("down");
  const wait = backoff;
  backoff = Math.min(backoff * 2, MAX_BACKOFF_MS);
  setTimeout(connect, wait);
}

export function startStream() {
  stopped = false;
  lastId = null;
  backoff = 1000;
  connect();
}

export function stopStream() {
  stopped = true;
  if (controller) controller.abort();
  controller = null;
  lastId = null;
  setLive("down");
}
