// Formatting for people: times, durations, sizes, device identifiers. All of it returns
// text or text-only elements.

import { h } from "./dom.js";

const dateTime = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});
const timeOnly = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});
const numbers = new Intl.NumberFormat();

export function count(n) {
  return numbers.format(n);
}

export function plural(n, one, many) {
  return `${count(n)} ${n === 1 ? one : many}`;
}

function parse(iso) {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : new Date(t);
}

/** "16 Nov, 14:03:22" in the viewer's zone; the exact UTC instant is in the tooltip. */
export function timeEl(iso) {
  if (!iso) return h("span", { class: "faint" }, "never");
  const date = parse(iso);
  if (!date) return h("span", {}, String(iso));
  return h("time", { datetime: iso, title: iso.replace("T", " ").replace("Z", " UTC") }, dateTime.format(date));
}

export function clockText(iso) {
  const date = iso ? parse(iso) : null;
  return date ? timeOnly.format(date) : "";
}

export function agoText(iso, now = Date.now()) {
  const date = iso ? parse(iso) : null;
  if (!date) return "";
  const s = Math.max(0, Math.round((now - date.getTime()) / 1000));
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function mmss(totalSeconds) {
  const s = Math.max(0, Math.round(totalSeconds));
  const hours = Math.floor(s / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const seconds = s % 60;
  const two = (n) => String(n).padStart(2, "0");
  return hours > 0 ? `${hours}:${two(minutes)}:${two(seconds)}` : `${two(minutes)}:${two(seconds)}`;
}

// One timer updates every live clock on the page, and forgets the ones that were removed.
const liveItems = new Set();
setInterval(() => {
  for (const item of liveItems) {
    if (!item.el.isConnected) {
      item.missed += 1;
      if (item.missed > 3) liveItems.delete(item);
      continue;
    }
    item.missed = 0;
    const text = item.fn();
    if (item.el.textContent !== text) item.el.textContent = text;
  }
}, 1000);

function liveText(el, fn) {
  el.textContent = fn();
  liveItems.add({ el, fn, missed: 0 });
  return el;
}

/** "5 min ago", kept current. */
export function liveAgo(iso) {
  const el = h("time", { datetime: iso, title: iso ? iso.replace("T", " ").replace("Z", " UTC") : null });
  return liveText(el, () => (iso ? agoText(iso) : "never"));
}

/** A clock counting down to `deadlineMs` (epoch milliseconds), as mm:ss. */
export function countdown(deadlineMs, className = "") {
  const el = h("span", { class: `num ${className}`.trim() });
  return liveText(el, () => mmss((deadlineMs - Date.now()) / 1000));
}

export function remainingSeconds(deadlineMs) {
  return Math.max(0, Math.round((deadlineMs - Date.now()) / 1000));
}

export function hex(n, width = 4) {
  return Number.isInteger(n) ? n.toString(16).padStart(width, "0") : "????";
}

export function vidPid(device) {
  return `${hex(device?.vendor_id)}:${hex(device?.product_id)}`;
}

export function shortFp(fp) {
  return fp && fp.length > 18 ? `${fp.slice(0, 10)}…${fp.slice(-5)}` : fp || "";
}

export function bytes(n) {
  if (!Number.isFinite(n)) return "unknown size";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${unit === 0 ? value : value.toFixed(1)} ${units[unit]}`;
}

export function titleCase(text) {
  return String(text).replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}
