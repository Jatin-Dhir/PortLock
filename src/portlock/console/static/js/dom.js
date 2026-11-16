// DOM construction. Everything that reaches the page goes through createElement and
// createTextNode, so text from a device (names, serials, volume labels) can never become
// markup. There is deliberately no helper here that takes an HTML string.

const PROPERTY_KEYS = new Set(["value", "checked", "disabled", "hidden", "selected", "indeterminate"]);

function append(parent, child) {
  if (child === null || child === undefined || child === false || child === true) return;
  if (Array.isArray(child)) {
    for (const item of child) append(parent, item);
  } else if (child instanceof Node) {
    parent.appendChild(child);
  } else {
    parent.appendChild(document.createTextNode(String(child)));
  }
}

/**
 * Build an element. `props`: `class`, `dataset`, `on<event>` handlers, `value`/`checked`/
 * `disabled`/`hidden` (set as properties, after the children exist), anything else as an
 * attribute. `style` is refused: the content security policy blocks inline styles, and a
 * page that needs a dynamic size sets a custom property with `setVar`.
 */
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  const deferred = [];
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === null || value === undefined || value === false) {
        if (PROPERTY_KEYS.has(key) && value === false && key !== "hidden") deferred.push([key, false]);
        continue;
      }
      if (key === "class") el.className = value;
      else if (key === "dataset") Object.assign(el.dataset, value);
      else if (key === "style") throw new Error("inline styles are blocked by the content security policy");
      else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
      else if (PROPERTY_KEYS.has(key)) deferred.push([key, value]);
      else el.setAttribute(key, value === true ? "" : String(value));
    }
  }
  for (const child of children) append(el, child);
  for (const [key, value] of deferred) el[key] = value;
  return el;
}

/** Replace everything inside `el` with `children`. */
export function replace(el, ...children) {
  el.replaceChildren();
  for (const child of children) append(el, child);
  return el;
}

/** A document fragment holding `children`. */
export function frag(...children) {
  const fragment = document.createDocumentFragment();
  for (const child of children) append(fragment, child);
  return fragment;
}

/** Set a CSS custom property (allowed under the content security policy, unlike style=""). */
export function setVar(el, name, value) {
  el.style.setProperty(name, value);
}

let counter = 0;
/** A page-unique id, for tying labels to controls. */
export function uid(prefix = "f") {
  counter += 1;
  return `${prefix}-${counter}`;
}
