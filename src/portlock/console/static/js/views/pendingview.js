// Pending devices: the ones policy could not decide, waiting for an operator.

import { h, replace } from "../dom.js";
import { mountPending } from "../pending.js";
import { pageHead } from "../ui.js";

export function mount(root) {
  const host = h("div", {});
  replace(
    root,
    pageHead(
      "Pending devices",
      "Policy could not decide these. In enforce mode they are blocked while they wait; in monitor mode they are not. A decision here applies to this device only.",
    ),
    host,
  );
  return mountPending(host);
}
