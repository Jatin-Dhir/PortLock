// Pending devices: the ones policy could not decide, waiting for an operator.

import { h, replace } from "../dom.js";
import { mountPending } from "../pending.js";
import { state } from "../store.js";
import { isWatchOnly } from "../truth.js";
import { pageHead } from "../ui.js";

export function mount(root) {
  const host = h("div", {});
  replace(
    root,
    pageHead(
      "Pending devices",
      isWatchOnly(state.status)
        ? "Policy could not decide these. They are not blocked while they wait: PortLock is watch-only on this computer. A decision here applies to this device only."
        : "Policy could not decide these. In enforce mode they are blocked while they wait; in monitor mode they are not. A decision here applies to this device only.",
    ),
    host,
  );
  return mountPending(host);
}
