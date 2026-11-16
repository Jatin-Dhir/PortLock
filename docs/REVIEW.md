# Code review of the upper layers

On 16 November 2026 two independent reviewers read the code that sits on top of the
detection and enforcement backends: the service pipeline (`core/service.py`, `core/store.py`),
the lockdown manager, the enforcers, the daemon, the console API and the command line. The
design had been reviewed twice before it was built (`DESIGN.md` section 14); this is the
first review of the code of these layers.

The two reviewers looked through different lenses.

- **Security.** What can a local program, an operator, or someone holding a stolen session
  token do that they should not be able to do? Can the safeguards be turned against the
  operator?
- **Correctness.** Does the code do what `DESIGN.md` says in the cases that are not on the
  happy path: restarts, clock changes, races, failures half way through?

Both reproduced their findings on the simulated machine (fake backend, fake enforcer, fake
clock and timer) with throwaway scripts and tests. **No enforcement mechanism was run
against a real device, a real registry, a real `/sys` or a real access list,** by the
reviewers or by the fixes. Where a fix touches such a mechanism, the table says so.

The reviewers reported 18 findings. One was found by both (the network lockout and the local
command line), so there are **17 findings**: 4 high, 9 medium and 4 low. The severities are
the reviewers'. Each fix has a regression test that fails without it, in
`tests/integration/test_review_fixes.py` and `tests/unit/test_review_api.py`, or in the test
file of the module concerned. **16 are fixed. 1 is fixed in part: its remainder is open and
explained in row 1.** Nothing was rejected.

| # | Severity | Where | What is wrong | Status |
| --- | --- | --- | --- | --- |
| 1 | high | `core/service.py`, `lockdown/manager.py` (`rollback`) | While default-deny was on (a lockdown, or the standing setting), convergence authorized every device that was not blocked by PortLock, not only the ones default-deny had held back. A built-in camera that the user or an administrator had disabled was switched on again, and nothing recorded it. A clean stop, the kill switch and `recover` did the same to every present device. | **Fixed in part.** PortLock now authorizes a device only if it blocked it or if it arrived under default-deny and has not been admitted yet (`_holds_back`). Convergence, a clean stop and the kill switch at run time follow that rule. **Open:** `portlock recover` and a kill switch found at start run without the database, so they cannot tell a device default-deny held back from one someone else disabled, and they still readmit every present device. That is deliberate: the alternative is a keyboard that stays dead. Tests: `test_a_lockdown_does_not_re_enable_...`, `test_standing_default_deny_...`, `test_a_clean_stop_does_not_re_enable_...`. |
| 2 | high | `console/api.py` (`users_recovery_codes`) | A session token alone could issue recovery codes for its own account. The new codes lift a lockdown and reset the password, so a stolen token became permanent control of the account, and issuing codes voided the operator's offline set. | **Fixed.** The caller's own current password is required (also when an administrator issues codes for someone else). The check is rate limited like a login and is not itself a sign-in. The command line and the web console ask for it. Tests: `test_a_bare_token_cannot_mint_recovery_codes`, `test_minted_codes_cannot_lift_...`. |
| 3 | high | `lockdown/manager.py` (timer), `console/cli.py` (`recover`) | The operating-system dead-man timer was armed for the exact expiry. The service lifts a second later, so `portlock recover` started while the service was still running, wrote the kill-switch file, and the service then switched itself to monitor mode for good. | **Fixed.** The timer is armed 30 seconds after the expiry, on engage, renewal, resume and clock changes, so the service lifts first. The timer runs `recover --dead-man`, which does nothing when a service is running. Tests: `test_the_lockdown_timer_is_armed_after_...`, `test_the_service_ends_an_expiring_lockdown_...`, `test_the_dead_man_recover_leaves_a_running_service_alone`. |
| 4 | high | `core/service.py` (`AuditWriter`) | After a restart the clock-rollback high-water mark was taken from the last audit record, not the latest time in the log. A rolled-back clock followed by a restart brought back an expired rule or grant. A unit test asserted the wrong value. | **Fixed.** `AuditLog.newest_timestamp()` returns the highest timestamp and the writer starts from it. `test_service_audit.py` now expects the later time. New tests cover an expiring rule across a restart and within one run. |
| 5 | medium | `service/daemon.py`, `console/api.py` (`lockdown_lift`) | The network lockout also applied to `portlock lockdown lift` from the elevated command line, against DESIGN 14.21: a local program could keep the administrator from lifting by failing logins for the administrator's name. Found by both reviewers. | **Fixed.** A lift that carries the command-line secret is checked on the local channel, which no lockout refuses; `portlock lockdown lift` sends the secret. A lift from the network is still refused during a lockout. Tests: `test_the_local_cli_lifts_...`, `test_a_lift_from_the_network_is_still_refused_...`, and an end-to-end command-line test. |
| 6 | medium | `console/cli.py` (`cmd_recover`) | The dead-man timer's `portlock recover` always created the kill-switch file. A lockdown that ran out while the machine was off, or a service that was down, left enforcement off for good. | **Fixed.** The timer runs `recover --dead-man`: it restores the journal and leaves the marker but never creates the kill-switch file. An operator's own `recover` still does. Test: `test_the_dead_man_recover_restores_without_the_kill_switch`. |
| 7 | medium | `lockdown/manager.py` (`rollback`) | `recover` and rollback skipped hubs when readmitting devices after default-deny. A dock plugged in while the service was down stayed unauthorized, and the keyboard behind it never appeared. | **Fixed.** Hubs are readmitted, and first. Test: `test_recover_readmits_a_hub_and_the_keyboard_behind_it`. |
| 8 | medium | `console/api.py` (`refine_change`) | An operator, who may engage but not lift, could lift an administrator's lockdown by cancelling its pending change within the 60 seconds, with no password. | **Fixed.** Cancelling a lockdown change needs `lift_lockdown`. The cancel is still audited as `change.rolled_back` with the person's name; the `lockdown.lifted` record it causes still names `system`. Tests: `test_an_operator_cannot_lift_...`, `test_an_operator_can_still_confirm_...`. |
| 9 | medium | `guard/seams.py` (`IcaclsDirPrivacy`) | On Windows the state directory could be created by a standard user before installation. `ensure_private` fixed the entries but not the owner, and an owner can rewrite the access list again later. | **Fixed, not run against a real access list.** `ensure_private` now takes ownership for the Administrators group, including what is already inside, before it grants anything, and fails closed if it cannot. `check` still cannot see the owner (`icacls` does not print it), so the guarantee is that `ensure_private` runs at every start. Tests use the fake command runner only. |
| 10 | medium | `core/service.py` (`_queue_scan`) | Requesting a manual rescan erased the previous verdict, so a device made read-only by a scan became writable until the rescan finished. | **Fixed.** The old verdict stays until the new scan replaces it. Test: `test_a_manual_rescan_keeps_the_device_read_only_...`. |
| 11 | medium | `core/service.py` (`_schedule_scans`) | With `scan: required`, a volume mounted after a clean scan was writable until it was scanned. | **Fixed.** A change of scan state re-evaluates the device, so it is read-only from the moment the new volume is queued. Test: `test_a_volume_mounted_after_a_clean_scan_...`. |
| 12 | medium | `core/service.py` (`_on_arrival`) | A device that a lockdown exempts (connected before it began) lost the exemption when the service restarted, because its connection time was reset to the restart. It could be blocked, the operator's only way in included. | **Fixed.** A device present at start keeps the connection time of the previous run if the backend's connection token proves it is the same connection. Without a token it still counts as new. Tests: `test_a_device_exempt_from_a_lockdown_stays_exempt_...`, `test_a_device_plugged_in_while_the_service_was_down_is_not_exempt`. |
| 13 | medium | `core/store.py` (`VOLATILE_KINDS`) | A Windows disk read-only record was not volatile, so it outlived the stick and the next stick given the same disk number inherited it: it was never journaled for the new device and never released. | **Fixed.** The kind is volatile and is discarded when the device leaves. Keying records by the owning device as well was not done. Test: `test_a_windows_disk_record_is_volatile_...`. The Windows enforcer was not run. |
| 14 | low | `console/api.py` (`_Server`) | A local program could hold all 32 request slots with connections that never finish their request, shutting out the command line and the console. | **Fixed.** When the slots are full, the connection that has waited longest for its request head is cut and its slot goes to the newcomer. A connection with a complete head is never cut. Tests: `test_idle_connections_do_not_shut_out_...`, `test_a_connection_with_a_complete_head_is_never_evicted`. |
| 15 | low | `tests/integration/test_expiration.py`, `tests/unit/test_service_audit.py` | The clock-rollback tests could not detect a broken high-water mark: the grant was already expired in the store, and rules and time windows were not covered. | **Fixed.** The shipped rollback tests stay as they are, and the one that asserted the wrong value is corrected (row 4). New tests use a rule's `expires`, within one run and across a restart. |
| 16 | low | `core/service.py` (`set_scope`) | Rolling back an unconfirmed scope widening could widen the scope again after the operator had narrowed it. | **Fixed.** Setting a scope first cancels any widening that waits for confirmation, then decides from where that leaves things, so a widening that is still wider than the last confirmed scope needs confirmation. Tests: `test_narrowing_the_scope_cancels_...`, `test_narrowing_to_a_scope_wider_...`. |
| 17 | low | `core/service.py` (`AuditWriter`) | When the audit backlog was full a failed flush dropped the newest events, and an event written at the wrong moment could land ahead of an older one. | **Fixed.** An event stays in the backlog until it is written, so nothing overtakes it, and the oldest is always the one dropped. Tests: `test_a_new_event_never_overtakes_...`, `test_a_failed_flush_keeps_the_oldest_event_first`. |

## What the fixes changed in the documents

`DESIGN.md` section 14 has four new items (24 to 27); they amend 14.12, 14.16 and 14.21.
`API.md` documents the `current_password` field of the recovery-codes request, the local
channel for lifts, the extra permission for cancelling a lockdown, and how idle connections
are handled. `OPERATIONS.md` describes `recover --dead-man` and the timer's 30-second grace,
and corrects a sentence that said a refused `recover` leaves the kill switch behind: the code
checks for administrator rights before it writes anything, and a test says so.

Existing tests were edited in seven files, and none was weakened or skipped. Each asserted
a contract that a fix changed, or (row 4) a wrong value:

- the lockdown tests that read the dead-man timer's time now expect the 30-second grace
  (`test_lockdown.py`, `test_lockdown_safeguards.py`);
- the rollback test now expects the hub to be readmitted (row 7);
- the dead-man command ends in `--dead-man` (`test_guard_factory.py`);
- `ensure_private` runs `/setowner` first and passes `/T /C` to the grant
  (`test_guard_seams.py`);
- the recovery-codes endpoint takes `current_password` (`test_console_api_endpoints.py`);
- the busy-server test fills the slots with requests in flight, because idle connections no
  longer hold them (`test_console_api_http.py`, row 14);
- `test_service_audit.py` expects the later time (row 4).
