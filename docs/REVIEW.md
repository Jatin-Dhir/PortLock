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

## Watch-only

Watch-only (`DESIGN.md` 14.28: a PortLock process that is not elevated, or whose files are
in a user's folders, changes nothing on the computer outside its own folder) was reviewed
in three rounds on 16 and 17 November 2026. Each round's reviewers worked on the code as
it then stood, through their own lenses, and reproduced what they found with throwaway
scripts on fakes and, for the live findings, with the real command line under a flight
recorder that refuses every program start, registry write and mutating seam. The
findings chosen for it (the most serious ones) were then re-checked, each by a separate
skeptic who tried to refute it. **No enforcement mechanism was run against a real device, a real
registry or a real access list** by the reviewers or by the fixes.

The counts come from the review journals (one result per reviewer and per skeptic); the
severities are the reviewers', and a skeptic's verdict may have lowered one.

| Round | What was reviewed | Reviewers (lenses) | Findings | Re-checked | Real | Fixed by |
| --- | --- | --- | --- | --- | --- | --- |
| 1, 16 November | the first watch-only change (per-user directories and a gate that opened in enforce mode), uncommitted on top of `d781c2a` | 3 (regressions for elevated installations, bypasses, an ordinary user's first run) | 26: 6 high, 11 medium, 9 low | 9 | 9 | `72c451f` (the design was corrected: watch-only is decided once per process, the mode does not decide it) |
| 2, 17 November | `72c451f` and `6419ea4` | 3 (the guarantee, an administrator's installation, the console) | 20: 3 high, 5 medium, 12 low | 7 | 7 | `36012b4` |
| 3, 17 November | `36012b4` | 2 (logic, an administrator's installation) | 14: 2 high, 4 medium, 8 low | 4 | 4 | the fourth pass, the commit after `36012b4` |

Every finding that was re-checked was found real; none was refuted. Below, one line for
each finding that was re-checked or that a reviewer rated high or medium (in round 3, every
finding). "Re-checked" marks the ones a skeptic confirmed.

**Round 1** (fixed by `72c451f` unless the line says otherwise)

- high, re-checked: a lockdown engaged while watch-only became real when the gate opened,
  without its dead-man timer. Fixed: the gate is gone; a watch-only process refuses a
  lockdown.
- high, re-checked: an elevated system-wide installation in monitor mode never made its
  directories private. Fixed: they are made private at every start (14.18).
- high, re-checked (medium in the verdict): a watch-only start after an enforcing run left
  its changes in place and said nothing was changed. Fixed: such a start is refused.
- medium: a watch-only start closed journal hold records. Fixed: a stand-in's result never
  closes a record.
- high: in monitor mode a lockdown on a system-wide installation did nothing but reported
  active. Fixed: there it blocks for real, as in section 11.
- medium: `recover` and the kill switch did nothing against a running watch-only service.
  Fixed by the corrected design: a watch-only process changes nothing, so there is nothing
  to undo, and `recover` refuses a per-user home.
- high, re-checked: in watch-only, approving a drive or requesting a scan started
  `MpCmdRun.exe`. Fixed: a watch-only scanner has no antivirus engine.
- medium, re-checked: the stand-in's "ok" closed holds of devices that stayed blocked.
  Fixed: only a result that really changed the system closes a record.
- medium, re-checked: the console said a watch-only lockdown blocked all removable storage.
  Fixed: watch-only is its own posture in the console.
- medium: an elevated `recover` trusted a journal in a per-user folder. Fixed: it refuses
  that folder.
- high, re-checked: the console never read `mode.watch_only` and said a lockdown or
  default-deny was blocking. Fixed.
- medium, re-checked (low in the verdict): no test caught watch-only reaching `icacls`
  when a kill-switch file exists. Fixed: tests that fail under both mutations.
- medium, re-checked: a killed service left files that ended the next start. Fixed.
- medium: a failed first `init` lost the audit key for good. Fixed: nothing is created
  until a password is accepted.
- medium: the online doctor said the directories were private in watch-only. Fixed: it
  says they were not checked.
- medium: the README did not warn against an administrator window. Fixed: it does, and
  `init` and `run` say which installation an elevated window uses.
- medium: starting in the stored mode setting was untested. Overtaken: the start-up path it
  names (the gate opening for a stored "enforce") was removed in `72c451f`; the mode no
  longer decides watch-only.

**Round 2** (all fixed by `36012b4`)

- medium, re-checked (low in the verdict): in watch-only, device rows showed solid
  "Denied" and "Read-only" chips under a legend saying solid means really changed. Fixed:
  intended chips are dashed.
- high, re-checked: a redirected AppData made an administrator's installation watch-only
  and `recover` refuse it. Found by two reviewers. Fixed: a profile variable on another
  computer is skipped.
- medium, re-checked: another account's folder counted as system-wide. Fixed.
- medium, re-checked: a journal line this version cannot parse was invisible to the start
  refusal, and the shutdown erased it. Fixed.
- high, re-checked: `init` beside a running service broke offline audit verification for
  good. Fixed: `init` refuses while a service runs from the same folder.
- medium, re-checked: `init` set aside a key store whose key had been shown. Fixed.
- medium: the location reason always said "this user's own folders". Fixed: each message
  is worded from the cause.

**Round 3** (all fixed by the fourth pass; each fix has a test that fails without it, in
`tests/unit/test_watch_only_pass4.py`, `tests/unit/test_console_js_truth.py` and the live
test)

- high, re-checked: two `init`s, or a service that came and went while `init` waited, left a
  shown key that did not verify, a second administrator, or no key. Fixed: `init` takes a
  snapshot of everything it decides on before the prompt and again under the lock, and
  changes nothing when they differ.
- high, re-checked (medium in the verdict): under the SYSTEM account another user's
  profile counted as system-wide. Fixed: the profiles folder comes from the registry (read
  only), `SystemDrive` and `PUBLIC` as well, and fails closed when none is known.
- medium, re-checked; found by both reviewers: on Python 3.13 and later `stop` and
  `status` said "not running" for a running service whose folder this user cannot search.
  Fixed: only a missing lock file means free.
- medium: homes outside `/home` and `/Users` counted as system-wide for root. Fixed: every
  login account's home in the account database, and `/mnt/<drive>/Users` under WSL.
- medium, re-checked: default-deny was reported in force in monitor mode. Fixed: `enabled`
  means in force, `stored` keeps the choice, a note says why; the console shows the stored
  choice with the note; `API.md` corrected.
- low: some names for this computer counted as a remote server. Fixed: trailing dots,
  name resolution (IPv4 and IPv6), own addresses.
- low: the root wording could call another user's home root's own, and `/root` passed
  when `HOME` was unset. Fixed: the account database decides.
- low: `init` said a key store's key was "never shown". Fixed: "that no administrator was
  set up with".
- low: each watch-only journal guard was untested on its own. Fixed: a test for each.
- low: no test for a UNC path to this computer's own address. Fixed.
- low: `API.md`'s settings examples showed the old shape. Fixed.
- low: `stop` said `runtime.json` "cannot be read" when it was read but its service did
  not answer. Fixed: it says the service is probably not running.
- low: the live test could fail without a fault (a port race, a 10-second limit on a whole
  process, a kill before `runtime.json` existed). Fixed, without weakening what it asserts.

**The fourth pass was tested but not reviewed again.** Its fixes have tests that fail
without them and the whole suite passes on Windows and under WSL, but no independent
reviewer has read it.
