# PortLock — architecture

This maps `DESIGN.md` onto the modules as they were built. `DESIGN.md` says *what* and
*why*; this says *where* and how the pieces meet. It describes the code in this
repository, and where it quotes a number or a name it was read from the code. Where this
file and `DESIGN.md` disagree, `DESIGN.md` wins (section 14 above all) and this file has a
bug. Where this file and the code disagree, the code is the truth and this file has a bug.

The reference for each module is its docstring; this document does not repeat signatures.
Section numbers and the E and D labels are cited from the source, so they are kept.

---

## 1. The process at a glance

One long-running process (`portlock run`, module `service.daemon`) hosts the device
backend, the pipeline, lockdown, scans, the HTTP API and the web console. The command line
is a second, short-lived process. A **service command** is an HTTP client of the local API.
A **local command** (`init`, `run`, `stop`, `recover`, `policy validate`,
`audit verify --offline`, `doctor --offline`, `service print-unit`/`print-task`, `simulate`,
`user ... --local`) works on files with the operating system's rights.

### 1.1 Files on disk

`state_dir` and `config_dir` come from `Config.paths` (`core.config`): the configuration
file, else `PORTLOCK_HOME` (`<home>/state`, `<home>/config`), else the platform default
(`%ProgramData%\PortLock` for both on Windows; `/var/lib/portlock` and `/etc/portlock`).

| File | Directory | Owner module | Purpose |
| --- | --- | --- | --- |
| `portlock.db` (+ `-wal`, `-shm` while open) | state | `core.db` and every store | every SQL table of every component |
| `portlock.db.damaged-<time>` | state | `service.daemon` | a database that failed its integrity check, renamed aside, never deleted |
| `journal.jsonl` | state | `core.store.RecoveryJournal` | the enforcement journal (3.1.3) |
| `audit.key` | state (by default) | `audit.log.AuditKeyStore` | the MAC key for the **next** audit record; the path is `audit.hmac_key_file` |
| `audit.head` | state | `audit.log` | sequence number and hash of the newest audit record |
| `portlock.lock` | state | `service.daemon.InstanceLock` | single-instance lock (an operating-system lock on one byte) |
| `runtime.json` | state | `service.daemon` | pid, host, port, run id, version and the command-line secret; exists only while running |
| `stop.request` | state | `service.daemon` | written by `portlock stop`; the ticker sees it |
| `last-recover.json` | state | `lockdown.manager` | left by `portlock recover` so the next start can audit it |
| `event-signing.key` | state | `audit.signing` | Ed25519 key for signed checkpoints; created on first use, only with the `signing` extra |
| `portlock.toml` | config | `core.config` | configuration |
| `policy.json` | config | `policy.loader` | the active policy |
| `DISABLE_ENFORCEMENT` | config | `lockdown.manager.KillSwitch` | the kill switch |
| `60-portlock-readonly.rules` | `/etc/udev/rules.d` (Linux) | `guard.linux.enforce` | written only when `baseline_read_only` is on; journaled and removed by restore |

The enforcement journal is a **file, not a table**, because `portlock recover` must work
without the service or the database and a write-ahead record must survive a damaged
database.

### 1.2 Dependency rule (who may import whom)

`tests/unit/test_import_rules.py` parses every module under `src/portlock` with `ast`
(imports inside functions and under `TYPE_CHECKING` count) and checks:

- `policy`, `scan`, `audit`, `auth` and `core.models` do not import `guard`, directly or
  transitively, and do not import `console`, `service` or `lockdown`.
- Only these modules import `guard` at all, and only the listed parts of it:
  `core.store` and `lockdown.manager` (`guard.base`, types only); `core.service`
  (`guard.base`, `guard.safety`); `service.daemon` (`guard`, `guard.base`, `guard.factory`,
  `guard.fake`, `guard.safety`, `guard.seams`); `console.cli` (`guard`, `guard.base`,
  `guard.factory`, `guard.safety`); `console.simulate` (`guard.base`, `guard.fake`,
  `guard.seams`, never the factory).
- Nothing outside `guard` imports `guard.linux` or `guard.windows`. They are reached only
  through `guard.factory`, which imports them inside functions.
- `service.install` imports only `core.config` and `core.errors`. `console.api` imports
  `core.service`, `core.*`, `auth`, `audit` and `lockdown.manager`; the last only for the
  `Credential` value and the error classes it maps to HTTP statuses, and it drives nothing
  there. This is the one deviation from the table that was first drawn up.

Consequences: `core.service` never imports a concrete backend or enforcer; they are
injected. Enforcement is driven from exactly two places, `core.service` (convergence) and
`lockdown.manager.rollback`/`recover`, and both go through a `SafeEnforcer`.

### 1.3 Threads

| Thread | Created by | Does |
| --- | --- | --- |
| main | the operating system | `service.daemon.run`: start-up, waits for a stop event, shutdown |
| `portlock-linux-backend`, `portlock-linux-fallback`, a mount-table thread | `guard.linux` | uevent pump, polling fallback, mount watching; they call `PortLockService.on_backend_event`, which only enqueues |
| `portlock-win-monitor` | `guard.windows.monitor` | device notifications |
| `portlock-pipeline` | `PortLockService.start` | drains the event queue and calls `handle_event` |
| `portlock-ticker` | `service.daemon` | `PortLockService.tick()` once a second; looks for `stop.request` |
| `portlock-scan` | `PortLockService` | runs one scan at a time |
| `portlock-api` | `console.api.ApiServer.start` | the accept loop |
| `portlock-api-N` | `console.api._Server` | one connection, or one event stream; at most 32 in flight, 8 streams |
| `portlock-audit-sink-<name>` | `audit.sinks.FanOut` | delivers records to external sinks |

The HTTP server is a small hand-written one on `socket`, not `http.server`. It refuses
address reuse, has a strict request parser, and loads the static console files into memory
at start.

### 1.4 Locks and their order

Outermost first. A thread takes a lock only if it holds none that is further down.

1. **L1 `PortLockService._lock`** (`RLock`): serialises everything that evaluates, enforces
   or changes lockdown, mode, policy or settings.
2. **L2 `RecoveryJournal._lock`**.
3. **L3 `Database._lock`** (re-entrant; taken by every store).
4. **L4 leaf locks**: `EventBus` internals, `AuditLog` hand-off to its sink.

Rules that follow: enforcer calls are made holding L1 and nothing else, never inside a
database transaction (operating-system calls can take seconds); `AuditLog.append` is never
called inside a transaction that might roll back (the key store advances when it returns);
event-bus handlers run on the publishing thread and must not call back into the service or
block (the API's stream handler only puts the event on a bounded queue); API threads hold no
lock while reading or writing a socket; read methods of `PortLockService` take no L1, they
read the store and an immutable snapshot, so the console stays responsive during a slow
enforcement; `LockdownManager` has no lock of its own and is called with L1 held.

---

## 2. Contracts shared by several modules

### 2.1 Identifiers, time and actors

- Timestamps in SQL, the journal, audit `data` and the API are `core.clock.utc_iso`
  strings. Durations are integer seconds or minutes. There are **no floats** anywhere that
  reaches the audit log, the journal or the API.
- A *connection* is one continuous presence of one device as observed by one run of the
  service, with an integer `connection_id`. A *service run* has a `run_id`, 16 lowercase
  hex characters.
- `actor` strings: a PortLock user name; `system` for what the service does on its own;
  `local-console` for commands authorised by operating-system rights alone.
- Fingerprints are `Fingerprint` objects inside the service and their `plk1:` string across
  SQL, the journal, audit and the API.

### 2.2 The enforcer implementation contract (both platforms)

`guard/base.py` defines the interface (`block`, `unblock`, `set_read_only`, `eject`,
`set_default_deny`, `restore`, `capabilities`). Both enforcers additionally keep these.

- **E1 Seams.** Every operating-system access goes through an injected seam object
  (`guard/seams.py`: `SysfsIO`, `BlockIO`, `RuleFileIO`, `RegistryIO`, `CfgMgrAPI`,
  `DiskIO`, `CommandRunner`, `ExternalTimer`, `DirPrivacy`), each with a real class and a
  fake. The enforcer classes have a `system()` constructor that wires the real ones.
- **E2 Write-ahead.** The constructor takes `write_ahead`. Immediately before each
  operating-system write the enforcer reads the current value, builds the `JournalEntry`
  and calls `write_ahead`. If that raises, the write is not made and the call returns
  `ok=False, error="journal unavailable: ..."`.
- **E3 Complete undo.** `result.undo` lists every change the call actually made, in order,
  also when `ok` is false (partial application).
- **E4 Admission is not an undoable change.** When `unblock` admits a device that was
  unusable only because default-deny kept it out, the change of the device's own state is
  not listed in `undo`; restoring "the previous value" would lock it out again.
- **E5 Restore.** `restore(entries)` needs nothing but the entries and works in a process
  that never made the change. It processes them newest first. Every entry is validated
  before anything is written: the kind must belong to the platform and the target must be
  one of the fixed, named targets. A value is reverted only if it still equals what was
  applied; otherwise it is left and named in `detail` (DESIGN 14.17).
- **E6 Kinds.** `guard.base.JournalKind` is the closed vocabulary: `sysfs_authorized`,
  `sysfs_authorized_default`, `block_read_only`, `udev_rule` (Linux); `win_devnode`,
  `win_disk_read_only`, `win_policy_value` (Windows); `fake` (the simulator). The service
  also writes `hold` records (3.6.6). `core.store` classes them: *volatile* (the operating
  system forgets them when the device leaves) are `sysfs_authorized`, `block_read_only` and
  `fake`; *global* (shared by several devices, always stored with the `global` scope) are
  `sysfs_authorized_default`, `udev_rule` and `win_policy_value`.
- **E7 Already unusable.** `block()` on a device that default-deny already keeps out
  returns `ok=True, changed=False, tier=preventive`.
- **E8 Bounded.** Subprocesses go through a `CommandRunner` with a timeout (8 s for the
  Linux commands) and an argument list, never a shell string.
- **E10 Shared mechanisms.** Where read-only can only be done class-wide (the Windows
  `Deny_Write` baseline), the mechanism string ends with `(class-wide)`.
- **E12 Pre-arming.** On Linux the baseline udev rule makes every USB disk read-only at
  `add`, before anything can mount it; `set_read_only(device, False)` releases an approved
  device. It is a standing baseline, not per device.
- **E13 Mechanism strings** are stable identifiers used in audit records and the API.
  Linux: `sysfs:authorized`, `sysfs:authorized_default`, `sysfs:remove`, `blkroset`,
  `udev-rule+blkroset`, `udev-rule`, `journal:restore`. Windows: `cfgmgr:disable-devnode`,
  `cfgmgr:request-eject`, `policy:device-install-restrictions`,
  `policy:removable-storage-deny-write(class-wide)`, `disk:read-only-attribute`,
  `journal:restore`. `SafeEnforcer` adds `dry-run`, `refused`, `out-of-scope`, `error` and
  `unsupported`.

(The first draft also numbered E9, how long capabilities may be cached, and E11, the error
for read-only on a device without storage. Neither is a contract the code keeps: the
service itself never asks for read-only on a device without storage.)

The exact paths, values and failure modes behind each mechanism are in
`docs/enforcement/linux.md` and `docs/enforcement/windows.md`. When a mechanism is
unavailable or marked UNVERIFIED there, the enforcer reports the capability as false; it
does not substitute an undocumented one.

### 2.3 `SafeEnforcer`

`SafeEnforcer` fixes `dry_run` at construction, and a dry-run instance passes **nothing**
through, restoring calls included. `core.service` therefore builds two wrappers around the
raw enforcer sharing one context provider: `live` (`dry_run=False`) and `dry`. Everything
that releases, admits or restores goes through `live` whatever the mode; `dry` records what
enforce mode would have done. `live` never refuses `restore`, `unblock`,
`set_read_only(device, False)` or `set_default_deny(False)`. It adds
`set_baseline_read_only`. Restricting calls are refused for protected devices
(mechanism `refused`) and answered `out-of-scope` for devices outside the enforcement
scope, so the two are never confused.

### 2.4 Audit conventions

- Only the event names in section 8 are used; the registry (`audit.events.REGISTRY`) is
  strict and refuses others.
- `device_fp` is set on every event about one device.
- `data` holds JSON scalars, lists and objects with ASCII keys; no floats; never a
  password, token, recovery code or key (`audit.log` redacts by key name as a safety net).
  Device descriptions go in as `UsbDevice.to_dict()` with long mount points truncated to
  256 characters.
- Every audit record the service writes is followed by an `audit.appended` bus event. The
  bus topics the service publishes, and their payloads, are the events of `API.md` 7.3.

---

## 3. Modules

### 3.1 `core/store.py` — state store and recovery journal

Persists what PortLock has seen and decided in SQLite, and keeps the enforcement journal
in a crash-safe file. It holds no policy and makes no decisions.

#### 3.1.1 Tables

All are created by migrations registered under component names (`core.db`), so each
component evolves on its own.

| Component | Tables |
| --- | --- |
| `store` | `devices`, `connections`, `decisions`, `scans`, `settings`, `enrolments`, `lockdown_state` (one row), `lockdown_history`, `pending_changes` |
| `audit` | `audit_log` (with triggers refusing `UPDATE`, `DELETE` and out-of-sequence `INSERT`) |
| `auth` | `auth_users`, `auth_recovery_codes`, `auth_throttle`, `auth_sessions` |
| grants | `grants` |
| scan | `scan_hashes` |

Decision rows are the queryable history; the audit log is the tamper-evident one. Nothing
is pruned automatically in this version.

`settings` keys are a closed set (`store.SETTING_KEYS`), each validated:

| key | value | meaning |
| --- | --- | --- |
| `mode` | `"monitor"` or `"enforce"` | the mode chosen at run time; overrides `Config.mode` |
| `scope` | one of the three scopes | overrides `Config.scope`; changed by a confirmed change |
| `default_deny` | boolean | whether default-deny is wanted |
| `protected_fingerprints` | array of fingerprints | administrator-pinned protected devices (on any port) |
| `scan.enabled` | boolean | overrides `Config.scan.enabled` |
| `lockdown.default_minutes` | integer | overrides `Config.lockdown.default_minutes` |
| `service.run` | `{"run_id","started_at"}` | present while a run is alive; left behind by a crash |
| `policy.last_good` | `{"hash","policy"}` | the last policy the service accepted from the file |

`enrolments` holds `(fingerprint, bus_path)` pairs with a label and who enrolled them. An
enrolment protects a device only when both match (DESIGN 14.1).

Every `StateStore` method is one transaction; `limit` is clamped to 1 to 500; unknown
change keys, setting keys and ids raise `StoreError` (a programming error); a row whose
JSON is damaged is skipped by list methods and reported by get methods.

#### 3.1.2 `StateStore`

The store's API (devices, connections, decisions, scans, enrolments, settings, lockdown
rows, pending changes) is in the module. Connection states are `new`, `protected`,
`allowed`, `read_only`, `pending`, `denied`; scan states `none`, `waiting`, `queued`,
`running`, `clean`, `suspicious`, `malicious`, `incomplete`, `error`; decision outcomes
`undetermined`, `not_needed`, `applied`, `would_apply`, `failed`, `refused`, `unsupported`.

#### 3.1.3 `RecoveryJournal`

A UTF-8 file, one canonical-JSON record per line, append-only between compactions,
owner-only, `fsync`ed. Two record shapes: `open` (id, time, scope, action, fingerprint and
the entry with kind, target, previous and applied value) and `close` (id, time, reason).

**The journal rule.** There is at most one open record per `(kind, target)`. Its `previous`
is the *baseline*: the value before PortLock first touched that target. `write_ahead(entry)`
(inside `recording(scope, action, fingerprint)`): if an open record exists, nothing; if the
action restricts (`block`, `read_only`, `default_deny_on`) or `previous` is unknown, append
an `open` record and `fsync`; otherwise nothing, because a releasing call over an existing
value must never create a baseline whose restoration would restrict. Outside `recording()`
it raises `StoreError` and the enforcer refuses the write (E2). `record(result)` then
closes records whose value returned to baseline and records opened for changes that did
not happen (`not applied`). `add_hold` appends a `hold` record for a device that was
already unusable when PortLock decided to block it. `discard_volatile(scope)` closes the
open volatile records of a device that left.

Loading replays the file; a torn final line or an invalid line is skipped and counted in
`corrupt_lines`. Entries are validated on replay against the fixed list of kinds and
targets, so a tampered journal cannot make a privileged restore write elsewhere.

### 3.2 `guard/linux/` — Linux backend and enforcer

*Backend* (`backend.py`, `sysfs.py`, `netlink.py`, `mounts.py`): enumerates from sysfs, maps
volumes from the mount table, listens on the kernel uevent socket with a polling fallback,
and ignores uevent content (it re-reads sysfs). Read-only.

*Enforcer* (`enforce.py`):

| Method | Mechanism | Journal kind | Tier |
| --- | --- | --- | --- |
| `block` | write `0` to the device's `authorized` | `sysfs_authorized` | reactive; preventive if E7 |
| `unblock` | write `1` (E4 applies) | `sysfs_authorized` | |
| `set_read_only(True)` | `BLKROSET` on the disk and every partition that exists; where the baseline rule is in place the storage was read-only from the start | `block_read_only` | reactive, best effort; preventive under the baseline |
| `set_read_only(False)` | clear `BLKROSET` | `block_read_only` | |
| `eject` | write `1` to `remove` | none (no undo in software) | reactive |
| `set_default_deny(True)` | write `0` to each host controller's `authorized_default` | `sysfs_authorized_default` | preventive for later arrivals |
| `set_baseline_read_only(True)` | write `60-portlock-readonly.rules` to `/etc/udev/rules.d` and reload udev | `udev_rule` | preventive |
| `restore` | per kind, validated (E5) | | |

The enforcer refuses any instance id that does not resolve to a directory under sysfs's
`devices`, and never touches a rules file it did not write. It reports a running USBGuard
(by its configuration file) as a conflict. `system_device_ids` maps the mounts `/`,
`/boot`, `/boot/efi`, `/efi`, `/usr`, `/var` and `/etc` through `/sys/dev/block`, following
`slaves/`, to the USB devices they sit on.

### 3.3 `guard/windows/` — Windows backend and enforcer

*Backend* (`api.py`, `monitor.py`, `enumerate.py`, `volumes.py`): `ctypes` only. Device
notifications through `CM_Register_Notification` with a polling fallback, enumeration,
device-to-volume mapping. Read-only; importing it on another platform is safe.

*Enforcer* (`enforce.py`): `ctypes` and `winreg`, behind `CfgMgrAPI`, `RegistryIO` and
`DiskIO`.

| Method | Mechanism | Journal kind | Tier |
| --- | --- | --- | --- |
| `block` | `CM_Disable_DevNode` persistent; refuses a node that is not disableable | `win_devnode` (plus `win_policy_value` under default-deny) | reactive; preventive if E7 |
| `unblock` | `CM_Enable_DevNode`; under default-deny add the instance id to the allow list | same | |
| `set_read_only` | per-disk read-only attribute, or class-wide `Deny_Write` (E10) | `win_disk_read_only`, `win_policy_value` | reactive, not dependable once mounted |
| `eject` | `CM_Request_Device_EjectW`; a veto is `ok=False` | none | reactive |
| `set_default_deny` | Device Installation Restrictions values | `win_policy_value` | preventive **only for never-installed devices** |
| `set_baseline_read_only` | `Deny_Write` for the disk and portable-device classes | `win_policy_value` | standing, class-wide |
| `restore` | per kind; a device node is located with the phantom flag so an unplugged device can be re-enabled | | |

Values it writes are under `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`
and `...\RemovableStorageDevices`. A pre-existing value written by someone else (a domain
policy) is reported as a conflict and `default_deny` is then not offered. The first
version of the disk attribute had no journal kind; `win_disk_read_only` now exists, and
the target must match `\\.\PhysicalDriveN`.

### 3.4 `guard/factory.py`, `guard/safety.py`, `guard/fake.py`, `guard/seams.py`

- **Factory.** Chooses the backend, enforcer, dead-man timer (`systemd-run`, or
  `schtasks`) and directory-privacy check (POSIX modes, or `icacls`) for the platform, and
  produces the guard half of `portlock doctor`. It is the only module that names the
  concrete platform classes. `create_enforcer` returns the raw enforcer; its callers are
  `service.daemon` and the `recover` command, both of which wrap it in a `SafeEnforcer`.
  `dead_man_command` is `<python> -I -m portlock recover --config <file>`.
- **`doctor`** never raises and changes nothing; it calls only `capabilities()`,
  `enumerate()`, `mechanisms()` and the privacy `check()`, and turns any exception into a
  `fail`. Checks: `guard.platform`, `guard.privilege`, `guard.backend`, `guard.detect`,
  `guard.enumerate` (a count only), `guard.block`, `guard.read_only`, `guard.eject`,
  `guard.default_deny`, `guard.baseline_read_only`, `guard.conflicts`,
  `guard.system_volume`, `guard.boot_default_deny` (Linux), `guard.state_dir`,
  `guard.config_dir`. A missing mechanism is `warn` when unprivileged and `fail` when
  privileged. Serial numbers, product names and instance ids are scrubbed from the report.
  The service appends its own checks (`service.*`).
- **`SafeEnforcer`, `is_protected`, `detect_clone`, `PortFlapGuard`** (`safety.py`): the
  choke point and the protection rules (DESIGN 2 and 14.1 to 14.6). A device is protected
  if it is only a hub, built in, backing the system volume, pinned, enrolled on this port,
  or input-only while HID enforcement is off. Being outside the enforcement scope is
  reported separately and is not protection.
- **`FakeBackend`, `FakeEnforcer`** (`fake.py`): the simulated machine that tests and
  `portlock simulate` use. They keep the contracts of `guard.base`.
- **Seams** (`seams.py`): see E1. Real subprocess, registry, sysfs, ctypes and
  directory-privacy implementations live here beside their fakes.

### 3.5 `lockdown/manager.py` — lockdown, commit-confirm, kill switch, rollback

- **`CommitConfirm`** (DESIGN 14.15): a change is *proposed* (the handler previews what it
  would block), applied, stored in `pending_changes`, and rolled back unless confirmed over
  the same channel within `commit_confirm_seconds`. It arms an operating-system timer
  (`portlock-confirm-<id>`) set 30 s past the deadline as a backstop. Four kinds are
  registered: `lockdown`, `enforce_mode`, `widen_scope`, `default_deny`. A change found
  unconfirmed at start is rolled back.
- **`LockdownManager`**: the persisted state machine (5.2). Its dead-man timer counts down
  on the monotonic clock and persists the time remaining; an operating-system timer named
  `portlock-lockdown` runs `portlock recover` at expiry. Lifting needs a credential
  checked by an injected verifier.
- **`KillSwitch`**: the file `DISABLE_ENFORCEMENT`, honoured only in a directory the
  injected privacy check calls private.
- **`rollback` and `recover`**: put every journaled setting back. `recover` needs neither
  the service nor the database nor any PortLock credential: it reads the journal file,
  requires operating-system administrator rights (`is_admin`), cancels the lockdown timer
  and writes `last-recover.json`. The `portlock recover` command creates the kill-switch
  file before it checks for those rights.

The manager decides *whether* a lockdown is in force and *which* devices are exempt;
blocking is done by the service's convergence, so one code path blocks devices.

### 3.6 `core/service.py` — the pipeline

`PortLockService` runs DESIGN 5 as amended by 14. Everything that touches the operating
system is injected: backend, raw enforcer, dead-man timer, directory-privacy check.

#### 3.6.1 Construction

Inputs: config, clock, store, journal, `AuditWriter`, bus, backend, enforcer, grant store,
scanner (or `None`), policy path, system-volume probe, timer, `recover_argv`, privacy
check, credential check, a doctor builder, `has_users`, `simulation` and `platform`. It
reads the lockdown row and nothing else; the rest happens in `start`.
`AuditWriter` never raises into the pipeline: a failed append goes to a bounded backlog
(1000) and is written later with `data.delayed` and `data.occurred_at`.

#### 3.6.2 Start, in order

Record the run (`service.run`); load settings; make and check the directories private
(failing that: a critical alert and enforce mode refused); note whether the kill switch is
set; audit a `last-recover.json`; load the policy and verify the tail of the audit log (256
records); audit `service.started`; close the previous run's connections; start the backend
and enumerate (three attempts); build the safety context; settle grants and journal
hygiene; honour the kill switch; resume lockdown and pending changes; reconcile every
device; finish a lift found at start; audit `service.recovered` after an unclean previous
run; start the pipeline and scan threads.

#### 3.6.3 Event handling

The backend's thread only enqueues (queue of 1000; an overflow drops the event and the
next tick resyncs). `portlock-pipeline` calls `handle_event`: `ARRIVED`, `REMOVED`,
`CHANGED`, `RESYNC`. A resync enumerates again and synthesises the difference.

#### 3.6.4 Read methods (no L1)

`status`, `list_connections`, `get_connection`, `list_devices`, `get_device`,
`list_decisions`, `list_grants`, `list_enrolments`, `get_policy`, `list_scans`, `get_scan`,
`lockdown_status`, `pending_changes`, `get_mode`, `get_settings`, `doctor`. Degraded
components in `status` are `store`, `journal`, `backend` and `audit_chain`, plus the
audit writer's backlog.

#### 3.6.5 Mutating methods (all take L1 and an `actor`)

`approve`, `deny`, `create_grant`, `revoke_grant`, `enroll`, `unenroll`, `release_port`,
`replace_policy`, `test_policy`, `request_scan`, `lockdown_engage`, `lockdown_confirm`,
`lockdown_renew`, `lockdown_lift`, `set_mode`, `set_scope`, `set_default_deny`,
`confirm_change`, `cancel_change`, `update_settings`, `verify_audit`, `reconcile`.
`set_mode(enforce)`, `set_scope` (widening), `set_default_deny(True)` and
`lockdown_engage` go through `CommitConfirm` and return a `change` the caller must
confirm. `update_settings` accepts only `protected_fingerprints` (each must be a device
that has been seen), `scan.enabled` and `lockdown.default_minutes`; everything else in the
configuration is file-only and needs a restart.

#### 3.6.6 Evaluation and convergence

For each connection: `verdict = SafeEnforcer.protection(device)`; `decision = decide(...)`
(`policy.decide`) from the policy result, grant, protection, lockdown and scan detection;
`desired = _desired(...)`; then `_converge` makes the operating system match and the
service stores and audits the result. The order is decide, journal, enforce, store and
audit; a failure to store or audit never skips enforcement.

Special decisions before the policy: a second device presenting an enrolled fingerprint
while the first is connected is denied with an alert; a device on a held port is denied
with an alert.

`_desired` has three rules. With the kill switch latched, everything is open. A protected
or safety-sourced decision is open. Otherwise the target (open, read-only or blocked, from
`_target_of`) is applied in enforce mode **or when the decision came from a lockdown**; in
monitor mode the device is left open and the intended state is recorded as `would_apply`.

Convergence only releases what PortLock restricted itself (D3). A device that was already
unusable when PortLock decided to block it gets a `hold` record so that PortLock knows to
release it later (D4). Revoking a device that has mounted volumes makes it read-only,
attempts a clean eject and only then blocks it (DESIGN 14.11). When read-only is decided
but cannot be enforced (not a storage device, no mechanism, or the call failed) the device
is left usable and writable and an alert is raised, unless `fail_closed`, which blocks it
(D16).

A decision's `scan: required` means the device is read-only until a scan of every volume is
clean (`_target_of`); a required scan that cannot run counts as an error, never as clean.

#### 3.6.7 `reconcile(trigger)` and `tick()`

`reconcile` re-evaluates every connection and returns a summary. `tick()` runs these steps,
each guarded so that one failing step alerts and does not stop the others: kill switch,
confirmations, lockdown, clock, grants, expiry, ports, external changes, resync, periodic,
scans. The external step (every 5 s) re-reads the policy file if it changed and notices
changes another process made to the database (the command line's `--local` commands). The
resync runs every 30 s and retries failed enforcements; the periodic step re-evaluates
everything every 60 s.

#### 3.6.8 Mode, kill switch, stop

The effective mode is `monitor` while the kill switch is latched, and also when `enforce`
is chosen but the state or configuration directory is not private. A clean `stop()` restores every journaled setting (unless
`fail_closed`), including an active lockdown's; the lockdown record stays and the next
start resumes it (D9). `stop` closes connections as `service_stop`.

#### 3.6.9 Policy

`replace_policy` validates, writes atomically, activates and audits `policy.changed` with
the old and new hashes. The file is also re-read when its modification stamp changes (D12).
An invalid file leaves the policy in force and audits `policy.invalid`.

#### 3.6.10 Scans

Scans are queued (16) for volumes the operating system mounted, run one at a time by
`portlock-scan`, and report through `scan.started`, `scan.finished` and `scan.detection`.
A watchdog cancels a scan that runs past its limits plus a grace period and abandons its
thread (at most four abandoned). Scans run in monitor mode too. A `suspicious` verdict
alone never denies; `malicious` follows `scan.on_detection`; incomplete or failed scans
never count as clean (POLICY 6).

#### 3.6.11 Threading, failure handling, audit

See 1.3, 1.4 and sections 6 to 8.

### 3.7 `service/daemon.py` — the process

`build_runtime` is the single composition root: it checks the database (a damaged file is
renamed aside and `AuditLog.start_fresh` begins a new log whose first record, 
`store.recovered`, names the old file's hash), opens the stores and the audit log (creating
the key store if `audit.hmac_key_file` is set and absent), builds the sinks (`file`,
`syslog`; a `clawnet` entry is accepted by the configuration but skipped with a warning),
and wires backend, enforcer, timer, privacy check and service. With `simulation=True` it
uses the fakes and never consults the platform factory.

`run` is the process: take the single-instance lock (exit 2 if held); honour the kill
switch from the journal file **before** the database is opened; build the runtime (exit 3
on `StoreError` or `AuditError` after rolling back, exit 4 on configuration errors);
`service.start`; start the API (exit 5 if it cannot listen); write `runtime.json` with a
fresh secret; start the ticker; wait; on SIGINT, SIGTERM or SIGBREAK, or `stop.request`,
stop the API and the service, remove `runtime.json` and close. A second signal during
shutdown is ignored for 10 s and then ends the process with code 1.

The secret in `runtime.json` is what the command line uses (4.2). A new audit key store's
initial key is shown once on standard error if there is a terminal, and otherwise cannot
be shown (a warning is logged).

---

## 4. Console modules

### 4.1 `console/api.py` — local HTTP API, event stream, static console

`docs/API.md` is the contract. The request path is: admission (32 in flight), strict parse,
`Host` allowlist, `Origin` and `Sec-Fetch-Site`, route and method, **bearer token**
authentication, permission (in `_authorize` and nowhere else), body validation (strict
JSON, no floats, unknown fields refused), the handler. There are no cookies and no CSRF
tokens (DESIGN 14.20). Logins are rate limited (30 a minute overall), at most two scrypt
verifications run at once on the network path (a third gets `busy`), and a login carrying
the command-line secret is checked on the local channel, which the network lockout never
blocks. `GET /ping` answers a challenge with an HMAC under the runtime secret so the
command line can authenticate the service before sending a credential. `GET /events` is a
server-sent stream read with `fetch`, because a browser `EventSource` cannot send the
`Authorization` header. Static files are loaded into memory at start and served with a
strict content security policy; a request never touches the file system.

### 4.2 `console/cli.py` — the command line

Service commands authenticate with a prompted password (or one line on standard input with
`--password-stdin`), make their calls and log out; nothing is stored. Before sending a
credential the command line proves it is talking to the service (D22). A privileged
command always authenticates. Confirm and cancel of a pending change use the channel
`cli:<user>`; a browser uses its session. Exit codes: 0 ok, 1 failed, 2 usage, 3 not
authenticated or not permitted, 4 the service is not running or did not prove who it is,
5 a check failed. The local commands are listed above; `portlock run` passes the daemon's
own codes through.

### 4.3 `console/static/` — the web console

Plain files, no build step, nothing from another host, no inline script or style:
`index.html`, four stylesheets, ES modules and a favicon. The token lives in memory only,
so a reload asks for the password again. Live updates come from the event stream. Device
text is rendered as text nodes. `tests/unit/test_console_static.py` checks every API call
the scripts make against `ROUTES` and bans the constructs the design forbids (HTML
injection sinks, `eval`, browser storage, cookies, `EventSource`, external URLs).

### 4.4 `service/install.py` — service definitions

`systemd_unit` and `windows_task_xml` return text for the administrator to review. Nothing
is installed, written or run. Windows uses a scheduled task at boot as SYSTEM rather than
a service, because a service needs a service-control dispatcher that the standard library
does not provide (D20).

### 4.5 `console/simulate.py` — `portlock simulate`

The whole service (real pipeline, audit log, accounts, lockdown and API) on a simulated
machine: a `FakeBackend`, a `FakeEnforcer`, a `FakeExternalTimer` and a `FakeDirPrivacy`,
all built by the module itself and passed explicitly to `build_runtime`. There is no
parameter that selects a real one. State lives in a fresh temporary directory removed on
exit; the scanner is a stand-in that reads no file. A test replaces every platform factory
with a function that fails and runs the simulation to prove it.

### 4.6 Integration tests

`tests/integration/` runs a whole `build_runtime` on `tmp_path` with a synchronous fake
backend, a fake enforcer that survives a "restart", a `FakeClock`, an in-memory timer and
privacy check (`harness.py`), and drives the API and the command line against it.

---

## 5. State machines

### 5.1 A device connection

A connection row exists from arrival to removal. Its `state` follows the current decision;
whether the operating system matches is the decision's `outcome`.

```
                 arrival / present at start
                          |
                        [new]
                          | evaluate
     +----------+---------+-----------+-----------+
     v          v         v           v           v
[protected] [allowed] [read_only] [pending] <--> [denied]
     +----------+------ re-evaluation ----+-----------+   (any state to any state)
                          |
          removed / resync / service stop / service restart
                          v
                      (closed)
```

| Trigger | Scope | Effect |
| --- | --- | --- |
| ARRIVED, or found at start | one | open connection, evaluate |
| CHANGED (a volume appeared or was mounted) | one | re-converge; schedule scans |
| grant or trust created, revoked, expired, spent | same fingerprint | re-evaluate |
| `approve` | same fingerprint | grant, clear resolution, re-evaluate |
| `deny` | one | `pending` becomes `denied` (a per-connection resolution); optional eject |
| policy replaced or its file changed | all | re-evaluate |
| a decision's `expires_at` reached (rule expiry, time window, grant expiry) | one | re-evaluate |
| lockdown engaged, lifted, expired; mode, scope or default-deny changed; kill switch | all | re-evaluate |
| `protected_fingerprints` or enrolments changed | all | re-evaluate |
| scan finished | one | re-evaluate with the scan's verdict |
| enforcement failed earlier | one | retried at the next resync (30 s) |
| REMOVED, resync, stop, restart | one / all | closed with the reason |

Mapping from decision to state and to the desired operating-system state:

| Decision | State | Enforce mode | Monitor mode |
| --- | --- | --- | --- |
| source `safety` | `protected` | open, never a restricting call | open |
| `allow` | `allowed` | open | open |
| `allow`, scan `required`, not yet clean | `read_only` | read-only | open (would be read-only) |
| `read_only` | `read_only` | read-only | open (would be read-only) |
| `pending` | `pending` (`denied` after an operator denial) | blocked | open (would be blocked) |
| `deny`, source `policy`, `scan` or `default` | `denied` | blocked | open (would be blocked) |
| `deny`, source `lockdown` | `denied` | blocked | **blocked** |

### 5.2 The lockdown manager

States: `idle`, `engaging`, `active`, `lifting`. Engage is a commit-confirm change: it
applies, lists what it holds, and is rolled back unless confirmed.

| From | Event | Guard | To | Audit |
| --- | --- | --- | --- | --- |
| idle | `engage` | 1 to `max_minutes`; kill switch clear; enforcer can block | engaging, then active | `lockdown.engaged`, `change.pending` |
| active | `engage` | | refused `lockdown_active` | |
| active | `renew` | 1 to `max_minutes` | active, new expiry | `lockdown.renewed` |
| idle | `renew`, `lift` | | refused `lockdown_not_active` | |
| active, engaging | `lift` | password or recovery code verified | lifting, then idle | `lockdown.lifted` |
| active | tick, expiry reached | | lifting, then idle | `lockdown.expired` |
| active, engaging | start, expiry passed | | lifting, then idle; never re-applied | `lockdown.expired` (found at start) |
| active, engaging | start, time remains | remaining within `max_minutes` | active | `service.recovered` mentions it |
| active, engaging | start, remaining above `max_minutes` | | lifting, then idle | `lockdown.expired` (clock anomaly) |
| any but idle | kill switch | | idle | `killswitch.activated` |
| engaging | change not confirmed | | idle | `change.rolled_back` |

While active, through convergence: every unprotected, non-exempt device is `deny` with
source `lockdown` and is blocked, in either mode; default-deny is on, so a new device is
unusable from the first instant; a new device that turns out to be protected or exempt is
admitted by the service as soon as it is evaluated. Exempt: a device without storage that
was connected before the lockdown began, and, if `lockdown.allow_new_input_devices`, a new
input-only device. Storage-like devices and devices that mix input with another function
are never exempt.

Limits, stated plainly: lockdown is in force only while the service runs. With the default
`scope = "storage"` a new non-storage, non-mixed device is outside the enforcement scope
and is usable even during lockdown; set `scope = "all_except_protected"` to hold every new
device. If the service dies during lockdown, the operating-system default-deny stays on
until the service restarts or `portlock recover` runs, and in that window a re-plugged
keyboard is refused by the operating system: run the service under a supervisor.

---

## 6. Crash-recovery matrix

What the next `start()` does with each piece of state a crash can leave behind. "Crash"
means the process ended without `stop()`: power loss, `kill -9`, an ended scheduled task.

| State found at start | What the service does |
| --- | --- |
| `service.run` setting present | The previous run was unclean; recorded in one `service.recovered`. |
| Open connections from the old run | Closed with `service_restart`. Devices present now get new connections with `present_at_start`. |
| Pending devices | Evaluated again; a device still present is `pending` again under a new connection id. An operator denial is per connection and is gone; the device is still blocked. |
| Journal: open record, device present, same fingerprint | Kept; a decision that blocks leaves it (the enforcer call is idempotent, the baseline is not overwritten); a decision that permits releases it. |
| Journal: open volatile record, device absent or a different device at that instance id | Discarded: the operating system forgot it. |
| Journal: open non-volatile instance record, device absent (orphan) | Evaluated against the device's last known description; restored if the decision now permits, or in monitor mode. Re-checked at every resync. |
| Journal: open global record (default-deny, class-wide read-only, a rules file) | Kept if still wanted; otherwise restored at the end of the first reconcile. |
| Half-applied enforcement | The record is written and `fsync`ed before the change (E2), so there is no state in which the operating system was changed and the journal does not know; restoring a value already in place is harmless. |
| Torn or corrupt journal line | Skipped and counted; every readable record is honoured; `journal` shows as degraded. |
| Lockdown `active`, expiry in the future | Resumed with the remaining time; default-deny re-applied in the first reconcile. |
| Lockdown `active` or `engaging`, expiry passed | Not re-applied; goes to `lifting` before devices are evaluated, the first reconcile releases what the journal holds, `lockdown.expired` is audited. |
| Lockdown `lifting` | The lift is completed. |
| Lockdown with remaining time above `max_minutes` | Treated as expired (clock anomaly). |
| A change waiting for confirmation | Rolled back (`change.rolled_back`). |
| One-time grant bound to a connection | Spent if its device is gone or a different device sits at that instance id. A re-plug into the same port while the service was down cannot be told from continuous presence (a documented limit). |
| Grants that expired while down | Expired and audited once each; the first reconcile already evaluates without them. |
| Kill-switch file present | Rollback from the journal file before the database is opened; mode written as `monitor`; lockdown forced idle; `killswitch.activated` and `recovery.restored` audited. |
| `last-recover.json` present | Audited as `recovery.restored` with its report, then deleted. |
| A scan that was queued or running | Marked cancelled; the device's new connection schedules scans afresh. |
| Policy file missing | The default policy. |
| Policy file invalid | `policy.invalid`; `policy.last_good` if stored, else the default policy. |
| Audit chain does not verify (tail check) | `audit.verification_failed` (critical); the service keeps running and appending; status and doctor show it. |
| Database damaged | Renamed aside, never deleted; a new log starts and its first record names the old file. If it cannot be moved aside or is from a newer PortLock: rollback from the journal (unless `fail_closed`), exit 3. |
| Stale `runtime.json` or `portlock.lock` | The lock is an operating-system lock and died with the process; `runtime.json` is overwritten; the command line detects a stale file because its challenge fails. |
| Sessions, login lockout counters | Persisted by `auth`; unaffected. |
| Input-device protection | Recomputed from enrolments and the devices present now; being present confers nothing. |

Between a crash and the next start nothing watches devices. What stays enforced is exactly
what the journal lists: blocked devices stay blocked, default-deny stays on if a lockdown
was active. Nothing new is blocked.

---

## 7. Failure handling

| Failure | Behaviour |
| --- | --- |
| An enforcer call returns `ok=False` | Outcome `failed`; `enforcement.failed` audited; an alert; retried at the next resync (30 s). A failed block leaves the device usable and the record says so. A failed read-only follows the *cannot* rule (3.6.6). |
| The capability is missing (not privileged, mechanism absent) | No call. Outcome `unsupported`, audited as `enforcement.failed` with `error = "unsupported: ..."`. `set_mode(enforce)` and `lockdown_engage` are refused up front (`enforcement_unavailable`). |
| The enforcer raises | `SafeEnforcer` turns it into `ok=False` (`mechanism="error"`). |
| `write_ahead` fails (journal unwritable) | The enforcer makes no change (E2). Restrictions cannot be added; releases of already open records still work. `journal` degraded. |
| Database locked beyond the busy timeout, or a `StoreError` in the pipeline | For a device event: deny if `fail_closed`, else pending in enforce mode; `store` degraded. For an API mutation: `store_unavailable` and no partial effect. Enforcement already in place is not touched. |
| Audit append fails | `AuditWriter` keeps a bounded backlog and flushes it later. Enforcement proceeds: failing to record must not become failing to protect. |
| An external audit sink fails or is slow | Isolated by `FanOut`; counted; never blocks an append. |
| `backend.enumerate()` raises | Retried; the backend is marked degraded and an alert raised; the resync keeps retrying; recovery is audited as `service.recovered`. Existing decisions stay enforced. |
| The backend's notification thread dies silently | The resync finds what it missed, so detection degrades to polling instead of stopping. |
| Event queue overflow | The event is dropped; a resync runs on the next tick. |
| A scan exceeds its limits, hangs or fails | `incomplete` / watchdog then `error` / `error`; never `clean`. |
| Evaluation raises for one device | Other devices are unaffected; the device is `pending` (denied if `fail_closed`; allowed and alerted if protected). |
| The system-volume query fails | Every storage device present at start is treated as system-backing and protected; `service.system_volume` reports it. |
| The API port is taken | The daemon stops cleanly and exits 5. |
| The wall clock jumps | Expiries use the later of the clock and the newest audit timestamp (DESIGN 14.12) and `clock.rollback_detected` is audited; a lockdown counts on the monotonic clock with a sanity check against `max_minutes`. |
| The process is killed | Section 6. |

---

## 8. Audit events

Only the names in the registry (`audit.events`) are used. `fp` means `device_fp` is set.

| Event | Emitted by | When |
| --- | --- | --- |
| `service.started`, `service.stopped`, `service.recovered`, `store.recovered` | service, daemon | start; stop; recovery after an unclean run or a degraded component; a damaged database set aside |
| `device.connected`, `device.changed`, `device.removed` (fp) | service | arrival; a volume appeared; removal or resync |
| `safety.suspicious_device`, `safety.clone_detected`, `safety.port_held` (fp) | service | storage with input, or a new input device; a second device with an enrolled fingerprint; a port hold-down |
| `decision.made` (fp) | service | every new or changed decision; operator denial |
| `enforcement.applied`, `enforcement.would_apply`, `enforcement.failed`, `enforcement.refused` (fp) | service | a live call changed something; monitor mode; a call failed or was unsupported; the safety layer refused |
| `grant.created`, `grant.used`, `grant.expired`, `grant.revoked`, `trust.added`, `trust.removed` (fp) | service | grants and trust |
| `enroll.added`, `enroll.removed` | service | enrolments of input devices |
| `policy.changed`, `policy.invalid` | service | a policy replaced or a changed file; an invalid file or rejected replace |
| `scan.started`, `scan.finished`, `scan.detection` (fp) | service | scans |
| `lockdown.engaged`, `.renewed`, `.lifted`, `.expired` | lockdown | 5.2 |
| `change.pending`, `change.confirmed`, `change.rolled_back` | lockdown | commit-confirm |
| `killswitch.activated`, `recovery.restored` | service | the kill-switch file seen; a rollback at stop, kill switch or recover marker |
| `mode.changed`, `config.changed` | service | `set_mode`; `update_settings` |
| `clock.rollback_detected` | service | the clock went back |
| `audit.verified`, `audit.verification_failed` | service | tail check at start; `verify_audit` |
| `auth.login`, `auth.logout`, `auth.failure`, `auth.lockout`, `auth.password_changed`, `auth.recovery_used`, `auth.user_created`, `auth.user_changed` | `AccountStore`, `console.api` | `auth.*` data carries the channel (`network` or `local`) and, when a session store is wired, `sessions_revoked`; never a secret |

`SECURITY_EVENT_FORMAT.md` is the wire format of the exported envelope.

---

## 9. Where each required area is tested

Unit tests are `tests/unit/test_<module>.py`; integration tests are in
`tests/integration/`, which drive a whole runtime and the API.

| Area | Unit | Integration |
| --- | --- | --- |
| Detection | `test_linux_backend`, `test_linux_netlink`, `test_win_backend`, `test_win_parse`, `test_guard_fake`, `test_service_pipeline` | `test_detection` |
| Authorisation, trust, grants | `test_grants`, `test_auth_accounts`, `test_service_pipeline`, `test_policy_decide` | `test_authorization`, `test_trusted`, `test_permissions` |
| Unauthorised devices, enforcement | `test_service_enforcement`, `test_guard_safety`, `test_enforce_linux`, `test_enforce_windows` | `test_unauthorized` |
| Removal, reconnection, expiry | `test_service_pipeline` | `test_removal`, `test_reconnection`, `test_expiration` |
| Restart and crash recovery | `test_store`, `test_service_daemon`, `test_service_pipeline` | `test_restart`, `test_cli_daemon` |
| Audit | `test_audit_log`, `test_audit_events`, `test_audit_sinks`, `test_audit_signing`, `test_service_audit` | `test_logging` |
| Lockdown, commit-confirm, kill switch, recover | `test_lockdown` | `test_lockdown_safeguards`, `test_design_section14` |
| API and command line | `test_console_api_auth`, `test_console_api_endpoints`, `test_console_api_events`, `test_console_api_http`, `test_console_cli`, `test_console_support`, `test_console_text` | `test_api_workflows`, `test_cli_end_to_end` |
| Console, simulation, service definitions | `test_console_static`, `test_console_simulate`, `test_service_install` | |
| Scanning | `test_scan_*` | `test_service_scan` (unit) |
| Architecture rules | `test_import_rules` | |
| Hardware (opt-in, read-only) | `tests/hardware/test_win_live.py`, `test_linux_live.py` with `--run-hardware` | |

Rules for every test: no real enforcement mechanism; no write to the real `/sys` or the
registry; no device disabled or ejected; synthetic identifiers only; no sleeping to make
time pass; nothing written outside `tmp_path`.

---

## 10. Decisions taken where `DESIGN.md` was open

| # | Decision |
| --- | --- |
| D1 | The enforcement journal is a file (`journal.jsonl`), written ahead of every operating-system change, so `portlock recover` needs no database. |
| D2 | Enforcers take a `write_ahead` hook; the journal keeps one baseline per `(kind, target)`; a releasing call never creates a baseline (the journal rule, 3.1.3). |
| D3 | PortLock releases only what it restricted. A device or setting that something else restricted is left alone, also when policy says allow. |
| D4 | A device that was already unusable when PortLock decided to block it gets a `hold` record, so PortLock knows to release it later. |
| D5 | Global settings are released by restoring PortLock's own records, never by "turn it off". |
| D6 | Convergence: the service computes a desired operating-system state per device from decision, mode, lockdown and kill switch, and makes it so. Enforcer calls are never made ad hoc. |
| D7 | Lockdown acts in monitor mode. It is an explicit administrator action. Lifting it in monitor mode leaves nothing restricted. |
| D8 | Operating-system default-deny is used during lockdown, and when the administrator turns it on (`default_deny`, a commit-confirm change). Ordinary enforce mode is reactive and reports itself as such. |
| D9 | A clean stop restores everything, an active lockdown's operating-system state included; the lockdown record stays and the next start resumes it. Lockdown is in force only while the service runs. |
| D10 | `fail_closed`: a device that cannot be evaluated is denied; read-only that cannot be enforced becomes a block; a required scan that cannot complete denies; when the state is unusable at start, journaled settings are not rolled back. |
| D11 | The run-time mode is a stored setting that overrides `Config.mode`. The kill switch overrides both and rewrites the setting to `monitor`, so removing the file never silently re-enables enforcement. |
| D12 | The policy comes from `policy.json` and from the API. The file is read at start and again whenever its modification stamp changes (checked every 5 s). An invalid file leaves the policy in force; at start an invalid file falls back to the last good policy, then to the default. |
| D13 | An operator's "deny" of a pending device is a per-connection resolution, not a decision source. Standing denials are policy rules. |
| D14 | A `suspicious` scan verdict never denies by itself; it caps at read-only. `malicious` follows `scan.on_detection`. Incomplete and failed scans never count as clean. |
| D15 | PortLock scans only volumes the operating system mounted and never mounts anything itself. Scans also run in monitor mode. |
| D16 | Read-only that cannot be enforced (no storage, no mechanism, a failed call) leaves the device usable with an alert, or blocks it under `fail_closed`. |
| D17 | Eject happens on an explicit operator request, and as the second step of revoking a mounted device. |
| D18 | The system-volume set is computed at each start and kept in memory. Pinned fingerprints and enrolments are stored and changed only by an administrator. If the system volume cannot be traced, every storage device present at that start is protected (one that arrives later cannot be backing the system volume) and `doctor` says so. |
| D19 | Safety-critical configuration (`hid_enforcement`, `acknowledge_lockout_risk`, `fail_closed`, `api.*`, `paths`, `auth`, `audit`) is file-only and needs a restart. The API changes three settings (3.6.5), and scope, mode and default-deny through commit-confirm. |
| D20 | On Windows the service runs as a scheduled task; graceful stop on every platform is the `stop.request` file. |
| D21 | The first administrator is created only by the local `portlock init`. The API never creates an account without an authenticated administrator. |
| D22 | The command line holds no stored credentials: it logs in, acts and logs out. It sends a credential only to a service that proved, through the challenge on `GET /ping`, that it holds the secret in `runtime.json`, or to a URL the operator named. |
| D23 | Local commands (`init`, `recover`, `user reset-password --local`, `user unlock --local`, offline verification) are authorised by operating-system rights and use the `local` lockout channel. |
| D24 | `portlock recover` leaves the kill-switch file in place and a marker for the next start to audit. |
| D25 | A connection belongs to one service run. Restart closes old connections and opens new ones. |
| D26 | `enforcement.applied` and `.would_apply` are audited on change, not on every idempotent re-application. |
| D27 | Nothing in the store is pruned automatically in this version. |
| D28 | The database is never repaired or deleted by PortLock; a damaged one is renamed aside. |
| D29 | A one-time grant survives a restart only if the same device is still present at the same instance id; it binds to a connection id supplied by the backend. |
| D30 | The event-stream id is `<run_id>-<seq>`; a client resuming across a restart gets a `reset`. |

---

## 11. Known gaps between design and code

- The `ClawNetSink` class exists in `audit.sinks` but the daemon does not build one, and
  the configuration has no place for its address, token or signing key. A `clawnet` sink
  entry is accepted and skipped with a warning.
- `console/cli.py` repeats the daemon's mapping from `AuthConfig` to `AuthPolicy` for local
  commands, and `console/simulate.py` writes `runtime.json` itself (a test checks the
  daemon accepts it).
- The service-install and dead-man-timer commands (`systemd-run`, `schtasks`) and the
  Windows `icacls` privacy check have only ever run against fakes.
- `docs/enforcement/linux.md` and the docstrings of `guard/linux/__init__.py` and
  `guard/windows/__init__.py` still describe the backends as observing only; the enforcers
  exist in `enforce.py`.
