# PortLock — architecture

This document maps `DESIGN.md` onto the modules that waves 2 and 3 build. `DESIGN.md` says
*what* and *why*; this says *where* and *exactly how the pieces meet*. It does not repeat
the design. Where the two disagree, `DESIGN.md` wins and this file has a bug.

Wave 1 (fingerprint, config, event bus, safety, fakes, audit, auth, policy, grants, scan,
the read-only Windows and Linux backends) is treated as given. Signatures of wave 1 code
quoted here were read from the specification and from the code as it stood while this was
written. **If a wave 1 signature differs from what is shown here, the code is
authoritative**: adapt, and report the difference in your hand-over notes.

Section 10 lists every decision this document takes where `DESIGN.md` was open.

---

## 1. The process at a glance

One long-running process (`portlock run`) hosts everything: device backend, pipeline,
lockdown, scans, the HTTP API and the web console. The CLI is a second, short-lived
process that either talks to the service over HTTP or, for a small set of *local-console*
commands, works on the files directly.

### 1.1 Files on disk

`state_dir` and `config_dir` come from `Config.paths`. On Windows they are the same
directory by default, so no two files share a name.

| File | Directory | Owner module | Purpose |
| --- | --- | --- | --- |
| `portlock.db` (+ `-wal`, `-shm`) | state | `core.db` | every SQL table of every component |
| `journal.jsonl` | state | `core.store.RecoveryJournal` | the enforcement journal (write-ahead, section 3.1.3) |
| `portlock.lock` | state | `service.daemon` | single-instance lock |
| `runtime.json` | state | `service.daemon` | how the CLI finds the running service |
| `stop.request` | state | `service.daemon` | graceful-stop request written by `portlock stop` |
| `last-recover.json` | state | `lockdown.manager` | left by `portlock recover` so the next start can audit it |
| `event-signing.key` | state | `audit.signing` | Ed25519 seed for exported checkpoints (optional) |
| `portlock.toml` | config | `core.config` | configuration |
| `policy.json` | config | `policy.loader` | the active policy |
| `DISABLE_ENFORCEMENT` | config | `lockdown.manager.KillSwitch` | the kill switch |

The enforcement journal is a **file, not a table**. `portlock recover` must work "without
the service or the database" (DESIGN §11), and a write-ahead record must survive a
corrupt database.

### 1.2 Dependency rule (who may import whom)

Arrows point at what a module may import. Anything not listed is forbidden.
`tests/unit/test_import_rules.py` (wave 2, owned with `core/service.py`) parses every
module under `src/portlock` with `ast` and fails on any import outside this table.

| Module | May import (besides the standard library) |
| --- | --- |
| `core.store` | `core.{db,clock,models,errors,canonical,fsutil}`, `guard.base` (types only) |
| `guard.linux.enforce` | `core.{models,errors}`, `guard.base`, `guard.linux.{sysfs,mounts}` |
| `guard.windows.enforce` | `core.{models,errors}`, `guard.base`, `guard.windows.{api,enumerate,volumes}` |
| `guard.factory` | `core.{config,models,errors,clock}`, `guard.base`, `guard.fake`, `guard.linux.*`, `guard.windows.*` (platform packages imported lazily, inside functions) |
| `lockdown.manager` | `core.{db,clock,config,models,errors,store}`, `guard.base` |
| `core.service` | `core.*`, `guard.base`, `guard.safety`, `lockdown.manager`, `policy.*`, `auth.grants`, `scan.*`, `audit.*` |
| `service.daemon` | everything above, plus `auth.*`, `guard.factory`, `console.api` |
| `console.api` | `core.service`, `core.{config,clock,errors,models,events}`, `auth.{accounts,sessions,passwords}`, `audit.log` |
| `console.cli` | `core.{config,clock,errors,store,fsutil}`, `service.{daemon,install}`, `lockdown.manager`, `guard.{factory,safety}`, `auth.{accounts,passwords}`, `audit.{log,signing}`, `policy.*`, `console.simulate` |
| `console.simulate` | `service.daemon`, `core.*`, `guard.fake` |
| `service.install` | `core.config` |

Consequences, stated so nobody has to derive them:

- `core.service` never imports a concrete backend or enforcer; they are injected.
- `console.api` never imports `guard`, `lockdown` or `core.store`; it reaches them through
  `PortLockService`.
- `policy`, `scan`, `audit`, `auth` and `core.models` never import `guard` (DESIGN §3).
- Enforcement is driven from exactly two places: `core.service` (convergence) and
  `lockdown.manager.rollback`. Both go through a `SafeEnforcer`. No other module holds an
  `Enforcer`.

### 1.3 Threads

| Thread | Created by | Does |
| --- | --- | --- |
| `portlock-main` | OS | `service.daemon.run`: start-up, waits for a stop signal, shutdown |
| backend thread(s) | the `DeviceBackend` | calls `PortLockService.on_backend_event`, which only enqueues |
| `portlock-pipeline` | `PortLockService.start` | drains the event queue, calls `handle_event` |
| `portlock-ticker` | `service.daemon` | calls `PortLockService.tick()` once a second; checks `stop.request` |
| `portlock-scan` | `PortLockService.start` | runs one scan at a time |
| `portlock-api` | `console.api.ApiServer.start` | accept loop |
| `portlock-api-N` | `ThreadingHTTPServer` | one request, or one event stream |
| audit sink thread | `audit.sinks.FanOut` | delivers records to external sinks |

### 1.4 Locks and their order

Outermost first. A thread may take a lock only if it holds none that is further down.

1. **L1 `PortLockService._lock`** (`threading.RLock`): serializes everything that
   evaluates, enforces, or changes lockdown, mode, policy or settings.
2. **L2 `RecoveryJournal._lock`** (`threading.Lock`).
3. **L3 `Database._lock`** (re-entrant; taken by every store).
4. **L4 leaf locks**: `EventBus` internals, `AuditLog` hand-off to its sink. Never hold
   one while taking another lock.

Rules that follow:

- Enforcer calls are made **holding L1 and nothing else**. Never call an enforcer inside
  `db.transaction()`: OS calls can take seconds.
- `AuditLog.append` is never called inside a transaction that might roll back.
- Event-bus handlers run on the publishing thread, which usually holds L1. A handler must
  not call back into the service and must not block; the API's stream handler only puts
  the event on a bounded queue.
- The scan thread and API threads enter L1 only through public `PortLockService` methods.
  The scan thread never holds L1 while a scan runs.
- API handler threads hold no lock while reading from or writing to a socket.
- Read methods of `PortLockService` (section 3.6.4) take no L1: they read the store and an
  immutable status snapshot, so the console stays responsive during a slow enforcement.
- `LockdownManager` has no lock of its own; it is only ever called with L1 held.

---

## 2. Contracts shared by several modules

### 2.1 Identifiers, time and actors

- Timestamps in SQL, the journal, audit `data` and the API are `core.clock.utc_iso`
  strings. Durations are integer seconds or minutes. **No floats** anywhere that reaches
  the audit log, the journal or the API.
- A *connection* is one continuous presence of one device as observed by one run of the
  service, identified by an integer `connection_id`.
- A *service run* is identified by `run_id`, 16 lowercase hex characters from
  `secrets.token_hex(8)`, generated in `PortLockService.__init__`.
- `actor` strings: a PortLock user name; `system` for anything the service does on its
  own; `local-console` for commands authorized by operating-system rights alone.
- Fingerprints are passed as `Fingerprint` objects inside the service and as their
  `value` string across SQL, journal, audit and API.

### 2.2 The enforcer implementation contract (both platforms)

`guard/base.py` defines the interface. Wave 2 enforcers additionally guarantee the
following, and `core.service` relies on each point.

- **E1 Seams.** Every OS access goes through an injected seam object. The class has a
  `system()` constructor that wires the real seams and a plain constructor that takes
  fakes.
- **E2 Write-ahead.** The constructor takes
  `write_ahead: Callable[[JournalEntry], None] | None`. Immediately before each OS write
  the enforcer reads the current value, builds the `JournalEntry` and calls
  `write_ahead(entry)`. If that raises, the write is **not** made and the call returns
  `ok=False, error="journal unavailable: ..."`. (DESIGN §2: the previous value is recorded
  *before* the change.)
- **E3 Complete undo.** `result.undo` lists every change the call actually made, in the
  order made, **also when `ok` is False** (partial application). An entry passed to
  `write_ahead` whose write then did not happen is left out of `undo`.
- **E4 Admission is not an undoable change.** When `unblock` admits a device that was
  unusable only because default-deny kept it out, the change of the device's own state
  (Linux `authorized` 0→1, Windows start of the device) is not listed in `undo`.
  Persistent configuration that had to be *added* to admit it (an allow-list value) is
  listed, with `previous=None`.
- **E5 Restore.** `restore(entries)` needs nothing but the entries: it works in a process
  that never made the change. It processes them in the order given. A target that already
  holds `previous` is success with `changed=False`. A target that no longer exists is
  success for a *volatile* kind (table below) and a failure otherwise. An unknown `kind`
  is `ok=False` naming it. `core.service` and `rollback` always pass **one entry per
  call**, so each entry has its own result.
- **E6 Kinds.** `JournalEntry.kind` comes from this closed vocabulary. `target`,
  `previous` and `applied` are opaque to everyone but the enforcer that wrote them.

  | kind | Platform | What it is | Scope | Volatile |
  | --- | --- | --- | --- | --- |
  | `sysfs-device` | Linux | an attribute of one device or interface (`authorized`) | instance | yes |
  | `blockro` | Linux | the read-only flag of one block node | instance | yes |
  | `sysfs-host` | Linux | an attribute of a host controller (`authorized_default`) | global | no |
  | `file` | Linux | a generated udev rule file | global | no |
  | `devnode` | Windows | enabled/disabled state of one device node | instance | no |
  | `diskattr` | Windows | the read-only attribute of one disk | instance | no |
  | `registry` | Windows | one policy registry value | global | no |
  | `hold` | (service) | a marker written by `core.service`, never by an enforcer | instance | yes |

  *Volatile* means the operating system forgets the state when the device disconnects.
  *Scope global* means the value is shared by several devices.
- **E7 Already unusable.** `block()` on a device that default-deny already keeps out
  returns `ok=True, changed=False, tier=PREVENTIVE` and does not add a second mechanism.
- **E8 Bounded.** No call blocks for more than 10 seconds. Subprocesses go through a
  `CommandRunner` with a timeout; an argument list, never a shell string.
- **E9 Capabilities** are computed without side effects and may be cached for at most
  5 seconds. A capability is True only if the mechanism exists *and* the process may use
  it now.
- **E10 Shared mechanisms.** If read-only can only be done class-wide, the enforcer keeps
  the set of instance ids that currently want it, keeps the class-wide setting on while
  the set is non-empty, and ends its `mechanism` string with `(class-wide)`. The set is
  in memory only; the service rebuilds it by re-applying every decision at start.
- **E11 Wrong device type.** `set_read_only(device, True)` on a device with no storage
  interface is `ok=False, error="not a storage device"`.
- **E12 Pre-arming.** `set_read_only(device, True)` may be called while the device is
  still blocked. If the platform has a race-free path (the generated udev rule), the
  enforcer arms it and reports `tier=PREVENTIVE`; if it has none it returns `ok=False`,
  and the service calls again after unblocking (section 3.6.6).
- **E13 Mechanism strings** are stable identifiers, used in audit records and the API:
  `sysfs:authorized`, `sysfs:authorized_default`, `sysfs:remove`, `blkroset`,
  `udev-rule+blkroset`, `cfgmgr:disable-devnode`, `cfgmgr:request-eject`,
  `policy:device-install-restrictions`, `policy:removable-storage-deny-write(class-wide)`,
  `disk:read-only-attribute`. `SafeEnforcer` adds `dry-run` and `refused`.

The exact paths, values, flags and failure modes behind each mechanism are specified in
`docs/enforcement/linux.md` and `docs/enforcement/windows.md`. Where a mechanism named
above turns out to be unavailable or marked UNVERIFIED there, the enforcer reports the
capability as False; it does not substitute an undocumented mechanism.

### 2.3 Assumptions about `SafeEnforcer`

`SafeEnforcer` fixes `dry_run` at construction, and a dry-run instance passes **nothing**
through, restoring calls included. `core.service` therefore builds two wrappers around
the injected enforcer, sharing one context provider:
`live = SafeEnforcer(inner, ctx, dry_run=False)` and
`dry = SafeEnforcer(inner, ctx, dry_run=True)`. Everything that releases, admits or
restores goes through `live` whatever the mode; `dry` is used only to record what
enforce mode would have done. `core.service` relies on `restore`, `unblock`,
`set_read_only(device, False)` and `set_default_deny` never being refused by `live`. If
the wave 1 class behaves differently, report it; do not work around it by calling `inner`
directly.

### 2.4 Audit conventions

- Only the event names in section 8 are used. The registry is strict.
- `device_fp` is set on every event about one device.
- `data` holds JSON scalars, lists and objects with ASCII keys; no floats; never a
  password, token, recovery code or key. Device descriptions go in as
  `UsbDevice.to_dict()` minus `volumes[].mount_point` contents longer than 256 characters.
- Every audit record written by the service is followed by a bus event `audit.appended`.
- The bus topics the service publishes, and their payloads, are exactly the events in
  `API.md` section 7.3 (`hello`, `reset` and `session.ended` are produced by the stream
  handler, not published). Payloads are built from the views' `to_dict()`, so they are
  JSON-serializable and float-free.

---

## 3. Wave 2 modules

### 3.1 `core/store.py` — state store and recovery journal

**Responsibility.** Persists what PortLock has seen and decided (devices, connections,
decisions, scans, settings) in SQLite, and keeps the enforcement journal in a crash-safe
file. It holds no policy and makes no decisions.

**Files.** `src/portlock/core/store.py`, `tests/unit/test_store.py`,
`tests/unit/test_journal.py`.

#### 3.1.1 SQL schema (component name `store`, one migration)

```sql
CREATE TABLE devices (
  fingerprint      TEXT PRIMARY KEY,
  confidence       TEXT NOT NULL CHECK (confidence IN ('high','low')),
  basis            TEXT NOT NULL,            -- JSON array of strings
  vendor_id        INTEGER NOT NULL,
  product_id       INTEGER NOT NULL,
  serial           TEXT,
  manufacturer     TEXT,
  product          TEXT,
  categories       TEXT NOT NULL,            -- JSON array, sorted
  storage_identity TEXT,
  description      TEXT NOT NULL,            -- JSON: UsbDevice.to_dict() at last sighting
  first_seen       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  connection_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE connections (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  fingerprint      TEXT NOT NULL REFERENCES devices(fingerprint),
  instance_id      TEXT NOT NULL,
  bus_path         TEXT,
  run_id           TEXT NOT NULL,
  present_at_start INTEGER NOT NULL CHECK (present_at_start IN (0,1)),
  connected_at     TEXT NOT NULL,
  removed_at       TEXT,
  close_reason     TEXT CHECK (close_reason IN
                     ('removed','resync','service_stop','service_restart')),
  state            TEXT NOT NULL CHECK (state IN
                     ('new','protected','allowed','read_only','pending','denied')),
  provisional      INTEGER NOT NULL DEFAULT 0 CHECK (provisional IN (0,1)),
  resolution       TEXT,                     -- JSON {"action","by","at","note"} or NULL
  scan_state       TEXT NOT NULL DEFAULT 'none' CHECK (scan_state IN
                     ('none','waiting','queued','running','clean','suspicious',
                      'malicious','incomplete','error')),
  last_scan_id     INTEGER,
  description      TEXT NOT NULL,            -- JSON: UsbDevice.to_dict(), latest
  decision_id      INTEGER
);
CREATE INDEX connections_open ON connections(instance_id) WHERE removed_at IS NULL;
CREATE INDEX connections_by_fp ON connections(fingerprint, id);

CREATE TABLE decisions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  connection_id INTEGER NOT NULL REFERENCES connections(id),
  fingerprint   TEXT NOT NULL,
  decided_at    TEXT NOT NULL,
  trigger       TEXT NOT NULL,
  access        TEXT NOT NULL,
  source        TEXT NOT NULL,
  rule_id       TEXT,
  grant_id      TEXT,
  scan          TEXT NOT NULL,
  alert         INTEGER NOT NULL CHECK (alert IN (0,1)),
  expires_at    TEXT,
  reasons       TEXT NOT NULL,               -- JSON array of strings
  policy_hash   TEXT NOT NULL,
  mode          TEXT NOT NULL,               -- effective mode when decided
  outcome       TEXT NOT NULL DEFAULT 'undetermined' CHECK (outcome IN
                  ('undetermined','not_needed','applied','would_apply','failed',
                   'refused','unsupported')),
  mechanism     TEXT,
  tier          TEXT NOT NULL DEFAULT 'none',
  detail        TEXT,
  error         TEXT,
  enforced_at   TEXT
);
CREATE INDEX decisions_by_connection ON decisions(connection_id, id);
CREATE INDEX decisions_by_fp ON decisions(fingerprint, id);

CREATE TABLE scans (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  connection_id INTEGER NOT NULL REFERENCES connections(id),
  fingerprint   TEXT NOT NULL,
  mount_point   TEXT NOT NULL,
  trigger       TEXT NOT NULL CHECK (trigger IN ('policy','manual')),
  requested_by  TEXT NOT NULL,
  state         TEXT NOT NULL CHECK (state IN ('queued','running','done','cancelled')),
  queued_at     TEXT NOT NULL,
  started_at    TEXT,
  finished_at   TEXT,
  verdict       TEXT,
  report        TEXT                         -- JSON: ScanReport.to_dict(), or NULL
);
CREATE INDEX scans_by_connection ON scans(connection_id, id);

CREATE TABLE settings (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,                  -- canonical JSON
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);
```

Decision rows are the queryable history; the audit log is the tamper-evident one. The
outcome columns of a decision row are updated in place. Nothing is pruned automatically
in this version.

`settings` keys are a closed set:

| key | value | meaning |
| --- | --- | --- |
| `mode` | `"monitor"` or `"enforce"` | the mode chosen at run time; overrides `Config.mode` |
| `protected_fingerprints` | array of fingerprint strings | administrator-pinned protected devices |
| `scan.enabled` | boolean | overrides `Config.scan.enabled` |
| `lockdown.default_minutes` | integer | overrides `Config.lockdown.default_minutes` |
| `service.run` | `{"run_id","started_at"}` | present while a run is alive; left behind by a crash |
| `policy.last_good` | `{"hash","policy"}` | the last policy the service accepted |

#### 3.1.2 `StateStore`

```python
class ConnectionState(StrEnum): NEW, PROTECTED, ALLOWED, READ_ONLY, PENDING, DENIED
class ScanState(StrEnum):      NONE, WAITING, QUEUED, RUNNING, CLEAN, SUSPICIOUS, MALICIOUS, INCOMPLETE, ERROR
class Outcome(StrEnum):        UNDETERMINED, NOT_NEEDED, APPLIED, WOULD_APPLY, FAILED, REFUSED, UNSUPPORTED

@dataclass(frozen=True, slots=True)
class DeviceRecord:      fingerprint: Fingerprint; device: UsbDevice; storage_identity: str | None
                         first_seen: datetime; last_seen: datetime; connection_count: int
@dataclass(frozen=True, slots=True)
class ConnectionRecord:  id: int; fingerprint: Fingerprint; device: UsbDevice; run_id: str
                         present_at_start: bool; connected_at: datetime
                         removed_at: datetime | None; close_reason: str | None
                         state: ConnectionState; provisional: bool
                         resolution: Mapping[str, Any] | None
                         scan_state: ScanState; last_scan_id: int | None; decision_id: int | None
@dataclass(frozen=True, slots=True)
class DecisionRecord:    id: int; connection_id: int; fingerprint: str; decided_at: datetime
                         trigger: str; decision: Decision; policy_hash: str; mode: Mode
                         outcome: Outcome; mechanism: str | None; tier: Tier
                         detail: str | None; error: str | None; enforced_at: datetime | None
@dataclass(frozen=True, slots=True)
class ScanRecord:        id: int; connection_id: int; fingerprint: str; mount_point: str
                         trigger: str; requested_by: str; state: str
                         queued_at: datetime; started_at: datetime | None
                         finished_at: datetime | None; verdict: str | None
                         report: Mapping[str, Any] | None

class StateStore:
    def __init__(self, db: Database, *, clock: Clock) -> None          # runs db.migrate("store", ...)

    # devices
    def record_sighting(self, device: UsbDevice, fingerprint: Fingerprint, *,
                        storage_identity: str | None) -> DeviceRecord
    def get_device(self, fingerprint: str) -> DeviceRecord | None
    def list_devices(self, *, limit: int = 100, before: str | None = None,
                     text: str | None = None) -> list[DeviceRecord]    # newest last_seen first

    # connections
    def open_connection(self, device: UsbDevice, fingerprint: Fingerprint, *, run_id: str,
                        present_at_start: bool, connected_at: datetime) -> ConnectionRecord
    def update_connection(self, connection_id: int, **changes: Any) -> ConnectionRecord
        # accepted keys: device, state, provisional, resolution, scan_state, last_scan_id, decision_id
    def close_connection(self, connection_id: int, *, removed_at: datetime,
                         reason: str) -> ConnectionRecord
    def close_open_connections(self, *, removed_at: datetime, reason: str) -> int
    def get_connection(self, connection_id: int) -> ConnectionRecord | None
    def open_connections(self) -> list[ConnectionRecord]               # oldest first
    def list_connections(self, *, open_only: bool = False, fingerprint: str | None = None,
                         before_id: int | None = None, limit: int = 100) -> list[ConnectionRecord]

    # decisions
    def add_decision(self, connection_id: int, decision: Decision, *, trigger: str,
                     policy_hash: str, mode: Mode, decided_at: datetime) -> DecisionRecord
        # also sets connections.decision_id, in the same transaction
    def set_outcome(self, decision_id: int, *, outcome: Outcome, mechanism: str | None,
                    tier: Tier, detail: str | None, error: str | None,
                    enforced_at: datetime) -> None
    def get_decision(self, decision_id: int) -> DecisionRecord | None
    def list_decisions(self, *, connection_id: int | None = None, fingerprint: str | None = None,
                       access: Access | None = None, before_id: int | None = None,
                       limit: int = 100) -> list[DecisionRecord]       # newest first

    # scans
    def add_scan(self, connection_id: int, fingerprint: str, mount_point: str, *,
                 trigger: str, requested_by: str, queued_at: datetime) -> ScanRecord
    def update_scan(self, scan_id: int, **changes: Any) -> ScanRecord
        # accepted keys: state, started_at, finished_at, verdict, report
    def get_scan(self, scan_id: int) -> ScanRecord | None
    def list_scans(self, *, connection_id: int | None = None, fingerprint: str | None = None,
                   before_id: int | None = None, limit: int = 100) -> list[ScanRecord]

    # settings
    def get_setting(self, key: str, default: Any = None) -> Any
    def set_setting(self, key: str, value: Any, *, by: str) -> None    # value: canonical-JSON-able
    def delete_setting(self, key: str) -> None
    def settings(self) -> dict[str, Any]
```

Semantics every implementer must share:

- Every method is one transaction. `limit` is clamped to 1..500. Unknown `**changes` keys,
  unknown setting keys and unknown ids raise `StoreError` (a programming error).
- `record_sighting` inserts or updates the `devices` row, refreshes `description` and
  `last_seen`, and increments `connection_count` only when called from `open_connection`
  (which calls it internally: callers call `open_connection` for an arrival and
  `record_sighting` alone for a `CHANGED` event).
- All SQL is parameterized. `text` filters use `LIKE` with escaped wildcards.
- Rows that fail to parse (corrupt JSON) are skipped by list methods and reported by get
  methods as `StoreError`; a list never fails because of one bad row.

#### 3.1.3 `RecoveryJournal`

The file is UTF-8, one canonical-JSON object per line, append-only between compactions,
owner-only. Two record shapes:

```
{"op":"open","id":"<16 hex>","ts":"<utc_iso>","scope":"<instance id>|global",
 "action":"<Action value>","fp":"<fingerprint>"|null,
 "entry":{"kind":...,"target":...,"previous":...,"applied":...}}
{"op":"close","id":"<16 hex>","ts":"<utc_iso>","reason":"<text>"}
```

```python
GLOBAL_SCOPE = "global"
VOLATILE_KINDS = frozenset({"sysfs-device", "blockro", "hold"})
GLOBAL_KINDS   = frozenset({"sysfs-host", "file", "registry"})
RESTRICTING    = frozenset({Action.BLOCK, Action.READ_ONLY, Action.DEFAULT_DENY_ON})

@dataclass(frozen=True, slots=True)
class JournalRecord:
    id: str; ts: datetime; scope: str; action: Action; fingerprint: str | None
    entry: JournalEntry

class RecoveryJournal:
    def __init__(self, path: Path, *, clock: Clock) -> None     # loads the file; never raises on bad content
    @property
    def corrupt_lines(self) -> int
    def open_records(self, *, scope: str | None = None,
                     actions: Collection[Action] | None = None) -> list[JournalRecord]  # newest first
    def has_open(self, *, scope: str | None = None,
                 actions: Collection[Action] | None = None) -> bool
    @contextmanager
    def recording(self, *, scope: str, action: Action,
                  fingerprint: str | None) -> Iterator[None]
    def write_ahead(self, entry: JournalEntry) -> None           # the hook handed to enforcers (E2)
    def record(self, result: EnforcementResult) -> None          # call inside recording(), after the enforcer returned
    def add_hold(self, *, scope: str, fingerprint: str | None) -> JournalRecord
    def close(self, ids: Iterable[str], *, reason: str) -> None
    def discard_volatile(self, scope: str, *, reason: str) -> list[JournalRecord]
    def compact(self) -> None
```

**The journal rule.** There is at most one open record per `(kind, target)`. Its
`previous` is the *baseline*: the value before PortLock first touched that target. A
record's stored scope is `GLOBAL_SCOPE` when `entry.kind in GLOBAL_KINDS`, whatever scope
the caller gave.

`write_ahead(entry)`, called by the enforcer before a write, inside `recording(scope,
action, fp)`:

1. If an open record exists for `(entry.kind, entry.target)`: do nothing.
2. Otherwise, if `action in RESTRICTING` or `entry.previous is None`: append an `open`
   record and `fsync`. Remember its id as *opened in this recording*.
3. Otherwise do nothing (a releasing call that changes an existing value never creates a
   baseline: restoring it would restrict).

Called outside `recording()` it raises `StoreError`; the enforcer then refuses the write
(E2).

`record(result)`, called by the service after the enforcer returned:

1. For each `e` in `result.undo` with an open record `R` for `(e.kind, e.target)`: if
   `e.applied == R.entry.previous`, close `R` with reason `returned to baseline`.
   Otherwise leave `R`.
2. For each `e` with no open record: apply steps 2–3 of `write_ahead` (this covers
   enforcers without the hook, such as `FakeEnforcer`).
3. Close every record *opened in this recording* whose entry is not in `result.undo`,
   with reason `not applied` (E3 makes this safe).

`add_hold` appends a record with `JournalEntry("hold", scope, None, None)` and action
`BLOCK`. `discard_volatile(scope)` closes the open records of that scope whose kind is in
`VOLATILE_KINDS`. `close` appends `close` records and `fsync`s. `compact` rewrites the
file with only the open records (`atomic_write_bytes`); it runs automatically when the
number of closed records exceeds 1000 and when the last open record closes.

Loading replays the file. A final line without a newline, or any line that is not a valid
record, is skipped and counted in `corrupt_lines`; the next write starts on a fresh line.
A `close` for an unknown id is ignored.

**Threading.** One `threading.Lock` (L2) around every method. The current `recording()`
context is an attribute of the journal, not thread-local: enforcement is serialized by L1,
and entering `recording()` while another is active raises `StoreError`.

**Failure handling.** A write that fails (disk full, permission) raises `StoreError`;
because of E2 the OS change is then not made. Reads never raise.

**Audit.** None: this module does not import `audit`.

**Test plan.** `test_store.py`: round-trips of every record type; `update_connection`
rejects unknown keys; open/close/list ordering and cursors; settings closed set; two
`Database` handles on one file; a corrupt JSON row is skipped by lists; 2000 connections
paged. `test_journal.py`: the journal rule, case by case (block→unblock returns to
baseline; default-deny on, admit with an allow-list value, re-block closes it; a releasing
call with a non-null `previous` opens nothing; write-ahead then failure closes as `not
applied`; second touch of the same target keeps the first baseline); global kinds are
stored with global scope; torn last line and garbage lines are skipped and counted;
compaction keeps exactly the open records; reopening the file in a second object gives
the same open set; `write_ahead` outside `recording()` raises; concurrent appends from
eight threads lose nothing.

### 3.2 `guard/linux/enforce.py` — Linux enforcer

**Responsibility.** Implements `Enforcer` with the mechanisms in DESIGN §6 as specified by
`docs/enforcement/linux.md`. It also answers which connected devices back the system
volume.

**Files.** `src/portlock/guard/linux/enforce.py`, `tests/unit/test_linux_enforce.py`.

```python
class SysfsIO(Protocol):
    def read_text(self, path: str) -> str            # stripped; raises OSError
    def write_text(self, path: str, value: str) -> None
    def exists(self, path: str) -> bool
    def listdir(self, path: str) -> list[str]
    def realpath(self, path: str) -> str

class BlockIO(Protocol):
    def get_read_only(self, node: str) -> bool        # BLKROGET
    def set_read_only(self, node: str, read_only: bool) -> None   # BLKROSET

class RuleFileIO(Protocol):
    def read(self, path: str) -> str | None           # None if absent
    def write(self, path: str, text: str) -> None      # atomic, mode 0644
    def remove(self, path: str) -> None

@dataclass(frozen=True, slots=True)
class CommandResult: returncode: int; stdout: str; stderr: str; timed_out: bool
class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult

class LinuxEnforcer(Enforcer):
    def __init__(self, *, sysfs: SysfsIO, block: BlockIO, rules: RuleFileIO,
                 runner: CommandRunner, is_root: Callable[[], bool],
                 sysfs_root: str = "/sys", rules_dir: str = "/run/udev/rules.d",
                 write_ahead: Callable[[JournalEntry], None] | None = None) -> None
    @classmethod
    def system(cls, *, write_ahead: Callable[[JournalEntry], None] | None = None) -> LinuxEnforcer

def system_device_ids(devices: Sequence[UsbDevice], *, sysfs: SysfsIO,
                      mountinfo: str) -> frozenset[str]
```

Method semantics beyond `guard/base.py` and section 2.2:

| Method | Mechanism | Journal kind | Tier |
| --- | --- | --- | --- |
| `block` | write `0` to `<instance_id>/authorized` | `sysfs-device` | reactive; preventive if E7 |
| `unblock` | write `1` to `<instance_id>/authorized` | `sysfs-device` (E4 applies) | — |
| `set_read_only(True)` | install the per-device udev rule if absent, reload udev, then `BLKROSET` on every block node of the device that exists now | `file`, `blockro` | preventive if the rule was in place before the device's block nodes appeared, else reactive |
| `set_read_only(False)` | clear `BLKROSET` on the device's nodes, remove the rule | `blockro`, `file` | — |
| `eject` | write `1` to `<instance_id>/remove` | none | — |
| `set_default_deny(True)` | write `0` to every `usbN/authorized_default` | `sysfs-host` | preventive |
| `set_default_deny(False)` | write `1` to every `usbN/authorized_default` (the service never calls this; it restores its own journal records instead, section 3.6.6) | `sysfs-host` | — |
| `restore` | per kind: write `previous` (`sysfs-*`), `BLKROSET` (`blockro`), rewrite or remove the file (`file`) | — | — |

- `UsbDevice.instance_id` is the resolved sysfs device path (wave 1). The enforcer
  refuses, with `ok=False`, any instance id that does not resolve to a directory under
  `<sysfs_root>/devices`: a guard against writing outside sysfs.
- Rule files are named `59-portlock-<12 hex of sha256(instance_id)>.rules`. The enforcer
  only ever writes or removes files with that prefix in `rules_dir`. Default
  `/run/udev/rules.d`, so a reboot removes PortLock's footprint. The rule text and the
  ordering claim behind it come from `docs/enforcement/linux.md`; if that document marks
  the ordering UNVERIFIED, `set_read_only` reports `tier=REACTIVE` always and says so in
  `detail`.
- A read-only flag set on a block node does not make an *already mounted* filesystem
  read-only. When the device has a mounted volume and the flag was set after the mount,
  the result is `ok=True`, `tier=REACTIVE`, and `detail` states that the mounted
  filesystem remains writable until remounted.
- Capabilities: `privileged = is_root()`; `block`/`eject` need root and a writable
  `authorized`/`remove`; `default_deny` needs root and at least one `authorized_default`;
  `read_only` needs root. Notes name a running USBGuard daemon (detected by the presence
  of its IPC socket path, read-only check) as a conflict.
- `system_device_ids`: parse `mountinfo` for the mounts `/`, `/boot`, `/boot/efi`, `/efi`,
  `/usr`, `/var`, `/etc`; map each `major:minor` through `<sysfs_root>/dev/block/`,
  following `slaves/` recursively to physical block devices; return the `instance_id` of
  every device in `devices` whose sysfs path is a prefix of such a block device's path.
  Raises `BackendError` if `mountinfo` cannot be parsed or `/` cannot be resolved.

**Threading.** Not thread-safe; called under L1. **Failure handling.** Per E3 and E10 of
the base contract: `OSError` becomes `ok=False` with `errno` name and path; `EACCES`/
`EPERM` say "not privileged"; `ENOENT` on a device path says "device is gone".
**Audit.** None. **Test plan.** Against fake seams built on a dict: every method in both
directions; idempotence; E2 (the hook is called before the write, and a raising hook
prevents the write); E3 on partial failure across several host controllers; E4; E5 for
each kind including a vanished target; E7; E12; the path-escape guard; rule file naming
and the refusal to touch foreign files; capability matrix for root and non-root;
`system_device_ids` on synthetic trees including a device-mapper stack; no test writes
under the real `/sys`.

### 3.3 `guard/windows/enforce.py` — Windows enforcer

**Responsibility.** Implements `Enforcer` with the mechanisms in DESIGN §6 as specified by
`docs/enforcement/windows.md`, using `ctypes` and `winreg` only. It also answers which
connected devices back the system volume.

**Files.** `src/portlock/guard/windows/enforce.py`, `tests/unit/test_win_enforce.py`.

```python
@dataclass(frozen=True, slots=True)
class RegValue: type: int; data: int | str | tuple[str, ...]      # REG_DWORD, REG_SZ, REG_MULTI_SZ

class RegistryIO(Protocol):                                       # HKLM only
    def get(self, key: str, name: str) -> RegValue | None
    def set(self, key: str, name: str, value: RegValue) -> None    # creates the key
    def delete(self, key: str, name: str) -> None                  # absent is not an error
    def values(self, key: str) -> dict[str, RegValue]

class CfgMgrAPI(Protocol):                                        # every method returns a CONFIGRET int first
    def locate(self, instance_id: str, *, phantom: bool) -> tuple[int, int]        # (cr, devinst)
    def status(self, devinst: int) -> tuple[int, int, int]                         # (cr, status, problem)
    def disable(self, devinst: int, *, persist: bool) -> int
    def enable(self, devinst: int) -> int
    def request_eject(self, devinst: int) -> tuple[int, int, str]                  # (cr, veto type, veto name)
    def reenumerate(self, devinst: int) -> int

class DiskIO(Protocol):
    def disk_numbers(self, device: UsbDevice) -> list[int]
    def get_read_only(self, disk: int) -> bool
    def set_read_only(self, disk: int, read_only: bool) -> None

class WindowsEnforcer(Enforcer):
    def __init__(self, *, cfgmgr: CfgMgrAPI, registry: RegistryIO, disks: DiskIO,
                 is_admin: Callable[[], bool],
                 write_ahead: Callable[[JournalEntry], None] | None = None) -> None
    @classmethod
    def system(cls, *, write_ahead: Callable[[JournalEntry], None] | None = None) -> WindowsEnforcer

def system_device_ids(devices: Sequence[UsbDevice], *, env: Mapping[str, str]) -> frozenset[str]
```

| Method | Mechanism | Journal kind | Tier |
| --- | --- | --- | --- |
| `block` | `CM_Disable_DevNode` with persistence; under default-deny also remove the device's allow-list value | `devnode`, `registry` | reactive; preventive if E7 |
| `unblock` | `CM_Enable_DevNode`; under default-deny add the device's instance id to the allow list and re-enumerate | `devnode`, `registry` (E4) | — |
| `set_read_only(True)` | per-disk read-only attribute if the research document confirms it for removable media, else class-wide `Deny_Write` (E10) | `diskattr` or `registry` | reactive |
| `set_read_only(False)` | the reverse | same | — |
| `eject` | `CM_Request_Device_EjectW` | none | — |
| `set_default_deny` | Device Installation Restriction values | `registry` | preventive |
| `restore` | per kind; `devnode` locates the node with the phantom flag so an unplugged device can be re-enabled | — | — |

- The real seam classes (`_RealCfgMgr`, `_RealRegistry`, `_RealDisks`) live in this file
  with their own `ctypes` prototypes. Wave 1's `guard/windows/api.py` is not edited.
  Importing the module on Linux must not fail: no `ctypes.windll` or `winreg` access at
  import time.
- A `registry` entry encodes type and data in `previous`/`applied` so that restoring puts
  back the exact value, and uses `None` for "value absent". Each allow-list addition is
  its own value and its own entry.
- `block()` must refuse (`ok=False`) a device whose status lacks `DN_DISABLEABLE`, naming
  that as the reason.
- A veto from `request_eject` is `ok=False` with the veto type and name in `error`.
- `system_device_ids`: the disks holding `%SystemDrive%` and `%SystemRoot%`, mapped to
  device instance ids through `volumes.py`; returns the `instance_id` of every device in
  `devices` that is, or is an ancestor of, such a disk. Raises `BackendError` on failure.
- Capabilities: `privileged = is_admin()`; every other capability is False without it.
  Notes name pre-existing Device Installation Restriction values not written by PortLock
  (a domain policy) as a conflict: `default_deny` is then reported False.

**Threading, failure handling, audit.** As 3.2; `CONFIGRET` and Win32 error codes appear
by name in `error`. **Test plan.** Against `FakeCfgMgr`, a dict-backed `FakeRegistry` and
`FakeDisks`: every method both ways; idempotence; E2–E5, E7, E10 (two devices sharing the
class-wide read-only setting, released in either order); a pre-existing registry value is
restored exactly, type included; an allow-list value added by `unblock` is removed by
`block` and by `restore`; `DN_DISABLEABLE` refusal; eject veto; phantom re-enable;
non-admin capability matrix; the module imports on Linux. No test writes the registry or
calls a real CfgMgr function that changes state.

### 3.4 `guard/factory.py` — platform selection and the capability report

**Responsibility.** Chooses the backend and enforcer for the running platform and
produces the guard half of `portlock doctor`. It is the only module that names concrete
platform classes.

**Files.** `src/portlock/guard/factory.py`, `tests/unit/test_factory.py`.

```python
def create_backend(config: Config, *, clock: Clock, platform: str | None = None) -> DeviceBackend
def create_enforcer(config: Config, *, platform: str | None = None,
                    write_ahead: Callable[[JournalEntry], None] | None = None) -> Enforcer
def system_instance_ids(devices: Sequence[UsbDevice], *, platform: str | None = None,
                        env: Mapping[str, str] | None = None) -> frozenset[str]

@dataclass(frozen=True, slots=True)
class DoctorCheck:  id: str; status: str; summary: str; detail: str = ""   # status: ok | warn | fail | info
@dataclass(frozen=True, slots=True)
class DoctorReport: generated_at: datetime; platform: str; version: str
                    backend: BackendCapabilities | None; enforcer: EnforcerCapabilities | None
                    checks: tuple[DoctorCheck, ...]
                    def to_dict(self) -> dict[str, Any]

def doctor(config: Config, *, clock: Clock, backend: DeviceBackend | None = None,
           enforcer: Enforcer | None = None, platform: str | None = None) -> DoctorReport
```

- `platform` defaults to `sys.platform`. `win32` → `WindowsBackend` / `WindowsEnforcer`;
  anything starting with `linux` → `LinuxBackend` / `LinuxEnforcer`; anything else raises
  `BackendError` ("unsupported platform") from the `create_*` functions. The factory
  never returns a fake on its own: fakes are passed in by tests and by `simulate`.
- `create_enforcer` returns the **raw** enforcer. Its only callers are
  `service.daemon.build_runtime` and the `recover` command, both of which wrap it in a
  `SafeEnforcer` before any call.
- `system_instance_ids` dispatches to the platform function; an unsupported platform
  raises `BackendError`.
- `doctor` never raises and never changes anything. When `backend`/`enforcer` are not
  given it creates them, calls only `capabilities()` and `enumerate()`, and turns any
  exception into a `fail` check. Checks, in this order, with these ids:
  `guard.platform`, `guard.privilege`, `guard.backend`, `guard.detect` (event-driven or
  polling), `guard.enumerate` (device **count** only), `guard.block`, `guard.read_only`,
  `guard.eject`, `guard.default_deny`, `guard.conflicts` (from capability notes),
  `guard.system_volume`. A missing capability is `warn` when unprivileged and `fail` when
  privileged. The report never contains a serial number, a product name or an instance id.

**Threading.** Pure functions. **Failure handling.** Above. **Audit.** None.
**Test plan.** Dispatch for `win32`, `linux`, `darwin`; lazy import (importing the factory
on one platform does not import the other's package); `doctor` with `FakeBackend` and
both privileged and unprivileged `FakeEnforcer` variants; `doctor` when `capabilities()`
raises; the report contains no identifying strings from a device with marker values.

### 3.5 `lockdown/manager.py` — lockdown state, dead-man timer, kill switch, rollback

**Responsibility.** Owns the persisted lockdown state machine with its dead-man timer,
the kill-switch file check, and `rollback`, the one routine that puts every journaled
setting back. It decides *whether* lockdown is in force and *which* devices are exempt;
blocking the devices is done by the service's convergence (3.6.6), so there is one code
path that blocks a device.

**Files.** `src/portlock/lockdown/__init__.py` (docstring and re-exports),
`src/portlock/lockdown/manager.py`, `tests/unit/test_lockdown.py`,
`tests/unit/test_rollback.py`.

#### 3.5.1 SQL schema (component name `lockdown`)

```sql
CREATE TABLE lockdown_state (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  state       TEXT NOT NULL CHECK (state IN ('idle','engaging','active','lifting')),
  engaged_at  TEXT,
  engaged_by  TEXT,
  reason      TEXT,
  expires_at  TEXT,
  renewed_at  TEXT,
  renew_count INTEGER NOT NULL DEFAULT 0,
  end_reason  TEXT,                          -- set while 'lifting'
  ended_by    TEXT,
  updated_at  TEXT NOT NULL
);
INSERT INTO lockdown_state (id, state, updated_at)
  VALUES (1, 'idle', strftime('%Y-%m-%dT%H:%M:%fZ','now'));

CREATE TABLE lockdown_history (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  engaged_at  TEXT NOT NULL,
  engaged_by  TEXT NOT NULL,
  reason      TEXT NOT NULL,
  ended_at    TEXT NOT NULL,
  ended_by    TEXT NOT NULL,
  end_reason  TEXT NOT NULL CHECK (end_reason IN
                ('lifted','expired','killswitch','clock_anomaly')),
  renew_count INTEGER NOT NULL
);
```

#### 3.5.2 API

```python
class LockdownError(PortLockError):       # codes: lockdown_active, lockdown_not_active,
    code = "lockdown_error"               #        invalid_duration, killswitch_active

class LockdownState(StrEnum): IDLE, ENGAGING, ACTIVE, LIFTING

@dataclass(frozen=True, slots=True)
class LockdownStatus:
    state: LockdownState
    active: bool                           # True for ENGAGING and ACTIVE
    engaged_at: datetime | None; engaged_by: str | None; reason: str | None
    expires_at: datetime | None; remaining_seconds: int | None
    renew_count: int; default_minutes: int; max_minutes: int
    def to_dict(self) -> dict[str, Any]

@dataclass(frozen=True, slots=True)
class ReconcileSummary:
    evaluated: int; changed: int; blocked: int; read_only: int; released: int; failed: int
    def to_dict(self) -> dict[str, int]

AuditFn = Callable[..., None]   # audit(event_type, *, severity=None, actor=None, device_fp=None, data=None)

class KillSwitch:
    def __init__(self, path: Path) -> None
    @property
    def path(self) -> Path
    def is_set(self) -> bool               # os.path.lexists; an unreadable directory counts as set

class LockdownManager:
    def __init__(self, db: Database, *, clock: Clock, config: LockdownConfig,
                 audit: AuditFn, reconcile: Callable[[str], ReconcileSummary],
                 default_minutes: Callable[[], int]) -> None
    @property
    def active(self) -> bool
    def status(self) -> LockdownStatus
    def engage(self, *, actor: str, minutes: int | None = None, reason: str = "") -> LockdownStatus
    def renew(self, *, actor: str, minutes: int | None = None) -> LockdownStatus
    def lift(self, *, actor: str, end_reason: str = "lifted") -> LockdownStatus
    def tick(self) -> None                 # the dead-man timer
    def resume(self) -> str                # at service start: 'idle' | 'resumed' | 'lift_pending'
    def finish_lift(self, summary: ReconcileSummary | None = None) -> None   # completes a 'lifting' state
    def force_idle(self, *, end_reason: str, actor: str) -> None   # kill switch: state only, no reconcile
    def is_exempt(self, device: UsbDevice, *, connected_at: datetime) -> bool

@dataclass(frozen=True, slots=True)
class RollbackReport:
    reason: str; restored: int; released: int; readmitted: int
    failed: tuple[tuple[str, str], ...]    # (journal record id, error)
    remaining: int                         # open records left in the journal
    def to_dict(self) -> dict[str, Any]

def rollback(journal: RecoveryJournal, enforcer: Enforcer, devices: Sequence[UsbDevice], *,
             reason: str) -> RollbackReport

RECOVER_MARKER = "last-recover.json"
def write_recover_marker(state_dir: Path, report: RollbackReport, *, at: datetime) -> None
def consume_recover_marker(state_dir: Path) -> dict[str, Any] | None
```

Semantics:

- `engage`: `LockdownError(lockdown_active)` unless idle. `minutes` defaults to
  `default_minutes()` and must be 1..`config.max_minutes` (`invalid_duration`). Steps:
  write `engaging` with `engaged_at = now`, `expires_at = now + minutes`; call
  `reconcile("lockdown.engaged")`; write `active`; audit `lockdown.engaged` with the
  summary. The service refuses before calling when the kill switch is set or the
  enforcer is not privileged (3.6.5).
- `renew`: only when active. `expires_at = now + minutes`, capped at
  `now + config.max_minutes`. Increments `renew_count`. Audits `lockdown.renewed`. No
  reconcile.
- `lift`: only when active or engaging. Writes `lifting` with `end_reason`; from that
  instant `active` is False; calls `reconcile("lockdown." + end_reason)`; writes `idle`
  and a history row; audits `lockdown.lifted` (`end_reason == "lifted"`) or
  `lockdown.expired` (`"expired"`, `"clock_anomaly"`). Whether the caller proved the
  administrator password or a recovery code is checked by `console.api` before the
  service is called (API.md); the manager trusts its caller.
- `tick`: when active, lifts with `end_reason="expired"`, actor `system`, if
  `clock.now() >= expires_at` **or** `clock.monotonic() >= ` the in-process monotonic
  deadline (set at engage, renew and resume from the remaining time). The second
  condition means setting the wall clock back cannot stretch a lockdown within one run.
- `resume`, called once from `PortLockService.start` before devices are evaluated:
  `idle` → `idle`. `engaging` or `active` with time remaining → `resumed` (`active` is
  True, so the first reconciliation re-applies the lockdown). `engaging` or `active` with
  `expires_at <= now` → write `lifting` with `end_reason="expired"` and return
  `lift_pending`; if the remaining time exceeds `config.max_minutes` (an impossible
  value: the clock went back, or the row was edited) do the same with
  `end_reason="clock_anomaly"`. `lifting` → `lift_pending`. In the `lift_pending` cases
  `active` is False from the start, so the first reconciliation never re-blocks anything
  for a lockdown that is over; it releases what the journal still holds.
- `finish_lift(summary)`: only in state `lifting`. Writes `idle` and the history row and
  audits `lockdown.lifted` or `lockdown.expired` per the stored `end_reason`, with
  `data.found_at_start = true`. `lift` uses it internally for its last step.
- `is_exempt` is consulted only for unprotected devices while lockdown is active. It
  returns True when **either** the device was connected before `engaged_at` and has no
  storage interface (lockdown "blocks all removable storage at once", it does not cut a
  printer that was already there), **or** the device is an input device without storage
  and `config.allow_new_input_devices` is True. Everything else, including every storage
  device and every other new device, is not exempt.
- `rollback` (also the engine of `portlock recover` and of a clean stop):
  1. `records = journal.open_records()` (newest first);
     `dd = any(r.action is Action.DEFAULT_DENY_ON for r in records)`.
  2. For each record whose kind is not `hold`: `enforcer.restore([record.entry])`; on
     `ok` close it with reason `reason`, else add to `failed`.
  3. For each `hold` record: if a device with that instance id is in `devices`,
     `enforcer.unblock(device)` and close on `ok`; if it is not present, close it.
  4. If `dd`: `enforcer.unblock(device)` for every non-hub device in `devices` (a device
     that arrived under default-deny while nothing was watching has no record). Count in
     `readmitted`. Results are not journaled.
  5. `journal.compact()`; return the report.
  It never raises and never calls a restricting method. `enforcer` must be a live
  `SafeEnforcer`.

**Threading.** No lock; every method is called with L1 held (the service), or in a
single-threaded CLI process (`rollback`). **Failure handling.** A `StoreError` while
writing state propagates to the service method, which fails the API call; the in-memory
state is changed only after the write succeeds. If the database cannot be read at
`tick`, the in-process monotonic deadline still lifts the lockdown: the dead-man timer
does not depend on the database. **Audit.** `lockdown.engaged`, `lockdown.renewed`,
`lockdown.lifted`, `lockdown.expired`, each with `actor`, `expires_at`, `renew_count`
and, for engage and lift, the `ReconcileSummary`.

**Test plan.** `test_lockdown.py` (with `FakeClock`, an in-memory database and a
recording `reconcile`): every transition of the state machine in section 5.2 and every
refused transition; duration validation; renewal cap; expiry by wall clock and by
monotonic clock with the wall clock set back; `resume` for each stored state, including
expired, `engaging`, `lifting` and the clock-anomaly case; a second manager on the same
database sees the same state; `is_exempt` truth table (storage/non-storage ×
before/after engage × input/not × `allow_new_input_devices`). `test_rollback.py` (with
`FakeEnforcer` and a real journal file): restores newest first; one failing entry does
not stop the rest and stays open; holds released for present devices and closed for
absent ones; the re-admission pass runs only when a default-deny record was open and
skips hubs; no restricting call is ever made (asserted on the fake's call log); the
marker file round-trips.

### 3.6 `core/service.py` — the pipeline

**Responsibility.** `PortLockService` runs DESIGN §5: it turns device events, time and
operator actions into decisions, converges the operating system onto them, and audits
every step. It is the only caller of grants, policy evaluation, scans and lockdown at
run time, and the only thing `console.api` talks to for device matters.

**Files.** `src/portlock/core/service.py`, `tests/unit/test_service_pipeline.py`,
`tests/unit/test_service_enforcement.py`, `tests/unit/test_service_restart.py`,
`tests/unit/test_service_scan.py`, `tests/unit/test_service_lockdown.py`,
`tests/unit/test_service_audit.py`, `tests/unit/test_import_rules.py`.

#### 3.6.1 Construction

```python
class ServiceError(PortLockError):     # codes listed in 3.6.5
    code = "service_error"

class AuditWriter:
    """Appends to the audit log, never raising into the pipeline."""
    def __init__(self, log: AuditLog, *, bus: EventBus, clock: Clock) -> None
    @property
    def log(self) -> AuditLog
    @property
    def degraded(self) -> bool
    def __call__(self, event_type: str, *, severity: Severity | None = None,
                 actor: str | None = None, device_fp: str | None = None,
                 data: Mapping[str, Any] | None = None) -> AuditRecord | None
    def auth_hook(self, event_type: str, severity: Severity, data: dict[str, Any]) -> None
        # the AuditCallback handed to AccountStore; actor is taken from data["actor"] or data["username"]
    def flush_backlog(self) -> int

class PortLockService:
    def __init__(self, *, config: Config, clock: Clock, store: StateStore,
                 journal: RecoveryJournal, audit: AuditWriter, bus: EventBus,
                 backend: DeviceBackend, enforcer: Enforcer, grants: GrantStore,
                 db: Database, scanner: Scanner | None,
                 policy_path: Path | None,
                 system_ids: Callable[[Sequence[UsbDevice]], frozenset[str]],
                 guard_doctor: Callable[[], DoctorReport] | None = None,
                 simulation: bool = False) -> None
```

`enforcer` is the raw enforcer; the constructor wraps it (2.3) and never stores the raw
object under a public name. `db` is used only to build the `LockdownManager`; the service
also builds the `KillSwitch` from `config.paths.kill_switch_file`. `DoctorReport` is imported for typing only
(`TYPE_CHECKING`), so `core.service` does not import `guard.factory`. The constructor
does no I/O beyond reading settings; everything else happens in `start()`.

`AuditWriter.__call__` appends and then publishes `audit.appended` on the bus. If the
append raises (`StoreError`, `AuditError`), it writes one line to `stderr`, keeps the
event in an in-memory backlog of at most 1000 (oldest dropped, drop count kept), sets
`degraded`, and returns `None`. `flush_backlog`, called from `tick`, re-appends in order
with `data.delayed = true` and `data.occurred_at` set, and clears `degraded` when empty.

#### 3.6.2 Start (`start()`), in order

1. Create `run_id`. Read the `service.run` setting: if present, the previous run did not
   stop cleanly; remember that. Write the new `service.run`.
2. If `KillSwitch.is_set()`: `_activate_killswitch()` (3.6.8) before anything else.
3. `consume_recover_marker`: if a marker exists, audit `recovery.restored` with its
   content and `actor="local-console"`.
4. Load the policy (3.6.9). Verify the last 256 audit records (`audit.verified` or
   `audit.verification_failed`, `data.scope = "tail"`).
5. Audit `service.started` (`version`, `mode`, `effective_mode`, `platform`, `run_id`,
   `previous_shutdown: "clean"|"unclean"`, `simulation`).
6. `store.close_open_connections(reason="service_restart", removed_at=now)`.
7. `devices = backend.enumerate()`; on `BackendError` retry twice, then continue with an
   empty list and mark the backend degraded (section 7).
8. Build the safety context: `protected_fingerprints` = the `protected_fingerprints`
   setting ∪ the fingerprint of every device in `devices` with an input interface
   (`device.is_hid`); `system_instance_ids = system_ids(devices)`, and if that raises
   `BackendError`, the instance id of **every storage device in `devices`** (a device
   that arrives after start cannot be backing the running system);
   `hid_enforcement_enabled = config.hid_enforcement_enabled`; `scope = config.scope`.
   The start-up input set lives in memory for this run only.
9. Grants: `grants.release_absent(instance ids of devices)`; then for each present device
   holding a bound grant whose fingerprint differs from the device's, `grants.release`;
   then `grants.expire_due(now)`. Audit `grant.expired` for each (`reason`:
   `service_restart` or `expired`).
10. Journal hygiene: `discard_volatile` every scope that is not a present instance id, or
    whose recorded fingerprint differs from the present device's.
11. `resumed = lockdown.resume()`.
12. `reconcile("start")` (3.6.7): opens a connection per device with
    `present_at_start=True`, audits `device.connected`, evaluates, converges.
13. If `resumed == "lift_pending"`: `lockdown.finish_lift(summary)` with the summary of
    step 12.
14. `backend.start(self.on_backend_event)`, then enumerate once more and feed the
    difference from step 7 through `handle_event` as synthesized arrivals and removals
    (a device that arrived between steps 7 and 14 would otherwise be missed).
15. Start the pipeline and scan threads. If the previous shutdown was unclean, audit
    `service.recovered` with what steps 6–13 did (`connections_closed`, `grants_spent`,
    `journal_records_found`, `journal_records_discarded`, `lockdown`).

`start()` raises only for a programming error or a `StoreError` on the first write; the
daemon turns that into exit code 3.

#### 3.6.3 Event handling

```python
def on_backend_event(self, event: DeviceEvent) -> None    # backend thread: queue.put_nowait only
def handle_event(self, event: DeviceEvent) -> None        # pipeline thread (or a test), takes L1
def tick(self) -> None                                    # ticker thread (or a test), takes L1
def stop(self) -> None
```

The queue holds at most 1000 events. If it is full the event is dropped, a flag is set,
and the next `tick` runs a resync (enumerate and diff), so an event storm cannot lose a
device for good.

**ARRIVED.**
1. If an open connection exists for `device.instance_id`: same fingerprint → treat as
   CHANGED; different fingerprint → process a synthesized REMOVED first.
2. `fp = fingerprint(device)`; `journal.discard_volatile(instance_id)`;
   `store.open_connection(...)`.
3. Audit `device.connected`; publish `device.connected`.
4. If not present at start and `device.is_hid`: audit `safety.suspicious_device` with
   `data.reason = "storage_with_input"` (severity `warning`) when
   `device.pairs_storage_with_input`, else `"new_input_device"` (severity `notice`).
   A storage-with-input device found at start is audited the same way with
   `data.present_at_start = true`.
5. `_reevaluate(connection, trigger="arrival")`.

**CHANGED.** Update the connection's description (`record_sighting`,
`update_connection(device=...)`), audit `device.changed` with the added and removed
volumes, re-run `_converge` for the current decision (idempotent; this is what applies
read-only to block nodes that appeared late), then `_schedule_scans`.

**REMOVED.** Find the open connection; none → ignore. Cancel its running scan.
`grants.release(instance_id)` and audit `grant.expired` (`reason="consumed"`) for each
grant returned. `journal.discard_volatile(instance_id, reason="device removed")`.
`close_connection(reason="removed")`. Audit and publish `device.removed`
(`connection_id`, `duration_seconds`, `state`). No enforcer call is made: the device is
gone, and non-volatile records stay open for when it returns (section 6).

**If anything in ARRIVED or `_reevaluate` raises unexpectedly** (a bug, a corrupt row,
an unusable store), `_evaluation_failed` runs: the exception type and message go to
`stderr`; if `config.fail_closed` and `is_protected` says the device is not protected,
the connection gets `Decision(DENY, DEFAULT, reasons=("evaluation failed", ...))` and is
converged like any deny; otherwise it gets `Decision(PENDING, DEFAULT, ...)` with outcome
`failed` and nothing is enforced. If `is_protected` itself raises, the device is left
alone. Either way `decision.made` and `enforcement.failed` are audited when possible.

#### 3.6.4 Read methods (no L1)

```python
def status(self) -> ServiceStatus
def list_connections(self, *, open_only: bool = True, state: ConnectionState | None = None,
                     fingerprint: str | None = None, before_id: int | None = None,
                     limit: int = 100) -> list[ConnectionView]
def get_connection(self, connection_id: int) -> ConnectionView            # not_found
def list_devices(self, *, limit: int = 100, before: str | None = None,
                 text: str | None = None) -> list[DeviceView]
def get_device(self, fingerprint: str) -> DeviceDetail                    # not_found
def list_decisions(self, **filters) -> list[DecisionView]
def list_grants(self, *, include_inactive: bool = False, kind: GrantKind | None = None) -> list[Grant]
def get_policy(self) -> PolicyInfo
def list_scans(self, **filters) -> list[ScanView]
def get_scan(self, scan_id: int) -> ScanView                              # not_found
def lockdown_status(self) -> LockdownStatus
def get_mode(self) -> ModeInfo
def get_settings(self) -> SettingsView
def doctor(self) -> DoctorReport
@property
def audit_log(self) -> AuditLog          # for query, export and checkpoint
@property
def bus(self) -> EventBus
```

`ConnectionView`, `DeviceView`, `DeviceDetail`, `DecisionView`, `ScanView`, `PolicyInfo`,
`ModeInfo`, `SettingsView` and `ServiceStatus` are frozen dataclasses defined in this
module. **Each one's `to_dict()` returns exactly the JSON object of the same name in
`API.md` section 4.** `status()` returns a snapshot object that mutating methods replace
under L1; reading it takes no lock. `doctor()` returns `guard_doctor()` (if given) with
service checks appended: `service.mode`, `service.killswitch`, `service.journal`,
`service.database`, `service.audit`, `service.signing`, `service.scan_engines`,
`service.lockdown`, `service.setup` (no administrator account yet is `warn`).

#### 3.6.5 Mutating methods (all take L1; all take `actor: str`)

```python
@dataclass(frozen=True, slots=True)
class Applied(Generic[T]):
    """The result of a mutating call, with what it caused."""
    value: T
    reevaluated: tuple[int, ...] = ()            # connection ids that were re-evaluated
    summary: ReconcileSummary | None = None       # set by calls that reconcile everything
    extra: Mapping[str, Any] = MappingProxyType({})   # call-specific, named below

def approve(self, connection_id: int, *, kind: GrantKind, read_only: bool = False,
            expires_at: datetime | None = None, note: str = "",
            allow_low_confidence: bool = False, actor: str) -> Applied[Grant]
            # extra: {"connection": ConnectionView}
def deny(self, connection_id: int, *, eject: bool = False, note: str = "",
         actor: str) -> Applied[ConnectionView]      # extra: {"eject": EnforcementResult | None}
def create_grant(self, fingerprint: str, kind: GrantKind, *, read_only: bool = False,
                 expires_at: datetime | None = None, note: str = "",
                 allow_low_confidence: bool = False, actor: str) -> Applied[Grant]
def revoke_grant(self, grant_id: str, *, actor: str) -> Applied[Grant]
def validate_policy(self, data: Mapping[str, Any]) -> tuple[str | None, tuple[str, ...]]   # (hash, problems)
def replace_policy(self, data: Mapping[str, Any], *, expected_hash: str | None = None,
                   actor: str) -> Applied[PolicyInfo]   # extra: {"previous_hash": str}
def test_policy(self, *, device: UsbDevice, policy: Mapping[str, Any] | None = None,
                at: datetime | None = None) -> PolicyTest            # read-only; takes L1 briefly
def request_scan(self, connection_id: int, *, mount_point: str | None = None,
                 actor: str) -> list[ScanView]
def lockdown_engage(self, *, minutes: int | None = None, reason: str = "",
                    actor: str) -> Applied[LockdownStatus]   # extra: {"default_deny": "applied"|"failed"|"unsupported"}
def lockdown_renew(self, *, minutes: int | None = None, actor: str) -> Applied[LockdownStatus]
def lockdown_lift(self, *, actor: str) -> Applied[LockdownStatus]
def set_mode(self, mode: Mode, *, actor: str) -> Applied[ModeInfo]
def update_settings(self, changes: Mapping[str, Any], *, actor: str) -> Applied[SettingsView]
def verify_audit(self, *, start_seq: int = 1, expected_head: tuple[int, str] | None = None,
                 actor: str) -> VerifyResult
```

`PolicyTest` is a frozen dataclass holding the fingerprint, the policy hash, the
`PolicyResult`, the `explain` trace and the `Decision`; its `to_dict()` is the response
of `POST /policy/test`.

`ServiceError` codes, which `console.api` maps to HTTP statuses (API.md section 3):
`not_found`, `invalid_request`, `not_connected`, `not_pending`, `unknown_device`,
`low_confidence`, `policy_invalid` (with `problems`), `policy_conflict`,
`killswitch_active`, `enforcement_unavailable`, `no_mounted_volume`, `scan_unavailable`,
`scan_queue_full`, `store_unavailable`. `LockdownError`, `GrantError` and `PolicyError`
pass through unchanged. Permission checks are **not** made here; `console.api` makes
them. A mutating method either completes or leaves no partial state: it writes the
store first and enforces after, and a `StoreError` before the first write becomes
`store_unavailable`.

- `approve`: the connection must be open (`not_connected`) and its state `pending` or
  `denied`-by-resolution (`not_pending`). Creates a grant for the connection's
  fingerprint (`GrantStore.create`; for `kind=ONCE` the service calls `grants.bind` for
  this connection immediately, so no other connection of an identical device can take it),
  clears any resolution, audits `grant.created` (or `trust.added` for `TRUST`), then
  re-evaluates every open connection with that fingerprint (`trigger="grant"`). If the
  policy denies the device by rule the grant is still created and the connection stays
  denied: the returned view shows it, and the decision's reasons say why.
- `deny`: the connection must be open and `pending`. Sets
  `resolution = {"action":"denied","by":actor,"at":now,"note":note}`, state `denied`,
  audits `decision.made` with `data.resolution = "denied"`. The decision itself is
  unchanged (still `pending`, still blocked); there is no "operator" decision source. If
  `eject`, calls `live.eject(device)` and audits the result. A denial lasts for this
  connection only; a standing denial is a policy rule.
- `create_grant` / `revoke_grant`: the fingerprint must be in `devices`
  (`unknown_device`), which is where its confidence comes from. Audit `grant.created` /
  `grant.revoked`, or `trust.added` / `trust.removed` when the kind is `TRUST`. Then
  re-evaluate open connections with that fingerprint and evaluate orphan records.
- `request_scan`: connection open (`not_connected`), a mounted volume
  (`no_mounted_volume`), scanner present and `scan.enabled` (`scan_unavailable`). Queues
  a `manual` scan. A manual scan of a device whose decision has `scan == none`, or of a
  protected device, is report-only.
- `lockdown_engage`: `killswitch_active` if the kill switch is set;
  `enforcement_unavailable` if the enforcer is not privileged or cannot block. Then
  `LockdownManager.engage`. **Lockdown acts in monitor mode too** (decision D7).
- `set_mode`: `killswitch_active` when asking for `enforce` with the kill switch set;
  `enforcement_unavailable` when asking for `enforce` with an enforcer that is not
  privileged or cannot block. Writes the `mode` setting, audits `mode.changed`
  (`old`, `new`), then `reconcile("mode")`.
- `update_settings`: accepts only `protected_fingerprints` (each must be a known
  fingerprint), `scan.enabled`, `lockdown.default_minutes` (1..`max_minutes`). Audits
  one `config.changed` per key with old and new values, rebuilds the safety context,
  then `reconcile("settings")`.
- `verify_audit`: runs `AuditLog.verify` (outside L1), then audits `audit.verified` or
  `audit.verification_failed` with the result.

#### 3.6.6 Evaluation and convergence

`_reevaluate(connection, trigger)`:

1. `now = clock.now()`; `verdict = is_protected(device, fp, context)`;
   `result = engine.evaluate(device, fp, now=now)`;
   `grant = grants.active_for(fp.value, now=now, instance_id=device.instance_id)`;
   `base = decide(device=..., fingerprint=fp, policy_result=result, grant=grant,
   protected=verdict.protected, protection_reasons=verdict.reasons,
   lockdown_active=lockdown.active,
   lockdown_exempt=lockdown.active and lockdown.is_exempt(device, connected_at=...),
   now=now)`.
2. `final = _scan_overlay(base, connection)` (3.6.10).
3. If `final` equals the connection's current decision and `trigger` is one of `expiry`,
   `periodic`, `grant`, `policy`, `settings`, `scan`: stop. (Triggers `arrival`, `start`,
   `mode`, `lockdown.*`, `retry` always continue to step 6 so convergence re-runs, but
   skip steps 4–5 when the decision is unchanged.)
4. `store.add_decision(...)`; audit `decision.made` (`connection_id`, the decision's
   `to_dict()`, `trigger`, `policy_hash`, `mode`, `protection_codes`). Severity is
   `warning` when `final.alert` or the access is `deny`, else the catalogue default.
5. If `final.grant_id` is set and this connection has not yet used that grant:
   `grants.bind` when the grant is `ONCE`; audit `grant.used`.
6. `_converge(connection, final)`; `store.set_outcome(...)`; audit the result (below).
7. Update the connection's `state` and `provisional`; publish `decision.made` with the
   `ConnectionView`; publish `alert` when `final.alert` or the outcome is `failed`.
8. `_schedule_scans(connection)`.

**Connection state from the decision.** Source `safety` → `protected`. Otherwise by
access: `allow` → `allowed`; `read_only` → `read_only`; `deny` → `denied`; `pending` →
`pending`, or `denied` while a resolution is set. `provisional` is True while a required
scan holds an `allow` at read-only.

**Desired OS state.** `_desired(connection, decision)` returns `(want, would)`:

1. Kill switch set → `(OPEN, None)`.
2. `decision.source is SAFETY` → `(OPEN, None)`.
3. `access` = `READ_ONLY` if the decision is `allow` with `scan == required` and the
   connection's scan state is not `clean`; else `decision.access`.
4. `target` = `OPEN` for `allow`, `READ_ONLY` for `read_only`, `BLOCKED` for `deny` and
   `pending`.
5. If the effective mode is `enforce`, or `decision.source is LOCKDOWN`: `(target, None)`.
   Otherwise (monitor): `(OPEN, target)`.

**Convergence.** `_converge` makes the OS match `want`, using `live`. Let `iid` be the
instance id, `mine_block = journal.has_open(scope=iid, actions={BLOCK})`,
`mine_ro = journal.has_open(scope=iid, actions={READ_ONLY})`,
`dd = journal.has_open(scope=GLOBAL_SCOPE, actions={DEFAULT_DENY_ON})`. Every enforcer
call is wrapped:

```python
def _call(self, scope, action, fp, fn):
    with self._journal.recording(scope=scope, action=action, fingerprint=fp):
        result = fn()
        self._journal.record(result)
    return result
```

- **`BLOCKED`.** If the capability is missing: outcome `unsupported`. Else
  `r = _call(iid, BLOCK, fp, lambda: live.block(device))`. If `r.ok` and there is still
  no open `BLOCK` record for `iid`, `journal.add_hold(scope=iid, fingerprint=fp)`: the
  device was already unusable, and PortLock now owns releasing it. Read-only records, if
  any, stay until the device is released.
- **`READ_ONLY`.** If the device has no storage interface or the capability is missing →
  *cannot* (below). `r1 = _call(iid, READ_ONLY, fp, lambda: live.set_read_only(device,
  True))` (pre-arming, E12). If `mine_block or dd`: when `config.fail_closed` and
  `not r1.ok`, stop here with outcome `failed`, the device stays blocked, and `detail`
  says read-only could not be armed before admission; otherwise `_admit(connection)` and
  call `set_read_only(device, True)` again, taking that result. If the final result is
  not `ok` → *cannot*.
- **`OPEN`.** If `mine_ro`: `_release_read_only`. If `mine_block or dd`: `_admit`. If
  neither applied, outcome `not_needed` and no enforcer call is made. **PortLock only
  releases what it restricted**: a device some other tool disabled is not touched.
  In monitor mode with `would` set, additionally call `dry.block(device)` or
  `dry.set_read_only(device, True)` and record outcome `would_apply` with that result.
- **`_admit`.** `r = _call(iid, UNBLOCK, fp, lambda: live.unblock(device))`. On `ok`:
  close the `hold` record; `live.restore([rec.entry])` each remaining open `BLOCK` record
  of `iid` and close it on `ok`.
- **`_release_read_only`.** `r = _call(iid, READ_WRITE, fp, lambda:
  live.set_read_only(device, False))`. On `ok`: restore and close each remaining open
  `READ_ONLY` record whose scope is `iid`. Global read-only records are handled by
  `_converge_global`.
- ***cannot*** (read-only decided, not enforceable). With `config.fail_closed`: converge
  to `BLOCKED` instead and record `detail = "read-only unavailable; blocked because
  fail_closed is set"`. Without it: outcome `failed` (or `unsupported`), the device is
  admitted and left writable, and an alert is raised. The decision is recorded as not
  enforced, never as blocked (DESIGN §2).

`_converge_global()`, run at the start and the end of every `reconcile`:

- `want_dd = lockdown.active and not killswitch`. If `want_dd` and the capability
  exists: `_call(GLOBAL_SCOPE, DEFAULT_DENY_ON, None, lambda:
  live.set_default_deny(True))` (start of reconcile, so nothing new slips in while
  devices are processed). Default-deny is used **only during lockdown** (decision D8).
- If not `want_dd` (end of reconcile): restore, one by one, every open global record
  with action `DEFAULT_DENY_ON` or `UNBLOCK` (allow-list footprints), closing each on
  `ok`. `set_default_deny(False)` is never called: restoring PortLock's own records puts
  back exactly what was there, and leaves alone a default-deny that someone else set.
- If no open connection wants `READ_ONLY`: restore and close open global records with
  action `READ_ONLY`.

**Audit of an enforcer result** (`_record_result`): `mechanism == "refused"` →
`enforcement.refused` (severity `error`: the pipeline should never ask for it);
`mechanism == "dry-run"` → `enforcement.would_apply`; `ok` → `enforcement.applied`;
otherwise `enforcement.failed`. Data: `connection_id`, `decision_id`, `action`,
`mechanism`, `tier`, `changed`, `detail`, `error`, `cause` (the decision source). To keep
idempotent re-application from flooding the log, `enforcement.applied` and
`enforcement.would_apply` are written only when `result.changed` is True or the
`(action, outcome, mechanism)` triple differs from the last one audited for that
connection; `enforcement.failed` only when the error text changes. A missing capability
is audited as `enforcement.failed` with `error = "unsupported: ..."`.

**Orphan records.** An *orphan* is an open, non-volatile, instance-scoped record whose
device has no open connection: a Windows device node that was disabled and then
unplugged, or one that is plugged in but, being disabled, raises no arrival notification
and may not be listed by the backend. The service must never depend on an arrival event
to release a device it disabled itself.
`_evaluate_orphans()` takes the device description from the newest connection row with
that instance id, computes the decision as in steps 1–2 of `_reevaluate` (no decision
row, no grant binding, no scan), and if `_desired` is `OPEN` restores and closes the
records, auditing `enforcement.applied` with `data.orphan = true`. This is what lets a
later grant or a switch to monitor mode re-enable a device that is not plugged in.

#### 3.6.7 `reconcile(trigger) -> ReconcileSummary` and `tick()`

`reconcile`: `_converge_global()` (restricting half); enumerate-and-diff if `trigger ==
"start"`; `_reevaluate` every open connection; `_evaluate_orphans()`;
`_converge_global()` (releasing half); refresh the status snapshot. It is called for
`start`, `mode`, `policy`, `settings`, `lockdown.*`, `killswitch`, `stop`.

`tick()` never raises; each step is wrapped and a failure is logged and alerted:

1. Kill switch: if `KillSwitch.is_set()` and not yet latched → `_activate_killswitch()`.
2. `lockdown.tick()`.
3. `grants.expire_due(now)` → audit `grant.expired` each; `_reevaluate`
   (`trigger="grant"`) open connections with those fingerprints.
4. `_reevaluate(trigger="expiry")` every open connection whose
   `decision.expires_at <= now`. (`Decision.expires_at` already includes rule expiry and
   time-window changes through `PolicyResult.valid_until`.)
5. Every 30 s, or at once after a dropped event: resync (`backend.enumerate()`, diff
   against open connections, synthesize ARRIVED/REMOVED with `data.synthesized = true`,
   close reason `resync`); `_reevaluate(trigger="retry")` connections whose outcome is
   `failed`; `_evaluate_orphans()`.
6. Every 60 s: `_reevaluate(trigger="periodic")` every open connection (acts only on a
   changed decision); `audit.flush_backlog()`.
7. Scan watchdog (3.6.10).

Latency bounds that follow: grant expiry and rule/time-window expiry are acted on within
one tick (1 s in the daemon); a missed backend event within 30 s.

#### 3.6.8 Mode, kill switch, stop

- **Effective mode** = `monitor` if the kill switch is latched; else the `mode` setting
  if present; else `config.mode`. `ModeInfo.source` says which (`killswitch`, `setting`,
  `config`).
- **`_activate_killswitch()`**: latch; write the `mode` setting as `monitor` (removing
  the file later does not silently re-enable enforcement: going back to `enforce` is an
  explicit, audited `set_mode`); `lockdown.force_idle(end_reason="killswitch",
  actor="system")` if active; `report = rollback(journal, live, connected devices,
  reason="killswitch")`; audit `killswitch.activated` (severity `critical`, with
  `lockdown_was_active`) and `recovery.restored` with the report; `reconcile("killswitch")`
  (records `would_apply` outcomes; makes no restricting call because `_desired` returns
  `OPEN`). When the file disappears the latch clears and `mode.changed` is **not**
  emitted: the mode stays `monitor`.
- **`stop()`**: stop the backend; cancel scans and join the scan thread (5 s); `report =
  rollback(journal, live, connected devices, reason="service_stop")`; audit
  `recovery.restored` if `report.restored + report.released > 0`; close open connections
  (`service_stop`); delete the `service.run` setting; audit `service.stopped` (`clean:
  true`, the report). A clean stop puts everything back, **an active lockdown
  included**: lockdown is in force only while the service runs, and its record stays
  `active` so the next start resumes it (decision D9).

#### 3.6.9 Policy

- At start: `policy_path` missing → `DEFAULT_POLICY`, `source = "default"`. Present and
  valid → use it, `source = "file"`, store it as `policy.last_good`. Present and invalid →
  audit `policy.invalid` with the problems; use `policy.last_good` if there is one
  (`source = "last_good"`), else `DEFAULT_POLICY`.
- The file is read at start only. At run time the policy changes through
  `replace_policy`, never by editing the file under a running service (decision D12).
- `replace_policy`: `parse_policy(data)` (`PolicyError` → `policy_invalid` with
  `problems`, audited as `policy.invalid`); if `expected_hash` is given and differs from
  the current hash → `policy_conflict`; `save_policy(policy_path, policy)`; swap the
  engine; store `policy.last_good`; audit `policy.changed` (`old_hash`, `new_hash`,
  `name`, `rules`); `reconcile("policy")`.
- `test_policy` evaluates a device against the active policy or a draft, returning the
  `PolicyResult`, the `explain` trace, the fingerprint, and the full `decide()` outcome
  with the device's live grant, protection and lockdown state. It changes nothing and
  audits nothing.

#### 3.6.10 Scans

PortLock scans only volumes the OS has mounted; it never mounts anything.

- `_schedule_scans(connection)`: for each volume with a `mount_point` not yet scanned on
  this connection, when the decision's `scan` is not `none`, the decision permits access,
  the device is not protected, `scan.enabled` is true and a scanner exists → `add_scan`
  (`trigger="policy"`) and enqueue. If the decision requires a scan and no volume is
  mounted yet, `scan_state = waiting`. If scanning is disabled or unavailable while the
  decision asks for one, the connection is treated as having outcome `error` (table
  below) and the reason says scanning is unavailable.
- The scan thread takes one job at a time from a queue of at most 16
  (`scan_queue_full`). Per job: audit `scan.started`; `report = scanner.scan(root,
  cancel=event, progress=...)` with no lock held; then under L1: `update_scan`, audit
  `scan.finished` (`scan_id`, `verdict`, counters, `truncated_reason`, finding counts by
  severity, engine statuses), audit `scan.detection` for each `suspicious` or
  `malicious` finding (at most 50 per scan, then one summary record with the remaining
  count), set the connection's `scan_state` to the worst verdict across its volumes, and
  `_reevaluate(connection, trigger="scan")`. Progress is published on the bus as
  `scan.progress` at most once a second.
- A removed connection sets the job's cancel event; the result is stored with state
  `cancelled` and no re-evaluation happens.
- **Overlay.** `_scan_overlay(base, connection)` applies only when `base.scan` is not
  `none`, `base.source` is not `SAFETY` and `base` permits access. It can only narrow.
  With `d = policy.scan.on_detection`:

  | Worst verdict | `d = deny` | `d = read_only` | `d = alert` |
  | --- | --- | --- | --- |
  | `clean` or no result yet | unchanged | unchanged | unchanged |
  | `malicious` | `deny` | `read_only` | unchanged, alert |
  | `suspicious` | `read_only` | `read_only` | unchanged, alert |
  | `incomplete` / `error`, scan `required` | `read_only`; `deny` if `fail_closed` | same | same |
  | `incomplete` / `error`, scan `on_mount` | unchanged, alert; `read_only` if `fail_closed` | same | same |

  When the overlay changes the access the decision's source becomes `SCAN`, a reason is
  appended and `alert` is set. The overlay lasts for the connection; to clear a false
  positive, change the policy so the device's action has `scan = none` (or disconnect and
  rescan). `suspicious` never denies on its own: heuristics are hints (decision D14).
- **Watchdog.** If a job is still running at `started_at + scan.max_seconds + 30 s`, set
  its cancel event; if it has not returned 30 s after that, mark it `done` with verdict
  `error` ("scan did not stop"), abandon the thread (it is a daemon thread) and start a
  new scan thread. After 4 abandoned threads scanning is disabled until restart and the
  status shows `scan` as degraded.

#### 3.6.11 Threading, failure handling, audit

Threading is section 1.3–1.4. Failure handling is section 7. Audit events by step are
section 8.

**Test plan** (all with `FakeBackend` in synchronous mode, `FakeEnforcer`, `FakeClock`,
an in-memory or `tmp_path` database and a `tmp_path` journal; no sleeping):

- `test_service_pipeline.py`: arrival of each factory device in monitor and enforce mode
  gives the expected decision, state, outcome and audit sequence; duplicate arrival;
  CHANGED adds a volume; removal; reconnection gets a new connection id and the same
  fingerprint; grant create/revoke/expire re-evaluates; ONCE grant bound, spent at
  removal, not valid for the next connection; rule expiry and a time window closing via
  `clock.advance` and `tick`; `approve` and `deny`; evaluation failure with and without
  `fail_closed`; resync finds a device whose event was dropped.
- `test_service_enforcement.py`: the `_desired` truth table; convergence for every
  (previous state → wanted state) pair, asserting the `FakeEnforcer` call log and the
  journal's open records; "only releases what it restricted"; read-only pre-arm, late
  block nodes, and the *cannot* path with and without `fail_closed`; capability missing;
  injected failures are retried and audited once; a protected device never receives a
  restricting call (a seeded random sweep over devices, contexts, policies, grants, modes
  and lockdown states asserting it on the inner fake); orphan records released by a later
  grant.
- `test_service_restart.py`: section 6, row by row: build a service, act, drop it without
  `stop()`, build another on the same database and journal.
- `test_service_scan.py`: with a stub `Scanner`: `on_mount` and `required` flows; every
  row of the overlay table; cancel on removal; the watchdog with a scanner that never
  returns (driven by `FakeClock`, the stuck call parked on an `Event`); queue limit.
- `test_service_lockdown.py`: engage blocks storage and holds new devices, protected
  devices untouched, exemptions; lift in enforce mode leaves policy-denied devices
  blocked with no unblock/block bounce (asserted on the call log); lift in monitor mode
  leaves the journal empty; expiry via `tick`; kill switch during lockdown; lockdown in
  monitor mode acts; engage refused with the kill switch set or an unprivileged enforcer.
- `test_service_audit.py`: the event names and required data keys of section 8 for each
  flow; the registry accepts every event the service emits; no secret-bearing key ever
  appears; an audit failure does not stop enforcement and the backlog is flushed;
  `AuditLog.verify` passes after a long mixed scenario.

### 3.7 `service/daemon.py` — the process

**Responsibility.** Composes every component from a `Config`, owns the single-instance
lock, the runtime file, signals and the ticker, and maps failures at start to exit
codes. It contains no pipeline logic.

**Files.** `src/portlock/service/__init__.py`, `src/portlock/service/daemon.py`,
`tests/unit/test_daemon.py`.

```python
EXIT_OK, EXIT_ERROR, EXIT_ALREADY_RUNNING, EXIT_STATE_UNUSABLE, EXIT_CONFIG, EXIT_PORT = 0, 1, 2, 3, 4, 5

@dataclass(slots=True)
class Runtime:
    config: Config; clock: Clock; db: Database; journal: RecoveryJournal
    audit_log: AuditLog; audit: AuditWriter; sinks: FanOut | None; bus: EventBus
    accounts: AccountStore; sessions: SessionStore; grants: GrantStore
    store: StateStore; service: PortLockService
    def close(self) -> None

def build_runtime(config: Config, *, clock: Clock | None = None,
                  backend: DeviceBackend | None = None, enforcer: Enforcer | None = None,
                  scanner: Scanner | None = None, platform: str | None = None,
                  simulation: bool = False) -> Runtime

class InstanceLock:
    def __init__(self, path: Path) -> None
    def acquire(self) -> bool            # non-blocking; fcntl.flock / msvcrt.locking on one byte
    def release(self) -> None

def read_runtime_file(state_dir: Path) -> dict[str, Any] | None
def request_stop(state_dir: Path) -> None            # writes stop.request atomically
def run(config: Config, *, install_signal_handlers: bool = True) -> int
```

`build_runtime` is the single composition root, used by `run`, by `simulate` and by the
integration tests. Order: `ensure_private_dir(state_dir)`; `RecoveryJournal`; `Database`;
`EventBus`; sinks from `config.audit.sinks` into a background `FanOut`; HMAC key read
from `config.audit.hmac_key_file` if set; `AuditLog(db, clock=..., hmac_key=...,
sink=fanout)`; `AuditWriter`; `AccountStore(db, clock=..., audit=writer.auth_hook,
policy=AuthPolicy built from config.auth)`; `SessionStore(db, clock=..., idle_timeout,
absolute_timeout, account_lookup=accounts.get_user)`; `GrantStore`; `StateStore`; the
scanner (engines from `config.scan.engines`, limits from `config.scan`); the backend and
the enforcer from `guard.factory` unless given, the enforcer created with
`write_ahead=journal.write_ahead`; `PortLockService`.

`run`:

1. `InstanceLock.acquire()`; held → print "already running", return 2.
2. **Before the database is opened**: if the kill-switch file exists, open the journal,
   build the enforcer, and `rollback(journal, SafeEnforcer(enforcer, ...), devices,
   reason="killswitch")` with `devices` from a best-effort `enumerate()`. A broken
   database must not stand between the operator and the kill switch.
3. `build_runtime`. `StoreError` (corrupt, or newer schema) → run `rollback` as in step 2
   with `reason="state_unusable"` unless `config.fail_closed`, print what to do, return 3.
   PortLock never deletes, repairs or recreates the database on its own: it holds the
   audit log.
4. `service.start()`; start `ApiServer` (bind failure → `service.stop()`, return 5);
   write `runtime.json` (`{"v":1,"pid","host","port","run_id","started_at","version"}`,
   atomic, owner-only).
5. Ticker thread: every second `service.tick()`; if `stop.request` exists, delete it and
   set the stop event.
6. Wait for the stop event (set by `SIGINT`, `SIGTERM`, and `SIGBREAK` on Windows).
7. Shutdown: stop the API server (close event streams), `service.stop()`, remove
   `runtime.json`, `Runtime.close()` (flush sinks 5 s, close the database), release the
   lock, return 0.

A second signal during shutdown is ignored for 10 s and then exits with 1.

**Threading.** `portlock-main` runs `run`; the ticker is the only other thread the daemon
creates. **Failure handling.** An exception from `tick` is caught inside `tick`. An
unexpected exception in `run` after start goes through the shutdown sequence in a
`finally`, then returns 1. **Audit.** None directly; `service.started` and
`service.stopped` come from the service.

**Test plan.** `build_runtime` on a `tmp_path` home with fakes produces a working
service; the lock refuses a second holder in the same process and in a subprocess;
`runtime.json` is written, private and removed; `stop.request` stops a running `run`
(started on a thread with `install_signal_handlers=False`, port 0); exit code 3 with a
truncated database file, with and without `fail_closed`, and the rollback that precedes
it; exit code 5 when the port is taken; the kill switch is honoured with a database that
cannot be opened.

---

## 4. Wave 3 modules

### 4.1 `console/api.py` — local HTTP API, event stream, static console

**Responsibility.** Serves `API.md` and the static web console on the loopback address,
and is the only place where sessions, CSRF, `Host`/`Origin` rules and role checks are
applied. It holds no device logic: every device operation is one `PortLockService` call.

**Files.** `src/portlock/console/__init__.py`, `src/portlock/console/api.py`,
`tests/unit/test_api_auth.py`, `tests/unit/test_api_security.py`,
`tests/unit/test_api_endpoints.py`, `tests/unit/test_api_events.py`.

```python
class ApiServer:
    def __init__(self, *, config: Config, clock: Clock, service: PortLockService,
                 accounts: AccountStore, sessions: SessionStore, audit: AuditWriter,
                 static_root: Traversable | None = None) -> None
    @property
    def address(self) -> tuple[str, int]        # the bound host and port (port 0 resolves here)
    def start(self) -> None                     # binds, starts portlock-api
    def stop(self, timeout: float = 5.0) -> None

@dataclass(frozen=True, slots=True)
class Route:
    method: str; pattern: str; permission: Permission | None    # None: public or session-only
    handler: Callable[[Request], Response]; csrf: bool
ROUTES: tuple[Route, ...]                        # the whole of API.md, one entry per endpoint
```

- Built on `http.server.ThreadingHTTPServer` with `daemon_threads = True`. HTTP/1.1,
  `Connection: close` on every response except the event stream. Bound to
  `config.api.host` only; `SO_REUSEADDR` off on Windows.
- Limits: 32 concurrent requests (the 33rd gets 503 without reading the body), 8 event
  streams, request line and headers 16 KiB, body 2 MiB, 30 s to receive a request, 10 s
  per write on a stream.
- Request handling order, each failing fast with the error in API.md: connection limit →
  parse → `Host` allowlist → `Origin`/`Sec-Fetch-Site` → route lookup → method → session
  cookie → CSRF (for routes with `csrf=True`) → permission (`can(session.role, ...)`) →
  body size and `Content-Type` → JSON parse and field validation → handler.
- Every handler is wrapped: `ServiceError`, `LockdownError`, `GrantError`, `PolicyError`,
  `AuthError`, `StoreError` map to the statuses in API.md; anything else is 500 with a
  request id, logged to `stderr` with the traceback, never returned to the client.
- `ROUTES` is data: `tests/unit/test_api_endpoints.py` walks it and asserts every route
  appears in `API.md` and every state-changing route has `csrf=True` and a permission.
- Static files are loaded once at start from `importlib.resources.files(
  "portlock.console") / "static"` into a dict of path → (bytes, content type, ETag).
  Requests never touch the filesystem, so there is no path traversal to get wrong.
  Unknown paths are 404; there is no directory listing and no SPA fallback for `/api/`.
- The event stream subscribes to the bus with a handler that only does
  `queue.put_nowait`; a full queue (256) marks the stream as lagged and it is closed, so
  the client reconnects and resumes or resets (API.md section 7).
- A stream checks that its session is still alive every 15 s **without refreshing it**:
  it looks for its `session_id` in `sessions.list_sessions(username)`. It must not call
  `validate`, which would let an open console tab keep a session alive for ever.
- Housekeeping: `sessions.purge_expired()` on every login and at most once a minute.
- Audit emitted here (through `AuditWriter`): `auth.logout`. Everything else under
  `auth.*` is emitted by `AccountStore`.

**Threading.** One accept thread, one thread per request. Handlers take no lock of their
own. **Failure handling.** A client that disconnects mid-response is ignored. A
`StoreError` is 503 `store_unavailable`. **Test plan.** `test_api_auth.py`: login,
cookie attributes, logout, session idle and absolute expiry with `FakeClock`, password
change ends other sessions, recovery flow, lockout responses identical for unknown and
known names, the three login limits. `test_api_security.py`: every `Host` and `Origin`
case in API.md; CSRF missing/wrong on every state-changing route (driven from `ROUTES`);
wrong `Content-Type`; oversized body; unknown fields; each role against every route
(driven from `ROUTES` and `can`); no CORS headers on any response; security headers on
every response; nothing secret in any error. `test_api_endpoints.py`: one success and
one failure per endpoint against a real server on port 0 backed by `build_runtime` with
fakes; response shapes checked against the field tables. `test_api_events.py`: framing,
replay with `Last-Event-ID`, `reset` on an unknown run or a gap, heartbeat, stream ends
when the session ends, lag closes the stream, the stream limit.

### 4.2 `console/cli.py` — the command line

**Responsibility.** `portlock`, the entry point for everything an administrator does. A
*service command* is an HTTP client of the API; a *local-console command* works on files
with operating-system rights and never needs the service.

**Files.** `src/portlock/console/cli.py`, `tests/unit/test_cli.py`.

```python
def main(argv: Sequence[str] | None = None) -> int
```

`argparse` only. Output is plain text; `--json` on any read command prints the API
response unchanged. Exit codes: 0 success; 1 the operation failed; 2 usage; 3 not
authenticated or not permitted; 4 service not running or not reachable; 5 a check failed
(`audit verify`, `policy validate`, `doctor` with a `fail`).

| Command | Kind | Does |
| --- | --- | --- |
| `run [--config PATH]` | local | `service.daemon.run` in the foreground |
| `stop` | local | `request_stop`; waits up to 15 s for `runtime.json` to vanish |
| `setup` | local | creates the **first** administrator (refuses if any user exists) |
| `recover [--dry-run]` | local | rollback from the journal, no database (below) |
| `user reset-password NAME --local`, `user unlock NAME --local` | local | `AccountStore.set_password` / `clear_lockout` directly on the database |
| `config init`, `config check`, `config show` | local | `config_to_toml`, `load_config` |
| `policy init`, `policy validate FILE`, `policy test FILE --device JSON` | local | `defaults`, `loader`, `engine`; no service |
| `audit verify --offline` | local | opens the database read-only, `AuditLog.verify` |
| `doctor [--offline]` | local or service | `guard.factory.doctor`; with a running service, `GET /doctor` |
| `service unit`, `service task` | local | print the definitions from `service.install` |
| `simulate [...]` | local | `console.simulate` |
| `status`, `devices`, `pending`, `approve`, `deny`, `trust`, `grant`, `policy show/apply/test --live`, `audit list/verify/export/checkpoint`, `scan`, `lockdown`, `mode`, `user`, `settings`, `password`, `watch` | service | one API call each (`watch` follows the event stream) |

- **Finding the service** (first that works): `--url` or `PORTLOCK_URL`; `runtime.json`
  in the state directory; nothing else. A service command without either prints why and
  returns 4.
- **Proving it is the service.** With `runtime.json`, the CLI calls `GET /api/v1/ping`
  and requires the returned `run_id` to equal the file's. Only then does it send
  credentials. `runtime.json` is readable only by those the operating system lets into
  the state directory, so a process squatting on the port cannot know the `run_id`. With
  `--url` the operator has named the endpoint and no check is possible; the CLI says so
  on `stderr` before prompting.
- **Authenticating.** Service commands other than `status` (which uses `ping`) log in:
  user name from `--user`, `PORTLOCK_USER` or a prompt; password from `getpass` or
  `--password-stdin`; never from an argument or an environment variable. The CLI logs in,
  performs the call with the session cookie and CSRF header, and logs out. Nothing is
  stored on disk.
- **Local-console commands** are authorized by the operating system alone: they need to
  open the state directory. They audit with `actor="local-console"` (through an
  `AuditLog` on the same database file, which is safe beside a running service).
  `AccountStore` calls use `channel=Channel.LOCAL`. This is the path that an attacker
  hammering the HTTP login cannot lock.
- **`recover`**: take `InstanceLock`. If the service holds it: create the kill-switch
  file, wait up to 10 s for the journal to empty (the running service honours the file
  within a tick), and report; if it does not empty, say that the service process must be
  stopped, return 1. If the lock is free: create the kill-switch file, build the
  platform enforcer, wrap it in a live `SafeEnforcer` with an empty context, best-effort
  `enumerate()`, `rollback(...)`, `write_recover_marker`, print the report. It opens no
  database. The kill-switch file is left in place so that a service started afterwards
  does not re-apply what was just undone; the output says how to remove it.
  `--dry-run` lists the open journal records and changes nothing.

**Threading.** Single-threaded. **Failure handling.** Every `PortLockError` becomes one
line on `stderr` and a non-zero exit; a traceback only with `PORTLOCK_DEBUG=1`.
**Audit.** Local commands: `auth.user_created`, `auth.password_changed`,
`auth.user_changed` (from `AccountStore`), `audit.verified` /
`audit.verification_failed` (offline verify does **not** append: the database is opened
read-only). **Test plan.** Argument parsing for every command; service commands against
a real `ApiServer` on port 0 with fakes; `ping` mismatch refuses to send credentials;
password never appears in `argv` handling or output; `setup` refuses a second user;
`recover` with a free lock, with a held lock, with `--dry-run`, and with a missing
database; exit codes.

### 4.3 `console/static/` — the web console

**Responsibility.** A static single-page console for the API: live devices and decisions,
the pending queue, grants and trust, policy, audit, scans, lockdown and users. It adds no
capability the API does not have.

**Files.** `src/portlock/console/static/index.html`, `app.js`, `app.css`, optional
further `.js` modules and `.svg` icons. No build step, no framework download, no
third-party script, font or stylesheet, no external request of any kind.

Rules the implementer must keep (they are what the server's Content-Security-Policy
enforces): no inline script or style, no `eval`, all DOM text set with `textContent`
(device strings are attacker-controlled), every state-changing `fetch` sends
`X-PortLock-CSRF`, the CSRF token is held in memory only and re-fetched from
`GET /auth/session` after a reload, one `EventSource` on `/api/v1/events` drives the
live views, and a `reset` event triggers a full refetch. The lockdown lift dialog asks
for the password or a recovery code every time. When `ping` reports `setup_required`
the console shows how to run `portlock setup` and nothing else.

**Test plan.** `tests/unit/test_static.py`: every file is served with the right content
type and headers; a scan of the files finds no inline event handler, no `innerHTML`
assignment, no `http://`/`https://` URL other than the documented relative ones, and no
`eval`/`Function(`.

### 4.4 `service/install.py` — service definitions

**Responsibility.** Generates the text of a systemd unit and of a Windows scheduled-task
definition for the administrator to review and apply. It installs nothing and changes no
system state.

**Files.** `src/portlock/service/install.py`, `tests/unit/test_install.py`.

```python
def systemd_unit(config: Config, *, executable: str) -> str
def windows_task_xml(config: Config, *, executable: str) -> str
def install_instructions(platform: str) -> str
```

- Linux: `Type=simple`, `ExecStart=<executable> run`, `Restart=always`, `RestartSec=2`
  (the dead-man timer and the release of held devices need the service alive),
  `ExecStop=<executable> stop`, and the hardening options from
  `docs/enforcement/linux.md`. That document is authoritative for the option list; the
  unit must leave `/sys` writable, allow `AF_NETLINK`, `AF_UNIX` and `AF_INET`, and make
  only the state directory, the configuration directory and the udev rules directory
  writable.
- Windows: a Task Scheduler definition that runs at boot as `SYSTEM` with highest
  privileges, restarts on failure, and has no execution time limit. A scheduled task is
  used because a real Windows service needs a service-control dispatcher, which the
  standard library does not provide (decision D20). `portlock stop` is the graceful
  stop; ending the task is a crash as far as section 6 is concerned.
- Paths are quoted for the target format and validated: a path containing a newline or
  a character the format cannot quote raises `ConfigError`.

**Test plan.** Golden-file comparison for default configurations on both platforms; the
systemd unit parses with `configparser`; the task XML parses with `xml.etree` and
contains no user name other than `SYSTEM`; hostile paths are refused; nothing is written
outside the path the caller passes.

### 4.5 `console/simulate.py` — `portlock simulate`

**Responsibility.** Runs the complete pipeline on `FakeBackend` and `FakeEnforcer` in a
temporary directory, so the product can be explored on any machine. It never touches a
real device, the real state directory or the real configuration.

**Files.** `src/portlock/console/simulate.py`, `tests/unit/test_simulate.py`.

```python
SCENARIOS: Mapping[str, Callable[[Simulation], None]]     # at least "tour"
class Simulation:
    def __init__(self, *, home: Path, clock: Clock, enforce: bool = True) -> None
    runtime: Runtime; backend: FakeBackend; enforcer: FakeEnforcer
    def plug(self, name: str) -> UsbDevice          # a named synthetic device
    def unplug(self, name: str) -> None
    def advance(self, seconds: int) -> None         # FakeClock only; also ticks
    def timeline(self) -> list[str]                 # one line per audit record since the last call
    def close(self) -> None
def run_simulation(args: argparse.Namespace) -> int
```

`portlock simulate` runs the `tour` scenario on a `FakeClock` and prints the timeline:
a trusted stick, an unknown stick that waits and is approved once, a storage-with-
keyboard device denied with an alert, a keyboard that is protected, a temporary grant
that expires, removal and reconnection, lockdown engaged and expiring. `--serve` instead
starts the real API and console on a free port over the simulated service (real clock),
creates one administrator with a random password printed once, and reads `plug NAME`,
`unplug NAME`, `quit` from standard input. The status reports `simulation: true` and the
console shows a banner. Devices are synthetic; identifiers start with `TEST`.

**Test plan.** The `tour` scenario's timeline matches a golden list of event types;
nothing is created outside `home`; `--serve` answers `ping` with `simulation: true`.

### 4.6 Integration tests

**Files.** `tests/integration/conftest.py` (a `runtime` fixture from `build_runtime` on
`tmp_path` with fakes, and an `api` fixture with a real server on port 0 and a logged-in
client per role), and one file per required area, named in section 9. They exercise the
system only through the HTTP API, the CLI entry point and `FakeBackend`.

---

## 5. State machines

### 5.1 A device connection

A connection row exists from arrival to removal. Its `state` follows the current
decision; whether the OS matches is the decision's `outcome`.

```
                 arrival / present at start
                          │
                        [new]
                          │ evaluate
     ┌──────────┬─────────┼───────────┬───────────┐
     ▼          ▼         ▼           ▼           ▼
[protected] [allowed] [read_only] [pending] ◄──► [denied]
     └──────────┴────── re-evaluation ┴───────────┘      (any state to any state)
                          │
          removed / resync / service stop / service restart
                          ▼
                      (closed)
```

| Trigger | Scope | Effect |
| --- | --- | --- |
| ARRIVED, or found at start | one | open connection, `new` → evaluate |
| CHANGED (a volume appeared or was mounted) | one | re-converge; schedule scans |
| grant or trust created, revoked, expired, spent | same fingerprint | re-evaluate |
| `approve` | same fingerprint | grant, clear resolution, re-evaluate |
| `deny` | one | `pending` → `denied` (resolution); optional eject |
| policy replaced | all | re-evaluate |
| `decision.expires_at` reached (rule expiry, time window, grant expiry) | one | re-evaluate |
| lockdown engaged, lifted, expired | all | re-evaluate |
| mode changed, kill switch | all | re-evaluate (same decisions, different desired OS state) |
| `protected_fingerprints` changed | all | re-evaluate |
| scan finished | one | overlay, re-evaluate |
| enforcement failed earlier | one | retried every 30 s |
| REMOVED, resync, stop, restart | one / all | closed with the reason |

Scan sub-state, per connection: `none` → `waiting` (a scan is wanted, nothing mounted
yet) → `queued` → `running` → one of `clean`, `suspicious`, `malicious`, `incomplete`,
`error`. A later volume can move it back to `queued`; the final value is the worst
across volumes.

Mapping from decision to state and to desired OS state:

| Decision | State | Enforce mode | Monitor mode |
| --- | --- | --- | --- |
| source `safety` | `protected` | open, never a restricting call | open |
| `allow` | `allowed` | open | open |
| `allow`, scan `required`, not yet clean | `read_only`, provisional | read-only | open (would be read-only) |
| `read_only` | `read_only` | read-only | open (would be read-only) |
| `pending` | `pending` (`denied` after an operator denial) | blocked | open (would be blocked) |
| `deny`, source `policy`/`scan`/`default` | `denied` | blocked | open (would be blocked) |
| `deny`, source `lockdown` | `denied` | blocked | **blocked** |

### 5.2 The lockdown manager

```
          engage                    reconcile done
 [idle] ─────────► [engaging] ───────────────────► [active] ──┐ renew
    ▲                   │                             │  ▲────┘
    │                   │ lift / expiry               │ lift (admin, re-authenticated)
    │                   ▼                             │ expiry (wall clock or monotonic)
    └───────────── [lifting] ◄────────────────────────┘ clock anomaly at start
       reconcile done        kill switch: [engaging|active|lifting] ──► [idle] directly
```

| From | Event | Guard | To | Audit |
| --- | --- | --- | --- | --- |
| idle | `engage` | 1 ≤ minutes ≤ max; kill switch clear; enforcer can block | engaging → active | `lockdown.engaged` |
| active | `engage` | — | refused `lockdown_active` | — |
| active | `renew` | 1 ≤ minutes ≤ max | active (new expiry) | `lockdown.renewed` |
| idle | `renew`, `lift` | — | refused `lockdown_not_active` | — |
| active, engaging | `lift` | caller proved password or recovery code | lifting → idle | `lockdown.lifted` |
| active | `tick`, expiry reached | — | lifting → idle | `lockdown.expired` |
| active, engaging | start, expiry passed | — | lifting → idle (never re-applied) | `lockdown.expired` (`found_at_start`) |
| active, engaging | start, time remains | remaining ≤ max | active | — (`service.recovered` mentions it) |
| active, engaging | start, remaining > max | — | lifting → idle | `lockdown.expired` (`clock_anomaly`) |
| lifting | start | — | idle | `lockdown.lifted` or `lockdown.expired` per stored reason |
| any but idle | kill switch | — | idle | `killswitch.activated` |

What lockdown does while active, through convergence: every unprotected, non-exempt
device is `deny` with source `lockdown` and is blocked, in either mode; default-deny is
on, so a new device is unusable from the first instant; a new device that turns out to
be protected or exempt is admitted by the service as soon as it is evaluated.

Safeguards, and where each lives: protected devices are never touched (`SafeEnforcer`,
plus `_desired` rule 2); dead-man timer (`LockdownManager.tick`, persisted expiry, the
monotonic guard); lift needs re-authentication (`console.api`); kill switch (`KillSwitch`,
checked at start before the database and every tick); `portlock recover` without service
or database (`rollback` on the journal file); clean stop restores everything
(`PortLockService.stop`).

Limits, stated plainly: lockdown is in force only while the service runs. With the
default `scope = "storage"`, a new non-storage device is outside the enforcement scope,
so it is protected and admitted even during lockdown; set `scope =
"all_except_protected"` to hold every new device. If the service dies during lockdown,
the OS default-deny stays on until the service restarts or `portlock recover` runs, and
in that window a re-plugged keyboard is refused by the OS: run the service under a
supervisor that restarts it.

---

## 6. Crash-recovery matrix

What the next `start()` does with each piece of state a crash can leave behind. "Crash"
means the process ended without `stop()`: power loss, `kill -9`, an ended scheduled task.

| State found at start | What the service does |
| --- | --- |
| `service.run` setting present | The previous run was unclean. Everything below is summarized in one `service.recovered` record. |
| Open connections from the old run | All closed with `service_restart` and `removed_at = now` (the true removal time is unknown and is not invented). Devices present now get new connections with `present_at_start = true`. |
| Pending decisions (connections waiting for an administrator) | Not carried over as such. The device, if still present, is evaluated again and is `pending` again under a new connection id. An operator denial (`resolution`) is per connection and is gone; the device is still blocked. |
| Journal: open record, device present, same fingerprint | Kept. The device is evaluated; a decision that blocks leaves the record as it is (the enforcer call is idempotent and the baseline is not overwritten); a decision that permits releases it. No window in which a denied device becomes usable. |
| Journal: open volatile record, device absent or a different device at that instance id | Discarded: the OS forgot the state when the device left. |
| Journal: open non-volatile instance record, device absent (orphan) | Kept and evaluated against the device's last known description; restored if the decision now permits, or if the mode is monitor. Re-checked every 30 s and on every reconcile. |
| Journal: open global record (default-deny, class-wide read-only, a generated rule file) | Kept if still wanted (lockdown active; a connection wanting read-only), otherwise restored at the end of the first reconcile. |
| Half-applied enforcement: record written ahead, OS change not made | The record's baseline equals the current value. It is kept or restored by the rows above; restoring writes the value that is already there. Harmless by construction. |
| Half-applied enforcement: OS change made, result never recorded | Same record, now with a real difference. Handled by the rows above. Because the record is written and `fsync`ed before the change (E2), there is no state in which the OS was changed and the journal does not know. |
| Journal with a torn or corrupt line | The line is skipped and counted (`service.journal` in doctor, `journal` in the status' degraded list). Every readable record is honoured. |
| Lockdown `active`, expiry in the future | Resumed. Default-deny is re-applied and devices re-evaluated in the first reconcile. The monotonic deadline is reset from the remaining time. |
| Lockdown `active` or `engaging`, expiry passed | Not re-applied. The state goes to `lifting` before devices are evaluated, the first reconcile releases what the journal still holds, then `lockdown.expired` is audited with `found_at_start`. |
| Lockdown `engaging` (crash mid-engage), time remaining | Treated as active: the first reconcile completes what engage started. |
| Lockdown `lifting` (crash mid-lift) | The lift is completed: state `idle`, history row, the stored end reason audited. |
| Lockdown with remaining time greater than `max_minutes` | Treated as expired (`clock_anomaly`). |
| One-time grant bound to a connection | `release_absent`: spent if its device is no longer present. Also spent if a different device now sits at that instance id. Kept if the same device is still present (a re-plug into the same port while the service was down cannot be told apart from continuous presence; documented limit). |
| Grants that expired while the service was down | `expire_due(now)`; each audited once; the first reconcile already evaluates without them. |
| Kill-switch file present | Rollback from the journal before the database is opened; mode setting written as `monitor`; lockdown forced idle; `killswitch.activated` and `recovery.restored` audited. |
| `last-recover.json` present | Audited as `recovery.restored` (`actor = local-console`) with the report it contains, then deleted. |
| A scan that was queued or running | Its row is marked `cancelled`. The connection it belonged to is closed; the device's new connection schedules scans afresh. |
| `mode` setting | Honoured (unless the kill switch is set). |
| Policy file missing | `DEFAULT_POLICY`. |
| Policy file invalid | `policy.invalid`; `policy.last_good` if stored, else `DEFAULT_POLICY`. |
| Audit chain does not verify (tail check) | `audit.verification_failed` (severity `critical`); the service keeps running and keeps appending; status and doctor show it. |
| Database corrupt or from a newer version | The daemon does not start: rollback from the journal (unless `fail_closed`), exit code 3, nothing deleted. |
| Stale `runtime.json` or `portlock.lock` | The lock is an OS lock and died with the process. `runtime.json` is overwritten. The CLI detects a stale file because `ping` fails or its `run_id` differs. |
| Sessions, login lockout counters | Persisted by `auth`; unaffected by a crash. Sessions end by their own timeouts. |
| Start-up input-device protection | Recomputed from the devices present now. Not persisted. |

Between a crash and the next start nothing watches devices. What stays enforced in that
window is exactly what the journal lists: blocked devices stay blocked, default-deny (if
a lockdown was active) stays on. Nothing new is blocked.

---

## 7. Failure handling

| Failure | Behaviour |
| --- | --- |
| An enforcer call returns `ok=False` | Decision outcome `failed`; `enforcement.failed` audited once per distinct error; `alert` published; retried every 30 s and on every reconcile. A failed block leaves the device usable and the record says so. A failed read-only follows the *cannot* rule (3.6.6). |
| The capability is missing (not privileged, mechanism absent) | No call. Outcome `unsupported`, audited as `enforcement.failed` with `error = "unsupported: ..."`. `set_mode(enforce)` and `lockdown_engage` are refused up front when blocking is impossible. |
| The enforcer raises | `SafeEnforcer` turns it into `ok=False` (`mechanism="error"`); handled as above. |
| `write_ahead` fails (journal unwritable) | The enforcer makes no change (E2). Outcome `failed`. Restrictions cannot be added while the journal is unwritable; releases still work for records already open. Status shows `journal` degraded. |
| Database locked beyond the 5 s busy timeout, or a `StoreError` in the pipeline | For a device event: `_evaluation_failed` (deny if `fail_closed`, else leave alone), `store` degraded. For an API mutation: the call fails with `store_unavailable` and no partial effect. Enforcement that is already in place is not touched. |
| Database corrupt while running | Every store call fails as above; the service stays up in a degraded state, keeps existing restrictions, and reports it. No repair is attempted. |
| Audit append fails | `AuditWriter` keeps a bounded backlog and flushes it later (3.6.1). Enforcement proceeds: failing to record must not become failing to protect. `audit` degraded. |
| An external audit sink fails or is slow | Isolated by `FanOut`; counted; shown in doctor. Never blocks an append. |
| `backend.enumerate()` raises | Retried; the backend is marked degraded and an `alert` is published; the 30 s resync keeps retrying. On recovery `service.recovered` is audited with `component = "backend"` and the length of the outage. Existing decisions stay enforced. |
| The backend's notification thread dies silently | The 30 s resync finds what it missed, so detection degrades to polling instead of stopping. After three consecutive resyncs that find missed events the service calls `backend.stop()` and `backend.start()` once. |
| Event queue overflow | The event is dropped, a resync runs on the next tick. |
| A scan exceeds its limits | The scanner reports `incomplete`; the overlay table applies. |
| A scan hangs | Watchdog (3.6.10): cancel, then abandon the thread and report `error`. |
| A scan engine fails | The scanner reports `error` for that engine; the verdict cannot be `clean`. |
| Evaluation raises for one device | `_evaluation_failed`; other devices are unaffected. |
| The policy file is invalid at start | Last good or default policy; `policy.invalid`. |
| The system-volume query fails | Every storage device present at start is treated as system-backing (protected); doctor shows `guard.system_volume` as `warn`. |
| The API port is taken | The daemon stops cleanly and exits 5. |
| The wall clock jumps | Lockdown: monotonic guard and the `max_minutes` sanity check. Sessions and lockouts: handled in `auth`. Grants and rules use the wall clock by definition. |
| The process is killed | Section 6. |

---

## 8. Audit events, step by step

Only these names are used. `fp` means `device_fp` is set.

| Event | Emitted by | When | Key data |
| --- | --- | --- | --- |
| `service.started` | service | `start` step 5 | version, mode, effective_mode, run_id, previous_shutdown |
| `service.stopped` | service | `stop` | clean, rollback report |
| `service.recovered` | service | after an unclean previous run; when a degraded component recovers | what was done / component, outage_seconds |
| `device.connected` (fp) | service | arrival; each device at start | connection_id, device, present_at_start, confidence, storage_identity |
| `device.changed` (fp) | service | CHANGED | connection_id, volumes_added, volumes_removed |
| `device.removed` (fp) | service | REMOVED, resync | connection_id, duration_seconds, state, synthesized |
| `safety.suspicious_device` (fp) | service | storage with input; new input device | connection_id, reason |
| `decision.made` (fp) | service | every new or changed decision; operator denial | connection_id, decision, trigger, policy_hash, mode, protection_codes, resolution |
| `enforcement.applied` (fp or none) | service | a live call succeeded and changed something | connection_id, action, mechanism, tier, changed, detail, cause, orphan |
| `enforcement.would_apply` (fp) | service | monitor mode | same |
| `enforcement.failed` (fp or none) | service | `ok=False`, unsupported, evaluation failure | same plus error |
| `enforcement.refused` (fp) | service | `SafeEnforcer` refused | same plus protection reasons |
| `grant.created` / `trust.added` (fp) | service | `approve`, `create_grant` | grant (id, kind, read_only, expires_at, confidence), connection_id |
| `grant.used` (fp) | service | first decision on a connection that honours the grant | grant_id, kind, connection_id |
| `grant.expired` (fp) | service | `expire_due`; a one-time grant spent | grant_id, kind, reason (`expired`, `consumed`, `service_restart`) |
| `grant.revoked` / `trust.removed` (fp) | service | `revoke_grant` | grant_id, kind |
| `policy.changed` | service | `replace_policy` | old_hash, new_hash, name, rules |
| `policy.invalid` | service | invalid file at start; rejected `replace_policy` | problems (at most 50), source |
| `scan.started` (fp) | service | a scan job begins | scan_id, connection_id, trigger |
| `scan.finished` (fp) | service | it ends | scan_id, verdict, counters, engines |
| `scan.detection` (fp) | service | each suspicious or malicious finding | scan_id, path, engine, rule, severity, sha256 |
| `lockdown.engaged` / `.renewed` / `.lifted` / `.expired` | lockdown | 5.2 | expires_at, renew_count, summary, end_reason |
| `killswitch.activated` | service | the file is seen | lockdown_was_active |
| `recovery.restored` | service | kill switch; stop; a recover marker | reason, restored, released, readmitted, failed, remaining |
| `mode.changed` | service | `set_mode` | old, new |
| `config.changed` | service | `update_settings` | key, old, new |
| `audit.verified` / `audit.verification_failed` | service | tail check at start; `verify_audit` | scope, checked, first_bad_seq, reason, macs_checked |
| `auth.login`, `auth.failure`, `auth.lockout`, `auth.password_changed`, `auth.recovery_used`, `auth.user_created`, `auth.user_changed` | `AccountStore` | as documented there | never a secret |
| `auth.logout` | `console.api` | logout | session_id |

---

## 9. Test plan mapped to the required areas

Unit tests are listed with each module. This table says where each required area is
proved, at both levels. Integration files are `tests/integration/test_<area>.py`.

| Area | Unit level | Integration level (through API and `FakeBackend`) |
| --- | --- | --- |
| USB detection | wave 1 backend tests; `test_service_pipeline.py` (arrival, duplicate arrival, CHANGED, dropped event found by resync, backend failure) | `test_detection.py`: a plugged device appears in `GET /devices` and as a `device.connected` stream event without polling; the arrival gap at start is covered |
| Device authorization | `test_service_pipeline.py` (unknown device is `pending`; `approve` with once, temporary, trust; low-confidence trust refused) | `test_authorization.py`: operator approves a pending device and it becomes usable; an auditor cannot; trust needs an administrator |
| Trusted device handling | `test_service_pipeline.py` (trust allows; read-only trust; trust does not beat a deny rule; revoked trust re-blocks at once) | `test_trusted.py`: add trust, reconnect, still allowed; remove trust, blocked within the same request |
| Unauthorized device handling | `test_service_enforcement.py` (pending and deny are blocked in enforce, `would_apply` in monitor; storage-with-input denied with an alert; operator `deny`, optional eject) | `test_unauthorized.py`: an unknown device is blocked and listed as pending; the BadUSB shape is denied, alerted and cannot be approved |
| Permission enforcement | `test_api_security.py` (every role × every route from `ROUTES`; CSRF, Host, Origin); `test_service_enforcement.py` (read-only decisions; the protected-device sweep) | `test_permissions.py`: read-only grant gives a read-only device; role matrix end to end; no session, no access |
| Device removal | `test_service_pipeline.py` (removal closes the connection, cancels the scan, spends the one-time grant, discards volatile records, makes no enforcer call) | `test_removal.py`: `device.removed` on the stream; history shows the connection with its duration |
| Reconnection | `test_service_pipeline.py` (new connection id, same fingerprint, decision recomputed; one-time grant not reused; a persistent block is still in force and is released by a grant) | `test_reconnection.py`: trusted device reconnects allowed; once-approved device reconnects pending; denied device reconnects denied |
| Policy expiration | `test_service_pipeline.py` (rule expiry, time window closing, temporary grant expiry, each by `clock.advance` + `tick`, each re-evaluated and enforced within one tick) | `test_expiration.py`: a temporary grant expires while the device is connected and the device is blocked; the stream shows `grant.changed` and `decision.made` |
| Service restart | `test_service_restart.py` (section 6 row by row); `test_daemon.py` | `test_restart.py`: stop and start a runtime on the same home: trust survives, the pending queue is rebuilt, a clean stop leaves the journal empty, an unclean one is recovered and audited |
| Security event logging | `test_service_audit.py`; wave 1 audit tests | `test_logging.py`: a scripted session produces exactly the expected event types in order; `POST /audit/verify` passes; the export verifies offline; tampering with one row is found |
| Lockdown safeguards | `test_lockdown.py`, `test_rollback.py`, `test_service_lockdown.py` | `test_lockdown_safeguards.py`: protected devices untouched; dead-man expiry; lift refused without re-authentication and for an operator; kill switch restores everything and blocks re-engage; `recover` works with the database removed |

Rules for every test in waves 2 and 3: no real enforcement mechanism; no real `/sys`
write, registry write, device disable or eject; synthetic identifiers only; no sleeping
to make time pass; nothing written outside `tmp_path`.

---

## 10. Decisions taken where `DESIGN.md` was open

| # | Decision |
| --- | --- |
| D1 | The enforcement journal is a file (`journal.jsonl`), not a table, written ahead of every OS change, so `portlock recover` needs no database. |
| D2 | Enforcers take a `write_ahead` hook; the journal keeps one baseline per `(kind, target)`; a releasing call never creates a baseline (the journal rule, 3.1.3). |
| D3 | PortLock releases only what it restricted. A device or setting that something else restricted is left alone, also when policy says allow. |
| D4 | A device that was already unusable when PortLock decided to block it gets a `hold` record, so PortLock knows to release it later. |
| D5 | Global settings are released by restoring PortLock's own records, never by "turn it off". |
| D6 | Convergence: the service computes a desired OS state per device from decision, mode, lockdown and kill switch, and makes the OS match. Enforcer calls are never made ad hoc. |
| D7 | Lockdown acts in monitor mode. It is an explicit administrator action, like switching to enforce. Lifting it in monitor mode leaves nothing restricted. |
| D8 | OS default-deny (the preventive tier) is used only during lockdown. Normal enforce mode is reactive and reports itself as such. |
| D9 | A clean stop restores everything, an active lockdown's OS state included; the lockdown record stays and the next start resumes it. Lockdown is in force only while the service runs. |
| D10 | `fail_closed` means: when a device cannot be evaluated, deny it; when read-only cannot be enforced, block instead; when a required scan cannot complete, deny; when the state is unusable at start, do not roll back. |
| D11 | The run-time mode is a stored setting that overrides `Config.mode`. The kill switch overrides both and rewrites the setting to `monitor`, so removing the file never silently re-enables enforcement. |
| D12 | The policy file is read at start only; changes at run time go through the API. Invalid policy at start falls back to the last good policy, then to the default. |
| D13 | An operator's "deny" of a pending device is a per-connection resolution, not a decision source. Standing denials are policy rules. |
| D14 | A `suspicious` scan verdict never denies by itself; it caps at read-only. `malicious` follows `scan.on_detection`. Incomplete and failed scans never count as clean. |
| D15 | PortLock scans only volumes the OS mounted and never mounts anything itself. Scans also run in monitor mode. |
| D16 | Read-only on a device without storage cannot be enforced and follows the *cannot* rule. |
| D17 | Eject happens only on an explicit operator request. |
| D18 | The start-up input-device set and the system-volume set are computed at each start and kept in memory. Pinned protected fingerprints are a stored setting, changed only by an administrator. If the system volume cannot be determined, every storage device present at start is protected. |
| D19 | Safety-critical configuration (`scope`, `hid_enforcement`, `acknowledge_lockout_risk`, `fail_closed`, `api.*`, `paths`, `auth`, `audit`) is file-only and needs a restart. The API can change three settings (3.6.5). |
| D20 | On Windows the service runs as a scheduled task; graceful stop on every platform is the `stop.request` file. |
| D21 | The first administrator is created only by the local `portlock setup` command. The API never creates an account without an authenticated administrator. |
| D22 | The CLI holds no stored credentials: it logs in, acts and logs out. It sends credentials only to a service whose `run_id` it verified through `runtime.json`, or to a URL the operator named. |
| D23 | Local-console commands (`setup`, `recover`, `user reset-password --local`, `user unlock --local`, offline verify) are authorized by operating-system rights and use the `LOCAL` lockout channel. |
| D24 | `portlock recover` leaves the kill-switch file in place and a marker for the next start to audit. |
| D25 | A connection belongs to one service run. Restart closes old connections and opens new ones; history is not stitched together. |
| D26 | `enforcement.applied` and `.would_apply` are audited on change, not on every idempotent re-application. |
| D27 | Nothing in the store is pruned automatically in this version. |
| D28 | The database is never repaired, recreated or deleted by PortLock. |
| D29 | A one-time grant survives a restart only if the same device is still present at the same instance id. |
| D30 | The event-stream id is `<run_id>-<seq>`; a client resuming across a restart gets a `reset`. |
