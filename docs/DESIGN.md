# PortLock — design decisions

This is the authoritative design for PortLock. It records *what was decided and why*.
`ARCHITECTURE.md` maps it onto modules, `docs/enforcement/` documents each operating-system
mechanism and its limits, `THREAT_MODEL.md` states what PortLock does and does not defend.

Where code and this document disagree, that is a bug in one of them: fix it and say which.

## 1. What PortLock is

PortLock decides what a USB device is allowed to do on a machine, makes the operating
system enforce that decision, and keeps a record that is hard to quietly alter.

Three things are deliberately kept apart, because confusing them is how tools in this
category end up claiming protection they do not provide:

1. **Detection** — noticing that a device arrived or left. Cheap, unprivileged, reliable.
2. **Decision** — policy, trust and grants turned into allow / read-only / deny / pending.
   Pure logic.
3. **Enforcement** — getting the kernel to actually refuse access. Privileged,
   OS-specific, and the only part that protects anything.

A PortLock that detects and decides but cannot enforce is a monitor, and it says so.

## 2. Principles

- **Safe by default.** A fresh install runs in `monitor` mode: it records what it would
  have done and changes nothing. `enforce` mode is an explicit administrator choice.
- **Never lock the operator out.** Keyboards, mice, hubs, internal devices and anything
  backing the system volume are *protected*. Every enforcement call passes through one
  choke point (`SafeEnforcer`) that refuses to act on a protected device, whatever policy
  says. Enforcing against HID devices is off unless two separate settings are enabled.
  The operator's own input devices are **enrolled** by an authenticated command, which
  records each one's fingerprint and port. An enrolled device stays protected when it is
  re-plugged into the same port, so the operator's keyboard never locks them out. Merely
  being connected when the service starts confers nothing: otherwise anyone who can cause
  a restart could turn a hostile device into a protected one.

  The category protection covers only devices whose every interface is an input device or
  a hub. A device that puts **any other function beside an input interface** (storage,
  network, serial, imaging, vendor-specific) is the shape of a "BadUSB" or network-tap
  implant; it goes to policy like any other device, and the default policy denies it and
  raises an alert.

  The cost of this principle is stated plainly: with default settings PortLock does **not**
  stop a malicious device that presents itself only as a keyboard. It records and alerts
  on new input devices; blocking them is the opt-in HID enforcement mode.
- **Nothing destructive.** PortLock never formats, repartitions, wipes or deletes. Blocking
  a device means the OS stops talking to it; the data on it is untouched.
- **Every change is reversible and journaled.** Before changing an OS setting PortLock
  records the previous value. Lifting a lockdown, stopping the service or running
  `portlock recover` puts exactly those values back.
- **Honest capability reporting.** Each backend reports what it can do on this machine
  right now (`portlock doctor`). If a mechanism is unavailable, the decision is logged as
  *not enforced*, never as blocked.
- **Small trusted base.** Standard library only at runtime. Python >= 3.11. The optional
  `signing` extra adds `cryptography` for Ed25519.
- **No default credentials.** The prototype's hardcoded `portlock123` is gone and is
  explicitly rejected as a password.

## 3. Module map

| Product name | Package | Responsibility |
| --- | --- | --- |
| PortLock Core | `portlock.core` | device model, fingerprinting, configuration, state store, event bus, the `PortLockService` pipeline |
| PortLock Guard | `portlock.guard` | detection and enforcement backends: `windows`, `linux`, and `fake` for tests and simulation; the safety choke point |
| PortLock Auth | `portlock.auth` | administrator accounts, password hashing, lockout, recovery codes, sessions, device grants |
| PortLock Policy | `portlock.policy` | policy model, validation, evaluation |
| PortLock Scan | `portlock.scan` | file inspection, hashing, heuristics, antivirus adapters |
| PortLock Audit | `portlock.audit` | hash-chained audit log, export, external sinks |
| PortLock Lockdown | `portlock.lockdown` | emergency lockdown and its recovery safeguards |
| PortLock Console | `portlock.console` | command line, local HTTP API, web console |

Dependency rule: `policy`, `scan`, `audit`, `auth` and `core.models` do not import
`guard`. Only `core.service` and `lockdown` drive enforcement, and only through the
`Enforcer` interface. Everything takes an injected clock, so time-dependent behaviour is
tested without sleeping.

## 4. Device identity

`UsbDevice` carries vendor id, product id, serial, manufacturer and product strings,
`bcdDevice`, device class, interface descriptors, the physical port path, the OS handle
for the current connection, and the volumes it exposes.

**Fingerprint** = `plk1:` + base32(SHA-256(canonical JSON of vendor id, product id,
normalized serial, manufacturer, product, bcdDevice, sorted interface triples))[:32].

Each fingerprint has a confidence:

- `high` — a serial is present and looks unique;
- `low` — no serial, or a known generic one (`0123456789ABCDEF`, all zeros, …).

**A fingerprint identifies; it does not authenticate.** Every field in it is supplied by
the device and can be copied by a device built to copy it. PortLock therefore treats a
fingerprint match as "this is plausibly the same device", lets policy demand `high`
confidence, flags composite devices that pair storage with a keyboard, and documents the
gap. Real device authentication needs hardware that can answer a cryptographic challenge,
which ordinary USB storage cannot.

## 5. The decision pipeline

On arrival, and for every device present at start:

1. Build the `UsbDevice`, compute the fingerprint, audit `device.connected`.
2. Safety check. A protected device is allowed and never enforced against.
3. Evaluate. Precedence, highest first:
   **safety > lockdown > scan detection > first matching policy rule > grant > policy default.**
   The first matching rule is final whether it says `allow`, `read_only` or `deny`. A grant
   acts only on a `pending` outcome: it never widens what a rule decided and never removes
   a scan requirement. To permit a device a rule denies, change the policy.
4. Enforce the decision if the mode is `enforce`; otherwise log `would_enforce`.
5. If access was granted and policy asks for it, scan the mounted volumes. A detection can
   downgrade the decision to `read_only` or `deny`.
6. Audit every step with its outcome and the mechanism used.

On removal: audit, consume one-time grants, drop per-connection state.
When a grant or rule expires while its device is connected: re-evaluate and enforce.
On service start: enumerate, expire what is due, re-apply every decision (enforcement
calls are idempotent), and resume or lift any lockdown according to its stored expiry.

## 6. Enforcement

Two tiers, and the difference matters:

- **Preventive** — the OS is told in advance to refuse devices that have not been
  authorized. A new device is unusable from the first instant.
- **Reactive** — PortLock sees the device, decides, then blocks it. There is a window,
  typically well under a second but not zero, in which the device was usable. PortLock
  reports which tier applied to each decision.

| Capability | Linux | Windows |
| --- | --- | --- |
| Detect | netlink kobject-uevent socket, sysfs attributes; polling fallback | `CM_Register_Notification` on the USB device interface class; polling fallback |
| Block one device | write `0` to the device's sysfs `authorized` | disable the device node (`CM_Disable_DevNode`) |
| Default-deny new devices | write `0` to each host controller's `authorized_default` | Device Installation Restriction policy values |
| Read-only | `BLKROSET` on the device's block nodes; generated udev rule for the race-free path | removable-storage `Deny_Write` policy (class-wide); per-disk read-only attribute |
| Eject | sysfs `remove` | `CM_Request_Device_Eject` |

Exact paths, values, privileges, kernel and Windows version requirements and failure modes
are in `docs/enforcement/linux.md` and `docs/enforcement/windows.md`, each with a reference to vendor documentation.

All OS access goes through thin seams (`SysfsIO`, `RegistryIO`, `CfgMgrAPI`,
`CommandRunner`) so the enforcement logic runs unmodified against fakes in tests.

**What has and has not been verified is stated plainly in the README.** Enforcement code
paths are exercised against fakes. Read-only device enumeration is exercised against real
hardware. No enforcement mechanism has been run against a real device by the test suite.

## 7. Policy

A policy is a versioned JSON document (TOML accepted on import):

```
{ "version": 1, "name": "...",
  "default": { "access": "pending" },
  "rules": [ { "id": "...", "enabled": true, "expires": null,
               "match": { vendor_id, product_id, serial, fingerprint, manufacturer, product,
                          category, interface_class, confidence, composite, bus_path, time },
               "action": { "access": "allow|read_only|deny|pending", "scan": "none|on_mount|required", "alert": false } } ],
  "scan": { "on_detection": "deny|read_only|alert" } }
```

First matching enabled, unexpired rule wins. String matches are case-insensitive globs.
Validation reports the exact path of each problem. Saves are atomic, and every change is
audited with the old and new content hash.

## 8. Authentication and grants

- Passwords: `hashlib.scrypt`, N = 2^17, r = 8, p = 1, 16-byte salt, constant-time compare,
  transparent re-hash when parameters are raised. Minimum length 12; known-bad passwords
  including the prototype's default are refused.
- Lockout: five consecutive failures start an exponential delay (30 s doubling to 15 min)
  that is persisted, so restarting the service does not reset it.
- Recovery codes: eight single-use 128-bit codes, stored as SHA-256 digests.
- Sessions: 256-bit random tokens stored hashed; 15 min idle and 8 h absolute timeout.
- Roles: `admin`, `operator` (may approve devices and issue temporary grants), `auditor`
  (read-only).
- Grants: `trust` (no expiry), `temporary` (until a time), `once` (this connection only),
  each optionally `read_only`.

## 9. Scanning

A bounded, read-only walk of a mounted volume: file count, byte and time limits; symlinks
are not followed off the volume. Engines:

- **Heuristics** — `autorun.inf`, executable and script types at the volume root, double
  extensions, hidden executables, shortcut files that launch a shell.
- **Hash sets** — SHA-256 against local known-bad and known-good lists.
- **Antivirus adapters** — ClamAV (`clamdscan` / `clamscan`) and Microsoft Defender
  (`MpCmdRun.exe`), used if installed, with timeouts and parsed results.

Scanning reports; it never deletes or modifies a file. Tests never write the EICAR test
string to disk, because doing so sets off the antivirus on the machine running them.

## 10. Audit log

An append-only SQLite table. Each record stores `hash = SHA-256(previous hash || canonical
JSON of the record)`. `portlock audit verify` walks the chain and reports the first record
that does not fit.

What this gives: any edit, deletion or reordering of past records is detectable by anyone
holding a later hash. What it does not: someone who can rewrite the whole database can
rebuild a consistent chain. Two mitigations are provided: an HMAC over each hash under a
key kept in a separate root-only file, and export of signed checkpoints to somewhere the
local administrator cannot rewrite (a file sink, syslog, or a ClawNet channel).

Events use a shared envelope, `docs/SECURITY_EVENT_FORMAT.md`, signed with Ed25519 over
canonical JSON (RFC 8785 restricted to integers and ASCII keys) — the same rules ClawNet
uses, so either project can verify the other's signatures.

## 11. Emergency lockdown

`portlock lockdown engage` blocks all removable storage at once and puts the OS into
default-deny for new devices. Because this is the feature most able to hurt its operator,
it carries the most safeguards:

- protected devices are never touched;
- a **dead-man timer**: lockdown lifts itself after a set time (default 60 min) unless
  renewed, the expiry is persisted, and an expired lockdown found at start-up is lifted;
- lifting needs the administrator password or a recovery code;
- a **kill switch**: if the file `DISABLE_ENFORCEMENT` exists in the configuration
  directory, the service restores every journaled setting and stays in monitor mode;
- `portlock recover` restores journaled settings without the service or the database,
  authorized by OS administrator rights alone, for the case where PortLock itself is broken.

## 12. Console

- **CLI** for everything. Privileged commands ask for the administrator password.
- **Local HTTP API** on `127.0.0.1`. Every request carries a bearer token in the
  `Authorization` header; there are no cookies, because cookies on `127.0.0.1` are shared
  with every other local port. `Host` allowlist against DNS rebinding.
- **Web console** served by the same process: static files, no build step.
- `portlock simulate` runs the complete pipeline against the fake backend, so the product
  can be explored on any machine without touching a real device.

## 13. Testing rules

- Tests never call a real enforcement mechanism: no registry writes, no device disable or
  eject, no writes under the real `/sys`, no service installation, no antivirus setting
  changes. The fake backend and the I/O seams exist so that nothing has to.
- Tests never record real device serial numbers, host names or user names. Fixtures are
  synthetic.
- Time is injected. Tests do not sleep to make things expire.
- Tests marked `hardware` read real device information without changing anything and are
  skipped unless asked for.
- The suite runs on Windows and on Linux.

## 14. Changes adopted after design review

Two independent reviews (operating-system security; application security and
reliability) were run against sections 1 to 13 before the service was built. The changes
below were adopted. **Where this section conflicts with anything above, or with
`ARCHITECTURE.md`, this section wins.**

### Protection

1. **Enrolment, not presence.** Being connected at start-up confers nothing. Input devices
   are enrolled by an authenticated command (`portlock enroll`, offered during `init`). An
   enrolment stores fingerprint and port path and protects a device only when both match.
   A second device presenting an enrolled fingerprint while the first is connected is
   denied and raises an alert.
2. **Input-only.** Category protection applies only to a device whose every interface is
   input (HID) or hub. Input beside any other function goes to policy; the default policy
   denies it with an alert.
3. **Built in** means directly on a root-hub port that firmware marks as not
   user-accessible. A device behind an external hub is never built in, whatever that hub
   claims about its own ports.
4. **Storage-like.** Mass storage and imaging devices (phones and cameras in MTP or PTP
   mode) are both in the default enforcement scope and both count as removable storage
   during lockdown.
5. **Scope** is part of the design: `storage` (the default), `storage_and_unknown`,
   `all_except_protected`. The default covers mass storage, imaging devices, and every
   device that puts another function beside an input interface, so the default policy's
   denial of those devices is actually enforced. Anything outside the scope is reported as
   not enforced, never as protected.
6. **Port hold-down.** More than a configured number of arrivals on one port within a
   short window holds that port blocked for a cool-down and coalesces the audit events, so
   a device cannot replay the reactive window indefinitely by re-enumerating.
7. **Device text is untrusted.** Every string a device supplies has control and format
   characters replaced and its length capped before it is stored, and consoles render it
   as text only.

### Decision

8. Precedence is as stated in section 5 above (already corrected there).
9. `scan: required` means: admit read-only, scan every volume, and apply the decided
   access only on a clean verdict. An incomplete or failed scan leaves the device read-only
   and raises an alert. Scanning defends against bad files on an honest device; a hostile
   device can serve different content after the scan, and the documentation says so.
10. The pipeline order is decide, journal, enforce, audit. A failure to store or audit
    never skips enforcement. In enforce mode a non-protected device that cannot be
    evaluated is treated as `pending`.
11. Revoking a device that has mounted volumes switches it to read-only, attempts a clean
    eject with a short timeout, and only then blocks it. The audit record says whether the
    removal was clean.
12. Expiries are evaluated against the later of the clock and the newest audit timestamp,
    so setting the clock back does not revive an expired grant or rule; the discrepancy
    raises an alert. A lockdown counts down on the monotonic clock and persists the time
    remaining.
13. Temporary grants have a ceiling (24 h for operators; 30 days by default for
    administrators). A low-confidence fingerprint may only receive a `once` grant or a
    temporary grant of at most 24 h, bound to the port. `once` binds to a connection id
    supplied by the backend, because the OS instance id survives a re-plug.

### Enforcement and lockdown

14. Tier claims, corrected. On Windows, Device Installation Restrictions stop only devices
    that were never installed on the machine; disabling the device node on every arrival
    is the backstop. Reactive read-only does not take away write access that a mount
    already has; read-only is dependable only as a standing baseline from which approved
    devices are released (`baseline_read_only`).
15. **Commit-confirm.** Switching to enforce, widening the scope, turning on default-deny
    and engaging lockdown each list what would be blocked, apply the change, and roll it
    back unless it is confirmed within 60 s over the same channel. An operator whose only
    way in is a USB network adapter or serial console gets it back automatically.
16. **Dead-man outside the process.** When default-deny or lockdown is engaged, a one-shot
    operating-system timer is armed to run `portlock recover` at expiry and is cancelled on
    lift or renewal, so the safety does not depend on the service staying alive.
17. Journal entries are typed and are validated on replay against a fixed list of targets.
    `restore` reverts a value only if it still equals what PortLock applied; otherwise it
    leaves it and audits that someone else changed it. `portlock recover` needs operating
    system administrator rights and leaves an audit record.
18. The state and configuration directories must be private. The service sets and verifies
    ownership and permissions at every start and refuses enforce mode otherwise. The
    kill-switch file is honoured only inside a directory verified to be private.
19. On Linux only `usbcore.authorized_default=0` on the kernel command line is preventive
    from boot. `portlock doctor` reports whether it is set.

### API, authentication, audit, storage

20. Bearer tokens, no cookies (section 12, already corrected). The listener refuses
    address reuse. The console ships a strict content security policy. The CLI
    authenticates the service through a secret in the private runtime file.
21. At most two password verifications run at once on the network path. The network
    lockout never blocks the local elevated CLI or recovery codes, so it cannot be used to
    keep the administrator out.
22. The audit MAC key ratchets forward with every record and the old key is erased, so
    someone who takes over the machine later cannot re-MAC earlier records. The head of
    the chain is also written to a separate file. The local MAC protects only against a
    writer who cannot read the current key, and the documentation says so.
23. The database is checked at start. A damaged file is renamed aside, never deleted, and
    the first record of the new log names the old file's hash and last known head.

### After the code review of the upper layers (16 November 2026)

`docs/REVIEW.md` lists every finding. Four of them changed what the design says; where
these conflict with anything above, these win.

24. **PortLock admits only what it holds back.** Default-deny (a lockdown, or the standing
    setting) leaves new devices unauthorized. PortLock authorizes a device only if it
    blocked it, or if it arrived while default-deny was in force and has not been admitted
    yet. A device that was already present, or that someone else disabled (Device Manager,
    an administrator, USBGuard), is left as that person left it, and stopping the service
    or the kill switch does not re-enable it. `portlock recover` runs without the database
    and cannot tell the two apart, so it readmits every present device, hubs first, because
    a keyboard behind an unauthorized dock would otherwise stay unusable.
25. **The dead-man timer fires after the service, and never writes the kill switch.** The
    operating-system timer for a lockdown is armed 30 seconds after its expiry (14.16 said
    "at expiry"), so the service's own lift, about a second after the expiry, comes first.
    The timer runs `portlock recover --dead-man`: with a running service it does nothing;
    with none it restores the journal and leaves the marker, but does not create
    `DISABLE_ENFORCEMENT`, so a lockdown that ended while the machine was off does not leave
    enforcement off for good. An operator's own `portlock recover` still creates it.
26. **Recovery codes and lockdown lifts need the same proof as the password.** Issuing
    recovery codes needs the caller's own current password, because a code can lift a
    lockdown and reset a password; a session token alone cannot. Cancelling a lockdown that
    awaits confirmation lifts it, so it needs `lift_lockdown`, not only `engage_lockdown`.
    A lift sent with the command-line secret has its password checked on the local channel,
    so the network lockout never blocks it (14.21 already said so; the lift path did not).
27. **The expiry high-water mark is the highest audit timestamp**, not the timestamp of the
    last record, so a clock set back and a restart do not bring back an expired rule or
    grant (14.12). A connection that survives a restart keeps the time it really arrived,
    when the backend's connection token proves it is the same connection, so a lockdown's
    exemption for devices connected before it began survives a restart.

### Watch-only (16 November 2026)

28. **A process that could never be trusted to enforce is watch-only, for its whole
    life.** A process is watch-only exactly when it is not elevated (administrator, root)
    or its state or configuration directory is not a system-wide location. Nothing else
    decides it, the mode included, and it is decided once, at start
    (`guard/watchonly.py`); there is no way out of it inside the process.

    - *Where.* An ordinary user's PortLock keeps its state per-user
      (`%LOCALAPPDATA%\PortLock`, the XDG directories); an elevated one uses
      `%ProgramData%\PortLock` or `/var/lib/portlock` and `/etc/portlock`. A directory
      counts as system-wide only if it is provably outside every user's profile
      (`core.config.per_user_cause`): this user's own (`USERPROFILE`, `LOCALAPPDATA`,
      `APPDATA`; `HOME`; on the running POSIX system also the home the account database
      gives the effective user, so `/root` counts when `HOME` is unset or `/`), another
      user's, and the folder all users share (`PUBLIC`). Another user's means: on Windows
      everything in the folder that holds the users' profiles, taken from sources that do
      not depend on who runs PortLock (`ProfilesDirectory` in the registry, read only, on
      Windows itself; `Users` on `SystemDrive`; the parent of `PUBLIC` unless it is a UNC
      path; and the parent of `USERPROFILE`, which under SYSTEM or LocalService is not that
      folder), failing closed when none of them is known; on POSIX `/home`, `/Users` and,
      on the running system, the home of every login account in the account database
      (uid at least `UID_MIN` from `/etc/login.defs`, default 1000, home a real directory
      other than `/`), under WSL `/mnt/<drive>/Users`, and the home of the account that
      started `sudo`, `doas` or `pkexec`. Other accounts' homes are compared before
      `HOME`, so a `HOME` left pointing at another user's home is that user's. So
      `sudo PORTLOCK_HOME=/home/alice/pl portlock run`, an elevated window opened with
      another administrator's credentials, or PortLock run as SYSTEM with a home in a
      user's profile, is watch-only. On
      the running system both sides are resolved (8.3 names, `..`, junctions, symbolic
      links, `subst` drives). It fails closed: a UNC or device-namespace candidate; a
      profile variable that is set but empty, relative or unresolvable; a UNC
      `USERPROFILE` or `LOCALAPPDATA`; a device-namespace profile variable; a profile
      variable that is a UNC path to this computer (`localhost`, `127.x`, `::1`, its own
      name, any of these with a trailing dot, and, on the running system, any name that
      resolves (IPv4 or IPv6) to a loopback address or one of this computer's own
      addresses, its own IPv6 address and DNS aliases included); a `SUDO_USER`,
      `DOAS_USER` or `PKEXEC_UID` whose home cannot be found. A server name that does not
      resolve is taken for another computer that cannot be reached now. An
      `APPDATA` or `PUBLIC` redirected to *another* computer (Folder Redirection on a
      domain PC) is skipped instead: no local directory can lie inside it, and failing
      closed there made every administrator's system-wide installation watch-only.
    - *Why, in words that are true.* The posture keeps the cause, and every message about
      the location is worded from it (the refusal, the `init` and `run` notices,
      `recover`'s refusal, the leftovers message, the doctor): this user's own folders;
      another user's folders; the folder all users share; the home folder of the account
      that runs it (root's `/root`, where a root installation must not live: said only
      when the location is in the home the account database gives the effective user,
      never on the strength of `HOME`); or a location PortLock cannot confirm is local
      and system-wide.
    - *What it gets.* The composition root gives a watch-only service inert stand-ins for
      the enforcer, the dead-man timer and the directory-privacy seam; the real objects
      are never built, so no command (`icacls`, `schtasks`, `systemd-run`), registry
      write, device call or permission change can happen. Its scanner has no antivirus
      engine, because ClamAV and Defender would start programs; heuristics and hash lists
      run in-process and only read. It changes nothing on the computer outside its own
      folder (on Linux that folder is still created with mode 0700).
    - *What it refuses.* Enforce mode, a lockdown and turning default-deny on are refused
      with the reason (`watch_only`, HTTP 409) and leave no pending change, lockdown
      record or setting behind. A lockdown is therefore never reported active unless it
      blocks. Decisions are audited as "would apply"; `ModeInfo` carries `watch_only` and
      `watch_only_reason`, and `can_enforce` is false. A default-deny setting an earlier,
      enforcing run stored is reported as not in force (`GET /default-deny`, the settings,
      the command line), with a note that the stored value is ignored.
    - *Default-deny in force, and stored.* In every process `GET /default-deny`'s
      `enabled` (and `runtime.default_deny` in the settings and the `settings.changed`
      event) means in force: stored on, the effective mode is enforce, and the kill switch
      is not latched. `stored` keeps the stored choice, and a note says why a stored "on"
      is not in force (monitor mode, the kill switch, watch-only); the console's control
      shows the stored choice with that note, so the choice does not look lost.
      `effective.default_deny` is what the service asks of the operating system right
      now (`_want_default_deny`), which an active lockdown also turns on.
    - *What it never does.* A stand-in's result is never *performed*
      (`EnforcementResult.performed`): no journal record is closed, and PortLock never
      forgets that it holds a device back, on a dry-run or watch-only result, in the
      service or in `rollback`. A watch-only process restores nothing, before the database
      or at its stop (it changed nothing), and never writes the journal at all: its
      journal is read-only, so it neither compacts nor rewrites it. It refuses to start
      when it finds open journal records, journal lines it cannot read, a journal it cannot
      open, or a lockdown that is not idle: an enforcing PortLock left them, and it can
      neither enforce nor undo them. That check is made from the files before anything is
      created, so a refused start leaves no database or audit key store behind. With an
      injected directory-privacy check it is refused (`ValueError`) before the kill switch
      is looked at, so the kill switch never builds the real enforcer there.
      `portlock recover` refuses a home that is not system-wide, whose journal programs
      other than an administrator's could have forged.
    - *Setting up beside a running service.* `init` refuses while a service runs from the
      same state directory (it holds the instance lock): that service would go on writing
      audit records without the key `init` creates, and offline verification with the key
      `init` showed would fail for good. It looks at the start and again just before it
      writes, holding the lock only while it writes, never while it waits for a password.
      Everything it decides on (the configuration file's bytes or absence, whether the
      database exists, whether it has users, any `auth.user_created` record, the audit
      head, whether the key file exists and its identity) is taken as one snapshot before
      the prompt and again once the lock is held; if they differ (another `init`
      finished, or a service came and went), it releases the lock, changes nothing and
      says "PortLock's files changed while init was waiting".
      A service without an administrator says: stop it (Ctrl+C), run `init`, start it
      again. `init` sets an existing audit key store aside (and audits the replacement)
      only when no administrator was set up with it: the database is missing, or it holds
      no record that an administrator was ever created (`auth.user_created`). (A service
      that ran first at a terminal may have shown its initial key, so `init` says "that no
      administrator was set up with", not "never shown".) Otherwise the key store is
      kept, as before watch-only existed.
    - *Asking whether a service runs.* `stop`, `status` and `init` treat the instance lock
      as free only when its file provably does not exist (`FileNotFoundError`,
      `NotADirectoryError` from `stat`); any other error means "cannot tell" (from Python
      3.13 `Path.is_file` answers False instead of raising for a directory that cannot be
      searched, which would call a running service "not running"). When the lock cannot be
      looked at and the runtime file names a service that does not answer, `stop` says it
      is probably not running.
    - *Every other process* (elevated, system-wide directories) is never called
      watch-only and behaves as before this item: the real objects are built at start,
      the directories are made private at every start (14.18), the kill switch is
      honoured, journaled changes are restored, and an engaged lockdown blocks for real
      with its dead-man timer, in monitor mode too (section 11).
