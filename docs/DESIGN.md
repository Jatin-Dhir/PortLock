# PortLock — design decisions

This is the authoritative design for PortLock. It records *what was decided and why*.
`ARCHITECTURE.md` maps it onto modules, `ENFORCEMENT.md` documents each operating-system
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
   **safety > lockdown > policy `deny` > grants and trust > other policy rules > policy default.**
   A grant upgrades `pending` to `allow` or `read_only`. It does not override an explicit
   `deny` rule; to permit such a device, change the policy.
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
are in `ENFORCEMENT.md`, each with a reference to vendor documentation.

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

- Passwords: `hashlib.scrypt`, N = 2^15, r = 8, p = 1, 16-byte salt, constant-time compare,
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
- **Local HTTP API** on `127.0.0.1`, session cookie (`HttpOnly`, `SameSite=Strict`) plus a
  CSRF header on state-changing requests, `Host` allowlist against DNS rebinding.
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
