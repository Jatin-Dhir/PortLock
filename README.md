# PortLock

PortLock decides what each USB device may do on a Windows or Linux machine, asks the
operating system to enforce that decision, and keeps a hash-chained record of what
happened. It keeps three things apart: **detection** (noticing that a device arrived),
**decision** (policy, trust and grants turned into allow, read-only, deny or pending) and
**enforcement** (getting the kernel to refuse access). Only enforcement protects anything,
and a machine where enforcement is unavailable or switched off is being monitored, not
protected; PortLock says so.

Status: alpha, version 0.2.0. The decision pipeline, the audit log, the command line, the
local HTTP API and the web console are built and tested. **No enforcement mechanism has
been run against a real device on either operating system.** Read "What has been verified"
before relying on it for anything.

## What works today

- **Detection.** Linux: kernel uevents and sysfs. Windows: device notifications through the
  Configuration Manager API. Both fall back to polling.
- **Decision.** A policy of ordered rules (first match wins), a default of "pending"
  (nothing is allowed until someone approves it), per-device grants (once, for a time, or
  trusted), a bounded scan of mounted volumes, and a lockdown that can be engaged in one
  command. The first-match, grant and scan precedence is in `docs/POLICY.md`.
- **Enforcement logic**, behind interfaces: block one device, refuse new devices
  (default-deny), read-only storage, eject. The Linux mechanisms are `authorized`,
  `authorized_default`, `BLKROSET` and a udev rule. The Windows mechanisms are disabling
  the device node, Device Installation Restrictions policy and Removable Storage Access
  policy. Every change is written to a journal first, so it can be undone.
- **Safety.** Hubs, keyboards, mice, built-in devices, the disk the system runs from and
  input devices you enrol are never touched. Switching to enforce mode, widening the scope,
  turning on default-deny and engaging a lockdown are rolled back after 60 seconds unless you
  confirm them. A lockdown ends by itself unless renewed, `DISABLE_ENFORCEMENT` in the
  configuration directory restores everything, and `portlock recover` restores everything
  without the service or its database.
- **Audit.** A hash-chained log with a forward-secure MAC, a head file, and optional copies
  to a file or syslog.
- **Console.** A command line, a local HTTP API (bearer tokens, loopback only) and a web
  console served by the same process. `portlock simulate` runs all of it against a
  simulated machine, so you can try it without touching a device.

## What has been verified, and what has not

Demonstrated:

- The whole decision pipeline (arrival, protection check, policy, grants, scans, lockdown,
  commit-confirm, restart recovery, audit) runs against a fake backend and a fake enforcer,
  through the service, the API and the command line, in the automated tests. The full suite
  passed on the development machine: 5883 passed and 71 skipped on Windows (Python 3.12),
  5864 passed and 90 skipped under WSL Ubuntu (Python 3.14). The skips are tests for the
  other platform and the opt-in hardware tests.
- The enforcement logic of both platforms runs against fakes of every operating-system call
  (a fake sysfs, a fake registry, a fake Configuration Manager, a fake command runner).
  What each call would write, and what the journal would restore, is checked there.
- Device enumeration, volume mapping and notification registration were run read-only
  against real hardware on one Windows machine (`tests/hardware`, opt-in with
  `--run-hardware`). Under WSL the Linux backend ran read-only too; WSL has no USB bus, so
  it found zero devices, and nothing about Linux device handling was shown on real
  devices.
- The CI workflow (`.github/workflows/ci.yml`) runs the linter and the full test suite on
  Linux and Windows runners for Python 3.11 to 3.14. It reads the repository and changes
  nothing on the runner beyond installing the package.
- `portlock init`, `run`, `status`, `stop`, `recover --dry-run` and the offline audit
  verification were run by hand, unprivileged, against a temporary directory under WSL.
  `init`, offline verification and `simulate` were run on Windows.

Not demonstrated:

- **Any enforcement mechanism against a real device, on either operating system.** No
  device has ever been blocked, made read-only or ejected by PortLock, and no policy value
  has been written to a real registry. Whether the kernel and Windows behave as
  `docs/enforcement/` says they do is untested.
- **The Windows command lines and API behaviours that `docs/enforcement/windows.md` marks
  UNVERIFIED**, and the Linux ones that `docs/enforcement/linux.md` marks the same way.
- **The generated service definitions.** The systemd unit and the Task Scheduler XML are
  produced and parse, but systemd and Task Scheduler have never loaded them.
- **`portlock doctor` against a real Windows machine.** It queries access lists with
  `icacls`, so it was not run on the development machine. Under WSL it ran and said what it
  should: no USB bus, not root.
- **A Windows with a display language other than English.** The directory-privacy check
  reads the names `icacls` prints; on another language it reports the directory as not
  private and refuses enforce mode (it fails closed), but this was not tried.
- **A hostile device.** Nothing was tested against a device built to deceive the host.
- **An external security audit.** None has been done.

## Requirements

- Python 3.11 or later. The runtime uses the standard library only.
- To enforce anything: Administrator on Windows, root on Linux. Without that, PortLock runs
  in monitor mode and `doctor` says what is missing.
- Linux: a kernel with the USB `authorized` attributes; `authorized_default` value `2`
  needs kernel 5.1 or later. Details are in `docs/enforcement/linux.md`.
- Optional: `pip install "portlock[signing]"` adds `cryptography` for Ed25519 signatures
  on exported audit checkpoints. ClamAV or Microsoft Defender, if present, are used by the
  scanner.

## Quick start

These commands were run on Windows (installed into a fresh virtual environment) and, where
marked, under WSL. None needs administrator rights, and none changes the machine.

Install:

```
python -m venv .venv
.venv/bin/pip install .            # Windows: .venv\Scripts\pip install .
.venv/bin/portlock --version       # portlock 0.2.0
```

Try everything on a simulated machine. Nothing real is read, blocked or changed:

```
portlock simulate
```

It prints a scripted tour (a keyboard, an unknown stick approved read-only, a stick with a
hidden keyboard denied, a trusted stick, a lockdown), then serves the web console and the
API on a printed address with a one-time password, and takes `plug NAME`, `unplug NAME`,
`list` and `quit`. `portlock simulate --no-serve` prints the tour and exits;
`--scenario none` starts empty. In another terminal you can use the command line against
it with the `PORTLOCK_HOME=...` line it prints.

Set up a real installation in monitor mode. `PORTLOCK_HOME` keeps this one in a
throwaway directory; leave it unset to use the system directories (`%ProgramData%\PortLock`
or `/var/lib/portlock` and `/etc/portlock`), which needs administrator rights:

```
export PORTLOCK_HOME=/tmp/portlock-try
portlock init                      # first administrator, audit key, 8 recovery codes
portlock doctor --offline          # what this machine can and cannot enforce (Linux, WSL)
portlock run                       # the service, in the foreground
```

and from another terminal with the same `PORTLOCK_HOME`:

```
portlock status                    # is it running
portlock devices                   # asks for the password
portlock audit verify              # walk the hash chain
portlock stop
```

`init` shows the audit verification key and the recovery codes once. Keep them offline (see
`docs/OPERATIONS.md`). On Windows, `portlock doctor` and `portlock run` use `icacls` to make
the state directories private, so they were not run on the development machine.

Run the tests (the suite creates many accounts with a deliberately slow password hash, so
expect several minutes):

```
pip install -e ".[dev]"
python -m pytest
```

## The safe default, and enforce mode

A fresh install runs in `monitor` mode. It decides, records "would block" or "would make
read-only" in the audit log, and changes nothing. Look at `portlock devices` and
`portlock audit tail` for a while before enforcing anything.

Enforce mode is an explicit choice (`portlock mode enforce`). Before you make it:

1. Run `portlock doctor` as the account the service runs as, and read every `warn` and
   `fail`. A mechanism reported unavailable is reported as *not enforced*, not as blocked.
2. Enrol your own keyboard and mouse (`portlock enroll`), and make sure there is a second
   way into the machine. The default scope (`storage`) does not touch input devices, but a
   lockdown, a wider scope or a mistake in policy can.
3. Know that the change is applied and then rolled back after 60 seconds unless you run
   `portlock confirm`.
4. On Linux, add `usbcore.authorized_default=0` to the kernel command line if you want
   devices refused before the service starts. PortLock does not edit the boot loader.

`docs/OPERATIONS.md` walks through all of this.

## Limitations

- **A fingerprint identifies a device; it does not authenticate it.** Every field in it is
  supplied by the device and can be copied.
- **Keyboards are allowed by default**, so a malicious device that presents only as a
  keyboard is recorded and alerted on but not stopped, unless you turn on HID enforcement
  (two settings, and a real risk of locking yourself out).
- **Enforcement is mostly reactive.** The device is usable between its arrival and the
  block, normally for well under a second but not for zero time. Only default-deny, and on
  Linux `usbcore.authorized_default=0` on the kernel command line, act before a device is
  usable, and on Windows default-deny does not stop a device Windows has installed before.
- **Read-only set after a device is mounted does not take away write access the mount
  already has.** It is dependable only as a standing baseline (`baseline_read_only`).
- **A scan reports on the files a device showed at one moment.** A hostile device can show
  different files later.
- **The audit log is tamper-evident, not tamper-proof.** Someone who controls the machine
  and the key can rewrite it; see `docs/THREAT_MODEL.md`.
- Lockdown is in force only while the service runs.
- The ClawNet audit sink exists in the code but is not wired into the service.
- The service-install steps are manual: PortLock generates a systemd unit or a Task
  Scheduler definition for you to review and install; it installs nothing itself.

## Documentation

| File | Contents |
| --- | --- |
| `docs/DESIGN.md` | what was decided and why; section 14 overrides everything else |
| `docs/ARCHITECTURE.md` | modules, files, threads, state machines, crash recovery |
| `docs/THREAT_MODEL.md` | assets, adversaries, and what PortLock does and does not stop |
| `docs/OPERATIONS.md` | installing, first run, enforce mode, lockdown, recovery, backup, uninstall |
| `docs/enforcement/windows.md`, `docs/enforcement/linux.md` | each operating-system mechanism, its limits, and what is UNVERIFIED |
| `docs/POLICY.md`, `docs/SCANNING.md` | policy rules and precedence; scanning and its limits |
| `docs/API.md`, `docs/SECURITY_EVENT_FORMAT.md` | the local HTTP API; the audit event envelope |

## Author

**Jatin Dhir**, [github.com/Jatin-Dhir](https://github.com/Jatin-Dhir). Released under the
MIT licence (`LICENSE`).
