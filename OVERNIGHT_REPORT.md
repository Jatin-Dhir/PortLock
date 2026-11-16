# Overnight report: PortLock

Branch `claude/overnight-security-framework`, 16 November 2026. `main` is untouched.

The short version: the repository held about 180 lines of Python that could not be
imported. It now holds a complete device-control service (decision pipeline, enforcers
for Linux and Windows, lockdown, audit, API, CLI, web console) that passes 5,883 tests.
**No enforcement mechanism has been run against a real device.** Everything that would
change the operating system has only ever run against fakes.

## 1. Original repository condition

- 18 files. `main.py`, both GUI files and `requirements.txt` were empty.
- The code could not run: `monitor.py` imported a function that `usb.py` does not define;
  `usb.py` used two undefined IOCTL constants and built an invalid drive path; the audit
  logger was a stub that did nothing.
- The administrator password was hardcoded as `portlock123` and compared in plain text.
- `data/logs.db` was committed and contains a real device serial number.
- The README described features (toast notifications, tray mode, auto-eject) that did not
  exist, and a file layout that did not match the repository.

## 2. Major architectural findings and decisions

- **Detection, decision and enforcement are kept apart.** Detecting a device protects
  nothing; only the operating system refusing it does. Every decision records whether it
  was enforced, by which mechanism, and whether that mechanism is preventive or reactive.
- **Monitor mode is the default.** A fresh install records what it would do and changes
  nothing. Enforce mode is an explicit administrator choice.
- **One choke point** (`SafeEnforcer`) refuses to act on protected devices whatever policy
  says. All operating-system access sits behind seams so the enforcement logic runs
  unmodified against fakes.
- **Standard library only** at runtime, Python 3.11 or later.
- **The design was reviewed before the service was built**, by two independent reviewers.
  The most serious finding: the first design treated any input device present at start-up
  as protected, which let anyone who could cause a restart turn a hostile device into a
  trusted one. That rule is gone. The 23 changes adopted are section 14 of
  [`docs/DESIGN.md`](docs/DESIGN.md).

## 3. Features implemented

| Area | State |
| --- | --- |
| USB insertion and removal detection | Built for Windows (SetupAPI, CfgMgr32 notifications) and Linux (sysfs, kernel uevent socket). Read-only. Run against real hardware on one Windows machine; under WSL, which has no USB bus. |
| Identification and fingerprinting | Built. Fingerprints identify, they do not authenticate, and the product says so. |
| Trusted devices, grants, temporary access | Built: trust, temporary, once; duration ceilings; low-confidence fingerprints bound to a port. |
| Policy management | Built: first-match rules, validation with exact error locations, test-a-device, expiry. |
| Unauthorized-device handling, blocking, read-only | Decision logic built and tested. Enforcers built for both platforms, **tested against fakes only**. |
| Emergency lockdown with recovery safeguards | Built: commit-confirm (rolls back unless confirmed in 60 s), dead-man timer outside the process, kill switch, `portlock recover`. |
| Security event monitoring and logs | Built: hash-chained audit log with a forward-secure MAC and a separate head file; signed, exportable events. |
| File inspection, hash verification | Built: bounded read-only walk, heuristics, known-bad and known-good hash sets. |
| Malware scanning integration | Adapters for ClamAV and Microsoft Defender, verified against synthetic tool output only. |
| Administrative controls | Built: accounts, roles, lockout that cannot be used to keep the administrator out, recovery codes, sessions. |
| Console | Built: CLI for every operation, local HTTP API, web console, `portlock simulate`. |

## 4. Files created and modified

216 files changed, about 108,000 lines added, on this branch.

- Created: `src/portlock/` (47,400 lines of Python; the web console is a further 5,900
  lines of static HTML, CSS and JavaScript with no build step), `tests/` (45,300 lines: 53
  unit and 15 integration test files), `docs/` (`DESIGN`, `ARCHITECTURE`, `API`, `POLICY`,
  `SCANNING`, `SECURITY_EVENT_FORMAT`, `THREAT_MODEL`, `OPERATIONS`, `enforcement/linux`,
  `enforcement/windows`), `pyproject.toml`, `.github/workflows/ci.yml`, `.gitattributes`,
  this report.
- Replaced: `README.md`, `.gitignore`.
- Removed: the prototype's `portlock/`, `gui/`, `main.py`, `data/`, `requirements.txt`.
  They remain in history at `003493c`.

## 5. Bugs discovered and fixed

- The prototype's defects listed in section 1: superseded.
- Found by design review and fixed before or during the build:
  - start-up presence conferring protection (the bypass described above);
  - a keyboard interface shielding any other function on the same device from policy;
  - "built in" decided by a bit the attacker's own hub supplies;
  - journal replay usable as an unvalidated privileged write;
  - session cookies shared with every other port on `127.0.0.1` (now bearer tokens);
  - device-supplied text reaching consoles unescaped;
  - a scan requirement that a grant could remove.
- Found during the build: `portlock recover` wrote the kill-switch file before checking
  for administrator rights, so a refused attempt left enforcement switched off. Fixed, with
  a regression test.
- Found by CI after everything passed locally: when two database handles appended at
  the same moment, the audit head file could be left one record behind, because each
  handle compared and wrote under its own lock. Compare-and-write now happens under a
  lock shared through the filesystem.
- A policy pitfall: vendor id `8087` written as a number was read as decimal and silently
  never matched vendor `0x8087`. Ids must now be hex strings.

## 6. Tests executed and their results

Run by the orchestrator on this machine, not just reported by the agents that wrote the code:

- Windows 11, Python 3.12: **5,883 passed, 71 skipped**, 5 min 20 s.
- Linux (WSL 2, Python 3.14): **5,864 passed, 90 skipped**, 3 min 42 s.
- `ruff check` and `ruff format --check`: clean.

Skips are platform-specific tests (Windows-only, Linux-only) and tests marked `hardware`.
The Linux run also skips tests that need the optional `cryptography` package, which is
not installed there.

Integration tests cover each area asked for: detection, authorization, trusted devices,
unauthorized devices, permission enforcement, removal, reconnection, policy expiration,
service restart, security event logging, lockdown safeguards.

On GitHub Actions, the last code change (`c1c3404`) passed lint and the full suite on
Linux and Windows across Python 3.11 to 3.14: nine jobs, all green. The run before it
had failed one test on Linux with Python 3.14; see section 5.

## 7. Build and runtime verification

- `python -m portlock simulate --no-serve` runs the complete pipeline on a simulated
  machine and prints each step; checked by hand.
- The web console was driven in a browser against the simulator: sign-in, approving a
  device, engaging, confirming and lifting a lockdown, verifying the audit log, with no
  script errors and no content-security-policy violations.
- Device enumeration was run read-only on this Windows machine. Only counts were
  recorded; no real identifier is in the repository.
- **Not verified:** any enforcement mechanism on a real device; the generated systemd unit
  (never loaded by systemd); the Windows scheduled-task and `icacls` command lines (marked
  UNVERIFIED in the code); `portlock doctor`, `run` and `status` on a real installation.

## 8. Git commits created

18 code commits, from `35777d0` (retire the prototype) to `c1c3404` (the audit race fix),
plus the commits that add and correct this report. `git log main..claude/overnight-security-framework`
lists them; each is one logical unit.

## 9. Changes pushed

Everything is pushed to `origin/claude/overnight-security-framework`. Nothing was pushed
to `main`, nothing was force-pushed, and no pull request was opened.

## 10. Remaining issues

- **The enforcers, lockdown manager, service, API and CLI have now had an independent code
  review** (16 November 2026: two reviewers, one with a security lens and one with a
  correctness lens). It produced 17 findings: 4 high, 9 medium and 4 low. 16 are fixed, each
  with a regression test. 1 is fixed in part and its remainder is open: `portlock recover`
  and a kill switch found at start still readmit every present device after default-deny,
  because they run without the database. Nothing was run against a real device. See
  `docs/REVIEW.md`.
- `portlock service print-unit` and `print-task` print their install steps with `\x0a`
  instead of line breaks. The generated files themselves are correct.
- The optional sink that publishes signed events to a ClawNet node exists and is tested
  against a local HTTP server, but the daemon's configuration cannot enable it yet.
- The enforcement journal has no MAC. Restore validates every target and only reverts
  values that still equal what was applied, which limits what a tampered journal can do.
- Directory privacy checking on Windows recognises only the English names of the SYSTEM
  and Administrators principals.
- A few docstrings in `guard/linux` and `guard/windows` still say the backends only
  observe.
- `data/logs.db` with a real serial number is still in the history of `main`. Removing it
  needs a history rewrite and a force-push, which was ruled out.
- A broken `.venv` directory is left in the local checkout (a safety check blocked its
  deletion). It is gitignored.

## 11. Known limitations

- **Enforcement is untested on real hardware on both operating systems.** Treat enforce
  mode as unproven until it has been tried on a disposable machine.
- Fingerprints are built from what a device says about itself and can be copied.
- With default settings a malicious device that presents itself only as a keyboard is not
  blocked. It is recorded and raises an alert. Blocking input devices is opt-in.
- Reactive blocking leaves a short window in which the device is usable. On Windows the
  preventive policy stops only devices that were never installed on that machine.
- Read-only applied after a volume is mounted does not take away write access it already
  has; the dependable form is the standing read-only baseline.
- A scan says nothing about what a hostile device serves afterwards.
- The audit log's local protections do not hold against someone with administrator
  rights who also rewrites the head file; exporting checkpoints off the machine does.
- No external security audit. [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) sets out what
  each kind of attacker can and cannot do.

## 12. Running it

Requires Python 3.11 or later. Nothing below touches a real device.

```bash
python -m pip install -e ".[dev]"
python -m pytest                       # the whole suite
python -m portlock simulate            # the full service on a simulated machine
```

`simulate` prints a banner, a scripted tour, and then the address of the web console with
a one-time administrator password. Open the address and sign in. Add `--no-serve` to
print the tour and exit.

On a machine you intend to protect, start in monitor mode: `portlock init`, then
`portlock doctor` to see what this machine can enforce, then `portlock run`. Read
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) before switching to enforce mode: enrol your
keyboard and mouse first.

## 13. Recommended next priorities

1. Try each enforcement mechanism on a disposable Linux machine and a disposable Windows
   machine with a real USB stick, and correct `docs/enforcement/` from what happens.
2. An independent security review of `core/service.py`, `lockdown/manager.py`,
   `guard/*/enforce.py` and `console/api.py`.
3. Load the generated systemd unit and Windows task on real systems; fix the UNVERIFIED
   command lines.
4. Wire the ClawNet sink into the configuration so signed events can leave the machine.
5. A MAC on the enforcement journal; non-English Windows principal names.
6. Packaging: a signed installer that sets the directory permissions the service checks.
