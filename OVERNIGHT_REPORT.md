# Overnight report: PortLock

Branch `claude/overnight-security-framework`, 16 November 2026. `main` is untouched.

The short version: the repository held about 180 lines of Python that could not be
imported. It now holds a complete device-control service (decision pipeline, enforcers
for Linux and Windows, lockdown, audit, API, CLI, web console) that passes 6,139 tests.
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
- **The first watch-only design was wrong.** Three independent reviewers examined it. It
  made *monitor mode* watch-only for every process and opened a gate when an administrator
  switched to enforce. That broke administrators' system-wide installations in monitor
  mode (their directories were never made private, and a lockdown was reported active
  while nothing was blocked, and became real without its dead-man timer when the gate
  opened), let the console say a lockdown blocked all removable storage when nothing was
  blocked, started Microsoft Defender's command-line scanner from a watch-only process
  when a drive was approved, and let a watch-only process close records of devices that
  stayed blocked. The design was corrected to one rule decided once per process: a process
  is watch-only exactly when it is not elevated or its directories are not system-wide, and
  then it refuses enforce mode, a lockdown and default-deny, starts no antivirus program
  and never closes a journal record on a result that changed nothing; every other process
  behaves as before, in monitor mode too. The console now shows a watch-only bar on every
  page and says "would" wherever nothing was applied.
  The corrected design is held by `tests/unit/test_watch_only.py` (70 tests: among them
  an ordinary user's start reaching no operating-system seam, the three refusals leaving
  nothing behind, and an elevated system-wide process in monitor mode making its
  directories private and engaging a real lockdown as before), by 17 tests that run the
  console's own wording under Node, and by a live test that runs the real service under a
  flight recorder on Windows and under WSL (`tests/hardware/test_watch_only_live.py`).
- Found by running the real service: on Windows with Python 3.12 or older, Ctrl+C and
  Ctrl+Break did not stop it, because the main thread sat in an untimed wait that a
  signal cannot interrupt there. The wait is now cut into short pieces; a test sends a
  real console break to a real process.
- Found by the review's ordinary-user pass: a closed window left files that made the next
  `stop` hang for 15 seconds and the next `run` exit a second after printing its address;
  a mistyped password at the first `init` lost the audit verification key for good;
  several messages named a `portlock` command that does not exist when running from the
  source folder. All fixed, each with a test.

## 6. Tests executed and their results

Run by the orchestrator on this machine, not just reported by the agents that wrote the code:

- Windows 11, Python 3.12: **6,139 passed, 92 skipped**, 8 min 12 s (run beside other work).
- Linux (WSL 2, Python 3.14): **6,126 passed, 106 skipped**, 4 min 56 s.
- `ruff check` and `ruff format --check`: clean.
- The opt-in live tests (`--run-hardware`; they read the real machine and change nothing):
  the 9 watch-only service tests pass on Windows and under WSL, beside the 8 Windows and
  5 Linux device tests that were there before.

Skips are platform-specific tests (Windows-only, Linux-only) and tests marked `hardware`.
The Linux run also skips tests that need the optional `cryptography` package, which is
not installed there.

Integration tests cover each area asked for: detection, authorization, trusted devices,
unauthorized devices, permission enforcement, removal, reconnection, policy expiration,
service restart, security event logging, lockdown safeguards.

On GitHub Actions, commit `36012b4` (the third watch-only pass) passed everything: lint,
the full suite on Linux and Windows across Python 3.11 to 3.14, and the read-only live
tests on a Linux and a Windows runner: eleven jobs, all green. For the commit before it
the Linux live-test job had failed: the test's flight recorder wrote its first report
after one second, and a fast runner had answered and been killed by then (a fault of
the test, fixed in `36012b4`). The fourth pass (`c7484fb`) then passed the same eleven jobs.

## 7. Build and runtime verification

- `python -m portlock simulate --no-serve` runs the complete pipeline on a simulated
  machine and prints each step; checked by hand.
- The web console was driven in a browser against the simulator: sign-in, approving a
  device, engaging, confirming and lifting a lockdown, verifying the audit log, with no
  script errors and no content-security-policy violations.
- Device enumeration was run read-only on this Windows machine. Only counts were
  recorded; no real identifier is in the repository.
- The real service was run in watch-only mode on one Windows machine (not elevated,
  `python -m portlock init`, `run` and `stop` from `src`, throwaway `PORTLOCK_HOME`, a
  non-default port), by the orchestrator, under a flight recorder that refuses and records
  every program start, registry write and mutating seam call. It listed 5 real USB devices
  (2 hubs, 1 mouse, 1 audio/video, 1 wireless; all 5 protected), answered on the event
  stream and verified its audit chain. Asked for enforce mode, a lockdown and default-deny
  it refused all three (`watch_only`); a console break stopped it with exit code 0. The
  recorder saw no program start, no registry write, no mutating seam call, no file
  written outside the throwaway directory and no socket other than `127.0.0.1`.
- Run against the code as it was before (commit `d781c2a`), the same recorder caught
  start-up calling `icacls` to change directory permissions, and a console request
  reaching the scheduled-task timer. The recorder refused both, so nothing was changed.
- The same run under WSL (no USB bus): the Linux backend started, the service answered,
  the three requests were refused and SIGINT stopped it with exit code 0.
- The console was opened in a browser against the real watch-only service: the watch-only
  bar, "Watch-only: nothing is being blocked", and the enforce, default-deny and lockdown
  controls disabled with the reason.
- A USB storage device was plugged in while the real watch-only service ran (17 November
  2026, by the owner, on that Windows 11 machine, with the committed version `36012b4`
  set up by typing the password at the `init` prompt). It appeared in the console as
  pending. The service's own records, read afterwards without identifiers, show one
  connection that was not present at start, of category storage with one mounted volume,
  in state pending under the default policy, and one `enforcement.would_apply` audit
  record: what it would have done, with nothing blocked.
- **Not done:** a device removed while the real service runs.
- **Not verified:** any enforcement mechanism on a real device; the generated systemd unit
  (never loaded by systemd); the Windows scheduled-task and `icacls` command lines (marked
  UNVERIFIED in the code); `portlock doctor`, `run` and `status` on an elevated,
  system-wide installation.

## 8. Git commits created

27 commits in all, from `35777d0` (retire the prototype) to the fourth watch-only pass,
including the commits that add and correct this report. `git log main..claude/overnight-security-framework`
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
