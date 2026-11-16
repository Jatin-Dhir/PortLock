# PortLock — operations

How to install PortLock as a service, set it up, move it to enforce mode safely, and take it
off the machine again. Read `THREAT_MODEL.md` first for what it does and does not do.

**What has been run.** Everything below was run by hand, unprivileged, against a temporary
directory (`PORTLOCK_HOME`) under WSL, or on Windows where noted, except the commands in
blocks headed **Not run**. Those use `systemctl`, `schtasks`, `icacls`, the registry or root
rights on a real machine. They were taken from the code and the generated definitions and
have never been executed by the author. Read each one before you run it. No enforcement
mechanism has been run against a real device.

All commands assume the `portlock` program is on the path. Without an installation, run
them as `python -m portlock ...` from the `src` folder. Sections 1 to 11 are about the
system-wide installation, run as administrator (root); section 0 is about the watch-only
one an ordinary user gets. Add `--config FILE` to any of them
if the configuration file is not in the default place.

## 0. Try it on your own PC (watch-only)

For a person who wants to see PortLock on their own computer without it changing anything.

**Who is watch-only.** A PortLock process is watch-only exactly when it could never be
trusted to enforce: it is **not elevated** (administrator on Windows, root on Linux), **or**
its state or configuration directory is **not a system-wide location** (it is inside a
user's own profile). This is decided once, at start, and the mode does not change it.
Files in a user's own folders can be changed by every program that user runs, so a policy
or journal kept there must never drive the real enforcer, even from an elevated process.
Which folders count, and how the edge cases fall, is in section 1 ("Where things are").
The reason PortLock gives is worded for the case at hand: this user's own folders, another
user's folders, the folder all users share, the home folder of the account that runs it
(a root installation must not live in `/root`), or a location PortLock cannot confirm is
local and system-wide.

**What a watch-only process does.** It lists the real USB devices, decides, audits and
serves the console. It runs no other program (no `icacls`, no `schtasks`, no antivirus),
writes no registry value, creates no timer or task and calls no device disable, enable or
eject function. The enforcer, the dead-man timer and the directory-permission tool are
never built: inert stand-ins (`guard/watchonly.py`) take their place for the whole life of
the process, and nothing inside it can switch them on. The only thing it changes is its own
folder (on Linux it creates that folder with mode `0700`, readable by you only).

**What it refuses**, with the plain reason (`409 watch_only` in the API) and leaving
nothing behind: switching to enforce mode, engaging a lockdown (it stays `idle`), and
turning default-deny on (turning it off stays allowed). Approving and denying devices work
and are recorded; nothing is blocked or ejected. Approving a drive, or asking for a scan,
reads the files on that drive with PortLock's own heuristics and hash lists; it starts no
antivirus program (`SCANNING.md`).

**If the state directory may hold changes an enforcing PortLock left in place**, a
watch-only process refuses to start. That is the case for open journal records, a lockdown
that is not idle, a journal line this version cannot read, and a journal it cannot open:
it cannot show there is nothing to undo, so it does not start and claim it changes
nothing. It says so on standard error, names the state directory and what it found, and
exits with code 3. It neither enforces nor undoes those changes, closes no record and
leaves the journal exactly as it was (a watch-only process never compacts or rewrites the
journal). What to do depends on where the directory is:

- **System-wide directories** (you started PortLock without administrator rights): start
  PortLock as administrator, or run `portlock recover` as administrator, on that
  installation.
- **Per-user directories** (your own, another user's or the shared folder): PortLock
  never enforces from there, and `recover` refuses them, because any program that user
  runs could have written the journal. Move the folder aside to start afresh, and have an
  administrator check the computer if the changes could be real. Open records cannot
  arise there by themselves, since nothing is ever enforced from a per-user folder; an
  unreadable journal line can.

> **Use an ordinary window, not an administrator one.** Open PowerShell normally, not with
> "Run as administrator" or "Terminal (Admin)" (on Linux, not with `sudo`). In an
> administrator window the default directories are the system-wide ones
> (`%ProgramData%\PortLock`, `/var/lib/portlock` and `/etc/portlock`): that is a
> **different installation, which can block devices**, also in monitor mode. `init` and
> `run` say so in plain words when they run elevated. If a system-wide installation already
> exists, an ordinary window still gets the separate watch-only one, and `init`, `status`
> and `stop` tell you that the other one exists.

In an ordinary PowerShell window, from the `PortLock` folder (Python 3.11 or later,
nothing installed):

```
cd src
python -m portlock init
python -m portlock run
```

`init` asks for an administrator name and a password (twice) and prints the audit
verification key and eight recovery codes once. It creates nothing until it has a password
it accepts, so a refused password costs nothing: run `init` again. Run `init` before
`run`, not beside it: while a PortLock service runs on the same state directory, `init`
refuses before it creates anything and says to stop the service first (a key created
beside a running service would leave records that can never be verified with it). It
checks again just before it writes, and holds no lock while it waits for your password.
A service started before any administrator exists says what to do: stop this service
(Ctrl+C), run `init`, then start it again. `run` prints the console
address (`http://127.0.0.1:47600/` unless `[api] port` says otherwise); open it and sign
in. If the port is taken, `run` names the configuration file and its `[api] port` setting.
If PortLock is already running, it prints that one's address and how to stop it.

**To stop it:** press Ctrl+C in its window, or run `python -m portlock stop` from another
ordinary window in the same folder. Closing the window is also safe: nothing on the
computer was changed, the next `run` removes the files the closed one left behind
(`runtime.json`, `stop.request`), and `stop` or `status` say at once that PortLock is not
running.

`python -m portlock doctor --offline` starts with two plain lines: `guard.watch_only` and
`guard.directories` (per-user, with the reason enforce mode is not available). Checks a
watch-only process does not make, such as whether the directories are private, are shown
as `info` "not checked", never as `ok`.

The files go to `%LOCALAPPDATA%\PortLock\state` and `...\config` (Linux:
`$XDG_STATE_HOME/portlock`, default `~/.local/state/portlock`, and
`$XDG_CONFIG_HOME/portlock`, default `~/.config/portlock`). Deleting that folder removes
PortLock completely.

**What was run.** These commands, on one Windows 11 machine, not elevated, with
`PORTLOCK_HOME` set to a new throwaway folder, `port` changed in that folder's
`portlock.toml`, and the password passed with `init --password-stdin`. Over the API the
service reported mode `monitor` and `watch_only`, the machine's real devices (counts only
were recorded), an event stream that answered, and an audit chain that verified. Asked for
enforce mode, a lockdown and default-deny, it refused each with `watch_only` and left no
lockdown and no pending change. A console break (what Ctrl+C sends) stopped it with exit
code 0; after a killed process, `stop` said at once that nothing was running and the next
`run` started normally. Every run was made under `tests/hardware/flight_recorder.py`,
which refuses and records each attempt to start a program, write the registry or call a
mutating operating-system seam, and records every file written and socket opened: nothing
was attempted, nothing was written outside the throwaway folder, and only `127.0.0.1` was
bound. The same checks are the test `tests/hardware/test_watch_only_live.py`
(`python -m pytest --run-hardware tests/hardware`); it passes on Windows and, where there
is no USB bus, under WSL. The console was opened in a browser against that service. Since then the owner has set it up by typing the password at the prompt and plugged a
USB storage device in while it ran: it appeared in the console as pending, and the
service recorded a storage device with one mounted volume, not present at start, and
one `enforcement.would_apply`. Unplugged, it left the list, and the service recorded the connection as closed
(`removed`) and one `device.removed`. Not done: anything as administrator.

## 1. Where things are

| | Windows | Linux |
| --- | --- | --- |
| State directory | `%ProgramData%\PortLock` | `/var/lib/portlock` |
| Configuration directory | `%ProgramData%\PortLock` (same directory) | `/etc/portlock` |
| Run as an ordinary user (watch-only) | `%LOCALAPPDATA%\PortLock\state` and `...\config` | `$XDG_STATE_HOME/portlock` and `$XDG_CONFIG_HOME/portlock` |
| Relocate both | `PORTLOCK_HOME=<home>` gives `<home>\state` and `<home>\config`; or set `[paths]` in `portlock.toml`. The file wins over the variable. | same |

Directories inside a user's folders are per-user, wherever they come from (the defaults,
`PORTLOCK_HOME` or `[paths]`): a process using them is watch-only for its whole life, even
when elevated, because every program that user runs could change them. A user's folders
are not only the account that runs PortLock:

- **Windows:** the profile (`USERPROFILE`) and the AppData folders, the shared `PUBLIC`
  folder, and every profile in the folder that holds the users' profiles, so another
  administrator's profile too. That folder is taken from sources that do not depend on who
  runs PortLock: `ProfilesDirectory` in the registry (read only), `Users` on
  `SystemDrive`, the parent of `PUBLIC`, and the parent of `USERPROFILE`. Under the SYSTEM
  or LocalService account the parent of `USERPROFILE` is not `C:\Users`, which is why
  the others are asked. If none of them is known, the location counts as not system-wide.
- **Linux:** the home directory (`HOME`), everything under `/home` and `/Users`, and, when
  PortLock runs natively, the home of every login account in the account database (uid of
  at least `UID_MIN` from `/etc/login.defs`, 1000 when it says nothing, and a home that is a
  real directory other than `/`), so `/export/home`, `/var/home` or `/srv/users` count too;
  under WSL also the Windows profiles under `/mnt/<drive>/Users`. Through `sudo`, `doas` or
  `pkexec` also the home of the account that asked for it (`SUDO_USER`, `DOAS_USER`,
  `PKEXEC_UID`). If one of those is set and its home cannot be found, the location counts
  as not system-wide. Root's own home (`/root`, as the account database gives it, also when
  `HOME` is unset or `/`) is no place for a root installation either: PortLock is
  watch-only there and says so. A `HOME` left pointing at another user's home (`su`
  without `-`) is that user's folder, not root's.

Another spelling of the profile does not get around this: short names
(`C:\Users\ALICE~1`), `\\?\` prefixes, `..`, junctions, symbolic links and `subst` drives
are resolved before comparing. A profile variable that points to a share on **another**
computer (AppData redirected to a file server with Folder Redirection, say) is skipped,
because no local directory can lie inside it, so it no longer makes an administrator's
system-wide installation watch-only. PortLock still fails closed, and counts the location
as not system-wide, for a `\\?\` or `\\.\` profile path, a UNC path to this computer
(`localhost`, `127.x`, `::1`, its own name, a name with a trailing dot such as
`127.0.0.1.`, its own IPv4 or IPv6 address, or a DNS name that resolves to one of them or
to a loopback address), a UNC `USERPROFILE` or `LOCALAPPDATA`, a
profile variable that is set but empty, relative or cannot be resolved, and a state or
configuration directory that is itself a UNC or device path.



| File | Directory | Purpose |
| --- | --- | --- |
| `portlock.db` | state | accounts, grants, trust, decisions, scans, audit records, lockdown state |
| `journal.jsonl` | state | what PortLock changed in the operating system, written before each change |
| `audit.key` | state | the audit MAC key for the **next** record (not the initial key) |
| `audit.head` | state | the newest audit record's number and hash |
| `runtime.json` | state | port, process id and the secret the command line uses; present only while running |
| `portlock.lock`, `stop.request`, `last-recover.json` | state | single-instance lock; stop request; marker left by `recover` |
| `portlock.toml` | config | configuration |
| `policy.json` | config | the active policy |
| `DISABLE_ENFORCEMENT` | config | the kill switch |

### Private directories

Both directories must be private to the account the service runs as. A system-wide
service (elevated, system-wide directories) makes them so at **every start, in monitor
mode too**, and then checks; if it cannot, it records a critical alert and **refuses
enforce mode** (it keeps monitoring). A watch-only process never touches permissions
outside its own folder. `portlock doctor` shows the result as `guard.state_dir` and
`guard.config_dir` (as `info` "not checked" in a watch-only process).

- Linux: owned by the service's user or root, mode `0700`, not a symbolic link, and every
  parent owned by that user or root and not writable by others (sticky directories such as
  `/tmp` are allowed). Run as root, `portlock init` creates `/var/lib/portlock` and
  `/etc/portlock` with mode `0700`.
- Windows: inheritance removed and access for LocalSystem and the Administrators group only.
  The service applies this with `icacls` at start. The check reads the names `icacls`
  prints, so on a Windows in another display language it reports the directory as not
  private and enforce mode stays refused (fail closed). That case has not been tried.

Check on Linux, as root, on the system-wide directories (**Not run**):

```
sudo portlock doctor --offline
```

Look for `guard.state_dir` and `guard.config_dir` reported as `ok` (private). That needs
root and the system-wide directories (`/var/lib/portlock` and `/etc/portlock`). Before the
directories exist the check reports that they do not exist; `portlock init` creates them.

Run as an ordinary user, or with a throwaway `PORTLOCK_HOME` (as under WSL), the process
is watch-only: `doctor` prints these two checks as `info` lines saying they were not
checked, because a watch-only process neither checks nor changes directory permissions.
That is expected, not a fault.

```
[info] guard.state_dir: the state directory was not checked for privacy: watch-only neither checks nor changes directory permissions
[info] guard.config_dir: the configuration directory was not checked for privacy: watch-only neither checks nor changes directory permissions
```

Do not run `portlock init` as one user and the service as another: the files would belong
to the first, and the service would refuse enforce mode. Use the service's account.

## 2. Installing as a service

PortLock generates a definition for you to review. It installs nothing.

### Linux (systemd)

```
portlock service print-unit --executable /usr/local/bin/portlock --output portlock.service
```

This was run (the file is written; "Nothing was installed" is printed). The unit runs
`portlock run --config /etc/portlock/portlock.toml` as root with
`CapabilityBoundingSet=CAP_SYS_ADMIN`, `ProtectSystem=strict`, writable paths limited to the
state directory, the configuration directory and `/etc/udev/rules.d`, `Restart=always`, and
without `ProtectKernelTunables` and `PrivateDevices` (PortLock could not enforce with them;
the file says why). `Restart=always` matters: a lockdown's dead-man timer and the release of
held devices need the service alive.

The path after `--executable` must be absolute. Use the `portlock` script of an
installation that is **importable by `python -I`**: the dead-man timer later runs
`<python> -I -m portlock recover`, and `-I` ignores `PYTHONPATH` and the current directory.
A copy run from a source checkout through `PYTHONPATH` will start but its timer will not
find the package. Install it into the interpreter's site-packages (`pip install .`).

**Not run** (needs root; review the unit first):

```
install -m 0644 portlock.service /etc/systemd/system/portlock.service
systemctl daemon-reload
portlock init
systemctl enable --now portlock
portlock doctor
```

The unit has never been loaded by systemd or checked with `systemd-analyze`. Whether the
service can arm its dead-man timer (`systemd-run`) under these restrictions is not
verified; test a lockdown on a machine where you can reach the console before you rely on
it. The same step list is printed by the command above on standard error.

### Windows (Task Scheduler)

PortLock runs as a scheduled task at boot as SYSTEM, because a Windows service needs a
service-control dispatcher that the standard library does not provide.

```
portlock service print-task --executable C:\PortLock\python.exe --output portlock-task.xml
```

Run on Windows: it writes a UTF-16 file and prints "Nothing was installed". The task runs at
boot as SYSTEM with the highest privileges, restarts on failure (every minute, up to 999
times) and has no time limit. `--executable` takes the Python interpreter (or the
`portlock.exe` launcher), with an absolute path. The install steps the command prints on
standard error show their line breaks as the text `\x0a` (a defect in how the command line
escapes that message); the file itself is correct.

**Not run** (needs an elevated prompt):

```
portlock init
schtasks /Create /TN "\PortLock\Service" /XML portlock-task.xml
schtasks /Run /TN "\PortLock\Service"
portlock doctor
```

`portlock stop` is the graceful stop. Ending the task with Task Scheduler is a crash as far
as PortLock is concerned: the next start recovers (section 8).

## 3. First run

```
portlock init
```

Run as the service's account, on a machine where the service is not running: for a
system-wide installation that means an administrator window (root on Linux), and `init`
says in plain words that this installation can block devices. Run on Windows and under WSL
with a throwaway home. It creates nothing until it has a password it accepts; after three
refused passwords it says so and that you can run `init` again. Before it writes, it looks
again at everything it decided on before the prompt (the configuration file, the database
and its users, whether an administrator was ever created, the key store); if another
`init` finished or a service started and stopped meanwhile, it changes nothing and asks
you to run `init` again. A key store that no administrator was set up with (left by a
`run` before `init`, or by a failed `init` of an older version) is moved aside, never
deleted, and replaced. Then it:

1. creates the directories (private on Linux; see section 1);
2. if there is no configuration file, writes `portlock.toml` with `[audit] hmac_key_file`
   set to `<state>/audit.key` (an existing file is never rewritten);
3. creates the audit key store and prints the **initial audit key** (`plak1-...`);
4. asks for the first administrator's name and a password of at least 12 characters, checked
   against known-bad passwords (the prototype's `portlock123` is refused);
5. prints **eight single-use recovery codes**.

The key and the codes are shown **once**. PortLock keeps only a digest of the codes and
never keeps the initial key.

- **Initial audit key.** Needed only to check MACs: `portlock audit verify --offline
  --key-file FILE`. Whoever holds it can forge the whole log, so it does not belong on the
  machine it protects. Store it with your offline backups or in a password manager on
  another system. If you lose it you still have the hash chain and the head file, but no
  MAC check.
- **Recovery codes.** Each lifts a lockdown or logs in once, in place of the password. Store
  them offline too. Issue a fresh set with `portlock user recovery-codes NAME` (it replaces
  the old set, and it uses the password you signed in with: a session alone cannot mint
  codes). A lost password is reset locally with `portlock user reset-password NAME
  --local`, which needs rights on the state directory, not a PortLock login.
- If you add `audit.hmac_key_file` to an existing installation, the next `portlock run`
  creates the key store and prints the key only if it is started from a terminal. Under a
  service manager it cannot be shown. Set the key file before the first `init`.

Start the service (foreground, for a first look; under systemd or Task Scheduler it is
started by them), then check it from another terminal:

```
portlock run
portlock status
portlock status --detail
portlock doctor
portlock audit verify
```

Run under WSL with a throwaway home. A new installation is in **monitor mode**:
`mode: monitor (chosen monitor, config)`. Starting takes a few seconds; `status` reports the
service as not running until it has written `runtime.json`. Each command that logs in
writes `auth.login` and `auth.logout` records to the audit log.

`portlock doctor` reports each mechanism. Under the real service account (root or
administrator, with the system-wide directories) every mechanism you expect should be
`ok`. Anything else is reported as *not enforced* in decisions, never as blocked. Run as an
ordinary user the process is watch-only, and `doctor` says so first (`guard.watch_only`,
with the reason), reports `warn` for `guard.privilege`, and lists every mechanism as `info`
"not probed (watch-only never touches enforcement mechanisms)"; in WSL it also reports
`fail` for the backend ("no USB bus under /sys"). `doctor` exits with 5 if any check is
`fail`.

On Linux, `doctor` also reports `guard.boot_default_deny`. Add `usbcore.authorized_default=0`
to the kernel command line (in your boot loader's configuration) if you want devices
refused before the service starts; PortLock never edits the boot loader. Test it where you
can recover from a boot with no usable keyboard.

## 4. Before enabling enforce mode

Do these in monitor mode, with the console of the machine in reach.

1. **Watch.** `portlock devices`, `portlock devices --history`, `portlock audit tail`. Look
   for what the default policy would block. A device you did not expect to be blocked is a
   policy to fix now.
2. **Enrol your input devices.** The operator's keyboard and mouse are protected only if
   they are enrolled, if they are hubs or input-only devices (protected unless HID
   enforcement is on), or if the platform reports them as built in. Being connected at start
   protects nothing (DESIGN 14.1). Enrol each device on the port you use:

   ```
   portlock devices                       # note the connection id of each input device
   portlock enroll 3 --label "desk keyboard"
   portlock enroll                        # list enrolments
   ```

   An enrolment binds the fingerprint **and** the port; plugged into another port, the device
   is an ordinary device. A second device presenting the same fingerprint while the first
   is connected is denied with an alert.
3. **Read the policy.** `portlock policy show`. The default is: input beside another
   function denied with an alert; everything else `pending`. Write a file to edit with
   `portlock policy init --example --output policy.json` (its sample rules are disabled, so
   it behaves like the default until you change it), check it with
   `portlock policy validate policy.json` and `portlock policy test`, and apply it with
   `portlock policy set policy.json`. First match wins; a grant never overrides a rule.
4. **Choose the scope.** `portlock scope` shows it. The default `storage` covers mass
   storage, imaging devices and input-plus-other devices. Other devices stay usable and are
   recorded as *not enforced*. Wider scopes can lock you out; each needs confirmation.
5. **Have another way in** (a remote shell or a second administrator) and know where the
   configuration directory is, so you can create `DISABLE_ENFORCEMENT` from elsewhere.

## 5. Commit-confirm

Four changes can lock the operator out, so each is applied, **listed, and rolled back
unless confirmed within 60 seconds** (`commit_confirm_seconds`, 10 to 600): switching to
enforce mode (`portlock mode enforce`), widening the scope (`portlock scope ...`), turning
on default-deny (`portlock default-deny on`) and engaging a lockdown. Confirmation must come
over the same channel: the command line confirms what the command line applied.

Default-deny is a standing setting that is **in force only in enforce mode**. Turned on in
monitor mode, it is stored and waits: `portlock default-deny` and `GET /default-deny` then
report `enabled` false and `stored` true with a note that says so, and the console's
control stays ticked with the same note. The kill switch takes it out of force the same
way. An engaged lockdown denies new devices by itself, in monitor mode too.

```
portlock mode enforce                  # applies, lists what would be blocked, asks "Keep it?"
portlock changes                       # what is waiting, and the time left
portlock confirm                       # keep it (confirm ID if more than one is waiting)
portlock cancel ID                     # roll it back now
```

Typing `yes` at the prompt confirms; `--confirm` confirms without asking. Without a
terminal the command prints the `confirm` and `cancel` commands and leaves the change to
roll back by itself. Behind this there is a second safeguard: when a change is applied,
an operating-system timer (`portlock-confirm-<id>`) is armed to roll it back 30 seconds past
the deadline even if the service has died. That timer has never been run against a real
`systemd-run` or `schtasks`.

If you are cut off, do nothing: the change rolls back. An operator whose only way in is a
USB network adapter or serial console gets it back automatically.

Switching to enforce is refused up front if the enforcer cannot block devices (no
mechanism, or a directory that is not private). In a watch-only process (not elevated, or
per-user directories) enforce mode, a lockdown and turning default-deny on are refused with
the code `watch_only` and the plain reason, and nothing is applied, so there is nothing to
confirm or roll back.
Run as an ordinary user, `portlock mode enforce` says `PortLock cannot change this
computer: it is not running as administrator. It stays watch-only: it shows and records,
and blocks nothing. (watch_only)` and exits 1; with a per-user home the sentence also
names the folders. Seen on Windows and under WSL.

## 6. Lockdown

```
portlock lockdown engage --reason "suspected intrusion" --minutes 60
portlock lockdown status
portlock lockdown renew --minutes 30
portlock lockdown lift                 # asks for the administrator password
portlock lockdown lift --recovery-code
```

Engaging a lockdown blocks all removable storage and turns on default-deny, in monitor mode
as well as enforce mode, in a system-wide service. A watch-only process refuses to engage
one (`watch_only`): the lockdown stays `idle`, so it can never be reported as active while
nothing is blocked. It is itself a commit-confirm change (section 5). Hubs, built-in
devices, the system volume and enrolled or pinned devices are never touched. A device
without storage that was connected before the lockdown stays; a new input-only device is
accepted if `lockdown.allow_new_input_devices` is true (the default).

- **The dead-man timer.** A lockdown ends by itself after `lockdown.default_minutes` (60)
  unless renewed, and never lasts longer than `max_minutes` (1440). The remaining time is
  stored and counted on the monotonic clock, so a restart resumes the remainder, and an
  expired lockdown found at start is lifted and not re-applied. Separately, an
  operating-system timer (`portlock-lockdown`, a systemd transient timer on Linux, the task
  `\PortLock\portlock-lockdown` on Windows) runs `portlock recover --dead-man` 30 seconds after
  expiry, so the lockdown ends even if the service has died; a living service lifts it
  first, within a second of the expiry, and cancels the timer. The timer's `recover` finds
  a running service and then does nothing at all, and otherwise restores the journal
  **without** creating the kill-switch file: the next start sees that the lockdown was
  recovered and enforces as before. Only an operator's own `portlock recover` creates the
  kill-switch file (below).
- **Lifting** needs the administrator password or a recovery code. An operator can engage a
  lockdown but not lift one.
- **A lockdown is in force only while the service runs.** A clean stop restores the
  operating-system settings, and the next start resumes the lockdown. If the service dies,
  default-deny stays on until it restarts or `portlock recover` runs, and in that window
  every new device, your keyboard included, is refused.

## 7. The kill switch and `portlock recover`

**The kill switch.** If the file `DISABLE_ENFORCEMENT` exists in the configuration
directory, the service restores every journaled setting, ends any lockdown, writes the mode
`monitor` and stays in monitor mode. It is checked at start before the database is opened
and on every tick (about once a second). It is honoured only inside a directory verified
to be private. Removing the file does **not** switch enforcement back on: set the mode
again deliberately (`portlock mode enforce`).

From another system, with write access to the configuration directory:

```
touch /etc/portlock/DISABLE_ENFORCEMENT          # Linux
```

(On Windows, create an empty file of that name in `%ProgramData%\PortLock`.)

**`portlock recover`.** Restores every journaled setting without the service, the database
or any PortLock password. It needs only the journal file and **operating-system
administrator rights**. It leaves an audit marker that the next start records, and it
**creates the kill-switch file first**, so enforcement stays off until you delete that file
and restart the service. (The dead-man timer runs `portlock recover --dead-man`, which
never creates it; see section 6.)

```
portlock recover --dry-run             # list what would be restored; changes nothing
portlock recover                       # restore it (administrator or root)
```

Run under WSL: `--dry-run` printed `0 open journal record(s) in .../journal.jsonl; nothing
was changed.` Without root, `recover` refuses with
`portlock recover needs operating-system administrator rights` (exit 3) before it writes
anything, so a failed attempt leaves no kill switch behind. If the service is running, `recover` creates the
file and waits up to 10 seconds for the service to empty the journal; if it does not,
stop the PortLock process and run `recover` again.

`recover` refuses a per-user installation (directories in a user's folders, section 1)
before it writes anything, the kill-switch file included: any program that user runs could
have written that journal, and an elevated `recover` would apply it with the real
enforcer. A per-user installation is watch-only and never changed anything to restore.

Order of preference when something is wrong: `portlock cancel` or let the commit-confirm
timer run; `portlock lockdown lift`; the kill switch; `portlock recover`.

## 8. Crashes and restarts

On the next start the service closes the old run's connections, re-evaluates every device
present, keeps or releases each journaled setting according to the new decisions, completes
a lockdown lift that was in progress, rolls back an unconfirmed change, and records
`service.recovered`. `ARCHITECTURE.md` section 6 lists every case. If the state cannot be
used (a damaged database, or one from a newer PortLock) the service restores journaled
settings (unless `fail_closed` is set), prints that nothing was deleted, and exits with
code 3. A damaged database is renamed to `portlock.db.damaged-<time>` and a new log begins,
its first record naming the old file's hash.

Exit codes of `portlock run`: 0 clean stop, 1 unexpected error, 2 already running, 3 state
unusable (including a watch-only process that found changes an enforcing PortLock left in
place, section 0), 4 configuration rejected, 5 the API could not listen. A second `portlock run`
prints `portlock is already running` and exits 2 (run under WSL).

## 9. The audit log

```
portlock audit tail -n 20
portlock audit query --type 'auth.*' --since 2026-11-01T00:00:00Z
portlock audit verify                                    # asks the service; checks the chain
portlock audit verify --offline                          # reads the database; service not needed
portlock audit verify --offline --key-file keyfile       # also checks every MAC
portlock audit export --output events.jsonl
```

All of these were run. `verify` against the service and `--offline` without a key check only
the chain and the head file and say `no MACs were checked`. With the initial key in a file
(one line, `plak1-...`) MACs are checked too. Do this from time to time, from a copy of the
state on a machine you trust, and record `portlock audit verify --json` output (the head's
number and hash) somewhere the administrator of this machine cannot rewrite. For that,
configure a sink in `portlock.toml`:

```
[[audit.sinks]]
type = "syslog"
target = "192.0.2.10:514"        # a literal address and UDP port; names are not resolved
min_severity = "notice"
```

A `file` sink writes on the same machine and protects nothing against its administrator
unless the file is on append-only or remote storage. The type `clawnet` is accepted by the
configuration but is not wired into the service in this version.

## 10. Backup and restore

Back up with the service **stopped** (`portlock stop`), so the database is complete and its
write-ahead files are gone:

- state directory: `portlock.db`, `audit.head`, `audit.key`, `journal.jsonl` (if present);
- configuration directory: `portlock.toml`, `policy.json`.

The backup contains password hashes and the next audit key. Keep it private, like the
directories themselves. Never back up `runtime.json`.

**Restore all of it, from one backup, together.** Restoring only an old `portlock.db` is
detected and reported (run under WSL): `the audit log DOES NOT verify at record 12: the log
ends at record 11 but the head file names record 16: records were removed, or the database
was replaced by an older copy`. That is the head file doing its job. Restoring the whole set
verified (`audit verify --offline --key-file ...`) and the service started. Restore with
the service stopped, as the service's account, then run `portlock audit verify`.

Backing up the initial audit key and the recovery codes is separate, and offline (section 3).

## 11. Uninstalling, and restoring every journaled setting

1. **Lift any lockdown and stop the service.** `portlock lockdown lift`, then
   `portlock stop`. A clean stop restores every journaled setting (unless `fail_closed` is
   set, which keeps restrictions across a stop on purpose).
2. **Make sure the journal is empty.** If the service cannot be stopped cleanly, or
   `fail_closed` is set:

   ```
   portlock recover
   portlock recover --dry-run             # must report 0 open journal records
   ```

3. **Remove the service definition.** **Not run:**

   ```
   systemctl disable --now portlock          # Linux
   rm /etc/systemd/system/portlock.service
   systemctl daemon-reload
   ```

   ```
   schtasks /Delete /TN "\PortLock\Service" /F    # Windows, elevated
   ```

4. **Remove any dead-man timer still armed.** **Not run:** `systemctl list-timers
   'portlock-*'` on Linux, `schtasks /Query /TN "\PortLock\"` on Windows; delete what is
   listed. A lift or stop cancels them, but a crash can leave one, and one that fires runs
   `portlock recover` and fails harmlessly if the program is gone.
5. **Check what `recover` and the journal should have put back.** Each of these was written
   by PortLock only under enforcement, and `recover` restores it:
   - Linux: each USB device's `authorized` attribute, each host controller's
     `authorized_default`, read-only flags on block devices, and the file
     `/etc/udev/rules.d/60-portlock-readonly.rules` (only if `baseline_read_only` was on;
     delete it yourself if it remains, then `udevadm control --reload`). Remove
     `usbcore.authorized_default=0` from the kernel command line if you added it.
   - Windows: disabled device nodes, the values under
     `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` and
     `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices` that PortLock set
     (`recover` restores each to its previous value or removes it), and disk read-only
     attributes. `restore` reverts a value only if it still equals what PortLock wrote; if
     someone else changed it, it is left alone and the audit log says so. Check these keys
     yourself if a domain policy also manages them.
6. **Remove the program and, if you no longer need them, the directories.** Delete the state
   and configuration directories only after you have kept whatever audit records you need;
   the log is in `portlock.db`. Delete `DISABLE_ENFORCEMENT` with the directory.
7. Delete the stored initial audit key and recovery codes when you no longer need to verify
   old backups.

## 12. When something fails

| Symptom | Meaning |
| --- | --- |
| `enforce mode refused` alert, `mode` shows `monitor` | a directory is not private; read `portlock doctor` |
| "PortLock cannot change this computer" (`watch_only`) when switching to enforce, engaging a lockdown or turning default-deny on | this process is watch-only: not elevated, or its directories are in a user's folders, or their location cannot be confirmed as local and system-wide; the reason says which (sections 0 and 1). Use the system-wide installation from an administrator window |
| a watch-only `run` refuses to start because an enforcing PortLock may have left changes (open records, a lockdown, or journal lines it cannot read) | system-wide directories: start PortLock as administrator, or run `portlock recover` as administrator, on that installation. Per-user directories: move the folder aside and have an administrator check the computer (section 0) |
| `init` refuses because a PortLock service is running from that state directory | stop the service (Ctrl+C in its window, or `portlock stop`), run `init`, then start it again |
| `init` says "PortLock's files changed while init was waiting" | another `init`, or a service that started and stopped, changed the files while it asked for the password; nothing was changed by this one. Run `init` again |
| `stop` or `status` says it "cannot tell whether the service is running" | this user cannot look into the state directory (another user's or the system-wide installation). Open a window as administrator, or as the user who runs it |
| `stop` says the service is "probably not running" | the lock cannot be looked at, and the address in `runtime.json` does not answer: the service most likely ended without cleaning up. An administrator (or its user) can confirm with `status` |
| `default-deny` is off with a note that it is "stored on but not in force" | default-deny applies only in enforce mode, and not under the kill switch; the choice is kept (section 5) |
| `run` says the port is taken | another program uses it; change `[api] port` in the configuration file it names |
| a decision says `not enforced` or `unsupported` | the mechanism is unavailable (not root, no such attribute, read-only sysfs) |
| `cannot be made private` | fix the directory's owner and mode, or the access list, then restart |
| exit code 5 from `run` | the API port is taken by another process (see above) |
| exit code 3 from `run` | the database is damaged or too new; nothing was deleted; restore a backup or move it aside |
| `audit verify` fails | the chain, head file or a MAC does not fit; the service marks the log degraded and raises a critical alert until a later verification succeeds |
