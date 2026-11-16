# PortLock — threat model

This states what PortLock tries to protect, from whom, and where it stops. It describes
the code as built. Where a statement depends on an operating-system mechanism, it says so:
**no enforcement mechanism has been run against a real device** (see the README), so every
"PortLock blocks X" below means "the code asks the operating system to block X, and the
logic that does so passes its tests against fakes". `DESIGN.md` gives the reasons for the
design; `enforcement/windows.md` and `enforcement/linux.md` give each mechanism's limits.

## 1. Assets

| Asset | Why it matters | Where it lives |
| --- | --- | --- |
| The host's data and integrity | the thing a hostile USB device attacks | the machine |
| The operator's access to the machine | PortLock can disable the keyboard and network adapter that would be used to undo it | input and network devices |
| The decision state | policy, trust list, grants, enrolments, mode | `portlock.db`, `policy.json`, `portlock.toml` |
| The enforcement journal | what PortLock changed, so it can be put back | `journal.jsonl` in the state directory |
| Administrator credentials | scrypt password hashes, sessions, recovery codes (stored as SHA-256 digests) | `portlock.db` |
| The runtime secret | lets the command line prove it is talking to the service and log in on the local channel | `runtime.json` in the state directory |
| The audit log | the record of what was seen, decided and done | `portlock.db` (`audit_log`), `audit.head`, `audit.key`, external copies |
| The audit initial key | the only thing that lets anyone check earlier MACs | shown once by `portlock init`; kept by the operator offline |

## 2. Scope

PortLock concerns USB devices on one machine. It does not defend against:

- other physical ports and buses (Thunderbolt and PCIe DMA, SD slots, FireWire, Bluetooth),
  network attacks, or firmware and boot-chain attacks;
- the host's own USB stack. A device is enumerated by the kernel before PortLock hears of
  it, so a driver or descriptor-parsing flaw is reachable before any block (the reactive
  window, section 4.3);
- an adversary who already runs as root or SYSTEM (section 3.4);
- anything that happens on a machine where the service is not running, or where only a
  watch-only PortLock runs (section 3.5): that one watches and records, and blocks nothing.

## 3. Adversaries

### 3.1 Someone with physical access and a hostile device

This is the adversary PortLock exists for. What it can and cannot do, with default settings:

| The device | What PortLock does |
| --- | --- |
| Unknown storage device | default policy: `pending`. Blocked in enforce mode; recorded as "would block" in monitor mode. Becomes usable only when an operator approves it, and then its volumes are scanned. |
| Storage plus a keyboard, network adapter, serial port or other function ("BadUSB" shape) | denied by the default rule `deny-input-with-other`, with an alert. A grant cannot override a rule. It gets no category protection. |
| Phone or camera in MTP or PTP mode | treated as storage: in the default scope, and a lockdown holds it. |
| A device that is only a keyboard or mouse | **allowed.** Protected input devices are never restricted, so a malicious keyboard is recorded (`safety.suspicious_device`, `new_input_device`) but not stopped. |
| A device that re-enumerates repeatedly to reopen the reactive window | the port is held blocked after more than 5 arrivals in 30 seconds, for 120 seconds without another arrival (configurable). |
| A second device presenting the fingerprint of an enrolled device while the first is connected | denied, with an alert (clone detection). |
| A device behind a hub | never "built in", whatever the hub claims about its ports. |
| A device with a copied identity (vendor, product, serial, strings) | **indistinguishable from the original.** See 5.1. |

What it cannot do: stop a device from being a keyboard (5.2), stop the first fraction of a
second after arrival (4.3), or tell a hostile device from the honest one it imitates.

### 3.2 A standard local user

A standard user on the machine cannot change the state of a system-wide PortLock: its
state and configuration directories are made private to the service's account
(Administrators and SYSTEM on Windows, root on Linux) at every start, in monitor mode as
well as enforce mode, and enforce mode is refused if they cannot be. (A standard user's own
PortLock is a different thing: section 3.5.) They cannot read `runtime.json`, so they cannot use the local login channel.

What they can do:

- **Reach the API.** It listens on loopback (`127.0.0.1`), which every local account can
  connect to. Every request but a few public ones needs a bearer token, obtained only with
  an administrator's, operator's or auditor's password. Password checks use scrypt
  (N = 2^17), at most two run at once on the network path (a third gets `busy`), and five
  failures start a delay of 30 seconds doubling to 15 minutes, which survives a restart.
- **Lock the real administrator out of the network path.** Failed attempts against a
  name lock that name on the network channel. The command line, which proves itself with
  the runtime secret, and recovery codes are not affected, so the administrator can still
  log in at the console of the machine. A user of the web console is affected until the
  delay passes.
- **Squat the port.** If another process holds `127.0.0.1:47600` before the service starts,
  the service exits with code 5 (it refuses address reuse). A web page served at that
  address could then ask for a password. The command line does not fall for this: it
  sends a random challenge and sends no credential unless the answer proves knowledge of
  the runtime secret. `portlock status` also reports the service as not running when it
  failed to start. If you use the web console, check that the service is running first.
- **Plug in a device.** This is 3.1.

### 3.3 Malware running as a user

Malware running as the logged-in account, without administrator rights, is in the same
position as a standard user (3.2), plus two things:

- **It can read what the user types.** If the administrator types their PortLock password
  into a terminal or the web console while such malware watches the keyboard, it has the
  password. PortLock cannot prevent that. A recovery code typed the same way is also lost.
- **It can persuade a human.** An operator can approve a device that malware has asked the
  user to plug in. Approval is a human decision and PortLock only records it.

Malware that can elevate is 3.4. A user who is in the Administrators group but is not
elevated (UAC) does not have access to the private directories, by design of the access
list, but that was not tested on a real machine.

The web console is served with no inline script, a content security policy, no cookies and
bearer tokens held in memory only, so another web page in the user's browser has nothing to
make the browser send to `127.0.0.1`. Device-supplied text is shown as text and escaped in
every API response.

### 3.4 Someone with administrator rights (root, SYSTEM, Administrators elevated)

PortLock is not a defence against this adversary. They can stop the service or kill it,
create `DISABLE_ENFORCEMENT`, edit `policy.json`, open the database, replace the program,
run `portlock recover`, change the operating-system settings PortLock manages, and read
the current audit key. What PortLock adds:

- Every sanctioned path (`portlock stop`, the kill switch, `recover`) restores the settings
  from the journal and leaves audit records. Killing the process leaves the journal as it
  was; the next start finds it and recovers.
- Records already in the audit log cannot be altered or deleted without detection by
  someone who holds the initial key (5.5), even by this adversary, **provided they did not
  also rewrite the head file and the key store and you do not hold an external copy**.
- Records written after the adversary took the current key can be forged, and the newest
  records can be removed without a trace in the local files alone.

Lifting a lockdown through PortLock needs the administrator password or a recovery code,
but that protects only against people who do not have operating-system administrator
rights: `portlock recover`, the kill switch and the dead-man timer all end a lockdown
without a PortLock credential, by design, so that PortLock itself can never be the thing
that cannot be undone.

### 3.5 A watch-only PortLock (a user's own, or any process that is not trusted to enforce)

A PortLock process is **watch-only** when it is not elevated (administrator, root), or when
its state or configuration directory is in a user's folders. It is decided once, at
start; the mode does not decide it, and nothing inside the process can change it. The
reason is the adversary of 3.3: every program a user runs can write that user's own
folders, so a policy, a configuration or an enforcement journal kept there could be written
by malware, and must never drive the real enforcer, not even from an elevated process.

"A user's folders" means any user's, not only the account that runs PortLock: an elevated
process started with another administrator's credentials, or through `sudo` with a
`PORTLOCK_HOME` in someone else's home, would otherwise enforce from a folder that other
user can forge. So every profile under the Windows profiles folder and the shared `PUBLIC`
folder count, and on Linux everything under `/home` and `/Users` and the home of the
account behind `sudo`, `doas` or `pkexec`; if that account's home cannot be found, the
location counts as not system-wide. Root's own home (`/root`) is refused too. Another
spelling of the profile (a short name, a `\\?\` path, `..`, a junction, a symbolic link, a
`subst` drive) is resolved before the comparison, and anything that cannot be resolved
counts as not system-wide (fail closed). One exception keeps administrators working on
managed PCs: a profile variable that points to a share on another computer (AppData
redirected to a file server) is skipped, because no local directory can lie inside it. A
UNC path to this computer, a UNC `USERPROFILE` or `LOCALAPPDATA`, and a state or
configuration directory that is itself a UNC or device path still fail closed.

What a watch-only process can do to the machine: nothing outside its own folder. It never
builds the enforcer, the dead-man timer or the directory-permission tool; inert stand-ins
take their place. It runs no program (no `icacls`, no `schtasks`, no antivirus scanner),
writes no registry value, creates no timer or task, changes no permission outside its own
folder and calls no
device disable, enable or eject function. Its scans read the files of a drive someone
approved or asked to scan, with PortLock's own heuristics and hash lists only. It refuses
enforce mode, a lockdown and turning default-deny on, so a lockdown can never be reported
as active while nothing is blocked.

What it means for the adversaries above:

- **It protects nothing.** A hostile device plugged in while only a watch-only PortLock
  runs is recorded, alerted on and shown in the console, and is fully usable. The console
  and the command line say "watch-only" for exactly this reason.
- **Its records are only as safe as the user's own folders.** Malware running as that user
  (3.3) can rewrite its database, its audit head file and its audit key store together, so
  its audit log shows nothing reliable against that malware. An external copy (a syslog
  sink) still helps.
- **It cannot be used to change the machine.** A forged policy or journal in a per-user
  folder reaches only inert stand-ins. `portlock recover` refuses a per-user home before it
  writes anything, so an elevated `recover` cannot be tricked into applying a forged
  journal with the real enforcer.
- **It cannot hide or undo an enforcing PortLock's changes.** If it finds open journal
  records, a lockdown that is not idle, a journal line it cannot read or a journal it
  cannot open in the directories it would use, it refuses to start, leaving the journal
  untouched. For system-wide directories it says to start PortLock, or run
  `portlock recover`, as administrator; for per-user ones, which `recover` refuses, it
  says to move the folder aside and have an administrator check the computer. It never
  closes a journal record on a result that changed nothing, and never compacts or
  rewrites the journal.
- **`init` beside a running service.** `init` refuses while a service holds the state
  directory, so a new audit key is never created under a service that would then write
  records without a MAC that no key can verify.

An administrator's system-wide PortLock is never watch-only. In monitor mode it builds the
real mechanisms at start, makes its directories private, honours the kill switch, restores
what an earlier run left, and a lockdown it engages blocks.

### 3.6 Someone who can restart the machine

Restarting (power, a crash, a forced reboot) is within reach of anyone with physical access
and of some local users. What it does:

- **It opens a window.** From power-on until the service has started, nothing decides or
  blocks. On Linux, `usbcore.authorized_default=0` on the kernel command line closes this;
  `portlock doctor` reports whether it is set. On Windows there is no equivalent from boot:
  Device Installation Restrictions stop only devices Windows has never installed, so a
  device that has been connected before is usable until the service starts as a scheduled
  task at boot.
- **It does not confer protection.** A device connected when the service starts is
  evaluated like any other. A hostile keyboard plugged in before a restart is not made
  "protected" by being present; only enrolments (fingerprint and port) and the other safety
  facts protect a device. This was a deliberate change (DESIGN 14.1): otherwise anyone who
  can cause a restart could turn a hostile device into a protected one.
- **It does not lift a lockdown early.** A lockdown found at start with time remaining is
  resumed with the remainder; one that has expired is lifted and never re-applied.
- **It can lift enforcement.** If the state is unusable at start (a damaged database, a
  database from a newer version) the service restores journaled settings and exits with
  code 3, unless `fail_closed` is set. A damaged database is renamed aside, never deleted.
  So breaking the database and restarting disables enforcement until someone fixes it.
- **A clean stop restores everything**, an active lockdown's settings included. Lockdown is
  in force only while the service runs. If the service dies during a lockdown, the
  operating-system settings stay in place until the next start or `portlock recover`. In
  that window default-deny refuses every new device, a re-plugged keyboard and an enrolled
  one included, because nothing is running to admit it. Run the service under a supervisor
  that restarts it.

## 4. What PortLock does and cannot do about devices

### 4.1 Preventive and reactive

A *preventive* mechanism makes the operating system refuse a device from its first
instant. A *reactive* one acts after the device has appeared. PortLock reports which tier
applied to each decision. As built:

- Linux: default-deny at run time (`authorized_default`) is preventive for later arrivals;
  `usbcore.authorized_default=0` on the kernel command line is preventive from boot;
  blocking one device is reactive.
- Windows: Device Installation Restrictions are preventive only for devices never
  installed on the machine; disabling the device node, the backstop, is reactive.

### 4.2 Read-only

Read-only set after a volume has mounted does not remove write access the mount already
has. It is dependable only as a standing baseline from which approved devices are released
(`baseline_read_only`, off by default). On Windows the baseline is class-wide, so per-device
release is not available with the native mechanisms. When a policy decides read-only and
the mechanism is unavailable or fails, the device is left **usable and writable** with an
alert, unless `fail_closed` is set, in which case it is blocked.

### 4.3 The reactive window

Between a device's arrival and its block there is a window in which it is usable. It is
normally well under a second and is never zero. In that window the device is enumerated by
the kernel, may be bound to a driver, and can be mounted by the desktop. Revoking a device
that is already mounted makes it read-only, tries a clean eject and then blocks it, but a
device that was already given access can have copied data out.

### 4.4 Scope

By default only storage-like devices, and devices that mix an input interface with another
function, are in the enforcement scope. A new network adapter, a serial device or a
vendor-specific device with no input interface is **outside the scope**: it is recorded as
*not enforced*, which is not the same as blocked, and it is usable. Widen the scope
(`storage_and_unknown`, `all_except_protected`) to hold them.

## 5. What PortLock does not claim

### 5.1 Fingerprints identify; they do not authenticate

A fingerprint is a hash of the vendor and product ids, serial number, manufacturer and
product strings, `bcdDevice` and the interface list. The device supplies every one of them.
A device built to copy another's descriptors produces the same fingerprint, and a
fingerprint can be read from a device you have held. So:

- "Trusted" means "has the same descriptors as the one someone approved", not "is the same
  hardware".
- Many cheap sticks have no serial or a generic one. Their fingerprint has `low`
  confidence and is shared by every identical stick. PortLock refuses to trust them
  permanently: they get a one-time grant or a temporary grant of at most 24 hours, bound
  to the port.
- Clone detection catches only the case where the original is connected at the same time.
  A copy plugged in while the original is away is accepted as the original.
- The enrolment of an input device binds fingerprint **and** port. A copy on that port
  while the real keyboard is unplugged is protected as the real one.

Real device authentication needs hardware that can answer a cryptographic challenge, which
ordinary USB devices cannot.

### 5.2 Keyboards are allowed by default

With default settings a device that presents only as a keyboard or mouse (a rubber-ducky
style device, a modified cable) is **allowed and cannot be blocked**. PortLock records
it and raises a notice. Blocking such devices needs HID enforcement, which takes two
settings (`hid_enforcement` and `acknowledge_lockout_risk`) and `scope =
"all_except_protected"`, and can disable the only keyboard on the machine. Enrol your own
keyboard and mouse first. A device that adds an input interface to storage is a different
case and is denied (3.1).

### 5.3 What a scan proves

A scan walks a mounted volume read-only and reports on the files that volume showed at that
moment. A clean verdict means no heuristic matched, no hash was on a bad list and any
installed antivirus found nothing, within the scan's limits. It does **not** mean:

- the device is honest: a hostile device can serve different content after the scan;
- the device has no other functions: scans never see a keyboard or a network adapter;
- the files are safe: PortLock ships no malware signatures, and heuristics recognise shapes
  such as `autorun.inf`, root executables and double extensions, not intent;
- everything was looked at: a scan has file, byte and time limits and reports `incomplete`
  when they are reached; an incomplete or failed scan is never treated as clean;
- anything about devices that are not mounted, such as an MTP phone, which PortLock never
  mounts itself.

### 5.4 What a decision proves

A decision record says what PortLock decided and which enforcement call it made. A
successful call means the operating-system API reported success. It is not an independent
check that the device can no longer be used.

### 5.5 What the audit log proves

The audit log is hash-chained, and each record carries a forward-secure MAC. Verified with
`portlock audit verify`, it shows that the records in the database form an unbroken chain
ending at the head the service last wrote. With the initial key (`--offline --key-file`),
it also shows that each record's MAC is valid. It **does not** show:

- **That the log is complete.** Nothing is recorded while the service is not running, and
  a device that came and went before the service started is not seen. A record exists only
  for what the service observed.
- **That nothing was removed from the end.** Dropping the newest records leaves a valid
  prefix. The head file catches it only if the head file was not also rewritten. An
  administrator can rewrite both. Only copies kept off the machine (a syslog or file sink
  on a remote, append-only target, exported checkpoints) can show truncation. A `file`
  sink on the same disk gives no such protection.
- **That a MAC-less verification means anything against a determined attacker.** Without
  the initial key, verification checks the chain only; someone who can rewrite the whole
  database can rebuild a consistent chain. The command says "no MACs were checked".
- **That records after the key was compromised are genuine.** Someone who read the current
  key can forge later records.
- **That the initial key is safe.** Whoever holds it can forge the whole log.
- **That the actor was the person.** The `actor` is the account that authenticated. A
  stolen password or session token is that account.
- **That the timestamps are true.** They come from the local clock. PortLock evaluates
  expiries against the later of the clock and the newest audit timestamp, so winding the
  clock back does not revive an expired grant, and audits a rollback; it cannot know the
  real time.
- **That what a device reported about itself was true.** Device text is recorded after
  sanitising control characters and capping length, but the content is the device's claim.

The service verifies the tail of the log at start and the operator can verify on demand. A
failed verification marks the audit chain degraded and raises a critical alert until a
later verification succeeds.

## 6. Residual risks you accept by using it

- A hostile device exploits the host before PortLock reacts, or acts as a keyboard.
- An administrator or malware with administrator rights turns PortLock off.
- A stolen password or recovery code does what its owner could.
- The administrator's password is captured at the keyboard.
- The service is down, or the machine just restarted, and nothing is enforced.
- The Windows and Linux mechanisms do not behave as documented on your system: they have
  not been run against a real device, and the UNVERIFIED items in `enforcement/` are open.
- PortLock has had no external security audit.
