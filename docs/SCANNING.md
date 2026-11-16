# PortLock — scanning

This is the reference for `portlock.scan`: what a scan looks at, what it reports, what
each heuristic means and why it has the severity it has, how the antivirus adapters are
run, and what has and has not been checked against the real tools. The design it
implements is `DESIGN.md`, sections 9 and 14.9. How a scan result changes a device's
access is `POLICY.md`, section 6.

## 1. What scanning does and does not defend against

**Scanning defends against bad files on an honest device. A hostile device can serve
different content after the scan.**

A USB device is a computer of its own. A flash drive built to deceive can answer the
reads of a scan with harmless data and answer later reads, by the user or by Windows, with
something else; it can also present a keyboard, a network adapter or a second disk that no
file scan ever sees. Scanning therefore says something about the files a device showed
PortLock at one moment. It says nothing about what the device is, and it is no substitute
for the shape checks in policy (`mixes_input_with_other`), for read-only access, or for
not plugging in a device nobody vouches for.

Within that limit, scanning catches what most removable-media infections actually are:
an ordinary stick carrying a worm's payload, a disguised program, an `autorun.inf`, or a
shortcut that launches a command interpreter.

Further limits, stated plainly:

- **Heuristics recognise shapes, not malice.** A `suspicious` finding means a person
  should look. On its own it never denies a device (`POLICY.md`, section 6).
- **PortLock ships no signatures.** Detection of known malware by name comes only from an
  antivirus product already installed on the machine (ClamAV or Microsoft Defender).
  Without one, a known-bad file is caught only if its digest is on a configured hash
  list.
- **A scan is bounded.** It stops at its file, directory, byte and time limits. A scan cut
  short is `incomplete`, never `clean`.
- **A read the device never answers cannot be interrupted.** The walk checks its time
  budget between reads; a device that stalls a single read holds that read until the
  operating system gives up. The service's watchdog abandons such a scan.

## 2. What a scan is

A scan is a bounded, **read-only** walk of a mounted volume (`portlock.scan.inspector`):

- every open is read-only and binary; nothing in the package, and none of the tools it
  runs, writes, renames, moves, quarantines or deletes anything on the volume;
- symbolic links, junctions and other reparse points are not followed unless
  `follow_symlinks` is set, and then only to targets inside the scan root on the same
  filesystem; a directory already visited or on another filesystem is not entered;
- only regular files are opened, and the open cannot block on a FIFO;
- the walk is breadth-first and lazy, so the shallow levels come first and a huge
  directory is never held in memory;
- permission errors and files that vanish mid-walk are recorded as `unread` and the walk
  carries on.

| Limit (`ScanLimits`) | Default | Effect when reached |
| --- | --- | --- |
| `max_files` | 100 000 | walk stops; `truncated_reason` names it |
| `max_dirs` | 20 000 | walk stops |
| `max_bytes` | 4 GiB read in total | no more reading |
| `max_seconds` | 300 s, on the injected clock | walk stops; each engine gets the same allowance as its timeout |
| `max_depth` | 32 levels | deeper directories are met but not entered |
| `max_file_bytes` | none | a larger file is not hashed and is listed as unread |
| `max_findings` | 5 000 per kind, plus 5 000 malicious | further findings are counted (`max_findings`) |
| `max_errors` | 1 000 | further unread entries are counted |

Every file met is hashed (SHA-256), looked up in the hash lists, and shown to the
heuristics. The antivirus engines that are available scan the same root at the same
time, each on its own thread, so their slow work overlaps the walk. One engine that fails,
times out or misbehaves is recorded and cannot affect the others or the walk; one that
ignores its own timeout is abandoned after `max_seconds` plus a grace period.

`Scanner.scan_bytes(name, data)` judges content held in memory as if it were a file of
that name, with the heuristics and the hash lists. Nothing is written to disk, which is
how detection can be exercised without tripping the machine's own antivirus.

## 3. The report and the verdict

A `ScanReport` records what was looked at, what was found (`findings`), what could not be
looked at (`errors`, each `unread` or `failed`), whether a limit or a cancellation cut it
short (`truncated`, `truncated_reason`), and which engines took part, with versions.

The verdict is derived from that content, never stored on its own, so a report cannot
claim `clean` while listing a detection. The first rule that applies wins:

1. `malicious` if any finding is malicious;
2. `suspicious` if any finding is suspicious;
3. `error` if an engine failed or the scan could not run (an issue of kind `failed`);
4. `incomplete` if a limit, a cancellation or an unreadable file left part of the volume
   unexamined;
5. `clean` otherwise.

`info` findings are observations and do not change the verdict. A scan in which no engine
took part (everything switched off) is `error`. `complete` says separately whether
anything was skipped. A stored report whose verdict does not match its content is
rejected when read back.

### Text from the device

Everything on the volume was chosen by whoever wrote it: file names, the launch targets
and `label=` of an `autorun.inf`, shortcut targets and arguments, folder settings, and the
antivirus output that quotes them. It is as untrusted as a device's descriptor strings
(`DESIGN.md` 14.7) and is made safe in **one place**: `portlock.scan.report.safe_text`,
applied by the constructors of `Finding`, `ScanIssue`, `EngineStatus`, `ScanReport` and
`ScanProgress`. No engine can put a raw string into a report by forgetting to escape it.

`safe_text` does for display what `portlock.core.models.sanitize_device_text` does for
descriptor strings, but shows each unsafe character as a visible escape instead of
replacing it, because the operator may need to see how a name was disguised: a file named
`photo<U+202E>gpj.exe` (which Explorer shows as `photoexe.jpg`) appears in a report as
`photo‮gpj.exe`. Control and format characters, line separators, non-standard
spaces, private-use and unassigned code points, lone surrogates and undecodable bytes are
all escaped. Text is also cut to a fixed length (2048 characters for paths, 1024 for
details).

## 4. Heuristics

Each heuristic recognises a file shape that removable-media malware keeps reusing. A rule
reports `suspicious` ("a person should look") unless the evidence is strong enough that
no ordinary volume would show it; the two cases that report `malicious` say why. A file
whose digest is on a known-good list has its heuristic findings suppressed, which is the
intended way to silence a false positive. The rule set has a version (`RULESET_VERSION`),
reported as the heuristics engine's version.

| Rule id | What it matches | Severity | Why that severity |
| --- | --- | --- | --- |
| `autorun.present` | `autorun.inf` at the volume root with no launch entries, or not read | info | A label and an icon are harmless. |
| `autorun.launch` | each `open=`, `shellexecute=` or `shell\verb\command=` entry of a root `autorun.inf`, with its target | suspicious | Conficker and most earlier USB worms spread this way (ATT&CK T1091), but since Windows 7 these entries are ignored for USB storage, and old installers still carry them. |
| `root.executable` | an executable or script at the volume root, by extension or by PE, ELF or Mach-O content | suspicious | The root is where lures and worms put their payload (T1204.002), and also where installers and portable tools legitimately live. |
| `name.bidi_override` | a right-to-left override or other bidirectional control in the name of an executable | **malicious** | It makes `photo<RLO>gpj.exe` display as `photoexe.jpg` (T1036.002). No legitimate program is named that way. On a file that is not executable it is `info`. |
| `name.double_extension` | a decoy document or media extension before the real one, `invoice.pdf.exe` | suspicious | Windows hides known extensions by default (T1036.007), but some software names its files carelessly. |
| `name.padded_extension` | a run of five or more blanks pushing the real extension out of view | suspicious | The same deception by other means. |
| `type.mismatch` | executable content under an extension that is never executable (`.jpg`, `.pdf`, `.zip`, …) | suspicious | A payload parked for a loader (T1036.008); it does not run on a double-click by itself. |
| `hidden.executable` | an executable with the hidden or system attribute | suspicious | Worms hide their copy (T1564.001); software on removable media has no reason to. |
| `shortcut.interpreter` | a `.lnk` whose target or arguments start `cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32` or `regsvr32` | suspicious | The folder-replacement trick of USB worms (T1204.002, T1059, T1218); administrators also make such shortcuts. A `.lnk` that cannot be parsed is `info`. |
| `desktopini.clsid` | a `desktop.ini` that turns its folder into a shell object through a CLSID | suspicious | Hides what is really inside (T1564). The Recycle Bin's own CLSID inside a recycle-bin folder is not reported. |
| `folder.masquerade` | a `.lnk` or program with the same name as a folder beside it | suspicious; **malicious** when the folder is hidden or system | A program beside its own data folder looks the same; a hidden folder with a same-named launcher beside it is the worm's signature, which an ordinary volume does not show. |

Rules read at most the leading bytes they need (64 KiB of `autorun.inf` and
`desktop.ini`, 256 KiB of a shortcut, the first 512 bytes of every file for magic
numbers). A rule that raises is recorded as a `failed` issue for that file; the other
rules and the rest of the scan go on.

## 5. Hash lists

A hash list (`portlock.scan.hashdb.HashSet`) is a named list of SHA-256 digests, each
`known_bad` or `known_good`, optionally labelled, kept in the PortLock database or in
memory. Lists are exchanged as text files: one digest per line, an optional label after
it, `#` comments; `sha256sum` output is accepted as it is.

- **known bad** gives a `malicious` finding with the entry's label;
- **known good** suppresses the heuristic findings for that exact file. It does not
  overrule an antivirus detection;
- when lists disagree, **bad wins** everywhere;
- the EICAR test file is recognised by its published digest, built in. Only the digest is
  stored, never the file, so the pipeline can be demonstrated without a detectable byte
  ever being written to disk;
- a list that cannot be read is a `failed` issue, never "no match".

## 6. Antivirus adapters

PortLock asks an installed product to scan the mounted volume and translates what it
prints into findings (`portlock.scan.av`). Rules every adapter follows:

- **Read-only.** ClamAV is run as `clamdscan` or `clamscan` with `--no-summary
  --infected -r <root>`, never with `--remove` or `--move`. Microsoft Defender is run as
  `MpCmdRun.exe -Scan -ScanType 3 -File <root> -DisableRemediation`. The adapter **always**
  passes `-DisableRemediation`, which stops Defender from quarantining or removing what it
  detects; there is no code path that builds the command without it.
- **No trust in `PATH`.** A tool is looked up by absolute path in the directories its
  installer uses. On POSIX it must be owned by root and not writable by anyone else, and
  so must its directory. On Windows the standard program directories are writable only by
  administrators under the default permissions; PortLock does not inspect ACLs.
- **No shell.** Commands are argument lists with a timeout, bounded output capture and a
  kill on cancel. Only the process PortLock started is ever killed.
- **Failure is never clean.** A tool that is missing is listed as unavailable. One that
  runs and fails (service stopped, disabled by policy, database missing, output that
  cannot be understood, timeout) is a `failed` issue, and detections read before the
  failure are kept. Defender's result is `clean` only on exit code 0 **and** the words
  "found no threats"; ClamAV's only on exit code 0 with no error line.

ClamAV is asked through its daemon (`clamdscan`) when the daemon answers, because the
signature database is already in memory; otherwise, or when the daemon cannot read a
freshly mounted volume, `clamscan` runs with the time that is left.

Detection names beginning `PUA.` and `Heuristics.` (ClamAV) or `PUA:` (Defender) are
reported as `suspicious`; every other detection is `malicious`.

## 7. What has and has not been verified

- The adapters are tested against a fake command runner and recorded tool output written
  by hand in each tool's format, with made-up paths and detection names
  (`tests/fixtures/av`). ClamAV has not been run by the test suite.
- One opt-in test (`hardware`, Windows only) runs the installed `MpCmdRun.exe`, read-only,
  on a directory of three harmless text files and expects `clean`. It is skipped unless
  `--run-hardware` is given.
- The walk, the hashing, the heuristics and the scanner are tested on synthetic volumes
  under a temporary directory, on Windows and on Linux. Known-bad content in those tests
  is ordinary bytes whose digest a test puts on a list; the EICAR string is never written,
  not even in test source.
- Nothing here has been run against a hostile device. The limits in section 1 are
  statements of design, not results of testing one.
