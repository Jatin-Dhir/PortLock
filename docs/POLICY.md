# PortLock — policy, grants and the decision

This is the reference for writing a policy, for what a grant does, and for how PortLock
combines safety, lockdown, scan results, policy and grants into one decision. It describes
`portlock.policy` and `portlock.auth.grants`. The design it implements is `DESIGN.md`,
sections 5, 7 and 8 as amended by section 14 (in particular 14.2, 14.8, 14.9 and 14.13).

Everything described here is pure logic. Whether a decision is actually *enforced* is a
separate matter (`ENFORCEMENT.md`).

## 1. The policy document

A policy is a JSON document. TOML is accepted when importing; PortLock always writes
JSON.

```json
{
  "version": 1,
  "name": "Office policy",
  "default": { "access": "pending", "scan": "on_mount", "alert": false },
  "rules": [
    {
      "id": "deny-input-with-other",
      "description": "The BadUSB and network-implant shape.",
      "enabled": true,
      "expires": null,
      "match": { "mixes_input_with_other": true },
      "action": { "access": "deny", "scan": "none", "alert": true }
    },
    {
      "id": "allow-team-sticks",
      "match": { "vendor_id": "0x1209", "product_id": ["0x0001", "0x0002"],
                 "confidence": "high" },
      "action": { "access": "allow", "scan": "required" }
    }
  ],
  "scan": { "on_detection": "deny", "on_incomplete": "read_only" }
}
```

| Key | Required | Meaning | If left out |
| --- | --- | --- | --- |
| `version` | yes | Document format. Only `1` is understood. | error |
| `name` | no | A label, at most 128 characters. | `""` |
| `default` | no | The action for a device no rule matches. | `{"access": "pending"}` |
| `rules` | no | Rules, evaluated in order. At most 2000. | none |
| `scan.on_detection` | no | What a scan detection does: `deny`, `read_only` or `alert` (section 6). | `deny` |
| `scan.on_incomplete` | no | What a `required` scan that did not finish, or failed, leaves the device with: `read_only` or `deny`. An alert is raised either way. | `read_only` |

Every value left out falls back to the restrictive choice. A key PortLock does not know
is an error, not something to ignore: a misspelt `"acces": "deny"` that is silently
dropped is a rule that does not do what its author thinks.

### Rules

| Key | Required | Meaning |
| --- | --- | --- |
| `id` | yes | 1 to 64 of `A-Z a-z 0-9 . _ -`, starting with a letter or digit. Unique in the policy; ids that differ only in case count as the same. |
| `description` | no | Free text, at most 512 characters, no control characters. |
| `enabled` | no | `false` skips the rule. Default `true`. |
| `expires` | no | `null`, or a UTC timestamp such as `"2026-06-01T12:00:00Z"`. From that instant on the rule is skipped. In TOML a date-time with an offset is accepted. |
| `match` | yes | Which devices the rule applies to. At least one criterion. |
| `action` | yes | What happens to them. |

**A rule with an empty `match` is rejected.** It would silently apply to every device,
and the policy `default` exists for exactly that.

### Actions

| Key | Values | Default |
| --- | --- | --- |
| `access` (required) | `allow`, `read_only`, `deny`, `pending` | |
| `scan` | `none`, `on_mount`, `required` (below) | `none` |
| `alert` | `true` raises an alert whenever this action applies | `false` |

`pending` means held until an administrator decides: blocked in enforce mode, recorded as
"would block" in monitor mode and in a watch-only process. It is the only outcome a grant
acts on (section 6).

What `scan` means:

- **`none`** — the device's volumes are not scanned. A scan an operator asks for anyway is
  a report and changes nothing.
- **`on_mount`** — once access is given, every mounted volume is scanned. A detection can
  take the access away (`scan.on_detection`). A scan that does not finish leaves the
  access as it was and raises an alert.
- **`required`** (`DESIGN.md` 14.9) — the device is admitted **read-only**, every volume
  is scanned, and the decided access is applied **only on a clean verdict**. A scan that
  does not finish, or fails, leaves the device read-only (or denied, if
  `scan.on_incomplete` is `deny`) and raises an alert. A detection is handled as for
  `on_mount`.

What a scan can and cannot tell you is in `SCANNING.md`: in short, it finds bad files on
an honest device; a hostile device can serve different content after the scan.

### Match criteria

Every criterion is optional. **All criteria that are present must match.** A criterion
that takes a list is an **any-of** list: it matches when **any one** of its values
matches, never "all of them". `"category": ["keyboard", "storage"]` matches a keyboard, a
flash drive, and a device that is both. A single value may be written wherever a list is
accepted. To require two things at once, use two criteria.

| Criterion | Takes | Matches when |
| --- | --- | --- |
| `vendor_id`, `product_id` | hex string, or a list of them | the device's id is one of them |
| `serial`, `manufacturer`, `product` | glob, or a list | the device's string matches one of them |
| `bus_path` | port pattern, or a list | the device is on, or behind, one of these ports |
| `fingerprint` | fingerprint value, or a list | the device's fingerprint is one of them (exact, no wildcards) |
| `category` | category, or a list | the device declares at least one of these functions |
| `interface_class` | number or hex string, or a list | at least one interface has one of these class codes |
| `confidence` | `high` or `low` | the fingerprint's confidence is exactly that |
| `composite` | `true` / `false` | the device does / does not declare more than one function |
| `storage_with_input` | `true` / `false` | the device does / does not pair storage with a keyboard, mouse or other HID interface |
| `mixes_input_with_other` | `true` / `false` | the device does / does not put an input interface beside **any** other function (storage, network, serial, imaging, vendor-specific, …); hubs do not count |
| `storage_like` | `true` / `false` | the device is / is not mass storage or an imaging device (a phone or camera in MTP or PTP mode) |
| `removable` | `true` / `false` | the device is / is not on an external port |
| `time` | a time window | the moment of evaluation is inside it |

Details that matter:

- **Vendor and product ids are hexadecimal strings**, with or without `0x`: `"0x0781"`,
  `"0781"` and `"781"` are all 0x0781, and `"1209"` is 0x1209. **A bare number is
  rejected**, with a message that says why: ids are written in hex everywhere else, so
  `8087` almost certainly means 0x8087, but as a number it is 0x1F97, and a rule written
  that way would silently never match. TOML's own hex literals (`0x8087`) arrive as plain
  numbers and are rejected for the same reason: quote them.
- **Interface classes** take a number or a hex string (`8` or `"0x08"`), up to two hex
  digits.
- **Categories** are `storage`, `keyboard`, `mouse`, `hid`, `hub`, `network`, `serial`,
  `audio_video`, `imaging`, `printer`, `smart_card`, `wireless`, `vendor`, `other`. A
  device has one category per function it declares; `category: "keyboard"` matches a
  flash drive that also presents a keyboard.
- **`mixes_input_with_other` is the wider shape check.** `storage_with_input` catches a
  drive that types; `mixes_input_with_other` also catches a keyboard that is a network
  adapter or a serial port. A keyboard with a built-in hub is input only and does not
  match.
- **A missing string never matches.** `serial: "*"` matches every device that reports a
  serial and no device that does not. Absence is not a wildcard. A string made of nothing
  but control characters and blanks counts as missing.
- **Unknown is neither true nor false.** If the platform does not say whether a device is
  removable, neither `removable: true` nor `removable: false` matches it.
- **`interface_class`** looks at the interfaces; for a device that reports none, the
  device class stands in.
- **Fingerprints** are `plk1:` followed by 32 base32 characters. They are compared
  exactly, in either letter case.
- A boolean criterion set to `false` is a criterion. `composite: false` matches every
  single-function device, which is most of them; that is allowed because it is explicit.

### Globs

`serial`, `manufacturer` and `product` are globs with the semantics of Python's
`fnmatch`:

| Pattern | Matches |
| --- | --- |
| `*` | any run of characters, including none |
| `?` | exactly one character |
| `[abc]`, `[a-f]` | one of the listed characters |
| `[!abc]` | one character that is not listed |

The whole string has to match: `Flash` does not match `Example Flash 16GB`, `*Flash*`
does. There is no escape character; write `[*]` for a literal asterisk and `[?]` for a
literal question mark. An unclosed `[` is an ordinary character.

Matching is case-insensitive and is done on **normalized** text. Both the pattern and the
device's string are folded to Unicode compatibility form (NFKC), stripped of control and
invisible format characters, have runs of whitespace collapsed to one space, are trimmed,
and are case-folded. A device cannot dodge `Evil Corp` by reporting `EVIL  CORP`, by
slipping in a zero-width space or a right-to-left override, or by using full-width
letters.

Device strings reach the engine already sanitized (`DESIGN.md` 14.7): every control or
format character has been replaced with U+FFFD. Whether the original was invisible or a
word break can no longer be told, so a string is matched in both readings, with the
replacement removed and with it as a space, and a pattern that matches either matches the
device. That gives a device nothing it lacked: it could always have reported the plain
string.

Matching does not use the host's file-name rules, so `/` and `\` are different characters
on every platform.

### Bus paths

A `bus_path` pattern names a **port** and matches a device **on that port or anywhere
behind it** (through hubs). It is compared **segment by segment**: segments are separated
by `.` in Linux paths (`1-2.3`) and by `#` in Windows location paths
(`PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(2)`).

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `1-2` | `1-2`, `1-2.4`, `1-2.4.1` | `1-21`, `1-20.3`, `1-3` |
| `1-2.*` | `1-2.3`, `1-2.3.1` | `1-2` itself |
| `1-*` | every port of bus 1, and what is behind them | `2-1` |
| `1-2*` | `1-2`, `1-20`, `1-21.4` (the wildcard is inside the first segment) | `1-3` |

Each segment is a glob as above, and a wildcard never crosses a separator. A pattern may
not start or end with a separator or contain two in a row.

### Time windows

```json
"time": { "days": ["mon", "tue", "wed", "thu", "fri"],
          "start": "09:00", "end": "17:00", "utc_offset_minutes": 60 }
```

| Key | Meaning | If left out |
| --- | --- | --- |
| `days` | the days on which the window **opens**: `mon` … `sun` | every day |
| `start`, `end` | local time of day, `HH:MM`; `start` is inside the window, `end` is not. Given together or not at all. | the whole day |
| `utc_offset_minutes` | local time minus UTC, from -720 to 840 | `0` (UTC) |

- If `end` is not later than `start`, the window runs past midnight, and the part after
  midnight belongs to the day on which the window opened: `days: ["fri"]`, `22:00` to
  `06:00` is Friday night until Saturday 06:00.
- Equal `start` and `end` mean 24 hours from `start`.
- A window that is open all day, every day, always matches and is rejected.
- The offset is fixed. **A window does not follow daylight-saving time**: PortLock takes
  no dependencies and the standard library has no time-zone database on Windows. Adjust
  the offset when the clocks change, or define the window in UTC.

A rule with a window does not match outside it; later rules, or the default, decide then.
The window is evaluated against the service's clock, and a decision that depends on a
window is re-evaluated when the window next opens or closes (section 3).

## 2. Validation and limits

`parse_policy` checks the whole document and reports **every** problem it finds, each
with the location of the offending value:

```
rules[2].match.vendor_id[1]: expected a string of up to 4 hexadecimal digits such as "0x0781", got 'wxyz'
rules[3].match.vendor_id: vendor and product ids must be hexadecimal strings, not bare numbers: the number 8087 is not the id 0x8087, so a rule written that way would silently never match; write it as "0x8087"
rules[2].action.access: required (allow, read_only, deny, pending)
rules[5].id: duplicate rule id 'BLOCK' (already used by rules[1]); ids differing only in case count as the same
```

`PolicyError.problems` holds the list. A policy with any problem is not loaded at all.

A policy document is untrusted input, so the work it can cause is bounded:

| Limit | Value |
| --- | --- |
| Rules per policy | 2000 (more are refused without being looked at) |
| Values in one list-valued criterion | 64 |
| Pattern length, before and after normalization | 128 characters |
| Wildcards (`*`, `?`, `[`) in one pattern | 16 |
| Rule id / policy name / description | 64 / 128 / 512 characters |
| Policy file size | 8 MiB |
| Problems listed in one error | 100 (the rest are counted) |
| Device string length used for matching | 126 characters (the device model's cap); 1024 inside the engine |

A USB string descriptor holds at most 126 characters, and `UsbDevice` cuts every device
string to that. The engine cuts again at 1024, which only a faulty backend could reach.

### Files

- `load_policy_file(path)` reads `.json` or `.toml`, UTF-8, with or without a byte-order
  mark. In JSON, a key given twice in the same object is an error (parsers disagree on
  which one wins), and so are `NaN` and `Infinity`.
- `save_policy(path, policy)` writes `.json` only, atomically: a reader sees the old file
  or the new one, and a crash midway leaves the old one. On POSIX the file is mode 0600.
- `dump_policy_json(policy)` gives stable text: the same policy always produces the same
  characters. Every optional key is written out, keys are in a fixed order, list-valued
  criteria are always lists, ids are `0x`-prefixed lowercase hex, timestamps are UTC.
- `policy_hash(policy)` is the hex SHA-256 of the policy's canonical JSON
  (`core/canonical.py`). It depends on the policy's content and not on how the file was
  laid out, so a JSON file and a TOML file that describe the same policy have the same
  hash. Audit records carry it. (Adding `scan.on_incomplete` to the written form changed
  the hash of every policy once, with no change of meaning.)

## 3. Evaluation

`PolicyEngine(policy).evaluate(device, fingerprint, now=...)` walks the rules in order.

1. A disabled rule is skipped.
2. A rule whose `expires` has been reached is skipped.
3. **The first remaining rule whose every criterion matches wins.**
4. If none does, the policy `default` applies.

Order therefore matters: put deny rules first and specific rules above general ones.

The result says which rule won (or that the default applied), lists the disabled and
expired rules that were passed over on the way, explains each criterion of the winning
rule, and carries `valid_until`: the earliest moment at which the same device could get a
different result through the passage of time alone, because the winning rule expires, its
time window closes, or the window of an earlier rule that otherwise matches opens. The
service re-evaluates then.

Evaluation is pure: no clock, no file, no device access. The time is passed in.

`PolicyEngine.explain(...)` is the diagnostic behind `portlock policy test`. It tests
every rule and every criterion and reports, per rule, `matched`, `shadowed` (matches, but
an earlier rule won), `no_match`, `disabled` or `expired`, with the reason.

## 4. The policies PortLock ships with

**The default policy** is what a fresh install runs:

- the default action is `pending` (with `scan: on_mount`, so a device that is later
  granted access is scanned when it mounts);
- exactly one rule, `deny-input-with-other`: a device that puts an input interface beside
  any other function is denied and raises an alert. That is the shape of a "BadUSB"
  stick or a network-tap implant, and such a device is not covered by the protection
  that keeps the operator's own keyboard working (`DESIGN.md` 2 and 14.2);
- scan detections deny; a required scan that does not finish leaves the device
  read-only.

Nothing is allowed automatically. A device gets access only when an administrator grants
it, and the deny rule cannot be overridden by a grant.

**The example policy** is what `portlock policy init` writes. It contains the same deny
rule and four sample rules: deny a product, allow a product during working hours, let a
vendor's storage in read-only, and require a scan before a grant takes full effect. The
sample rules are **disabled**, and their vendor and product ids are placeholders.
Installed unedited, the example policy behaves exactly like the default policy.

## 5. Grants

A grant is an administrator's decision to let one device in. It is attached to the
device's fingerprint.

| Kind | Lasts | `expires_at` |
| --- | --- | --- |
| `trust` | until revoked | must not be given |
| `temporary` | until `expires_at` | required, in the future, no further away than the caller's ceiling |
| `once` | for one connection | optional; if given, it also ends the grant while it waits or while the device is connected |

Each kind is full access or `read_only`.

**Ceilings** (`DESIGN.md` 14.13). `GrantStore.create` takes `max_duration`, the longest a
temporary grant may run, from the caller, because the caller knows the role of whoever is
granting: `OPERATOR_MAX_DURATION` (24 h) for operators, `ADMIN_MAX_DURATION` (30 days by
default; configuration may lower it) for administrators. A temporary grant without a
ceiling is refused rather than made unlimited. When a ceiling is given for a one-time
grant with an expiry, it applies too.

**Low-confidence fingerprints.** A device with no serial number, or a generic one, has a
`low`-confidence fingerprint that is shared by *every unit of that model*. Granting it
grants them all. Such a fingerprint:

- never gets a `trust` grant;
- may get a `once` grant, or a `temporary` grant of at most `LOW_CONFIDENCE_MAX_DURATION`
  (24 h), whatever the role;
- and every grant for it must be **bound to a port**: `create(..., port=bus_path)`. The
  grant then applies only to a device reported on exactly that `bus_path` (not to one
  behind a hub on it). Any grant may be bound to a port; for low confidence it is
  required.

The refusals have the code `grant_low_confidence`. A decision that honours a
low-confidence grant says so in its reasons.

**Connections.** A one-time grant binds to the connection that first uses it:
`bind(grant_id, device)` records `connection_key(device)`, which is the backend's
`UsbDevice.connection_id`, different for every physical connection. Only when a backend
supplies no connection id is the OS instance id used, and that is weaker: the instance id
survives a re-plug, so a stick unplugged and plugged back into the same port before its
removal was processed is still the bound connection. `release(device)` spends the grant
when the device is removed; at start-up `release_absent(present_devices)` spends the ones
whose device went away while the service was not running.

**When several grants apply**, `GrantStore.active_for(fingerprint, now=..., device=...)`
chooses one, always the same way:

1. read-only before full: a second, broader grant must not quietly lift a restriction;
2. `trust` and `temporary` before `once`: a one-time grant lasts for this connection at
   most, and choosing it would spend it when a longer grant already covers the device;
3. a one-time grant already bound to this connection before an unused one;
4. the longest remaining: no expiry first, then the latest expiry;
5. the oldest, then by id.

A grant bound to another connection, or to another port, never applies. Without a
`device`, only grants bound to neither apply.

**Expiry.** A grant stops applying at the instant of its expiry. `expire_due(now)` marks
the grants that have run out and returns each exactly once, so the service can audit the
expiry and re-evaluate the device.

**Revocation.** `revoke(grant_id, by)` ends a grant immediately and records who did it.

## 6. The decision

`decide(...)` weighs everything. Precedence, highest first (`DESIGN.md` 5 and 14.8):

**safety > lockdown > scan detection > first matching policy rule > grant > policy default**

1. **Safety.** A protected device (an enrolled input device on its enrolled port, an
   input-only device or hub, a built-in device, anything backing the system volume) is
   `allow`, source `safety`, whatever else is true. It is never scanned.
2. **Lockdown.** While lockdown is active, every other device is `deny`, source
   `lockdown`, unless the lockdown manager exempts it. An exempt device is decided by the
   steps below as if there were no lockdown.
3. **Scan detection.** A detection on this connection is a **ceiling** over steps 4 to 6:
   the result is whichever of the ceiling and their outcome lets less through, in the
   order deny, pending, read_only, allow. When the ceiling decides, the source is `scan`.
   Every detection raises an alert.
4. **First matching policy rule.** Its `allow`, `read_only` or `deny` is **final**,
   source `policy`. No grant changes it, in either direction: a read-only grant does not
   narrow an `allow` rule and a full grant does not widen a `read_only` rule. To change
   what a rule decides, change the policy. A rule that says `pending` falls through.
5. **Grant.** A grant acts **only on a `pending` outcome**, from a rule or from the
   default. It gives `allow`, or `read_only` for a read-only grant, source `grant`.
6. **Policy default.** Otherwise the default stands, source `default`.

### Truth table

For a device that is **not protected**, **not locked down** (lockdown inactive, or active
with the device exempt) and has **no scan detection**:

| Policy says | Came from | No grant | Full grant | Read-only grant |
| --- | --- | --- | --- | --- |
| `deny` | a rule | `deny` · policy | `deny` · policy | `deny` · policy |
| `read_only` | a rule | `read_only` · policy | `read_only` · policy | `read_only` · policy |
| `allow` | a rule | `allow` · policy | `allow` · policy | `allow` · policy |
| `pending` | a rule | `pending` · policy | `allow` · grant | `read_only` · grant |
| `deny` | the default | `deny` · default | `deny` · default | `deny` · default |
| `read_only` | the default | `read_only` · default | `read_only` · default | `read_only` · default |
| `allow` | the default | `allow` · default | `allow` · default | `allow` · default |
| `pending` | the default | `pending` · default | `allow` · grant | `read_only` · grant |

Each cell is *access · source*. A scan detection then applies its ceiling to that cell:

| Cell's access | No detection | Alert only | Ceiling `read_only` | Ceiling `deny` |
| --- | --- | --- | --- | --- |
| `allow` | unchanged | unchanged, alert | `read_only` · scan | `deny` · scan |
| `read_only` | unchanged | unchanged, alert | unchanged, alert | `deny` · scan |
| `pending` | unchanged | unchanged, alert | unchanged, alert | `deny` · scan |
| `deny` | unchanged | unchanged, alert | unchanged, alert | unchanged, alert |

And above all of it sit two rows that override everything:

| Condition | Result |
| --- | --- |
| the device is protected | `allow` · safety, in every case, with or without lockdown or a detection |
| lockdown is active, the device is neither protected nor exempt | `deny` · lockdown, in every case |

`tests/unit/test_policy_decide.py` checks every one of the 768 combinations of these
tables (protected or not × four lockdown states × four detections × 24 policy and grant
cells).

Points worth reading twice:

- **A default of `deny` is not lifted by a grant.** A grant acts only on `pending`. A
  policy meant to let in exactly the devices an administrator approves therefore uses a
  default of `pending`, which is what the shipped policies do. An approved device is the
  one with a grant; every other device stays blocked as `pending`.
- **A rule is final.** An `allow` or `read_only` rule decides whatever grants exist; a
  `deny` rule cannot be lifted by a grant. A grant matters only where policy said "ask an
  administrator".
- **A grant never removes a scan requirement.** The decision's `scan` is always the
  applying policy action's, also when a grant decides the access.
- **A detection never widens.** A `read_only` ceiling on a `pending` device leaves it
  `pending`; if a grant later acts on it, the result is held to `read_only`.

### Scan detections from scan results

`scan_detection_for(verdict, requirement=..., scan_policy=policy.scan)` turns the worst
scan verdict of a connection into the detection `decide` takes:

| Verdict | Requirement | Detection |
| --- | --- | --- |
| none yet, or `clean` | any | none |
| any | `none` | none: such a scan is only a report |
| `malicious` | `on_mount`, `required` | `on_detection`: ceiling `deny`, ceiling `read_only`, or alert only |
| `suspicious` | `on_mount`, `required` | ceiling `read_only`; alert only when `on_detection` is `alert`. A suspicious finding never denies on its own: heuristics recognise a shape, not malice. |
| `incomplete`, `error` | `required` | `on_incomplete`: ceiling `read_only` or ceiling `deny` |
| `incomplete`, `error` | `on_mount` | alert only |

The verdict words are those of `portlock.scan.report.Verdict` (`ScanVerdict` in
`portlock.policy.decide` has the same values, so the policy package does not import the
scanner).

The read-only hold *while* a required scan runs is not a detection: the decision says
`scan: required` and the service keeps an `allow` at read-only until the connection's
scans are clean.

### The rest of the decision

- **`alert`** is the applying policy action's, or true when there is a scan detection.
  A protected device's `scan` is always `none` while its `alert` is kept, so an operator
  learns that policy objected to a device that safety let through.
- **`rule_id`** names the matching rule, if any, also when the source is `grant` or
  `scan`. **`grant_id`** names the grant that acted, which is only ever on a `pending`
  outcome. Neither is set on a `safety` or `lockdown` decision.
- **`expires_at`** is the earliest of the acting grant's expiry and the moment the policy
  result stops being valid (the rule's expiry, or an earlier change of a time window). The
  service re-evaluates the device then. It is not set on `safety` and `lockdown`
  decisions.
- **`reasons`** say, in order, what decided and why, including what was overridden.
- **A grant that must not be honoured is ignored**, and the reasons say so: one for a
  different fingerprint, one that has ended or reached its expiry, a one-time grant bound
  to a different connection, and a grant limited to another port. A usable grant that a
  rule or a non-pending default leaves nothing to do is named as not used.

## 7. What policy cannot do

- **A fingerprint identifies; it does not authenticate.** Every field a rule can match,
  the serial and the fingerprint included, is reported by the device and can be copied by
  a device built to copy it. An `allow` rule on a vendor id, a product string or a
  fingerprint admits anything that claims to be that. Prefer `read_only`, require `high`
  confidence, and keep `allow` for devices you would hand a key to.
- **`mixes_input_with_other` catches a shape, not an intent.** A malicious device that
  presents itself only as a keyboard has no other function and does not match it. See
  `DESIGN.md`, section 2, for what PortLock does and does not do about input devices.
- **A scan is a point in time.** It finds bad files on an honest device. A hostile device
  can serve different content after it has been scanned (`SCANNING.md`).
- **Policy decides; it does not enforce.** A `deny` is only as good as the enforcement
  mechanism available on the machine. In `monitor` mode no policy decision is enforced
  (only an engaged lockdown blocks, in a system-wide service), and a watch-only process
  (`OPERATIONS.md` section 0) enforces nothing at all.
- **Time windows use the service's clock** and a fixed UTC offset. Expiries are checked
  against the later of the clock and the newest audit record (`DESIGN.md` 14.12), but
  someone who can set the system clock forward can still open a window early.
