# PortLock security event format — version 1

This is the wire format for security events that leave a PortLock machine: the envelope,
how it is signed, how a receiver verifies it, and how it ties back to the audit log. It is
the contract between PortLock (Python, `portlock/audit/events.py` and
`portlock/audit/signing.py`) and ClawNet (JavaScript), which verifies these events.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

The executable form of this document is `tests/fixtures/security-event-vectors.json`.
Where the two disagree, that is a bug in one of them.

## 1. The envelope

An event is one JSON object with exactly these members:

```json
{
  "v": 1,
  "id": "00000000000000000000000000000001",
  "ts": 0,
  "source": { "product": "portlock", "version": "0.2.0", "host": "lab-1" },
  "type": "service.started",
  "severity": "info",
  "subject": {},
  "data": {},
  "chain": null,
  "sig": {
    "alg": "ed25519",
    "key": "sFuVtWIQ5xsG8hQARRJgq0GSoxpAYEAg14s4mEz8JYQ=",
    "value": "myFP4TgeeFEJmOvZfeGL1Y6+jaaFvd0DwWKuD/momwzhH0Q9FgEQ2WUrYxtSOUnPN1UTHB2jTOWf11pOQ3ziAA=="
  }
}
```

(This is the `minimal` test vector; its key is a published test key.)

| Member | Type | Rules |
| --- | --- | --- |
| `v` | integer | The envelope version. MUST be `1`. |
| `id` | string | Exactly 32 lowercase hexadecimal characters (128 bits). Unique per event; receivers MAY use it to discard duplicates. Opaque: see section 6 for how PortLock derives it. |
| `ts` | integer | When the event happened: **milliseconds** since 1970-01-01T00:00:00Z, `0` to `9007199254740991`. An integer, never a string or a fraction. |
| `source.product` | string | MUST be `"portlock"`. |
| `source.version` | string | The emitting PortLock version. 1 to 64 characters, no control characters. |
| `source.host` | string | The label the operator chose for the machine. 1 to 255 characters, no control characters. It is configuration, not the operating system's host name, and it is a claim: only the signing key authenticates the sender. |
| `type` | string | The event type: lowercase dotted words, e.g. `device.connected`. At most 64 characters, matching `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`. Section 7 lists the types PortLock emits. |
| `severity` | string | One of `debug`, `info`, `notice`, `warning`, `error`, `critical`. |
| `subject` | object | Who or what the event is about. PortLock uses `actor` (a user name or `system`) and `device_fp` (a device fingerprint, `plk1:` plus 32 base32 characters), each present only when known. MAY be empty. |
| `data` | object | Event details; the shape depends on `type`. MAY be empty. |
| `chain` | object or `null` | The position in the sender's audit log that this event commits to: `{"seq": integer >= 0, "hash": 64 lowercase hex characters}`. `null` if the event is not tied to the log. See section 6. |
| `sig.alg` | string | MUST be `"ed25519"`. |
| `sig.key` | string | The signer's 32-byte Ed25519 public key in base64: a canonically encoded point that is not of small order (section 4, step 4). |
| `sig.value` | string | The 64-byte Ed25519 signature in base64. |

Rules that apply to the whole object:

- There are no other members at the top level, in `source`, in `chain` or in `sig`. A
  version-1 verifier MUST reject an event that has any. Anything event-specific goes in
  `subject` or `data`, which are free-form.
- All numbers anywhere in the event are integers in the range `-(2^53 - 1)` to
  `2^53 - 1`. There are no fractions and no exponents. This is why `ts` is in
  milliseconds: number formatting is where canonical JSON implementations diverge, so the
  format has no numbers that need formatting.
- All object keys, at any depth, are printable ASCII (U+0020 to U+007E).
- All strings are well-formed Unicode (no lone surrogates). They are **not** normalised:
  `e` followed by U+0301 and the single character U+00E9 are different strings and give
  different signatures.
- Objects and arrays nest at most 32 deep.
- The canonical encoding of the whole event is at most 262144 bytes (256 KiB).
- base64 is RFC 4648 section 4: the standard alphabet (`+` and `/`), with `=` padding, no
  whitespace or line breaks.

An unsigned event (what exists before signing) is the same object without `sig`.

## 2. Canonical JSON

Signatures are computed over bytes, so every implementation must turn the same event into
the same bytes. PortLock uses RFC 8785 (JSON Canonicalization Scheme) restricted to a
subset in which there is nothing left to disagree about:

1. Object members are written in ascending order of their keys, compared by code unit.
   Keys are ASCII, so this is plain byte order: `"1" < "B" < "_" < "a" < "aa" < "b"`.
2. No whitespace anywhere outside strings.
3. `null`, `true` and `false` are written as those literals.
4. Integers are written in plain decimal, with a leading `-` if negative and no leading
   zeros. `-0` is written `0`.
5. Strings are written in double quotes as UTF-8, escaping only what must be escaped:
   `\"`, `\\`, the short forms `\b` `\t` `\n` `\f` `\r`, and `\u00xx` (lowercase hex) for
   the other characters below U+0020. Everything else, including U+007F, U+2028, U+2029
   and all non-ASCII characters, is written as itself. `/` is not escaped.
6. A value outside the subset (a fraction, an integer out of range, a non-ASCII key, a
   lone surrogate, nesting deeper than 32) is an error, never silently adjusted.

In JavaScript, `JSON.stringify(string)` produces exactly the string encoding of rule 5 for
a well-formed string, and `Number.isSafeInteger` is exactly the integer range.

The canonicaliser has its own vector file, `tests/fixtures/canonical-json.json`, which both
projects run.

## 3. Signing

```
signed_bytes = UTF8("portlock/1/security-event") || 0x00 || canonical(event without "sig")
signature    = Ed25519_sign(private_key, signed_bytes)
```

- `UTF8("portlock/1/security-event") || 0x00` is 26 bytes:
  `706f72746c6f636b2f312f73656375726974792d6576656e7400`. It is a domain separator: a
  signature made for an event can never be passed off as a signature over some other
  message signed with the same key, and the other way round.
- `event without "sig"` is the event object with the `sig` member removed and nothing else
  changed.
- Ed25519 is "pure" Ed25519 as in RFC 8032 section 5.1: no context, no pre-hash. The
  private key is the 32-byte seed; the public key is the 32-byte encoding of the point.
- The signer then adds
  `"sig": {"alg": "ed25519", "key": base64(public_key), "value": base64(signature)}`.

Ed25519 signing is deterministic, so signing the same event with the same key always
gives the same signature. The test vectors rely on that.

## 4. Verifying

A verifier MUST perform every step and MUST reject the event if any step fails. It MUST
NOT throw on malformed input in a way that takes down the caller; a bad event is an
expected input.

1. The event is a JSON object with a `sig` member. *(otherwise: `not_signed`)*
2. The event has exactly the members of section 1, of the stated types and within the
   stated ranges, and can be canonicalised. *(`malformed_event`)*
3. `sig.key` is base64 of exactly 32 bytes and `sig.value` is base64 of exactly 64 bytes.
   The base64 MUST be the one canonical spelling: decode, re-encode, and require the
   result to equal the input. That rejects whitespace, missing padding, the URL-safe
   alphabet and stray bits in the last character. *(`bad_key_encoding`,
   `bad_signature_encoding`)*
4. The public key is one a signature can mean anything under. Read the 32 key bytes as a
   little-endian integer and clear bit 255 (the sign of x); call the result `y`.
   - `y` MUST be less than `p = 2^255 - 19`. Otherwise the key is a second spelling of
     another point, and libraries disagree about whether to reduce it.
     *(`bad_key_encoding`)*
   - `y` MUST NOT be the y-coordinate of a point of small order. There are five such
     values, each shared by a point and its negative, which covers all eight points of
     order 1, 2, 4 and 8 (as 32-byte little-endian hex):

     ```
     0000000000000000000000000000000000000000000000000000000000000000   order 4
     0100000000000000000000000000000000000000000000000000000000000000   order 1 (identity)
     26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05   order 8
     c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a   order 8
     ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f   order 2
     ```

     Under such a key a "signature" can be made without any private key (for the
     identity, `R = identity, S = 0` satisfies the verification equation for every
     message), and some widely used Ed25519 libraries accept it. *(`weak_key`)*

   This step MUST be done by the verifier itself, before any Ed25519 library sees the
   key, because libraries differ here and a verdict must not depend on which one is
   used. No honest key is affected: a real public key is a multiple of the base point by
   a clamped scalar, which is never of small order.
5. If the verifier has a set of trusted keys, `sig.key` is one of them.
   *(`untrusted_key`)* See section 5.
6. `Ed25519_verify(public_key, signed_bytes, signature)` succeeds, with `signed_bytes`
   built as in section 3 from the event as received. The implementation MUST reject a
   signature whose scalar `S` is not less than the group order (RFC 8032 section 5.1.7);
   otherwise one event has more than one valid signature. A key that is not a point on
   the curve at all fails here. *(`signature_mismatch`)*

The names in parentheses are the `code` values that PortLock's `verify_event` returns.
Other implementations only need to reject, but the vector file states the expected reason
for each invalid event, and matching it shows the event was rejected for the right cause.
PortLock reports the first failing step in the order above, so an event that is wrong in
several ways gets the code of the earliest step.

A parser that accepts duplicate object keys can be shown one thing while a stricter parser
sees another. Verifiers SHOULD parse with a parser that rejects duplicate keys, or
canonicalise from the raw text with one that does.

### JavaScript sketch (Node.js)

```js
import { createPublicKey, verify } from "node:crypto";

function strictBase64(text, length) {
  if (typeof text !== "string") return null;
  const raw = Buffer.from(text, "base64");
  return raw.length === length && raw.toString("base64") === text ? raw : null;
}

const P = 2n ** 255n - 19n;
const SMALL_ORDER_Y = new Set([
  0n,
  1n,
  2707385501144840649318225287225658788936804267575313519463743609750303402022n,
  55188659117513257062467267217118295137698188065244968500265048394206261417927n,
  P - 1n,
]);

function usableKey(key) {
  // Step 4: little-endian y with the sign bit (bit 255) cleared.
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(key[i]);
  y &= (1n << 255n) - 1n;
  return y < P && !SMALL_ORDER_Y.has(y);
}

function verifySecurityEvent(event, canonical /* your canonicaliser */) {
  // Steps 1 and 2 (shape checks) come first and are omitted here.
  const key = strictBase64(event.sig.key, 32);
  const signature = strictBase64(event.sig.value, 64);
  if (key === null || signature === null) return false;
  if (!usableKey(key)) return false;
  const { sig, ...unsigned } = event;
  const message = Buffer.concat([
    Buffer.from("portlock/1/security-event\0", "utf8"),
    Buffer.from(canonical(unsigned), "utf8"),
  ]);
  const publicKey = createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: key.toString("base64url") },
    format: "jwk",
  });
  return verify(null, message, publicKey, signature);
}
```

## 5. Which keys to trust

The public key travels inside the event. A signature that verifies therefore proves only
that the event is intact and was signed by *whoever holds that key*: anyone can generate a
key and sign anything. It becomes evidence about a particular PortLock machine only when
the verifier compares `sig.key` with a key it learned out of band, when the machine was
enrolled. PortLock's `verify_event(event, trusted_keys=[...])` does this; without
`trusted_keys` the caller must inspect the returned public key itself.

Each PortLock installation has one signing key: a 32-byte seed in a file that only the
service account can read (`load_or_create_key`). Someone who can read that file can sign
as that machine. Replacing the key is a new enrolment. There is no key identifier or
rotation mechanism in version 1; the key itself is the identifier.

`source.host`, `source.version` and everything else in the event are claims made by the
signer. Bind them to the key at enrolment if they matter.

## 6. The audit chain and checkpoints

PortLock's audit log is a hash chain. Record `n` stores

```
hash_n = SHA-256( bytes.fromhex(hash_(n-1)) || canonical(body_n) )
body_n = { "seq": n, "ts": "...", "event_type": "...", "severity": "...",
           "actor": string or null, "device_fp": string or null, "data": { ... } }
```

with `hash_0 = SHA-256("portlock-audit-v1")`
= `66733296c9268618439464e304e8b8fbbec7ba390d114a728e3cc7e6f97c2849`. Here `ts` is the
record's time as a string, `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, always six fractional
digits), and the hash input is the 32 raw bytes of the previous hash followed by the
canonical JSON of the body. Sequence numbers start at 1 and have no gaps.

When the log has a MAC key store each record also stores a MAC under a key that moves
forward with every record:

```
k_n   = SHA-256( UTF8("portlock-audit-ratchet") || k_(n-1) )
mac_n = HMAC-SHA256( k_n, bytes.fromhex(hash_n) )
```

`k_0` is generated when the key store is created, handed to the administrator once to
keep offline, and never stored on the machine; it is anchored at the log's head at that
moment (record 0 for a new log), and records up to the anchor carry no MAC. The machine
keeps only the key for the next record and replaces it as soon as a record is committed,
so whoever takes the machine over later cannot compute the key of any record already
written. Verifying the MACs needs `k_0`. The MAC never leaves the machine in an event and
a receiver cannot check it: it protects the local log against a later intruder and
against a writer who cannot read the key file, and it cannot stop the holder of the
current key from forging records after the last genuine one, or from dropping records at
the end.

The machine also keeps the newest `(seq, hash)` in a small file beside the database and
checks the log against it, which catches a database that was truncated or replaced on
its own. Neither replaces the checkpoints below: only evidence held by someone else
survives an intruder who can rewrite everything on the machine.

An event built from audit record `n` has:

- `type`, `severity` and `data` copied from the record;
- `subject` holding the record's `actor` and `device_fp`, each only if not null;
- `ts` equal to the record's time in milliseconds, rounded down;
- `chain` equal to `{"seq": n, "hash": hash_n}`;
- `id` equal to the first 32 hex characters of
  `SHA-256( UTF8("portlock/1/event-id") || 0x00 || UTF8(source.host) || 0x00 || raw hash_n )`,
  so exporting the same record twice gives the same `id`.

Events not built from a record (`chain` is `null`) carry a random 128-bit `id`.

Because `hash_n` depends on every earlier record, **a signed event with a non-null `chain`
is a checkpoint**: the signer has committed to the entire log up to `seq`. A receiver that
keeps these events can later tell that the sender's log was tampered with:

- two validly signed events from the same key with the same `chain.seq` but different
  `chain.hash` mean the log was rewritten (or forked);
- a log that, on inspection, ends before a `chain.seq` the receiver holds was truncated;
- given an exported log (`AuditLog.export_jsonl`: one canonical JSON record per line, with
  `prev_hash`, `hash` and `mac`), the receiver can recompute every hash and compare the
  result at each `seq` it holds a checkpoint for.

The vector file's `audit_chain` section contains a three-record log with every
intermediate value (the hashed bytes, each hash, `k_0`, each `k_n` and each MAC), and the
second valid vector is the signed event for its third record.

A log that had to be started again because its database was damaged begins with a
`store.recovered` record whose `data` names the damaged file's SHA-256
(`damaged_sha256`) and its last known head (`last_known_head`, `{"seq", "hash"}` or
`null`), so a checkpoint of the old log can still be matched against the file that was
set aside.

## 7. Event types

`type` is one of the following for events emitted by PortLock. Each has a default
severity, which the emitter may override for a particular event; receivers MUST use the
`severity` in the event, not this table. A receiver SHOULD accept, and treat as opaque, a
well-formed `type` it does not know: later PortLock versions add types without changing
`v`.

<!-- catalogue:begin -->
| Type | Default severity | Meaning |
| --- | --- | --- |
| `device.connected` | `info` | A USB device arrived, or was present at start-up. |
| `device.removed` | `info` | A USB device was unplugged. |
| `device.changed` | `info` | A connected device gained new information, typically a mounted volume. |
| `decision.made` | `info` | The pipeline decided what a device may do, and why. |
| `enforcement.applied` | `notice` | The operating system was changed to enforce a decision. |
| `enforcement.would_apply` | `info` | Monitor mode: what would have been enforced. Nothing was changed. |
| `enforcement.failed` | `error` | An enforcement mechanism failed or is unavailable; the decision is not enforced. |
| `enforcement.refused` | `warning` | The safety choke point refused to act on a protected device. |
| `safety.suspicious_device` | `warning` | A device has a shape associated with attacks, such as storage paired with a keyboard. |
| `safety.clone_detected` | `warning` | A second device presented an enrolled fingerprint while the first was connected; it was denied. |
| `safety.port_held` | `warning` | Too many arrivals on one port: it is held blocked for a cool-down and further arrivals are coalesced. |
| `grant.created` | `notice` | An access grant was issued for a device. |
| `grant.used` | `info` | A grant permitted a device connection. |
| `grant.expired` | `info` | A grant reached its expiry or was consumed. |
| `grant.revoked` | `notice` | A grant was withdrawn before it expired. |
| `trust.added` | `notice` | A device was added to the trusted set. |
| `trust.removed` | `notice` | A device was removed from the trusted set. |
| `enroll.added` | `notice` | An input device was enrolled by fingerprint and port, so it is protected on that port. |
| `enroll.removed` | `notice` | An enrolled input device lost its enrolment. |
| `policy.changed` | `notice` | The policy was replaced; carries the old and new content hash. |
| `policy.invalid` | `error` | A policy document was rejected by validation. |
| `scan.started` | `info` | A content scan of a mounted volume began. |
| `scan.finished` | `info` | A content scan ended; carries its totals and limits. |
| `scan.detection` | `warning` | A scan engine flagged a file on a volume. |
| `auth.login` | `info` | An administrator, operator or auditor signed in. |
| `auth.logout` | `info` | A session ended by sign-out or timeout. |
| `auth.failure` | `warning` | A sign-in or privileged confirmation failed. |
| `auth.lockout` | `warning` | Repeated failures locked an account for a while. |
| `auth.password_changed` | `notice` | An account's password was changed. |
| `auth.recovery_used` | `warning` | A single-use recovery code was spent. |
| `auth.user_created` | `notice` | An account was created. |
| `auth.user_changed` | `notice` | An account's role or state was changed, or removed. |
| `lockdown.engaged` | `warning` | Emergency lockdown began: removable storage is blocked. |
| `lockdown.renewed` | `notice` | The lockdown dead-man timer was extended. |
| `lockdown.lifted` | `notice` | An administrator ended the lockdown. |
| `lockdown.expired` | `warning` | The dead-man timer ran out and the lockdown lifted itself. |
| `killswitch.activated` | `critical` | The kill-switch file was found: enforcement is off and settings were restored. |
| `recovery.restored` | `warning` | Journaled operating-system settings were put back, by the service or by 'portlock recover'. |
| `service.started` | `info` | The PortLock service started. |
| `service.stopped` | `notice` | The PortLock service stopped cleanly. |
| `service.recovered` | `warning` | The service started after an unclean stop and reconciled its state. |
| `store.recovered` | `critical` | A damaged database was moved aside; this new log names its hash and last known head. |
| `mode.changed` | `notice` | The mode changed between monitor and enforce. |
| `config.changed` | `notice` | A configuration setting was changed. |
| `change.pending` | `notice` | A change that could lock the operator out was applied and rolls back unless confirmed in time. |
| `change.confirmed` | `notice` | A pending change was confirmed over the same channel and is kept. |
| `change.rolled_back` | `warning` | A pending change was not confirmed in time, or was refused, and was rolled back. |
| `clock.rollback_detected` | `warning` | The wall clock is behind the newest audit timestamp; expiries use the later time. |
| `audit.verified` | `info` | The audit chain was walked and found intact. |
| `audit.verification_failed` | `critical` | The audit chain does not verify: the log was altered or damaged. |
<!-- catalogue:end -->

Severities, least to most serious:

| Severity | Meaning | Syslog severity (RFC 5424) |
| --- | --- | --- |
| `debug` | Diagnostic detail. | 7 |
| `info` | Normal operation. | 6 |
| `notice` | A deliberate change worth a second look. | 5 |
| `warning` | Something that may need action, or a reduction in protection. | 4 |
| `error` | Something failed; a decision may not be enforced. | 3 |
| `critical` | Protection is off, or the audit trail itself cannot be trusted. | 2 |

## 8. What must never be in an event

No password, session token, recovery code, HMAC key or private key is ever placed in
`subject` or `data`. As a safety net PortLock replaces the value of any member whose key
is one of `api_key`, `authorization`, `cookie`, `csrf_token`, `current_password`,
`hmac_key`, `new_password`, `old_password`, `passphrase`, `passwd`, `password`,
`private_key`, `recovery_code`, `recovery_codes`, `secret`, `session_token`,
`signing_key` or `token` (compared without regard to case, at any depth) with the string
`[redacted]`. That catches a secret under an expected name; it cannot catch one inside a
free-text message, so the rule is not to log them at all.

Events do describe devices: vendor and product ids, product strings and serial numbers
appear in `data`. Treat exported events as sensitive inventory data.

## 9. Test vectors

`tests/fixtures/security-event-vectors.json` contains:

- `valid`: signed events with, for each, the test seed, the public key, the event, the
  canonical bytes of the unsigned event (as text and as base64), the exact signed bytes,
  their SHA-256, and the signature. One event contains non-ASCII text, an unnormalised
  combining sequence, a character outside the Basic Multilingual Plane, every kind of
  escape, key-ordering traps and the extreme integers.
- `invalid`: events that MUST be rejected, each a single change to a valid event, with the
  reason: altered content, a substituted key, a flipped signature bit, a non-canonical
  signature scalar (`S + L`), a signature made without the domain separator, every base64
  laxity, unknown members, wrong types, a fraction, an unsafe integer, and public keys of
  small order (the identity, a point of order 8) and with a non-canonical y-coordinate,
  each paired with a signature that the plain Ed25519 equation accepts.
- `signing.refused_public_keys`: the rule of section 4, step 4, with the field prime and
  the five refused y-coordinates.
- `audit_chain`: a three-record audit log with hashes, `k_0`, each ratcheted MAC key, the
  MACs and the bytes that were hashed.

The seeds and the MAC key in that file are published test values. They MUST NOT be used
for anything else.

An implementation conforms if it accepts every `valid` event, reproduces `canonical_b64`
and `signing_input_b64` byte for byte, rejects every `invalid` event, and (if it signs)
reproduces each `signature_b64` from `seed_hex`. The `invalid` entries with `expect`
`weak_key` show why step 4 is not optional: a verifier that skips it accepts them.

## 10. Versioning

- `v` changes only for a change that would make a correct version-1 verifier accept
  something it should not, or compute different signed bytes. A verifier MUST reject a
  `v` it does not implement.
- The domain separator carries the same number (`portlock/1/...`); a version-2 format
  will use a different separator, so a signature can never be valid under two versions.
- New event types and new members inside `subject` and `data` are not version changes.

## 11. What this format does not give

- **Confidentiality.** Events are signed, not encrypted. Protect the channel.
- **Freshness.** Nothing here stops a valid old event from being sent again. Receivers
  that care discard an `id` they have already seen and, for chained events, a `chain.seq`
  that does not advance.
- **Completeness.** A signature says an event is authentic, not that no event was
  withheld. Gaps in `chain.seq` across the events a receiver holds are expected (not every
  record is exported); a missing record is only provable by comparing an exported log
  against a later checkpoint.
- **Protection from a compromised sender.** Whoever controls the machine and its signing
  key can sign false events from then on. Checkpoints received *before* the compromise
  still pin the log as it was.
- **Local proof of time.** `ts` is the sender's clock.
