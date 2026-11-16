# PortLock — local HTTP API

The contract between the PortLock service and its two clients: the web console and the
`portlock` command line (DESIGN §12). `console/api.py` implements it; `ARCHITECTURE.md`
section 4.1 says how, as amended by DESIGN §14.20 (bearer tokens, no cookies, no CSRF
tokens). This document describes what was built, and `tests/unit/test_console_api_endpoints.py`
checks it against the code: every route in the code is in the index of section 8, and the
other way round. Every example value is synthetic.

Contents: 1 conventions · 2 transport rules · 3 errors · 4 shared objects ·
5 authentication · 6 endpoints · 7 event stream · 8 endpoint index.

---

## 1. Conventions

- Base URL: `http://<api.host>:<api.port>/api/v1` (default `http://127.0.0.1:47600/api/v1`).
  Plain HTTP on a loopback address only; the service refuses to bind anything else.
- Requests and responses are JSON, UTF-8. A request with a body must send
  `Content-Type: application/json` (a `charset=utf-8` parameter is allowed). A body is a
  JSON object, with no floating-point numbers, no duplicate member names, nesting at most
  32 deep. **Unknown fields in a request body or query string are an error**
  (`invalid_request`), never ignored; every problem is reported at once.
- Types used below: `string`, `int`, `bool`, `object`, `array<T>`, `T | null`.
  `time` is a string `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, fixed width) in responses; a
  request may send `YYYY-MM-DDTHH:MM:SSZ` too. There are **no floating-point numbers**
  anywhere in the API.
- `fingerprint` is a string `plk1:` followed by 32 lower-case base32 characters (`a-z`,
  `2-7`). In a path it may be sent as is or percent-encoded.
- Ids in a path are validated by their shape: a connection id or scan id is digits, a
  grant id is 32 hex characters, a change id is 16 hex characters, a user name is 3 to 32
  characters of `a-z 0-9 . _ -` (any letter case). A path that does not have the shape of
  its route is `404 not_found`.
- Lists that can grow are paged with `limit` (1–500, default 100) and a cursor
  (`before_id`, `before`, or `until_seq`). The response carries `next` (the cursor for the
  next page) or `null` when there is no more.
- Every response has an `X-Request-Id` header (16 hex characters); errors repeat it in
  the body.
- A successful state-changing request returns the changed object, so a client never needs
  a second request to learn the result.
- Text a device supplied (names, serial numbers, volume labels) is **data**: it is returned
  as JSON strings, with `<`, `>` and `&` written as JSON escapes (`\u003c`, `\u003e`,
  `\u0026`) so that pasting a response into HTML cannot turn it into markup. Clients must
  still display it as text, never as markup.

## 2. Transport rules

Applied to every request, in this order, before anything else is looked at.

1. **Limits.** At most 32 requests in flight; the 33rd is answered `503 server_busy` by
   the accept thread, without a body being read and without a thread being started. When
   all 32 are taken and one of them has still not sent a complete request line and headers,
   the one that has waited longest is disconnected and its place goes to the new
   connection, so a program that opens connections and sends nothing cannot keep the
   command line and the console out; `503` is answered only when all 32 have sent their
   requests.
   Request line and headers at most 16 KiB (`431`); body at most 2 MiB (`413
   body_too_large`, decided from `Content-Length` before the body is read); 30 seconds to
   send the whole request (a slower client is disconnected); 10 seconds for any one write
   to the client, event stream included. At most 8 event streams (section 7). The parser
   is strict: `Transfer-Encoding` (chunked bodies) is refused, a header that may not
   repeat (`Host`, `Content-Length`, `Content-Type`, `Authorization`, `Origin`, ...)
   repeated is `400`, a body on a `GET`, `HEAD` or `DELETE` is `400`, `Expect:
   100-continue` is honoured.
2. **`Host`.** Must be exactly `<api.host>:<port>`, `localhost:<port>`, or, when bound to
   `::1`, `[::1]:<port>`, where `<port>` is the port actually bound. Anything else, or a
   missing header: `421 host_not_allowed`. This is the defence against DNS rebinding: a
   hostile page that resolves its own name to 127.0.0.1 still sends its own name in
   `Host`.
3. **`Origin` and `Sec-Fetch-Site`.** If `Origin` is present it must be `http://` + an
   allowed `Host` value; otherwise `403 origin_not_allowed`. If `Sec-Fetch-Site` is present
   it must be `same-origin` or `none`; otherwise `403 origin_not_allowed`. Both rules apply
   to every method, `GET` included. A request with neither header (the command line)
   passes this step.
4. **Route and method.** `OPTIONS`, `TRACE` and `CONNECT` are `405`: no preflight is ever
   answered and no CORS header is ever sent, so no other origin can read a response. A
   known path with the wrong method is `405` with an `Allow` header; an unknown path is
   `404`.
5. **Authentication, permission, then the body** (section 5). A request that is refused
   before its body is read has its unread body drained for up to 2 seconds, so that the
   client reads the error instead of a connection reset.

There are **no cookies**: the API never sets one and ignores any it receives. The token is
sent in the `Authorization` header (section 5), which a web page on another local port
cannot cause the browser to attach, so there is no CSRF token either.

The listener refuses address reuse (DESIGN §14.20): on Windows `SO_EXCLUSIVEADDRUSE` and
no `SO_REUSEADDR`; on POSIX `SO_REUSEADDR`, which only lets a restart bind a port with
connections in `TIME_WAIT` and never lets two processes listen on one port. If the port is
in use the service exits with code 5 instead of sharing it.

Headers on every response: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Cross-Origin-Resource-Policy: same-origin`, `Connection: close` (the event stream too: it
ends when the connection closes), `Server: PortLock`. Static console files also carry
`Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none';
frame-ancestors 'none'`, an `ETag` and `Cache-Control: no-cache`.

**Static files.** The console's files (`src/portlock/console/static/`) are read into
memory when the server starts and served from there: a request never touches the file
system, so there is no path to traverse. `GET /` serves `index.html`; `GET /static/<path>`
and `GET /<path>` serve the file of that name; `HEAD` and `If-None-Match` work; any other
path or method is an error. They need no session (they contain no data). Only `.html`,
`.js`, `.mjs`, `.css`, `.svg`, `.png`, `.ico`, `.json`, `.txt` and `.woff2` files of at
most 2 MiB are served.

## 3. Errors

Every error has the same body:

```json
{"error": {"code": "not_pending", "message": "only a pending device can be denied",
           "details": null, "request_id": "5d0c1b7a9e3f4a62"}}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `code` | string | stable; clients branch on this, never on `message` |
| `message` | string | one sentence for a person; never contains a secret |
| `details` | object \| null | code-specific, see below |
| `request_id` | string | also in `X-Request-Id` |

| Status | Code | When | `details` |
| --- | --- | --- | --- |
| 400 | `invalid_request` | malformed JSON, wrong type, unknown field, value out of range, unusable header | `{"problems":[{"path":"minutes","message":"must be 1 to 1440"}]}` |
| 400 | `policy_invalid` | a policy document failed validation | `{"problems":["rules[2].match.vendor_id: ..."]}` |
| 400 | `password_policy` | a new password is too weak | `{"problems":["must be at least 12 characters"]}` |
| 401 | `unauthenticated` | no bearer token, or it is unknown, expired or ended | null |
| 401 | `invalid_credentials` | wrong user name, password or recovery code | null |
| 401 | `reauthentication_failed` | the confirming password or code was wrong | null |
| 403 | `forbidden` | the role lacks the permission | `{"permission":"manage_trust"}` |
| 403 | `origin_not_allowed` | section 2 rule 3 | null |
| 403 | `account_disabled` | correct password, disabled account | null |
| 404 | `not_found` | no such object or route | null |
| 404 | `no_pending_change` | no such change is waiting for confirmation (it may have been rolled back) | null |
| 405 | `method_not_allowed` | | null |
| 409 | `not_connected` | the connection has ended | null |
| 409 | `not_pending` | the connection is not waiting for a decision | null |
| 409 | `unknown_device` | a fingerprint PortLock has never seen | null |
| 409 | `low_confidence` | trust asked for a low-confidence fingerprint (never possible), or a grant for one without `allow_low_confidence` | null |
| 409 | `grant_invalid` | the grant's fields do not fit its kind, or the expiry is not allowed (in the past, beyond the role's ceiling) | null |
| 409 | `policy_conflict` | `expected_hash` does not match the active policy | `{"hash":"<current>"}` |
| 409 | `lockdown_active` / `lockdown_not_active` | wrong lockdown state for the request | null |
| 409 | `invalid_duration` | lockdown minutes out of range | `{"max_minutes":1440}` |
| 409 | `killswitch_active` | enforcement is disabled by the kill-switch file | null |
| 409 | `enforcement_unavailable` | this machine or process cannot enforce | null (the message says why) |
| 409 | `not_private` | enforce mode is refused: the state or configuration directory is not private | null |
| 409 | `watch_only` | this process is watch-only (DESIGN §14.28): enforce mode, a lockdown and turning default-deny on are refused, and nothing is left behind | null (the message is ModeInfo's `watch_only_reason`) |
| 409 | `no_mounted_volume` / `scan_unavailable` / `scan_queue_full` | scan cannot be started | null |
| 409 | `wrong_channel` | a pending change must be confirmed over the channel that made it | null |
| 409 | `confirmation_expired` | the confirmation arrived after the deadline; the change was rolled back | null |
| 409 | `not_ready` / `change_pending` | the change is still being applied; or one of its kind is already waiting | null |
| 409 | `timer_unavailable` | the operating-system rollback timer could not be armed, so the change was not applied | null |
| 409 | `last_admin` | the change would leave no enabled administrator | null |
| 409 | `user_exists` | | null |
| 413 | `body_too_large` | | null |
| 415 | `unsupported_media_type` | body without `application/json` | null |
| 421 | `host_not_allowed` | section 2 rule 2 | null |
| 429 | `locked_out` | the account is locked out | `{"retry_after_seconds":120}` |
| 429 | `rate_limited` / `busy` | login limits, section 5.6 | `{"retry_after_seconds":5}` |
| 431 | `invalid_request` | the request line and headers exceed 16 KiB | null |
| 500 | `internal_error` | a bug; the message is generic and the traceback is only in the log | null |
| 503 | `store_unavailable` | the database could not be read or written | null |
| 503 | `server_busy` / `too_many_streams` | section 2 rule 1; more than 8 event streams | null |

429 responses also carry a `Retry-After` header in whole seconds; 401 responses carry
`WWW-Authenticate: Bearer realm="portlock"`.

---
## 4. Shared objects

Each object below is produced by the `to_dict()` of the class named, so the API and the
service cannot drift apart.

### 4.1 `User` (`auth.accounts.User`)

| Field | Type |
| --- | --- |
| `username` | string |
| `role` | `"admin"` \| `"operator"` \| `"auditor"` |
| `enabled` | bool |
| `created_at`, `password_changed_at` | time |
| `last_login_at` | time \| null |

### 4.2 `Session` (`auth.sessions.Session`; the token is never part of it)

| Field | Type |
| --- | --- |
| `session_id` | string (16 hex; not secret) |
| `username`, `role` | string |
| `created_at`, `last_seen_at`, `expires_at`, `idle_expires_at` | time |
| `client` | `"cli"` \| `"console"` \| `"api"` \| null |

`client` is `"cli"` when the login carried the command-line secret (5.7), `"console"` when
the request carried an `Origin` header and `"api"` otherwise; nothing from the request is
copied into it.

### 4.3 `Device` (`core.models.UsbDevice.to_dict()`)

| Field | Type |
| --- | --- |
| `instance_id` | string |
| `vendor_id`, `product_id`, `device_class` | int |
| `serial`, `manufacturer`, `product`, `bus_path` | string \| null |
| `bcd_device` | int \| null |
| `interfaces` | array<{`cls`: int, `subcls`: int, `protocol`: int}> |
| `removable` | bool \| null |
| `volumes` | array<{`device_node`: string, `mount_point`, `label`, `fs_type`, `fs_uuid`: string \| null, `size_bytes`: int \| null, `read_only`: bool \| null}> |
| `categories` | array<string>, sorted |

Device strings come from the device and are untrusted text: clients must display them as
text, never as markup.

### 4.4 `Decision`

`core.models.Decision.to_dict()` plus where and when it was made.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | int | |
| `decided_at` | time | |
| `access` | `"allow"` \| `"read_only"` \| `"deny"` \| `"pending"` | |
| `source` | `"safety"` \| `"lockdown"` \| `"policy"` \| `"grant"` \| `"scan"` \| `"default"` | |
| `reasons` | array<string> | readable, in order of evaluation |
| `rule_id`, `grant_id` | string \| null | |
| `scan` | `"none"` \| `"on_mount"` \| `"required"` | |
| `alert` | bool | |
| `expires_at` | time \| null | when it will be re-evaluated because of time alone |
| `trigger` | string | `arrival`, `start`, `grant`, `policy`, `expiry`, `scan`, `mode`, `settings`, `lockdown.engaged`, `lockdown.lifted`, `lockdown.expired`, `killswitch`, `retry`, `periodic` |
| `policy_hash` | string | SHA-256 hex of the policy that was evaluated |
| `mode` | `"monitor"` \| `"enforce"` | effective mode at the time |

### 4.5 `Enforcement`

What the operating system was actually made to do for the current decision.

| Field | Type | Notes |
| --- | --- | --- |
| `outcome` | `"undetermined"` \| `"not_needed"` \| `"applied"` \| `"would_apply"` \| `"failed"` \| `"refused"` \| `"unsupported"` | `would_apply`: monitor mode. `failed` and `unsupported` mean **not enforced** |
| `os_state` | `"open"` \| `"read_only"` \| `"blocked"` | what PortLock made, or left, the OS doing |
| `would` | `"read_only"` \| `"blocked"` \| null | in monitor mode, what enforce mode would do |
| `mechanism` | string \| null | e.g. `sysfs:authorized`, `cfgmgr:disable-devnode`, `dry-run` |
| `tier` | `"preventive"` \| `"reactive"` \| `"none"` | DESIGN §6 |
| `detail`, `error` | string \| null | |
| `at` | time \| null | |

### 4.6 `Connection` (`core.service.ConnectionView`)

The central object: one device, for one continuous presence, with its decision. It is
what the device list returns and what the event stream pushes.

| Field | Type | Notes |
| --- | --- | --- |
| `connection_id` | int | |
| `run_id` | string | the service run that observed it |
| `fingerprint` | fingerprint | |
| `confidence` | `"high"` \| `"low"` | |
| `basis` | array<string> | descriptor fields behind the fingerprint |
| `storage_identity` | string \| null | |
| `display_name` | string | |
| `device` | Device | latest description |
| `connected_at` | time | |
| `removed_at` | time \| null | null while connected |
| `close_reason` | `"removed"` \| `"resync"` \| `"service_stop"` \| `"service_restart"` \| null | |
| `present_at_start` | bool | |
| `state` | `"new"` \| `"protected"` \| `"allowed"` \| `"read_only"` \| `"pending"` \| `"denied"` | |
| `provisional` | bool | held at read-only until a required scan is clean |
| `protected` | bool | |
| `protection_codes` | array<string> | `hub`, `built_in`, `system_volume`, `protected_fingerprint`, `input_device`, `out_of_scope`, `safety_check_failed` |
| `decision` | Decision \| null | null only in state `new` |
| `enforcement` | Enforcement \| null | |
| `scan` | {`state`: string, `scan_id`: int \| null} | state: `none`, `waiting`, `queued`, `running`, `clean`, `suspicious`, `malicious`, `incomplete`, `error` |
| `resolution` | {`action`: `"denied"`, `by`: string, `at`: time, `note`: string} \| null | an operator's denial of a pending device |
| `first_seen` | time | when this fingerprint was first seen |
| `connection_count` | int | times this fingerprint has connected |

```json
{"connection_id": 42, "run_id": "9f2c4e1ab07d3355",
 "fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e", "confidence": "high",
 "basis": ["vid", "pid", "serial", "manufacturer", "product", "bcd", "ifaces"],
 "storage_identity": null, "display_name": "Example Corp Example Flash 16GB",
 "device": {"instance_id": "test/1-1", "vendor_id": 4617, "product_id": 1,
            "serial": "TEST0001A7C3", "manufacturer": "Example Corp",
            "product": "Example Flash 16GB", "bcd_device": 256, "device_class": 0,
            "interfaces": [{"cls": 8, "subcls": 6, "protocol": 80}], "bus_path": "1-1",
            "removable": true, "volumes": [], "categories": ["storage"]},
 "connected_at": "2026-01-01T09:00:00.000000Z", "removed_at": null, "close_reason": null,
 "present_at_start": false, "state": "pending", "provisional": false,
 "protected": false, "protection_codes": [],
 "decision": {"id": 311, "decided_at": "2026-01-01T09:00:00.020000Z", "access": "pending",
              "source": "default", "reasons": ["no enabled, unexpired rule matched; the policy default applies"],
              "rule_id": null, "grant_id": null, "scan": "on_mount", "alert": false,
              "expires_at": null, "trigger": "arrival",
              "policy_hash": "3b1f...e9", "mode": "enforce"},
 "enforcement": {"outcome": "applied", "os_state": "blocked", "would": null,
                 "mechanism": "sysfs:authorized", "tier": "reactive",
                 "detail": "wrote 0 to authorized", "error": null,
                 "at": "2026-01-01T09:00:00.041000Z"},
 "scan": {"state": "none", "scan_id": null}, "resolution": null,
 "first_seen": "2026-01-01T09:00:00.000000Z", "connection_count": 1}
```

### 4.7 `KnownDevice` and `DeviceDetail`

`KnownDevice` (`core.service.DeviceView`): `fingerprint`, `confidence`, `basis`,
`storage_identity`, `display_name`, `device` (Device, last sighting), `first_seen`,
`last_seen` (time), `connection_count` (int), `connected` (bool),
`trust` (`"full"` \| `"read_only"` \| null: an active trust grant).

`DeviceDetail` is `KnownDevice` plus `connections` (array<Connection>, newest first, at
most 20), `grants` (array<Grant>, active and ended, newest first, at most 50) and
`decisions` (array<Decision>, newest first, at most 50).

### 4.8 `Grant` (`auth.grants.Grant.to_dict()`)

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | 32 hex characters, random |
| `fingerprint` | fingerprint | |
| `confidence` | `"high"` \| `"low"` | when granted |
| `kind` | `"trust"` \| `"temporary"` \| `"once"` | |
| `read_only` | bool | |
| `created_at` | time | |
| `granted_by` | string | |
| `expires_at` | time \| null | required for `temporary`; never for `trust` |
| `note` | string | at most 512 characters |
| `bound_connection` | string \| null | the connection a one-time grant is bound to |
| `bound_port` | string \| null | the port a low-confidence grant is bound to |
| `bound_at`, `ended_at` | time \| null | |
| `end_reason` | `"revoked"` \| `"expired"` \| `"used"` \| null | |
| `ended_by` | string \| null | |

### 4.9 `PolicyInfo`

| Field | Type | Notes |
| --- | --- | --- |
| `policy` | object | the policy document, exactly as `policy_to_dict` writes it (`docs/POLICY.md`) |
| `hash` | string | SHA-256 hex of its canonical JSON |
| `name` | string | |
| `rules` | int | number of rules |
| `source` | `"file"` \| `"default"` \| `"last_good"` | where the active policy came from |
| `loaded_at` | time | |

### 4.10 `AuditRecord` (`audit.log.AuditRecord.to_dict()`)

`seq` (int), `ts` (time), `event_type` (string), `severity` (`"debug"` \| `"info"` \|
`"notice"` \| `"warning"` \| `"error"` \| `"critical"`), `actor` (string \| null),
`device_fp` (fingerprint \| null), `data` (object), `prev_hash`, `hash` (64 hex),
`mac` (64 hex \| null).

### 4.11 `Scan` (`core.service.ScanView`)

| Field | Type | Notes |
| --- | --- | --- |
| `id`, `connection_id` | int | |
| `fingerprint` | fingerprint | |
| `mount_point` | string | |
| `trigger` | `"policy"` \| `"manual"` | |
| `requested_by` | string | a user name, or `system` |
| `state` | `"queued"` \| `"running"` \| `"done"` \| `"cancelled"` | |
| `queued_at` | time | |
| `started_at`, `finished_at` | time \| null | |
| `verdict` | `"clean"` \| `"suspicious"` \| `"malicious"` \| `"incomplete"` \| `"error"` \| null | never `clean` unless everything was examined |
| `summary` | {`files_seen`, `files_hashed`, `bytes_hashed`: int, `findings`: {`info`, `suspicious`, `malicious`: int}, `errors`: int, `truncated_reason`: string \| null} \| null | |
| `report` | object \| null | `ScanReport.to_dict()` (`docs/SCANNING.md`); only in `GET /scans/{id}` |

### 4.12 `Lockdown` (`lockdown.manager.LockdownStatus`)

`state` (`"idle"` \| `"engaging"` \| `"active"` \| `"lifting"`), `active` (bool),
`engaged_at`, `expires_at` (time \| null), `engaged_by`, `reason` (string \| null),
`remaining_seconds` (int \| null), `renew_count`, `default_minutes`, `max_minutes` (int),
`pending_change_id` (string \| null: the engagement is waiting to be confirmed, 4.17),
`confirm_remaining_seconds` (int \| null), `external_timer_armed` (bool: the
operating-system dead-man timer is set).

### 4.13 `ModeInfo`

`mode` (the chosen mode), `effective_mode` (what is in force), both `"monitor"` \|
`"enforce"`; `source` (`"config"` \| `"setting"` \| `"killswitch"`); `killswitch` (bool);
`can_enforce` (bool); `notes` (array<string>: why it cannot, if it cannot; each a
sentence of its own, with a capital letter and a full stop, which a console may show as
a paragraph); `watch_only` (bool); `watch_only_reason` (string \| null).

`watch_only` is true for a process that can never be trusted to enforce: it is not
elevated, or its state or configuration directory is not a system-wide location (DESIGN
§14.28). It is decided when the process starts and never changes while it runs; the mode
does not decide it. `watch_only_reason` then says, in one or two plain sentences, what
PortLock cannot do here and why (for example "PortLock cannot change this computer: it is
not running as administrator, and its files are in this user's own folders, which every
program this user runs could change. It stays watch-only: it shows and records, and blocks
nothing."). The part about the location is true for the case at hand: this user's own
folders, another user's folders, the folder all users share, the home folder of the
account that runs it (root's `/root`), or a location PortLock cannot confirm is local and
system-wide (a network or device path, or a profile variable it could not read). It is
`null` when `watch_only` is false. In a watch-only process
`effective_mode` is always `"monitor"`, `can_enforce` is false, and the same sentence is
the message of every `watch_only` error. A console reads these two fields, and nothing
else, to know whether the process is watch-only. An elevated process with system-wide
directories is never watch-only, in monitor mode either: there `watch_only` is false and an
engaged lockdown blocks (6.11).

### 4.14 `Status` (`core.service.ServiceStatus`)

| Field | Type |
| --- | --- |
| `service` | `"portlock"` |
| `version`, `run_id`, `host_label`, `platform` | string |
| `started_at` | time |
| `uptime_seconds` | int |
| `simulation` | bool |
| `mode` | ModeInfo |
| `lockdown` | Lockdown |
| `policy` | {`name`, `hash`, `source`: string, `rules`: int} |
| `backend` | {`name`: string, `event_driven`, `healthy`: bool, `last_error`: string \| null, `notes`: array<string>} |
| `enforcer` | {`name`: string, `privileged`, `block`, `read_only`, `eject`, `default_deny`: bool, `notes`: array<string>}; in a watch-only process `name` is `"watch-only"` and the four capabilities are false |
| `counts` | {`connected`, `protected`, `allowed`, `read_only`, `pending`, `denied`, `not_enforced`: int} |
| `audit` | {`head_seq`: int, `head_hash`: string, `keyed`: bool, `backlog`: int, `sink_failures`: int} |
| `journal` | {`open_records`, `corrupt_lines`: int} |
| `degraded` | array<string>: any of `backend`, `store`, `audit`, `audit_chain`, `journal`, `scan` |
| `setup_required` | bool |

### 4.15 `Doctor` (`guard.factory.DoctorReport`, with the service's checks added)

`generated_at` (time), `platform`, `version` (string), `worst` (`"ok"` \| `"warn"` \|
`"fail"`), `backend`, `enforcer` (as in Status, or null), `mechanisms` (array<object>:
what each enforcement mechanism needs and whether it is available), `checks`:
array<{`id`: string, `status`: `"ok"` \| `"warn"` \| `"fail"` \| `"info"`, `summary`:
string, `detail`: string}>. The guard checks are `guard.*`, the service's are
`service.*`. The report contains device counts only, never a serial number, a product name
or an instance id.

The guard checks, in order: `guard.watch_only` and `guard.directories` (the posture of a
running service or of `portlock doctor`; `info`), `guard.platform`, `guard.privilege`,
`guard.backend`, `guard.detect`, `guard.enumerate`, `guard.block`, `guard.read_only`,
`guard.eject`, `guard.default_deny`, `guard.baseline_read_only`, `guard.conflicts`,
`guard.system_volume`, `guard.boot_default_deny` (Linux only), `guard.state_dir`,
`guard.config_dir`. The service's: `service.mode`, `service.killswitch`,
`service.journal`, `service.database`, `service.audit`, `service.signing`,
`service.scan_engines`, `service.lockdown`, `service.privacy`, then
`service.system_volume` and `service.baseline_read_only` when they apply, and
`service.setup`.

In a watch-only process (4.13) no enforcement mechanism is probed and no command is run:
`guard.watch_only` says watch-only, with the reason and that the antivirus engines are not
used; `guard.block` to `guard.baseline_read_only`, `guard.state_dir`, `guard.config_dir`
and `service.privacy` are `info` lines that say they were not probed or checked (never
`ok`); `service.scan_engines` says in its `detail` that antivirus engines are not used in
watch-only; `guard.directories` says why the directories are not system-wide, in the
same words as the reason. In any other process `guard.watch_only` says it is not
watch-only and every mechanism is probed.

### 4.16 `Settings`

| Field | Type | Notes |
| --- | --- | --- |
| `config` | object | `Config.to_dict()`: the configuration file as loaded. Read-only here |
| `runtime` | {`protected_fingerprints`: array<fingerprint>, `scan.enabled`: bool, `lockdown.default_minutes`: int, `scope`: string, `default_deny`: bool} | the three values `PATCH /settings` can change, and the two that have their own endpoints (`/scope`, `/default-deny`); `default_deny` is the value in force (as `GET /default-deny`'s `enabled`) |
| `effective` | {`scan_enabled`: bool, `lockdown_default_minutes`: int, `hid_enforcement_enabled`: bool, `scope`: string, `fail_closed`: bool, `baseline_read_only`: bool, `default_deny`: bool} | what is in force |
| `notes` | array<string> | sentences about settings that do not take effect as stored: in a watch-only process, a default-deny an earlier run stored on ("A default-deny setting stored by an earlier run is ignored: ..."); otherwise empty |

### 4.17 `Change` (a change waiting for confirmation)

Enforce mode, a wider scope, default-deny and a lockdown are applied under commit-confirm
(DESIGN §14.15): the change is made at once and rolled back unless it is confirmed within
`timeout_seconds` over the channel that made it. The same shape comes back from
`PUT /mode`, `PUT /scope`, `PUT /default-deny`, `POST /lockdown/engage` and
`GET /changes`.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | 16 hex characters |
| `kind` | `"lockdown"` \| `"enforce_mode"` \| `"widen_scope"` \| `"default_deny"` | |
| `status` | `"applying"` \| `"awaiting"` | |
| `actor` | string | who made it |
| `created_at`, `deadline_at` | time | |
| `timeout_seconds` | int | |
| `remaining_seconds` | int | only from `GET /changes` and the confirm and cancel answers |
| `preview` | array<{`instance_id`, `name`, `vid_pid`: string, `outcome`: `"block"` \| `"protected"` \| `"exempt"` \| `"not_enforced"`, `reason`: string}> | what the change blocks, listed before it was applied |

### 4.18 `Enrolment`

`fingerprint`, `bus_path` (the port), `label` (string \| null), `enrolled_at` (time),
`enrolled_by` (string). An enrolled input device is protected only on exactly that port
(DESIGN §14.1).

---

---

## 5. Authentication

### 5.1 The flow

1. The client sends the user name and password to `POST /auth/login`.
2. The server answers with the user, the session and the **bearer token**:
   `{"user": ..., "session": ..., "token": "<43 URL-safe characters>"}`. The token is 256
   random bits; the server stores only its SHA-256 digest, so a copy of the database yields
   no usable session. It is shown once. **No cookie is set.**
3. Every later request carries `Authorization: Bearer <token>`. There is no CSRF token: a
   bearer token is not attached by the browser on its own, so a page on another origin
   cannot make a request that carries it. The token must not be put in a URL, a query
   string or storage that outlives the tab; a web console keeps it in memory and asks
   again after a reload.
4. A session ends after 15 minutes without a request (`api.session_idle_minutes`) or 8
   hours after login (`api.session_max_hours`), whichever comes first; on logout; and
   when the account's password or role changes or the account is disabled or deleted. An
   ended session answers `401 unauthenticated`. The event stream does not count as
   activity.
5. A browser's `EventSource` cannot send an `Authorization` header, so the console reads
   the event stream with `fetch` and a stream reader (section 7).

Roles and permissions are those of `auth.accounts.can()`, which is authoritative:

| Role | Permissions |
| --- | --- |
| `admin` | all |
| `operator` | `view`, `view_audit`, `approve_device`, `issue_temporary_grant`, `run_scan`, `engage_lockdown` |
| `auditor` | `view`, `view_audit`, `export_audit` |

The role needed for each endpoint is enforced in one place (`_authorize` in
`console/api.py`): the route's permission is checked before the body is read, and what
depends on the request (the kind of grant, the kind of pending change, whose account) after
it is parsed, by the same function. Section 8 lists both.

Because the token travels in a header and not in a cookie, a program on the same machine
that serves a page on another loopback port gets nothing from a logged-in administrator's
browser. A local program that can read the browser's memory or the command line's process
can of course still use a token it finds: log out when done and keep the idle timeout
short.

### 5.2 `POST /auth/login` — public

Request: `username` (string), `password` (string).
Response 200: `user` (User), `session` (Session), `token` (string).
Errors: 401 `invalid_credentials` (identical for an unknown name and a wrong password, in
content and in timing); 403 `account_disabled`; 429 `locked_out`, `rate_limited`, `busy`.

```json
// request
{"username": "alice", "password": "correct horse battery staple"}
// response 200
{"user": {"username": "alice", "role": "admin", "enabled": true,
          "created_at": "2026-01-01T08:00:00.000000Z",
          "password_changed_at": "2026-01-01T08:00:00.000000Z",
          "last_login_at": "2026-01-01T09:00:00.000000Z"},
 "session": {"session_id": "0a1b2c3d4e5f6071", "username": "alice", "role": "admin",
             "created_at": "2026-01-01T09:00:00.000000Z",
             "last_seen_at": "2026-01-01T09:00:00.000000Z",
             "expires_at": "2026-01-01T17:00:00.000000Z",
             "idle_expires_at": "2026-01-01T09:15:00.000000Z", "client": "console"},
 "token": "example-bearer-token-not-a-real-one-0123456"}
```

### 5.3 `POST /auth/logout` — any session

No body. Response 204. Ends this session only. Audited as `auth.logout`.

### 5.4 `GET /auth/session` — any session

Response 200: `user` (User), `session` (Session), `permissions` (array<string>: what this
role may do, for the console to hide what it cannot). The token is not repeated.

```json
{"user": {"username": "alice", "role": "admin", "enabled": true, "created_at": "2026-01-01T08:00:00.000000Z",
          "password_changed_at": "2026-01-01T08:00:00.000000Z", "last_login_at": "2026-01-01T09:00:00.000000Z"},
 "session": {"session_id": "0a1b2c3d4e5f6071", "username": "alice", "role": "admin",
             "created_at": "2026-01-01T09:00:00.000000Z", "last_seen_at": "2026-01-01T09:03:00.000000Z",
             "expires_at": "2026-01-01T17:00:00.000000Z", "idle_expires_at": "2026-01-01T09:18:00.000000Z",
             "client": "console"},
 "permissions": ["approve_device", "change_mode", "edit_policy", "engage_lockdown", "export_audit",
                 "issue_temporary_grant", "lift_lockdown", "manage_trust", "manage_users", "run_scan",
                 "view", "view_audit"]}
```

### 5.5 Changing a password, and recovery codes

**`POST /auth/password` — any session.** Request: `current_password`, `new_password`
(strings). The current password is checked with the same lockout as a login. On success
every session of the account is ended, a new one is created, and the response is the same
shape as login (a new token). Errors: 401 `reauthentication_failed` (a locked-out account
is 429 `locked_out`), 400 `password_policy`.

```json
// request
{"current_password": "correct horse battery staple", "new_password": "an even longer new passphrase"}
// response 200: as POST /auth/login
```

**`POST /auth/recovery` — public.** For an account whose password is lost. Request:
`username`, `recovery_code`, `new_password` (strings). A new password that fails the
password policy is refused (400 `password_policy`) **before** the single-use code is
spent, so a weak password does not cost a code. The code is then consumed and the password
set, every session of the account is ended, and the response is the same shape as login.
Recovery codes have their own lockout counter (none: they carry 128 random bits), so an
attacker who locks the password cannot lock this path. A wrong code, an unknown name and a
disabled account are all `401 invalid_credentials`: the caller cannot tell which.

```json
// request
{"username": "alice", "recovery_code": "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345", "new_password": "a brand new long passphrase"}
// response 200: as POST /auth/login
```

Recovery codes are issued by `POST /users/{username}/recovery-codes` (6.12).

### 5.6 Login rate limiting

Three limits apply to `POST /auth/login`, `POST /auth/recovery`, `POST /auth/password`
and the re-authentication in `POST /lockdown/lift` (the last through the account store
only). All answer 429 with `Retry-After`.

1. **Per-account lockout** (`locked_out`), implemented by `AccountStore`: five
   consecutive failures start a delay of 30 seconds that doubles to 15 minutes, persisted
   across restarts. A refused attempt does not evaluate the password and does not extend
   the delay. Unknown user names are counted and delayed exactly like real ones, so the
   response never reveals whether a name exists.
2. **Global budget** (`rate_limited`): at most 30 credential checks in any 60 seconds
   across all names, counted in memory.
3. **Concurrency** (`busy`): at most `auth.max_concurrent_verifications` (default 2)
   password checks run at once on the network path, because each needs about 128 MiB. A
   further attempt is answered `busy` at once, without being counted, evaluated or
   audited, instead of waiting for a turn. This is the "too many logins are being
   verified" answer.

Limits 2 and 3 exist because every client of a loopback API has the same address, so there
is no per-client limit to apply. They mean a local program can make **network** logins fail
for a while. It cannot lock an administrator out of the machine: a login that carries the
command-line secret (5.7) is checked on the **local** channel, which no lockout or limit
applies to; recovery codes are never locked out; and `portlock recover` and the
kill-switch file need no login at all.

### 5.7 How the command line finds and authenticates to the service

1. **Find.** `--url` or `PORTLOCK_URL` if given; otherwise `runtime.json` in the state
   directory, which the service writes at start:
   `{"v": 1, "pid": 4242, "host": "127.0.0.1", "port": 47600, "run_id": "9f2c4e1ab07d3355", "started_at": "2026-01-01T08:59:00.000000Z", "version": "0.2.0", "secret": "<random>"}`.
   The file is readable only by accounts the operating system lets into the state
   directory, so it holds a per-run secret that only they know. `--url` refuses a host
   that is not a loopback address.
2. **Verify the service before sending any credential.** The command line calls
   `GET /ping` with the header `X-PortLock-Challenge: <32 random hex characters>`. The
   service answers with `proof`, the HMAC-SHA256 under the secret of
   `"portlock/ping/1" 0x00 <challenge>` in hex. The command line requires the proof to be
   right and `run_id` to equal the file's. A program that merely grabbed the port knows
   neither, so it never sees a password. With `--url` there is no secret to compare, and
   the command line says so on standard error.
3. **Authenticate.** `POST /auth/login` with a prompted password (or `--password-stdin`)
   and, when the secret is known, the header `X-PortLock-CLI-Secret: <secret>`, which
   makes the service check the login on the local channel (5.6). Then the calls, each with
   the bearer token, then `POST /auth/logout`. The command line sends no `Origin` header
   and stores nothing on disk. Commit-confirm (6.13) treats every session of the command
   line as one channel per user (`cli:<user>`), so `portlock lockdown engage` and
   `portlock confirm` may be separate commands; a browser session is its own channel.
4. **Without the service.** `init`, `recover`, `user reset-password --local`,
   `user unlock --local`, `audit verify --offline`, `policy validate`, `doctor --offline`,
   `service print-unit`, `service print-task` and `simulate` do not use this API
   (`docs/ARCHITECTURE.md` 4.2). `init` refuses while a service runs from the same state
   directory (stop it first, then start it again after `init`), so that every audit
   record after `init` carries the MAC of the key it shows.
5. **When the instance lock cannot be opened** (another user's or an administrator's
   installation), `status` and `stop` fall back to `runtime.json` and the verified ping
   of step 2; if that file cannot be read either, they say plainly that they cannot tell
   whether the service is running, and why (exit code 4).

The **first administrator** is created by `portlock init` on the machine, never through
this API. Until then `GET /ping` reports `setup_required: true` and every login fails.

---
## 6. Endpoints

Paths are relative to `/api/v1`. "Permission" is what the session's role must have;
"session" means any logged-in user; "public" means no session. Every request except the
public ones carries `Authorization: Bearer <token>` (section 5).

### 6.1 Liveness and status

**`GET /ping` — public.** Enough to find the service and nothing more.

```json
{"service": "portlock", "api": 1, "version": "0.2.0", "run_id": "9f2c4e1ab07d3355",
 "setup_required": false, "simulation": false}
```

Fields: `service`, `version`, `run_id` (string), `api` (int), `setup_required`,
`simulation` (bool). With the header `X-PortLock-Challenge: <16 to 128 lower-case hex
characters>` the answer also carries `proof` (string), see 5.7.

**`GET /status` — `view`.** Response: Status (4.14).

```json
{"service": "portlock", "version": "0.2.0", "run_id": "9f2c4e1ab07d3355", "host_label": "unnamed-host",
 "platform": "linux", "started_at": "2026-01-01T08:59:00.000000Z", "uptime_seconds": 600, "simulation": false,
 "mode": {"mode": "enforce", "effective_mode": "enforce", "source": "setting", "killswitch": false,
          "can_enforce": true, "notes": [], "watch_only": false, "watch_only_reason": null},
 "lockdown": {"state": "idle", "active": false, "engaged_at": null, "engaged_by": null, "reason": null,
              "expires_at": null, "remaining_seconds": null, "renew_count": 0, "default_minutes": 60,
              "max_minutes": 1440, "pending_change_id": null, "confirm_remaining_seconds": null,
              "external_timer_armed": false},
 "policy": {"name": "PortLock default policy", "hash": "3b1f...e9", "source": "default", "rules": 1},
 "backend": {"name": "linux", "event_driven": true, "healthy": true, "last_error": null, "notes": []},
 "enforcer": {"name": "linux", "privileged": true, "block": true, "read_only": true, "eject": true,
              "default_deny": true, "notes": []},
 "counts": {"connected": 4, "protected": 2, "allowed": 1, "read_only": 0, "pending": 1, "denied": 0, "not_enforced": 0},
 "audit": {"head_seq": 1280, "head_hash": "77aa...04", "keyed": false, "backlog": 0, "sink_failures": 0},
 "journal": {"open_records": 1, "corrupt_lines": 0}, "degraded": [], "setup_required": false}
```

### 6.2 Devices

**`GET /devices` — `view`.** The devices connected now. Query: `state` (one Connection
state, optional). Response: `devices` (array<Connection>, oldest connection first).
Not paged: it is bounded by what is plugged in (at most 500 are returned).

```json
{"devices": [ { "connection_id": 42, "state": "pending", "...": "a Connection, section 4.6" } ]}
```

**`GET /devices/history` — `view`.** Past and present connections, newest first. Query:
`limit`, `before_id` (a `connection_id`), `fingerprint`, `open` (`true` \| `false`,
optional). Response: `connections` (array<Connection>), `next` (int \| null).

```json
{"connections": [ { "connection_id": 41, "removed_at": "2026-01-01T08:40:00.000000Z",
                    "close_reason": "removed", "...": "a Connection" } ], "next": 12}
```

**`GET /devices/known` — `view`.** Every device PortLock has seen, most recently seen
first. Query: `limit`, `before` (a fingerprint from the previous page), `text` (matches
manufacturer, product, serial or fingerprint). Response: `devices` (array<KnownDevice>),
`next` (fingerprint \| null).

```json
{"devices": [ {"fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e", "confidence": "high",
               "basis": ["vid", "pid", "serial"], "storage_identity": null,
               "display_name": "Example Corp Example Flash 16GB", "device": {"...": "a Device"},
               "first_seen": "2026-01-01T09:00:00.000000Z", "last_seen": "2026-01-01T09:00:00.000000Z",
               "connection_count": 1, "connected": true, "trust": null} ], "next": null}
```

**`GET /devices/{fingerprint}` — `view`.** Response: DeviceDetail (4.7). 404 if unknown.

```json
{"fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e", "confidence": "high", "connected": true,
 "trust": null, "connection_count": 1, "...": "the other KnownDevice fields",
 "connections": [ {"connection_id": 42, "...": "a Connection"} ], "grants": [], "decisions": [ {"id": 311, "...": "a Decision"} ]}
```

**`GET /connections/{connection_id}` — `view`.** Response: `connection` (Connection),
`decisions` (array<Decision>, newest first, at most 100: the history of this connection),
`scans` (array<Scan> without `report`, at most 100).

```json
{"connection": {"connection_id": 42, "...": "a Connection"},
 "decisions": [ {"id": 311, "access": "pending", "...": "a Decision"} ], "scans": []}
```

### 6.3 Decisions

**`GET /decisions` — `view`.** The decision history, newest first. Query: `limit`,
`before_id`, `connection_id`, `fingerprint`, `access`. Response: `decisions`
(array<Decision>: 4.4, which names its trigger, policy hash and mode but not its
connection: filter by `connection_id` to see one connection's), `next` (int \| null).

```json
{"decisions": [ {"id": 311, "decided_at": "2026-01-01T09:00:00.020000Z", "access": "pending",
                 "source": "default", "trigger": "arrival", "...": "the other Decision fields"} ], "next": null}
```

### 6.4 Approving or denying a pending device

**`POST /connections/{connection_id}/approve`.** Permission by `kind`: `once` needs
`approve_device`; `temporary` needs `approve_device` and `issue_temporary_grant`;
`trust` needs `approve_device` and `manage_trust`.

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | `"once"` \| `"temporary"` \| `"trust"` | default `"once"` |
| `read_only` | bool | default false |
| `expires_in` | string | `30m`, `2h`, `7d`, ...; for `temporary` give this or `expires_at`; optional for `once`; not allowed for `trust` |
| `expires_at` | time | must be in the future; not with `expires_in` |
| `note` | string | optional, at most 512 characters, no control characters |

Response 200: `grant` (Grant), `connection` (Connection, after re-evaluation),
`reevaluated` (array<int>: every connection id that was re-evaluated). The connection's
state tells the outcome. If a policy rule denies the device the grant is created but the
device stays denied, and `connection.decision.reasons` says so: a grant never overrides
an explicit deny. A temporary grant is limited to the role's ceiling (operators 24 hours;
administrators `grants.max_temporary_hours_admin`), and to 24 hours for a low-confidence
device (one without a unique serial number, whose fingerprint every unit of its model
shares), which is also bound to its port; `trust` for such a device is always refused,
`409 low_confidence`, and the message says what to use instead (DESIGN §14.13). Errors:
409 `not_connected` (no connection with this id is open), `not_pending`, `low_confidence`,
`grant_invalid`.

```json
// request
{"kind": "temporary", "expires_in": "2h", "read_only": true, "note": "contractor laptop backup"}
// response 200
{"grant": {"id": "4f7a9c21d0b84e16a3c5e7f901b2d4a6", "fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e",
           "confidence": "high", "kind": "temporary", "read_only": true,
           "created_at": "2026-01-01T09:05:00.000000Z", "granted_by": "bob",
           "expires_at": "2026-01-01T11:05:00.000000Z", "note": "contractor laptop backup",
           "bound_connection": null, "bound_port": null, "bound_at": null, "ended_at": null,
           "end_reason": null, "ended_by": null},
 "connection": {"connection_id": 42, "state": "read_only", "...": "a Connection"},
 "reevaluated": [42]}
```

**`POST /connections/{connection_id}/deny` — `approve_device`.** Records that an operator
looked at a pending device and refused it. The device stays blocked for this connection;
it is pending again the next time it is plugged in (a standing denial is a policy rule).
Request: `eject` (bool, default false: also ask the OS to eject it), `note` (string,
optional). Response 200: `connection` (Connection, state `denied`, `resolution` set),
`eject` ({`ok`: bool, `error`: string \| null} \| null). Errors: 409 `not_connected`,
`not_pending`.

```json
// request
{"eject": false, "note": "unknown stick found in the car park"}
// response 200
{"connection": {"connection_id": 42, "state": "denied",
                "resolution": {"action": "denied", "by": "bob", "at": "2026-01-01T09:06:00.000000Z",
                               "note": "unknown stick found in the car park"}, "...": "a Connection"},
 "eject": null}
```

### 6.5 Trust

Trust is a grant of kind `trust`: it has no expiry and lasts until removed.

**`GET /trust` — `view`.** Response: `trust` (array<Grant>, active trust grants, newest
first).

```json
{"trust": [ {"id": "91c0e2aa5b7d4f03b6a8c1d2e3f40516", "kind": "trust", "read_only": false, "...": "a Grant"} ]}
```

**`POST /trust` — `manage_trust`.** Request: `fingerprint` (must be a device PortLock has
seen), `read_only` (bool, default false), `note` (string, optional). Response 201:
`grant` (Grant), `reevaluated` (array<int>). Errors: 409 `unknown_device`; 409
`low_confidence` for a device without a unique serial number, which can never be trusted
(use `POST /grants`, which limits the grant to the device's port).

```json
// request
{"fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e", "read_only": false, "note": "backup drive, asset 0042"}
// response 201
{"grant": {"id": "91c0e2aa5b7d4f03b6a8c1d2e3f40516", "kind": "trust", "expires_at": null, "...": "a Grant"}, "reevaluated": [42]}
```

**`DELETE /trust/{grant_id}` — `manage_trust`.** Response 200: `grant` (Grant, ended with
`end_reason: "revoked"`), `reevaluated` (array<int>). A connected device that depended on
the trust is re-evaluated, and blocked if nothing else permits it, before the response is
sent. 404 if there is no such active trust grant.

```json
{"grant": {"id": "91c0e2aa5b7d4f03b6a8c1d2e3f40516", "kind": "trust", "ended_at": "2026-01-01T10:00:00.000000Z",
           "end_reason": "revoked", "ended_by": "alice", "...": "a Grant"}, "reevaluated": [42]}
```

### 6.6 Grants

**`GET /grants` — `view`.** Query: `include_inactive` (bool, default false), `kind`,
`fingerprint`. Response: `grants` (array<Grant>, newest first; all kinds).

```json
{"grants": [ {"id": "4f7a9c21d0b84e16a3c5e7f901b2d4a6", "kind": "temporary", "...": "a Grant"} ]}
```

**`POST /grants` — `issue_temporary_grant`.** A grant for a device that need not be
connected. Request: `fingerprint` (seen before), `kind` (`"temporary"` \| `"once"`;
`"trust"` is refused here, use `/trust`), `read_only` (bool), `expires_in` or
`expires_at` (required for `temporary`, optional for `once`), `note`,
`allow_low_confidence` (bool, default false: a device without a unique serial number
shares its fingerprint with every unit of its model, so granting it needs this flag; the
grant is then bound to the device's port, and a temporary one is limited to 24 hours).
Response 201: `grant` (Grant), `reevaluated` (array<int>). Errors: 409 `unknown_device`,
`low_confidence`, `grant_invalid`.

```json
// request
{"fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e", "kind": "once", "read_only": false, "note": "one-off import"}
// response 201
{"grant": {"id": "0d3b6f8e1a2c49571234567890abcdef", "kind": "once", "expires_at": null, "...": "a Grant"}, "reevaluated": []}
```

**`DELETE /grants/{grant_id}`.** Permission: `issue_temporary_grant` for a `temporary` or
`once` grant; `manage_trust` for a `trust` grant. Response 200: `grant`, `reevaluated`,
as `DELETE /trust/{grant_id}`. Revoking an ended grant is 404.

```json
{"grant": {"id": "0d3b6f8e1a2c49571234567890abcdef", "end_reason": "revoked", "ended_by": "bob", "...": "a Grant"}, "reevaluated": []}
```

### 6.7 Enrolments and held ports

**`GET /enrolments` — `view`.** Response: `enrolments` (array<Enrolment>, 4.18).

**`POST /enrolments` — `manage_trust`.** Enrols a connected device on its port
(DESIGN §14.1): it stays protected there, and only there. Request: `connection_id` (int),
`label` (string, optional, at most 128 characters). Response 201: `enrolment`
(Enrolment), `reevaluated` (array<int>). Errors: 409 `not_connected`; 400
`invalid_request` if the platform reports no port for the device.

**`DELETE /enrolments/{fingerprint}` — `manage_trust`.** Query: `bus_path` (optional: only
this port; default every port of the fingerprint). Response 200: `removed` (int),
`summary` (object, as in lockdown engage, 6.10). 404 if nothing was removed.

**`POST /ports/release` — `manage_trust`.** Ends a port hold-down early (DESIGN §14.6: a
port with too many arrivals in a short time is held blocked for a cool-down). Request:
`port` (string, the bus path). Response 200: `released` (true), `reevaluated`
(array<int>). 404 `not_found` if the port is not held.

```json
{"released": true, "reevaluated": [44]}
```

### 6.8 Policy

**`GET /policy` — `view`.** Response: PolicyInfo (4.9).

```json
{"policy": {"version": 1, "name": "PortLock default policy",
            "default": {"access": "pending", "scan": "on_mount", "alert": false},
            "rules": [{"id": "deny-input-with-other", "enabled": true, "expires": null,
                       "description": "...", "match": {"mixes_input_with_other": true},
                       "action": {"access": "deny", "scan": "none", "alert": true}}],
            "scan": {"on_detection": "deny"}},
 "hash": "3b1f...e9", "name": "PortLock default policy", "rules": 1, "source": "default",
 "loaded_at": "2026-01-01T08:59:00.000000Z"}
```

**`POST /policy/validate` — `view`.** Checks a document and changes nothing. Request:
`policy` (object). Response 200 always: `valid` (bool), `problems` (array<string>, each
`<location>: <fault>`), `hash` (string \| null: the hash it would have).

```json
// request
{"policy": {"version": 1, "name": "draft", "default": {"access": "pending"},
            "rules": [{"id": "r1", "match": {"vendor_id": "0xZZZZ"}, "action": {"access": "allow"}}]}}
// response 200
{"valid": false, "problems": ["rules[0].match.vendor_id: not a hexadecimal number between 0x0000 and 0xffff"], "hash": null}
```

**`PUT /policy` — `edit_policy`.** Replaces the policy: validate, save atomically, switch,
re-evaluate every connected device, audit `policy.changed` with both hashes. Request:
`policy` (object), `expected_hash` (string, 64 hex, optional: the hash the client last saw;
a mismatch is 409 `policy_conflict`, so two administrators cannot silently overwrite each
other). Response 200: PolicyInfo plus `previous_hash` (string) and `summary` (what the
re-evaluation did: `evaluated`, `changed`, `blocked`, `read_only`, `released`, `failed`).
Errors: 400 `policy_invalid`, 409 `policy_conflict`.

```json
// request
{"expected_hash": "3b1f...e9", "policy": {"version": 1, "name": "site policy", "default": {"access": "pending"},
  "rules": [{"id": "trust-lab-vendor", "match": {"vendor_id": "0x1209", "confidence": "high"},
             "action": {"access": "read_only", "scan": "required"}}]}}
// response 200
{"policy": {"...": "as stored"}, "hash": "c4d2...10", "name": "site policy", "rules": 1, "source": "file",
 "loaded_at": "2026-01-01T09:30:00.000000Z", "previous_hash": "3b1f...e9",
 "summary": {"evaluated": 4, "changed": 2, "blocked": 1, "read_only": 1, "released": 0, "failed": 0}}
```

**`POST /policy/test` — `view`.** What would the policy do with this device? Changes
nothing. Request: exactly one of `connection_id` (int), `fingerprint` (a known device; its
last description is used) or `device` (a Device object with `vendor_id` and `product_id`;
`instance_id` and `volumes` may be omitted; only the fields of 4.3 are accepted); optionally
`policy` (a draft document; default: the active policy) and `at` (time; default: now).
Response 200 (`core.service.PolicyTest.to_dict()`):

| Field | Type | Notes |
| --- | --- | --- |
| `fingerprint` | fingerprint | of the tested device |
| `confidence` | `"high"` \| `"low"` | |
| `policy_hash` | string | of the policy that was tested |
| `matched_rule` | string \| null | the rule that decided, if any |
| `matched_default` | bool | the policy default decided |
| `skipped` | array<array<string>> | rules that were skipped, with the reason |
| `valid_until` | time \| null | when the answer next changes because of time alone |
| `explain` | array<{`rule_id`, `outcome`, `summary`: string, `would_match`: bool, `criteria`: array<{`criterion`, `detail`: string, `matched`: bool}>}> | every rule; `outcome` is `matched`, `shadowed`, `no_match`, `disabled` or `expired` |
| `decision` | Decision fields `access`, `source`, `reasons`, `rule_id`, `grant_id`, `scan`, `alert`, `expires_at` | the full precedence: safety, lockdown, scan, policy, grants |

Errors: 400 `policy_invalid` (the draft) or `invalid_request` (a malformed device), 404
`not_found`, 409 `unknown_device`.

```json
// request
{"device": {"vendor_id": 4617, "product_id": 5, "serial": "TEST0005BAD1", "product": "Example Flash 16GB",
            "interfaces": [{"cls": 8, "subcls": 6, "protocol": 80}, {"cls": 3, "subcls": 1, "protocol": 1}],
            "removable": true}}
// response 200
{"fingerprint": "plk1:b2c4d6e2f3g5h7j2k4m6n2p4q6r2s4t6", "confidence": "high", "policy_hash": "3b1f...e9",
 "matched_rule": "deny-input-with-other", "matched_default": false, "skipped": [], "valid_until": null,
 "explain": [{"rule_id": "deny-input-with-other", "outcome": "matched", "would_match": true,
              "summary": "matched: deny", "criteria": [{"criterion": "mixes_input_with_other", "matched": true, "detail": "..."}]}],
 "decision": {"access": "deny", "source": "policy", "reasons": ["rule deny-input-with-other denies this device"],
              "rule_id": "deny-input-with-other", "grant_id": null, "scan": "none", "alert": true, "expires_at": null}}
```

### 6.9 Audit

**`GET /audit` — `view_audit`.** Query, all optional: `since_seq`, `until_seq` (int);
`since`, `until` (time); `type` (repeatable event type; `auth.*` matches an area);
`min_severity`; `device_fp`; `actor`; `text` (substring of the stored data); `limit`
(1–500, default 100); `order` (`desc` default, or `asc`). Response: `records`
(array<AuditRecord>), `head` ({`seq`: int, `hash`: string}), `next` (int \| null: pass as
`until_seq` for `desc`, `since_seq` for `asc`).

```json
{"records": [{"seq": 1280, "ts": "2026-01-01T09:05:00.120000Z", "event_type": "grant.created",
              "severity": "notice", "actor": "bob", "device_fp": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e",
              "data": {"grant": {"id": "4f7a9c21d0b84e16a3c5e7f901b2d4a6", "kind": "temporary", "read_only": true}, "connection_id": 42},
              "prev_hash": "19be...c7", "hash": "77aa...04", "mac": null}],
 "head": {"seq": 1280, "hash": "77aa...04"}, "next": 1279}
```

**`POST /audit/verify` — `view_audit`.** Walks the hash chain. It is a `POST` because
the result is itself recorded (`audit.verified` or `audit.verification_failed`).
Request, all optional: `start_seq` (int, default 1), `expected_head` ({`seq`: int,
`hash`: string}: a head saved earlier, to detect truncation or replacement). Response
200 whether or not it verified:

| Field | Type | Notes |
| --- | --- | --- |
| `ok` | bool | |
| `checked` | int | records verified |
| `first_bad_seq` | int \| null | |
| `reason` | string \| null | |
| `macs_checked` | int | 0 means no key was supplied: a fully rebuilt chain would not be noticed |
| `head` | {`seq`: int, `hash`: string} \| null | last record that verified |
| `head_checked` | bool | the log was compared with its head file and matched |
| `keyed` | bool | the log carries MACs |

```json
// request
{"expected_head": {"seq": 1200, "hash": "5e11...9a"}}
// response 200
{"ok": true, "checked": 1281, "first_bad_seq": null, "reason": null, "macs_checked": 0,
 "head": {"seq": 1281, "hash": "a0c3...5d"}, "head_checked": true, "keyed": false}
```

**`GET /audit/export` — `export_audit`.** Query: `since_seq` (int, default 1). Response
200 with `Content-Type: application/x-ndjson` and
`Content-Disposition: attachment; filename="portlock-audit.jsonl"`: one canonical-JSON
AuditRecord per line, in sequence order, streamed without `Content-Length` (the body ends
when the connection closes; a stream that stops early means the log could not be read to
the end). Verify it with `portlock audit verify` or any implementation of the chain in
`audit/log.py`.

```
{"actor":null,"data":{"version":"0.2.0"},"device_fp":null,"event_type":"service.started","hash":"...","mac":null,"prev_hash":"...","seq":1,"severity":"info","ts":"2026-01-01T08:59:00.000000Z"}
```

**`GET /audit/checkpoint` — `export_audit`.** The current head, for keeping somewhere
the local administrator cannot rewrite. Response: `checkpoint` ({`seq`, `count`: int,
`hash`: string, `ts`: time}), `signed_event` (object \| null: the head record as a signed
security event, `docs/SECURITY_EVENT_FORMAT.md`, signed with the key in
`event-signing.key` in the state directory (created on first use); null when the optional
signing support is not installed or the log is empty).

```json
{"checkpoint": {"seq": 1281, "hash": "a0c3...5d", "ts": "2026-01-01T09:40:00.000000Z", "count": 1281},
 "signed_event": null}
```

### 6.10 Scans

**`POST /scans` — `run_scan`.** Queue a scan of a connected device's mounted volume.
PortLock scans only what the OS has mounted and never changes anything on the volume.
Request: `connection_id` (int), `mount_point` (string, optional: one of the device's
mount points; default: all of them, one scan each). Response 202: `scans` (array<Scan>,
state `queued`). A manual scan of a protected device, or of one whose policy action has
`scan: none`, is report-only: it does not change the decision. Errors: 404, 409
`not_connected`, `no_mounted_volume`, `scan_unavailable`, `scan_queue_full`.

```json
// request
{"connection_id": 42}
// response 202
{"scans": [{"id": 7, "connection_id": 42, "fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e",
            "mount_point": "/media/test", "trigger": "manual", "requested_by": "bob", "state": "queued",
            "queued_at": "2026-01-01T09:10:00.000000Z", "started_at": null, "finished_at": null,
            "verdict": null, "summary": null, "report": null}]}
```

**`GET /scans` — `view`.** Query: `limit`, `before_id`, `connection_id`, `fingerprint`.
Response: `scans` (array<Scan> without `report`), `next` (int \| null).

```json
{"scans": [{"id": 7, "state": "done", "verdict": "clean",
            "summary": {"files_seen": 212, "files_hashed": 212, "bytes_hashed": 48211200,
                        "findings": {"info": 0, "suspicious": 0, "malicious": 0}, "errors": 0, "truncated_reason": null},
            "...": "the other Scan fields"}], "next": null}
```

**`GET /scans/{scan_id}` — `view`.** Response: `scan` (Scan with `report`).

```json
{"scan": {"id": 7, "state": "done", "verdict": "suspicious", "...": "the other Scan fields",
          "report": {"root": "/media/test", "verdict": "suspicious", "files_seen": 212,
                     "findings": [{"path": "autorun.inf", "engine": "heuristics", "rule": "autorun-inf",
                                   "severity": "suspicious", "detail": "open=setup.exe", "sha256": null}],
                     "errors": [], "engines": [{"name": "heuristics", "available": true, "version": null}],
                     "...": "the rest of ScanReport.to_dict()"}}}
```

### 6.11 Lockdown

**`GET /lockdown` — `view`.** Response: Lockdown (4.12).

```json
{"state": "active", "active": true, "engaged_at": "2026-01-01T10:00:00.000000Z", "engaged_by": "bob",
 "reason": "suspected intrusion", "expires_at": "2026-01-01T11:00:00.000000Z", "remaining_seconds": 3180,
 "renew_count": 0, "default_minutes": 60, "max_minutes": 1440, "pending_change_id": null,
 "confirm_remaining_seconds": null, "external_timer_armed": true}
```

**`POST /lockdown/engage` — `engage_lockdown`.** Blocks all removable storage and puts
the OS into default-deny for new devices, **in monitor mode too**. Protected devices are
never touched. A watch-only process (4.13) refuses it with 409 `watch_only`: the lockdown
stays `idle` and nothing is recorded, so a lockdown is never `active` unless it really
blocks. It is applied at once **under commit-confirm** (DESIGN §14.15): it is
rolled back unless `POST /changes/{id}/confirm` arrives within `commit_confirm_seconds`
(default 60) over the same channel (5.7), so an operator whose only way in is a USB network
adapter gets the machine back. After confirmation it lifts itself at `expires_at` unless
renewed. Request: `minutes` (int, 1–`max_minutes`, default `default_minutes`), `reason`
(string, optional, at most 256 characters). Response 200: `lockdown` (Lockdown), `summary`
({`evaluated`, `changed`, `blocked`, `read_only`, `released`, `failed`: int}), `change`
(Change, 4.17, with the devices it blocks in `preview`). Errors: 409 `watch_only`,
`lockdown_active` (use renew), `invalid_duration`, `killswitch_active`,
`enforcement_unavailable`.

```json
// request
{"minutes": 60, "reason": "suspected intrusion"}
// response 200
{"lockdown": {"state": "active", "active": true, "expires_at": "2026-01-01T11:00:00.000000Z", "...": "a Lockdown"},
 "summary": {"evaluated": 4, "changed": 1, "blocked": 1, "read_only": 0, "released": 0, "failed": 0},
 "change": {"id": "dc5439cc1af20f93", "kind": "lockdown", "status": "awaiting", "actor": "bob",
            "created_at": "2026-01-01T10:00:00.000000Z", "deadline_at": "2026-01-01T10:01:00.000000Z",
            "timeout_seconds": 60, "remaining_seconds": 60,
            "preview": [{"instance_id": "test/1-1", "name": "Example Flash 16GB", "vid_pid": "1209:0001",
                         "outcome": "block", "reason": "removable storage"}]}}
```

**`POST /lockdown/renew` — `engage_lockdown`.** Restarts the dead-man timer. Request:
`minutes` (int, optional, same range): the lockdown now ends that long from now.
Response 200: `lockdown`. Errors: 409 `lockdown_not_active`, `invalid_duration`.

```json
// request
{"minutes": 120}
// response 200
{"lockdown": {"state": "active", "expires_at": "2026-01-01T12:07:00.000000Z", "renew_count": 1, "...": "a Lockdown"}}
```

**`POST /lockdown/lift` — `lift_lockdown`, with re-authentication.** The session alone is
not enough: the request must prove the administrator's password or spend one of their
recovery codes. Request: exactly one of `password` (string) or `recovery_code` (string),
belonging to the session's own account. Response 200: `lockdown` (state `idle`),
`summary` (as engage: what was released, what stays blocked because policy still says
so; or null). Errors: 401 `reauthentication_failed`, 429 `locked_out`, 409
`lockdown_not_active`. A request that carries the command-line secret (5.7) has its
password checked on the **local** channel, which a network lockout never refuses
(DESIGN §14.21), so failed logins by another program cannot keep the administrator at the
elevated command line from lifting; `portlock lockdown lift` sends the secret. Without it
the password is checked on the network channel and `locked_out` applies.

```json
// request
{"password": "correct horse battery staple"}
// response 200
{"lockdown": {"state": "idle", "active": false, "expires_at": null, "...": "a Lockdown"},
 "summary": {"evaluated": 4, "changed": 1, "blocked": 0, "read_only": 0, "released": 1, "failed": 0}}
```

If the service is not running, the lockdown is lifted with `portlock recover`, which
needs operating-system administrator rights and no PortLock login. `recover` refuses a
home that is not a system-wide location (this user's or another user's folders, the
folder all users share, root's own home, or a location it cannot confirm is local):
programs other than an administrator's could have written its journal, and a PortLock
kept there is watch-only and never changed anything.

### 6.12 Mode, scope, default-deny, doctor, settings

**`GET /mode` — `view`.** Response: ModeInfo (4.13).

```json
{"mode": "monitor", "effective_mode": "monitor", "source": "config", "killswitch": false, "can_enforce": true, "notes": [],
 "watch_only": false, "watch_only_reason": null}
```

In a watch-only process (4.13):

```json
{"mode": "monitor", "effective_mode": "monitor", "source": "config", "killswitch": false, "can_enforce": false,
 "notes": ["PortLock cannot change this computer: ...", "Antivirus engines are not used in watch-only: ..."],
 "watch_only": true,
 "watch_only_reason": "PortLock cannot change this computer: it is not running as administrator, and its files are in this user's own folders, which every program this user runs could change. It stays watch-only: it shows and records, and blocks nothing."}
```

**`PUT /mode` — `change_mode`.** Request: `mode` (`"monitor"` \| `"enforce"`). Switching
to `enforce` is applied at once under commit-confirm (6.13): the response carries `change`
and the mode is rolled back unless it is confirmed in time; switching to `monitor` puts
back everything PortLock changed (an active lockdown excepted) and has no `change`.
Response 200: `mode` (ModeInfo), `summary` (as lockdown engage, or null), `change` (Change
or null). Errors: 409 `watch_only` (switching to `enforce` in a watch-only process; nothing
is proposed or written, and switching to `monitor` stays allowed), `killswitch_active`,
`enforcement_unavailable`, `not_private`.

```json
// PUT /mode {"mode": "enforce"} in a watch-only process: 409
{"error": {"code": "watch_only", "message": "PortLock cannot change this computer: it is not running as administrator, ... It stays watch-only: it shows and records, and blocks nothing.", "details": null}}
```

```json
// request
{"mode": "enforce"}
// response 200
{"mode": {"mode": "monitor", "effective_mode": "monitor", "source": "config", "killswitch": false, "can_enforce": true, "notes": [],
          "watch_only": false, "watch_only_reason": null},
 "summary": null,
 "change": {"id": "5b0e9d1c7a3f4286", "kind": "enforce_mode", "status": "awaiting", "...": "a Change"}}
```

**`GET /scope` — `view`.** Response: `scope` (string: which devices can be enforced
against, DESIGN §14.5), `scopes` (array<string>: the choices, narrowest first: `storage`,
`storage_and_unknown`, `all_except_protected`).

**`PUT /scope` — `change_mode`.** Request: `scope`. Widening the scope is applied under
commit-confirm; narrowing is not. Response 200: `scope`, `summary` (or null), `change`
(Change or null). 400 `invalid_request` for an unknown scope. (The input-device
enforcement of DESIGN §2 needs two further settings in the configuration file and is not
reachable here.)

**`GET /default-deny` — `view`.** Response: `enabled` (bool): standing operating-system
default-deny for new devices in enforce mode, as it is in force; `stored` (bool): the
stored setting; `note` (string \| null). A watch-only process denies nothing: there
`enabled` is false even when an earlier, enforcing run stored it on, `stored` is true and
`note` says that the stored setting is ignored. Elsewhere `enabled` equals `stored` and
`note` is null. `portlock default-deny` prints the note under its answer.

```json
// GET /default-deny in a watch-only process that finds it stored on
{"enabled": false, "stored": true,
 "note": "A default-deny setting stored by an earlier run is ignored: this process is watch-only and denies nothing."}
```

**`PUT /default-deny` — `change_mode`.** Request: `enabled` (bool). Turning it on is
applied under commit-confirm. Response 200: `enabled`, `summary`, `change`. Errors: 409
`watch_only` (turning it on in a watch-only process; nothing is proposed or written, and
turning it off stays allowed), `killswitch_active`.

**`GET /doctor` — `view`.** What this machine can do right now. Response: Doctor (4.15),
whose first lines say whether this process is watch-only.

```json
{"generated_at": "2026-01-01T09:00:00.000000Z", "platform": "linux", "version": "0.2.0", "worst": "warn",
 "backend": {"name": "linux", "event_driven": true, "healthy": true, "last_error": null, "notes": []},
 "enforcer": {"name": "linux", "privileged": true, "block": true, "read_only": true, "eject": true, "default_deny": true, "notes": []},
 "mechanisms": [],
 "checks": [{"id": "guard.watch_only", "status": "info", "summary": "not watch-only: this process runs as administrator with system-wide directories, so it uses the enforcement mechanisms below (in monitor mode it blocks only an engaged lockdown)", "detail": ""},
            {"id": "guard.privilege", "status": "ok", "summary": "running as administrator", "detail": ""},
            {"id": "guard.detect", "status": "ok", "summary": "arrivals are pushed by the operating system", "detail": ""},
            {"id": "guard.enumerate", "status": "ok", "summary": "4 USB device(s) connected", "detail": ""},
            {"id": "service.signing", "status": "warn", "summary": "audit records carry no MAC (no key store configured)", "detail": ""}]}
```

**`GET /settings` — `view`.** Response: Settings (4.16).

```json
{"config": {"mode": "monitor", "scope": "storage", "hid_enforcement": false, "...": "Config.to_dict()"},
 "runtime": {"protected_fingerprints": [], "scan.enabled": true, "lockdown.default_minutes": 60,
             "scope": "storage", "default_deny": false},
 "effective": {"scan_enabled": true, "lockdown_default_minutes": 60, "hid_enforcement_enabled": false,
               "scope": "storage", "fail_closed": false, "baseline_read_only": false}}
```

**`PATCH /settings` — `edit_policy`.** Changes one or more of the three run-time
settings; each change is audited as `config.changed`. Request: any of
`protected_fingerprints` (array<fingerprint>, each a device PortLock has seen; replaces
the list), `scan.enabled` (bool), `lockdown.default_minutes` (int, at least 1 and at
most `max_minutes`). Response 200: Settings plus `summary` (the re-evaluation, or null).
Everything else in `config` (HID enforcement, `fail_closed`, the API address, paths,
authentication and audit settings) can be changed only in the configuration file, by
someone with operating-system rights, followed by a restart: it is deliberately out of
reach of the web console. Errors: 400 `invalid_request`, 409 `unknown_device`.

```json
// request
{"protected_fingerprints": ["plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e"]}
// response 200
{"config": {"...": "unchanged"}, "runtime": {"protected_fingerprints": ["plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e"],
 "scan.enabled": true, "lockdown.default_minutes": 60, "scope": "storage", "default_deny": false},
 "effective": {"...": "as GET"}, "summary": {"evaluated": 4, "changed": 0, "blocked": 1, "read_only": 0, "released": 0, "failed": 0}}
```

### 6.13 Commit-confirm: pending changes

Switching to enforce mode, widening the scope, turning on default-deny and engaging a
lockdown can lock the operator out, so each is applied at once and **rolled back unless
confirmed** within `commit_confirm_seconds` (default 60) over the same channel
(DESIGN §14.15). An operating-system timer rolls it back even if the service dies. The
channel is the session for a browser and `cli:<user>` for the command line (5.7); a
confirmation from another channel is `409 wrong_channel`.

**`GET /changes` — `view`.** Response: `changes` (array<Change>, oldest first).

**`POST /changes/{change_id}/confirm`.** Permission: the one the change needed:
`engage_lockdown` for a lockdown, `change_mode` for the others (and `view` to see it at
all). No body. Response 200: `change` (Change), `confirmed` (true). Errors: 404
`no_pending_change`, 409 `wrong_channel`, `confirmation_expired` (the change was rolled
back), `not_ready`.

**`POST /changes/{change_id}/cancel`.** Same permissions, and for a lockdown also
`lift_lockdown`, because cancelling a lockdown that waits for confirmation lifts it. Rolls
the change back now. No body. Response 200: `change`, `cancelled` (true). 404 `no_pending_change`.

```json
{"change": {"id": "dc5439cc1af20f93", "kind": "lockdown", "...": "a Change"}, "confirmed": true}
```

### 6.14 Users

All need `manage_users` unless stated. After any change to an account's password, role
or enabled state, every session of that account is ended. The last enabled administrator
cannot be deleted, disabled or demoted (409 `last_admin`). `{username}` is
case-insensitive.

**`GET /users`.** Response: `users` (array of User plus `recovery_codes_remaining`
(int) and `locked_out_seconds` (int: time left on a password lockout through the API, 0
if none)).

```json
{"users": [{"username": "alice", "role": "admin", "enabled": true, "created_at": "2026-01-01T08:00:00.000000Z",
            "password_changed_at": "2026-01-01T08:00:00.000000Z", "last_login_at": "2026-01-01T09:00:00.000000Z",
            "recovery_codes_remaining": 8, "locked_out_seconds": 0}]}
```

**`POST /users`.** Request: `username` (3–32 characters from `a-z 0-9 . _ -`),
`password`, `role` (`admin`, `operator` or `auditor`). Response 201: `user`. Errors: 400
`invalid_request`, `password_policy`; 409 `user_exists`.

```json
// request
{"username": "bob", "password": "a long operator passphrase", "role": "operator"}
// response 201
{"user": {"username": "bob", "role": "operator", "enabled": true, "created_at": "2026-01-01T09:20:00.000000Z",
          "password_changed_at": "2026-01-01T09:20:00.000000Z", "last_login_at": null}}
```

**`PUT /users/{username}/role`.** Request: `role`. Response 200: `user`.

```json
// request
{"role": "auditor"}
// response 200
{"user": {"username": "bob", "role": "auditor", "enabled": true, "...": "a User"}}
```

**`POST /users/{username}/disable`** and **`POST /users/{username}/enable`.** No body.
Response 200: `user`.

```json
{"user": {"username": "bob", "role": "auditor", "enabled": false, "...": "a User"}}
```

**`POST /users/{username}/password`.** Administrative reset; also clears the account's
lockouts. Request: `new_password`. Response 200: `user`. Errors: 400 `password_policy`.

```json
// request
{"new_password": "a temporary long passphrase"}
// response 200
{"user": {"username": "bob", "...": "a User"}}
```

**`POST /users/{username}/recovery-codes` — `manage_users`, or the account's own
session.** Issues a fresh set and invalidates the previous one. The codes are returned
**once** and stored only as digests. A recovery code can lift a lockdown and reset a
password, so a session token alone is not enough: the request carries the **caller's own
current password** (also when an administrator issues codes for someone else). Request:
`current_password` (string, required). Response 200: `username`, `codes` (array<string>, 8
codes), `issued_at` (time). Errors: 400 `invalid_request` (no `current_password`), 401
`reauthentication_failed`, 429 `locked_out`, `rate_limited` or `busy` (the password check
is counted and limited like a login, and is not itself a sign-in).

```json
// request
{"current_password": "correct horse battery staple"}
// response 200
{"username": "alice", "issued_at": "2026-01-01T09:25:00.000000Z",
 "codes": ["ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345", "…7 more…"]}
```

**`POST /users/{username}/unlock`.** Clears the account's failed-attempt counters. No
body. Response 200: `user`.

```json
{"user": {"username": "bob", "...": "a User"}}
```

**`DELETE /users/{username}`.** Response 204.

---

## 7. The event stream

**`GET /events` — `view`.** A server-sent event stream (`Content-Type:
text/event-stream`) that pushes everything the console shows live. With it the console
never polls: it loads state once over the endpoints above and then applies events.

The request carries `Authorization: Bearer <token>` like any other. A browser's
`EventSource` cannot send that header (and a token in the query string is not allowed), so
the console opens the stream with `fetch` and reads `response.body` with a stream reader,
parsing the frames below itself; reconnecting means sending `Last-Event-ID` itself.

### 7.1 Framing

```
retry: 3000

id: 9f2c4e1ab07d3355-118
event: device.connected
data: {"connection":{"connection_id":42,"state":"new", ... }}

: keep-alive

```

- One frame per event: `id`, `event`, one `data` line holding a JSON object, a blank
  line. `data` never contains a raw newline.
- `id` is `<run_id>-<seq>`: the service run and the event's sequence number in it.
- A comment line `: keep-alive` is sent every 15 seconds of silence.
- The first frame is always `hello` (after the `retry: 3000` line). `hello` and the other
  frames the server makes up itself (`reset`, `session.ended`) carry no `id`: a client
  resumes from the last `id` it saw.
- An event whose payload cannot be encoded is skipped, and `internal.*` bus topics are
  never sent.
- At most 8 streams are open at once (503 `too_many_streams`). A client that cannot keep
  up (256 events behind, or a write that blocks for 10 seconds) is disconnected and
  should reconnect.
- The stream ends when the session ends. It is not activity: an open stream does not
  keep a session alive; every 15 seconds the server checks that the session is still
  listed, without refreshing it. Before closing for that reason it sends `session.ended`
  (`expired` if the idle or absolute timeout had passed, `revoked` otherwise).
- `audit.appended` frames are sent only to sessions with `view_audit`.

### 7.2 Resuming

On reconnect the client sends `Last-Event-ID`; it may instead pass
`?since=<run_id>-<seq>`. Anything else is 400.

- Same `run_id` and the event after `seq` is still in the server's history (the last
  1000 events): the server sends `hello` with `resumed: true`, then every missed event,
  then continues live. Nothing is lost or repeated.
- Otherwise (the service restarted, or the gap is too old): the server sends `hello`
  with `resumed: false` followed by `reset`. On `reset` the client must discard what it
  holds and reload it from `GET /status`, `GET /devices` and whatever else it shows.
- A first connection with neither header nor parameter gets `hello` with `resumed:
  false` and no `reset`.

### 7.3 Events

| Event | Payload | Sent when |
| --- | --- | --- |
| `hello` | `run_id`: string, `seq`: int (latest), `resumed`: bool, `server_time`: time | first frame |
| `reset` | `reason`: `"restart"` \| `"gap"` | the client's state is stale |
| `session.ended` | `reason`: `"expired"` \| `"revoked"` | just before the stream closes |
| `device.connected` | `connection`: Connection (state `new`, no decision yet) | a device arrived |
| `decision.made` | `connection`: Connection (decision and enforcement filled in) | a decision was made or changed, for any reason |
| `device.changed` | `connection`: Connection | new information for a connection (a volume appeared) |
| `device.removed` | `connection_id`: int, `fingerprint`, `removed_at`: time, `close_reason`: string | a device left |
| `enforcement.result` | `connection_id`: int \| null, `fingerprint` \| null, `enforcement`: Enforcement, `action`: string | an enforcement call finished (null ids: a machine-wide setting) |
| `grant.changed` | `change`: `"created"` \| `"used"` \| `"expired"` \| `"revoked"`, `grant`: Grant | |
| `policy.changed` | `hash`, `previous_hash`, `name`: string, `rules`: int | |
| `scan.started` | `scan`: Scan (no report) | |
| `scan.progress` | `scan_id`: int, `files_seen`: int, `bytes_hashed`: int | at most once a second per scan |
| `scan.finished` | `scan`: Scan (no report) | |
| `lockdown.changed` | `change`: `"engaged"` \| `"renewed"` \| `"lifted"` \| `"expired"`, `lockdown`: Lockdown | |
| `mode.changed` | `mode`: ModeInfo | includes the kill switch appearing or going away |
| `settings.changed` | `runtime`: object (as in Settings) | |
| `status.changed` | `degraded`: array<string>, `counts`: object (as in Status) | a degraded flag or a count changed |
| `alert` | `severity`: string, `title`, `message`: string, `connection_id`: int \| null, `fingerprint` \| null, `audit_seq`: int \| null | something a person should look at: a suspicious device, a scan detection, a decision with `alert`, an enforcement failure |
| `audit.appended` | `seq`: int, `ts`: time, `event_type`, `severity`: string, `actor`: string \| null, `device_fp` \| null | every audit record (`view_audit` only) |

What the console sees when an unknown stick is plugged in, in order, with no request
made: `device.connected` (the row appears) → `decision.made` (the row shows `pending`
and `blocked`) → `enforcement.result` → `status.changed` (the pending count). When an
operator approves it from another browser: `grant.changed` → `decision.made` (the row
turns `allowed`) → `enforcement.result` → `status.changed`. When it is pulled out:
`device.removed`.

Every payload that concerns a connection carries the whole `Connection`, so a client
applies an event by replacing its copy; it never has to merge fields or keep count of
what it missed.

---

## 8. Endpoint index

"Permission" is checked before the body is read; "also" is checked after the body is
parsed (`_authorize` in `console/api.py`). The CSRF column of earlier versions is gone:
there are no cookies and no CSRF tokens (DESIGN §14.20).

| Method | Path | Permission | Also |
| --- | --- | --- | --- |
| GET | `/ping` | public | |
| POST | `/auth/login` | public | |
| POST | `/auth/recovery` | public | |
| POST | `/auth/logout` | session | |
| GET | `/auth/session` | session | |
| POST | `/auth/password` | session | |
| GET | `/status` | `view` | |
| GET | `/devices` | `view` | |
| GET | `/devices/history` | `view` | |
| GET | `/devices/known` | `view` | |
| GET | `/devices/{fingerprint}` | `view` | |
| GET | `/connections/{connection_id}` | `view` | |
| GET | `/decisions` | `view` | |
| POST | `/connections/{connection_id}/approve` | `approve_device` | `issue_temporary_grant` for `temporary`, `manage_trust` for `trust` |
| POST | `/connections/{connection_id}/deny` | `approve_device` | |
| GET | `/trust` | `view` | |
| POST | `/trust` | `manage_trust` | |
| DELETE | `/trust/{grant_id}` | `manage_trust` | |
| GET | `/grants` | `view` | |
| POST | `/grants` | `issue_temporary_grant` | |
| DELETE | `/grants/{grant_id}` | `issue_temporary_grant` | `manage_trust` for a `trust` grant |
| GET | `/enrolments` | `view` | |
| POST | `/enrolments` | `manage_trust` | |
| DELETE | `/enrolments/{fingerprint}` | `manage_trust` | |
| POST | `/ports/release` | `manage_trust` | |
| GET | `/policy` | `view` | |
| POST | `/policy/validate` | `view` | |
| PUT | `/policy` | `edit_policy` | |
| POST | `/policy/test` | `view` | |
| GET | `/audit` | `view_audit` | |
| POST | `/audit/verify` | `view_audit` | |
| GET | `/audit/export` | `export_audit` | |
| GET | `/audit/checkpoint` | `export_audit` | |
| POST | `/scans` | `run_scan` | |
| GET | `/scans` | `view` | |
| GET | `/scans/{scan_id}` | `view` | |
| GET | `/lockdown` | `view` | |
| POST | `/lockdown/engage` | `engage_lockdown` | |
| POST | `/lockdown/renew` | `engage_lockdown` | |
| POST | `/lockdown/lift` | `lift_lockdown` | password or recovery code in the body |
| GET | `/changes` | `view` | |
| POST | `/changes/{change_id}/confirm` | `view` | the permission of the change: `engage_lockdown` (lockdown) or `change_mode` |
| POST | `/changes/{change_id}/cancel` | `view` | as confirm; a lockdown also needs `lift_lockdown` |
| GET | `/mode` | `view` | |
| PUT | `/mode` | `change_mode` | |
| GET | `/scope` | `view` | |
| PUT | `/scope` | `change_mode` | |
| GET | `/default-deny` | `view` | |
| PUT | `/default-deny` | `change_mode` | |
| GET | `/doctor` | `view` | |
| GET | `/settings` | `view` | |
| PATCH | `/settings` | `edit_policy` | |
| GET | `/users` | `manage_users` | |
| POST | `/users` | `manage_users` | |
| PUT | `/users/{username}/role` | `manage_users` | |
| POST | `/users/{username}/disable` | `manage_users` | |
| POST | `/users/{username}/enable` | `manage_users` | |
| POST | `/users/{username}/password` | `manage_users` | |
| POST | `/users/{username}/recovery-codes` | session | `manage_users`, unless it is the caller's own account; the caller's `current_password` in the body |
| POST | `/users/{username}/unlock` | `manage_users` | |
| DELETE | `/users/{username}` | `manage_users` | |
| GET | `/events` | `view` | |

Outside `/api/v1`: `GET /`, `GET /static/...` and `GET /<file>` serve the web console's
files without a session (they contain no data); every other path is 404.
