# PortLock — local HTTP API

The contract between the PortLock service and its two clients: the web console and the
`portlock` command line (DESIGN §12). `console/api.py` implements it; `ARCHITECTURE.md`
section 4.1 says how. Every example value is synthetic.

Contents: 1 conventions · 2 transport rules · 3 errors · 4 shared objects ·
5 authentication · 6 endpoints · 7 event stream · 8 endpoint index.

---

## 1. Conventions

- Base URL: `http://<api.host>:<api.port>/api/v1` (default `http://127.0.0.1:47600/api/v1`).
  Plain HTTP on a loopback address only; the service refuses to bind anything else.
- Requests and responses are JSON, UTF-8. A request with a body must send
  `Content-Type: application/json`. Unknown fields in a request body or query string are
  an error (`invalid_request`), never ignored.
- Types used below: `string`, `int`, `bool`, `object`, `array<T>`, `T | null`.
  `time` is a string `YYYY-MM-DDTHH:MM:SS.ffffffZ` (UTC, fixed width). There are **no
  floating-point numbers** anywhere in the API.
- `fingerprint` is a string `plk1:` followed by 32 base32 characters. In a path it may be
  sent as is or percent-encoded.
- Lists that can grow are paged with `limit` (1–500, default 100) and a cursor
  (`before_id` or `before`). The response carries `next` (the cursor for the next page) or
  `null` when there is no more.
- Every response has an `X-Request-Id` header (16 hex characters); errors repeat it in
  the body.
- A successful state-changing request returns the changed object, so a client never needs
  a second request to learn the result.

## 2. Transport rules

Applied to every request, in this order, before anything else is looked at.

1. **Limits.** At most 32 requests in flight; request line and headers at most 16 KiB;
   body at most 2 MiB; 30 seconds to send the request. Over a limit: 503
   `server_busy`, 431, 413 `body_too_large`, or the connection is closed.
2. **`Host`.** Must be exactly `<api.host>:<port>`, `localhost:<port>`, or, when bound
   to `::1`, `[::1]:<port>`, where `<port>` is the port actually bound. Anything else,
   or a missing header: 421 `host_not_allowed`. This is the defence against DNS
   rebinding: a hostile page that resolves its own name to 127.0.0.1 still sends its
   own name in `Host`.
3. **`Origin` and `Sec-Fetch-Site`.** If `Origin` is present it must be
   `http://` + an allowed `Host` value; otherwise 403 `origin_not_allowed`. If
   `Sec-Fetch-Site` is present it must be `same-origin` or `none`; otherwise 403
   `origin_not_allowed`. Both rules apply to every method, `GET` included. A request
   with neither header (the CLI) passes this step.
4. **Method.** `OPTIONS`, `TRACE` and `CONNECT` are 405. No CORS header is ever sent, so
   no other origin can read a response.
5. **Session**, **CSRF**, **permission** (section 5), then the body.

Headers on every response: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Cross-Origin-Resource-Policy: same-origin`, `Connection: close` (except the event
stream), `Server: PortLock`. Static console files also carry
`Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none';
frame-ancestors 'none'`.

## 3. Errors

Every error has the same body:

```json
{"error": {"code": "not_pending", "message": "connection 42 is not waiting for a decision",
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
| 400 | `invalid_request` | malformed JSON, wrong type, unknown field, value out of range | `{"problems":[{"path":"minutes","message":"must be 1 to 1440"}]}` |
| 400 | `policy_invalid` | a policy document failed validation | `{"problems":["rules[2].match.vendor_id: ..."]}` |
| 400 | `password_policy` | a new password is too weak | `{"problems":["must be at least 12 characters"]}` |
| 401 | `unauthenticated` | no session, or it expired or was ended | null |
| 401 | `invalid_credentials` | wrong user name, password or recovery code | null |
| 401 | `reauthentication_failed` | the confirming password or code was wrong | null |
| 403 | `forbidden` | the role lacks the permission | `{"permission":"manage_trust"}` |
| 403 | `csrf_failed` | `X-PortLock-CSRF` missing or wrong | null |
| 403 | `origin_not_allowed` | section 2 rule 3 | null |
| 403 | `account_disabled` | correct password, disabled account | null |
| 404 | `not_found` | no such object or route | null |
| 405 | `method_not_allowed` | | null |
| 409 | `not_connected` | the connection has ended | null |
| 409 | `not_pending` | the connection is not waiting for a decision | `{"state":"allowed"}` |
| 409 | `unknown_device` | a fingerprint PortLock has never seen | null |
| 409 | `low_confidence` | trust asked for a low-confidence fingerprint without `allow_low_confidence` | null |
| 409 | `grant_invalid` | the grant's fields do not fit its kind, or the expiry is not in the future | null |
| 409 | `policy_conflict` | `expected_hash` does not match the active policy | `{"hash":"<current>"}` |
| 409 | `lockdown_active` / `lockdown_not_active` | wrong lockdown state for the request | null |
| 409 | `invalid_duration` | lockdown minutes out of range | `{"max_minutes":1440}` |
| 409 | `killswitch_active` | enforcement is disabled by the kill-switch file | null |
| 409 | `enforcement_unavailable` | this machine or process cannot enforce | `{"notes":["not running as administrator"]}` |
| 409 | `no_mounted_volume` / `scan_unavailable` / `scan_queue_full` | scan cannot be started | null |
| 409 | `last_admin` | the change would leave no enabled administrator | null |
| 409 | `user_exists` | | null |
| 413 | `body_too_large` | | null |
| 415 | `unsupported_media_type` | body without `application/json` | null |
| 421 | `host_not_allowed` | section 2 rule 2 | null |
| 429 | `locked_out` | the account is locked out | `{"retry_after_seconds":120}` |
| 429 | `rate_limited` / `busy` | login limits, section 5.6 | `{"retry_after_seconds":5}` |
| 500 | `internal_error` | a bug; the message is generic | null |
| 503 | `store_unavailable` | the database could not be read or written | null |
| 503 | `server_busy` / `too_many_streams` | section 2 rule 1; more than 8 event streams | null |

429 responses also carry a `Retry-After` header in whole seconds.

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

### 4.2 `Session` (`auth.sessions.Session`, without the CSRF token)

| Field | Type |
| --- | --- |
| `session_id` | string (16 hex; not secret) |
| `username`, `role` | string |
| `created_at`, `last_seen_at`, `expires_at`, `idle_expires_at` | time |
| `client` | string \| null |

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
| `id` | string | random |
| `fingerprint` | fingerprint | |
| `confidence` | `"high"` \| `"low"` | when granted |
| `kind` | `"trust"` \| `"temporary"` \| `"once"` | |
| `read_only` | bool | |
| `created_at` | time | |
| `granted_by` | string | |
| `expires_at` | time \| null | required for `temporary`; never for `trust` |
| `note` | string | at most 512 characters |
| `bound_instance_id` | string \| null | a one-time grant in use |
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
`remaining_seconds` (int \| null), `renew_count`, `default_minutes`, `max_minutes` (int).

### 4.13 `ModeInfo`

`mode` (the chosen mode), `effective_mode` (what is in force), both `"monitor"` \|
`"enforce"`; `source` (`"config"` \| `"setting"` \| `"killswitch"`); `killswitch` (bool);
`can_enforce` (bool); `notes` (array<string>: why it cannot, if it cannot).

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
| `enforcer` | {`name`: string, `privileged`, `block`, `read_only`, `eject`, `default_deny`: bool, `notes`: array<string>} |
| `counts` | {`connected`, `protected`, `allowed`, `read_only`, `pending`, `denied`, `not_enforced`: int} |
| `audit` | {`head_seq`: int, `head_hash`: string, `keyed`: bool, `backlog`: int, `sink_failures`: int} |
| `journal` | {`open_records`, `corrupt_lines`: int} |
| `degraded` | array<string>: any of `backend`, `store`, `audit`, `audit_chain`, `journal`, `scan` |
| `setup_required` | bool |

### 4.15 `Doctor` (`guard.factory.DoctorReport`)

`generated_at` (time), `platform`, `version` (string), `backend`, `enforcer` (as in
Status, or null), `checks`: array<{`id`: string, `status`: `"ok"` \| `"warn"` \|
`"fail"` \| `"info"`, `summary`: string, `detail`: string}>. The report contains device
counts only, never a serial number, a product name or an instance id.

### 4.16 `Settings`

| Field | Type | Notes |
| --- | --- | --- |
| `config` | object | `Config.to_dict()`: the configuration file as loaded. Read-only here |
| `runtime` | {`protected_fingerprints`: array<fingerprint>, `scan.enabled`: bool, `lockdown.default_minutes`: int} | the three values the API can change |
| `effective` | {`scan_enabled`: bool, `lockdown_default_minutes`: int, `hid_enforcement_enabled`: bool, `scope`: string, `fail_closed`: bool} | what is in force |

---

## 5. Authentication

### 5.1 The flow

1. The client sends the user name and password to `POST /auth/login`.
2. The server answers with the user, the session and a **CSRF token** in the body, and
   sets the **session cookie**:
   `Set-Cookie: portlock_session=<token>; HttpOnly; SameSite=Strict; Path=/; Max-Age=<absolute timeout in seconds>`.
   The token is 256 random bits; the server stores only its SHA-256 digest. The cookie
   has no `Secure` attribute because the API is plain HTTP on loopback by design.
3. Every later request carries the cookie. Every request whose method is not `GET` or
   `HEAD` must also carry `X-PortLock-CSRF: <csrf token>`; otherwise 403 `csrf_failed`.
   The comparison is constant-time. The two login endpoints are the only state-changing
   requests without it (there is no session yet); they are protected by the `Origin`
   rule and the JSON content type.
4. A session ends after 15 minutes without a request (`api.session_idle_minutes`) or 8
   hours after login (`api.session_max_hours`), whichever comes first; on logout; and
   when the account's password or role changes or the account is disabled or deleted.
   An ended session answers 401 `unauthenticated`. The event stream does not count as
   activity.
5. The CSRF token lives in page memory only. After a reload the console gets it again
   from `GET /auth/session`.

Roles and permissions are those of `auth.accounts.can()`, which is authoritative:

| Role | Permissions |
| --- | --- |
| `admin` | all |
| `operator` | `view`, `view_audit`, `approve_device`, `issue_temporary_grant`, `run_scan`, `engage_lockdown` |
| `auditor` | `view`, `view_audit`, `export_audit` |

A known limit, stated plainly: browsers do not scope cookies by port. A program on the
same machine that serves a page on another loopback port, and gets a logged-in
administrator's browser to open it, receives the session cookie. `HttpOnly`,
`SameSite=Strict` and the `Host`/`Origin` rules do not prevent that. Log out when done,
and keep the idle timeout short.

### 5.2 `POST /auth/login` — public

Request: `username` (string), `password` (string).
Response 200: `user` (User), `session` (Session), `csrf_token` (string).
Errors: 401 `invalid_credentials` (identical for an unknown name and a wrong password,
in content and in timing); 403 `account_disabled`; 429 `locked_out`, `rate_limited`,
`busy`.

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
 "csrf_token": "example-csrf-token-not-a-real-one"}
```

`client` is `"console"` when the request carries an `Origin` header and `"cli"`
otherwise; nothing from the request is copied into it.

### 5.3 `POST /auth/logout` — any session

No body. Response 204, with `Set-Cookie: portlock_session=; Max-Age=0; Path=/`. Ends
this session only. Audited as `auth.logout`.

### 5.4 `GET /auth/session` — any session

Response 200: `user` (User), `session` (Session), `csrf_token` (string),
`permissions` (array<string>: what this role may do, for the console to hide what it
cannot).

```json
{"user": {"username": "alice", "role": "admin", "enabled": true, "created_at": "2026-01-01T08:00:00.000000Z",
          "password_changed_at": "2026-01-01T08:00:00.000000Z", "last_login_at": "2026-01-01T09:00:00.000000Z"},
 "session": {"session_id": "0a1b2c3d4e5f6071", "username": "alice", "role": "admin",
             "created_at": "2026-01-01T09:00:00.000000Z", "last_seen_at": "2026-01-01T09:03:00.000000Z",
             "expires_at": "2026-01-01T17:00:00.000000Z", "idle_expires_at": "2026-01-01T09:18:00.000000Z",
             "client": "console"},
 "csrf_token": "example-csrf-token-not-a-real-one",
 "permissions": ["approve_device", "change_mode", "edit_policy", "engage_lockdown", "export_audit",
                 "issue_temporary_grant", "lift_lockdown", "manage_trust", "manage_users", "run_scan",
                 "view", "view_audit"]}
```

### 5.5 Changing a password, and recovery codes

**`POST /auth/password` — any session.** Request: `current_password`, `new_password`
(strings). The current password is checked with the same lockout as a login. On success
every session of the account is ended, a new one is created, and the response is the
same shape as login (new cookie, new CSRF token). Errors: 401 `reauthentication_failed`,
400 `password_policy`, 429 `locked_out`.

```json
// request
{"current_password": "correct horse battery staple", "new_password": "an even longer new passphrase"}
// response 200: as POST /auth/login
```

**`POST /auth/recovery` — public.** For an account whose password is lost. Request:
`username`, `recovery_code`, `new_password` (strings). The code is single-use and is
consumed by this request if it is valid, whether or not the new password is then
accepted. On success the password is set, every session of the account is ended, and
the response is the same shape as login. Recovery codes have their own lockout counter,
so an attacker who locks the password cannot lock this path. Errors: 401
`invalid_credentials`, 400 `password_policy` (the code is spent; use another), 403
`account_disabled`, 429.

```json
// request
{"username": "alice", "recovery_code": "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345", "new_password": "a brand new long passphrase"}
// response 200: as POST /auth/login
```

Recovery codes are issued by `POST /users/{username}/recovery-codes` (6.12).

### 5.6 Login rate limiting

Three limits apply to `POST /auth/login`, `POST /auth/recovery`, `POST /auth/password`
and the re-authentication in `POST /lockdown/lift`. All answer 429 with `Retry-After`.

1. **Per-account lockout** (`locked_out`), implemented by `AccountStore`: five
   consecutive failures start a delay of 30 seconds that doubles to 15 minutes, persisted
   across restarts. A refused attempt does not evaluate the password and does not extend
   the delay. Unknown user names are counted and delayed exactly like real ones, so the
   response never reveals whether a name exists. The API always passes
   `channel=Channel.REMOTE`.
2. **Global budget** (`rate_limited`): at most 30 credential checks in any 60 seconds
   across all names, counted in memory.
3. **Concurrency** (`busy`): at most 8 credential checks in flight.

Limits 2 and 3 exist because every client of a loopback API has the same address, so
there is no per-client limit to apply. They mean a local program can make API logins
fail for a while. It cannot lock an administrator out of the machine: recovery codes
have a separate counter, the command line's local commands use a separate channel, and
`portlock recover` and the kill-switch file need no login at all.

### 5.7 How the command line finds and authenticates to the service

1. **Find.** `--url` or `PORTLOCK_URL` if given; otherwise `runtime.json` in the state
   directory, which the service writes at start:
   `{"v": 1, "pid": 4242, "host": "127.0.0.1", "port": 47600, "run_id": "9f2c4e1ab07d3355", "started_at": "2026-01-01T08:59:00.000000Z", "version": "0.2.0"}`.
   The file is readable only by accounts the operating system lets into the state
   directory.
2. **Verify.** The CLI calls `GET /ping` and requires its `run_id` to equal the one in
   `runtime.json` before sending any credential. A program that grabbed the port cannot
   know that value. With `--url` there is nothing to compare, and the CLI says so.
3. **Authenticate.** `POST /auth/login` with a prompted password (or `--password-stdin`),
   the call itself with the cookie and CSRF header, then `POST /auth/logout`. The CLI
   sends no `Origin` header and stores nothing on disk.
4. **Without the service.** `setup`, `recover`, `user reset-password --local`,
   `user unlock --local`, `audit verify --offline`, `policy validate`, `doctor --offline`
   and `simulate` do not use this API (ARCHITECTURE 4.2).

The **first administrator** is created by `portlock setup` on the machine, never through
this API. Until then `GET /ping` reports `setup_required: true` and every login fails.

---

## 6. Endpoints

Paths are relative to `/api/v1`. "Permission" is what the session's role must have;
"session" means any logged-in user; "public" means no session. Every non-`GET` endpoint
needs the CSRF header unless marked public.

### 6.1 Liveness and status

**`GET /ping` — public.** Enough to find the service and nothing more.

```json
{"service": "portlock", "api": 1, "version": "0.2.0", "run_id": "9f2c4e1ab07d3355",
 "setup_required": false, "simulation": false}
```

Fields: `service`, `version`, `run_id` (string), `api` (int), `setup_required`,
`simulation` (bool).

**`GET /status` — `view`.** Response: Status (4.14).

```json
{"service": "portlock", "version": "0.2.0", "run_id": "9f2c4e1ab07d3355", "host_label": "unnamed-host",
 "platform": "linux", "started_at": "2026-01-01T08:59:00.000000Z", "uptime_seconds": 600, "simulation": false,
 "mode": {"mode": "enforce", "effective_mode": "enforce", "source": "setting", "killswitch": false,
          "can_enforce": true, "notes": []},
 "lockdown": {"state": "idle", "active": false, "engaged_at": null, "engaged_by": null, "reason": null,
              "expires_at": null, "remaining_seconds": null, "renew_count": 0, "default_minutes": 60, "max_minutes": 1440},
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
Not paged: it is bounded by what is plugged in.

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
first. Query: `limit`, `before` (a `last_seen` time), `text` (matches manufacturer,
product, serial or fingerprint). Response: `devices` (array<KnownDevice>),
`next` (time \| null).

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
`scans` (array<Scan> without `report`).

```json
{"connection": {"connection_id": 42, "...": "a Connection"},
 "decisions": [ {"id": 311, "access": "pending", "...": "a Decision"} ], "scans": []}
```

### 6.3 Decisions

**`GET /decisions` — `view`.** The decision history, newest first. Query: `limit`,
`before_id`, `connection_id`, `fingerprint`, `access`. Response: `decisions`
(array of Decision with two more fields: `connection_id` (int), `fingerprint`, and
`enforcement` (Enforcement)), `next` (int \| null).

```json
{"decisions": [ {"id": 311, "connection_id": 42, "fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e",
                 "access": "pending", "source": "default", "trigger": "arrival", "...": "the other Decision fields",
                 "enforcement": {"outcome": "applied", "os_state": "blocked", "...": "an Enforcement"}} ], "next": null}
```

### 6.4 Approving or denying a pending device

**`POST /connections/{connection_id}/approve`.** Permission by `kind`: `once` needs
`approve_device`; `temporary` needs `approve_device` and `issue_temporary_grant`;
`trust` needs `manage_trust`.

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | `"once"` \| `"temporary"` \| `"trust"` | default `"once"` |
| `read_only` | bool | default false |
| `expires_in` | string | `30m`, `2h`, `7d`, ...; for `temporary` give this or `expires_at` |
| `expires_at` | time | must be in the future |
| `note` | string | optional, at most 512 characters |
| `allow_low_confidence` | bool | needed for `trust` on a low-confidence fingerprint: a device without a unique serial shares its fingerprint with every unit of its model |

Response 200: `grant` (Grant), `connection` (Connection, after re-evaluation),
`reevaluated` (array<int>: every connection id that was re-evaluated). The connection's
state tells the outcome. If a policy rule denies the device the grant is created but the
device stays denied, and `connection.decision.reasons` says so: a grant never overrides
an explicit deny. Errors: 409 `not_connected`, `not_pending`, `low_confidence`,
`grant_invalid`.

```json
// request
{"kind": "temporary", "expires_in": "2h", "read_only": true, "note": "contractor laptop backup"}
// response 200
{"grant": {"id": "g_4f7a9c21d0b84e16", "fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e",
           "confidence": "high", "kind": "temporary", "read_only": true,
           "created_at": "2026-01-01T09:05:00.000000Z", "granted_by": "bob",
           "expires_at": "2026-01-01T11:05:00.000000Z", "note": "contractor laptop backup",
           "bound_instance_id": null, "bound_at": null, "ended_at": null, "end_reason": null, "ended_by": null},
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
{"trust": [ {"id": "g_91c0e2aa5b7d4f03", "kind": "trust", "read_only": false, "...": "a Grant"} ]}
```

**`POST /trust` — `manage_trust`.** Request: `fingerprint` (must be a device PortLock has
seen), `read_only` (bool, default false), `note` (string, optional),
`allow_low_confidence` (bool, default false). Response 201: `grant` (Grant),
`reevaluated` (array<int>). Errors: 409 `unknown_device`, `low_confidence`.

```json
// request
{"fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e", "read_only": false, "note": "backup drive, asset 0042"}
// response 201
{"grant": {"id": "g_91c0e2aa5b7d4f03", "kind": "trust", "expires_at": null, "...": "a Grant"}, "reevaluated": [42]}
```

**`DELETE /trust/{grant_id}` — `manage_trust`.** Response 200: `grant` (Grant, ended with
`end_reason: "revoked"`), `reevaluated` (array<int>). A connected device that depended on
the trust is re-evaluated, and blocked if nothing else permits it, before the response is
sent. 404 if there is no such trust grant.

```json
{"grant": {"id": "g_91c0e2aa5b7d4f03", "kind": "trust", "ended_at": "2026-01-01T10:00:00.000000Z",
           "end_reason": "revoked", "ended_by": "alice", "...": "a Grant"}, "reevaluated": [42]}
```

### 6.6 Grants

**`GET /grants` — `view`.** Query: `include_inactive` (bool, default false), `kind`,
`fingerprint`. Response: `grants` (array<Grant>, newest first; all kinds).

```json
{"grants": [ {"id": "g_4f7a9c21d0b84e16", "kind": "temporary", "...": "a Grant"} ]}
```

**`POST /grants` — `issue_temporary_grant`.** A grant for a device that need not be
connected. Request: `fingerprint` (seen before), `kind` (`"temporary"` \| `"once"`;
`"trust"` is refused here, use `/trust`), `read_only` (bool), `expires_in` or
`expires_at` (required for `temporary`, optional for `once`), `note`. Response 201:
`grant` (Grant), `reevaluated` (array<int>). Errors: 409 `unknown_device`,
`grant_invalid`.

```json
// request
{"fingerprint": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e", "kind": "once", "read_only": false, "note": "one-off import"}
// response 201
{"grant": {"id": "g_0d3b6f8e1a2c4957", "kind": "once", "expires_at": null, "...": "a Grant"}, "reevaluated": []}
```

**`DELETE /grants/{grant_id}`.** Permission: `issue_temporary_grant` for a `temporary` or
`once` grant; `manage_trust` for a `trust` grant. Response 200: `grant`, `reevaluated`,
as `DELETE /trust/{grant_id}`. Revoking an ended grant is 404.

```json
{"grant": {"id": "g_0d3b6f8e1a2c4957", "end_reason": "revoked", "ended_by": "bob", "...": "a Grant"}, "reevaluated": []}
```

### 6.7 Policy

**`GET /policy` — `view`.** Response: PolicyInfo (4.9).

```json
{"policy": {"version": 1, "name": "PortLock default policy",
            "default": {"access": "pending", "scan": "on_mount", "alert": false},
            "rules": [{"id": "deny-storage-with-input", "enabled": true, "expires": null,
                       "description": "...", "match": {"storage_with_input": true},
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
`policy` (object), `expected_hash` (string, optional: the hash the client last saw; a
mismatch is 409 `policy_conflict`, so two administrators cannot silently overwrite each
other). Response 200: PolicyInfo plus `previous_hash` (string) and `reevaluated`
(array<int>). Errors: 400 `policy_invalid`, 409 `policy_conflict`.

```json
// request
{"expected_hash": "3b1f...e9", "policy": {"version": 1, "name": "site policy", "default": {"access": "pending"},
  "rules": [{"id": "trust-lab-vendor", "match": {"vendor_id": "0x1209", "confidence": "high"},
             "action": {"access": "read_only", "scan": "required"}}]}}
// response 200
{"policy": {"...": "as stored"}, "hash": "c4d2...10", "name": "site policy", "rules": 1, "source": "file",
 "loaded_at": "2026-01-01T09:30:00.000000Z", "previous_hash": "3b1f...e9", "reevaluated": [42, 43]}
```

**`POST /policy/test` — `view`.** What would the policy do with this device? Changes
nothing. Request: exactly one of `connection_id` (int), `fingerprint` (a known device;
its last description is used) or `device` (a Device object; `instance_id`, `volumes` and
`categories` may be omitted); optionally `policy` (a draft document; default: the active
policy) and `at` (time; default: now). Response 200:

| Field | Type | Notes |
| --- | --- | --- |
| `fingerprint` | {`value`: fingerprint, `confidence`: string, `basis`: array<string>} | of the tested device |
| `policy_hash` | string | of the policy that was tested |
| `result` | {`access`, `scan`: string, `alert`: bool, `rule_id`: string \| null, `matched_default`: bool, `skipped`: array<{`rule_id`, `reason`: string}>, `explanation`: array<string>, `valid_until`: time \| null} | the policy alone |
| `trace` | array<{`rule_id`, `outcome`, `summary`: string, `would_match`: bool, `criteria`: array<{`criterion`, `detail`: string, `matched`: bool}>}> | every rule; `outcome` is `matched`, `shadowed`, `no_match`, `disabled`, `expired` |
| `decision` | Decision fields `access`, `source`, `reasons`, `rule_id`, `grant_id`, `scan`, `alert`, `expires_at` | the full precedence: safety, lockdown, policy, grants |

Errors: 400 `policy_invalid` (the draft), 404 `not_found`, 409 `unknown_device`.

```json
// request
{"device": {"vendor_id": 4617, "product_id": 5, "serial": "TEST0005BAD1", "product": "Example Flash 16GB",
            "interfaces": [{"cls": 8, "subcls": 6, "protocol": 80}, {"cls": 3, "subcls": 1, "protocol": 1}],
            "removable": true}}
// response 200
{"fingerprint": {"value": "plk1:b2c4d6e2f3g5h7j2k4m6n2p4q6r2s4t6", "confidence": "high", "basis": ["vid", "pid", "serial", "product", "ifaces"]},
 "policy_hash": "3b1f...e9",
 "result": {"access": "deny", "scan": "none", "alert": true, "rule_id": "deny-storage-with-input",
            "matched_default": false, "skipped": [], "explanation": ["storage_with_input: the device pairs storage with an input interface"],
            "valid_until": null},
 "trace": [{"rule_id": "deny-storage-with-input", "outcome": "matched", "would_match": true,
            "summary": "matched: deny", "criteria": [{"criterion": "storage_with_input", "matched": true, "detail": "..."}]}],
 "decision": {"access": "deny", "source": "policy", "reasons": ["rule deny-storage-with-input denies this device"],
              "rule_id": "deny-storage-with-input", "grant_id": null, "scan": "none", "alert": true, "expires_at": null}}
```

### 6.8 Audit

**`GET /audit` — `view_audit`.** Query, all optional: `since_seq`, `until_seq` (int);
`since`, `until` (time); `type` (repeatable event type); `min_severity`; `device_fp`;
`actor`; `text` (substring of the stored data); `limit` (1–500, default 100); `order`
(`desc` default, or `asc`). Response: `records` (array<AuditRecord>), `head` ({`seq`:
int, `hash`: string}), `next` (int \| null: pass as `until_seq` for `desc`, `since_seq`
for `asc`).

```json
{"records": [{"seq": 1280, "ts": "2026-01-01T09:05:00.120000Z", "event_type": "grant.created",
              "severity": "notice", "actor": "bob", "device_fp": "plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e",
              "data": {"grant": {"id": "g_4f7a9c21d0b84e16", "kind": "temporary", "read_only": true}, "connection_id": 42},
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
| `macs_checked` | int | 0 means no key is configured: a fully rebuilt chain would not be noticed |
| `head` | {`seq`: int, `hash`: string} \| null | last record that verified |
| `keyed` | bool | |

```json
// request
{"expected_head": {"seq": 1200, "hash": "5e11...9a"}}
// response 200
{"ok": true, "checked": 1281, "first_bad_seq": null, "reason": null, "macs_checked": 0,
 "head": {"seq": 1281, "hash": "a0c3...5d"}, "keyed": false}
```

**`GET /audit/export` — `export_audit`.** Query: `since_seq` (int, default 1). Response
200 with `Content-Type: application/x-ndjson` and
`Content-Disposition: attachment; filename="portlock-audit.jsonl"`: one canonical-JSON
AuditRecord per line, in sequence order, streamed. Verify it with
`portlock audit verify` or any implementation of the chain in `audit/log.py`.

```
{"actor":null,"data":{"version":"0.2.0"},"device_fp":null,"event_type":"service.started","hash":"...","mac":null,"prev_hash":"...","seq":1,"severity":"info","ts":"2026-01-01T08:59:00.000000Z"}
```

**`GET /audit/checkpoint` — `export_audit`.** The current head, for keeping somewhere
the local administrator cannot rewrite. Response: `checkpoint` ({`seq`, `count`: int,
`hash`: string, `ts`: time}), `signed_event` (object \| null: the checkpoint as a signed
security event, `docs/SECURITY_EVENT_FORMAT.md`; null when the optional signing support
is not installed).

```json
{"checkpoint": {"seq": 1281, "hash": "a0c3...5d", "ts": "2026-01-01T09:40:00.000000Z", "count": 1281},
 "signed_event": null}
```

### 6.9 Scans

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
            "verdict": null, "summary": null}]}
```

**`GET /scans` — `view`.** Query: `limit`, `before_id`, `connection_id`, `fingerprint`.
Response: `scans` (array<Scan> without `report`), `next` (int \| null).

```json
{"scans": [{"id": 7, "state": "done", "verdict": "clean",
            "summary": {"files_seen": 212, "files_hashed": 212, "bytes_hashed": 48211200,
                        "findings": {"info": 0, "suspicious": 0, "malicious": 0}, "errors": 0, "truncated_reason": null},
            "...": "the other Scan fields"}], "next": null}
```

**`GET /scans/{id}` — `view`.** Response: `scan` (Scan with `report`).

```json
{"scan": {"id": 7, "state": "done", "verdict": "suspicious", "...": "the other Scan fields",
          "report": {"root": "/media/test", "verdict": "suspicious", "files_seen": 212,
                     "findings": [{"path": "autorun.inf", "engine": "heuristics", "rule": "autorun-inf",
                                   "severity": "suspicious", "detail": "open=setup.exe", "sha256": null}],
                     "errors": [], "engines": [{"name": "heuristics", "available": true, "version": null}],
                     "...": "the rest of ScanReport.to_dict()"}}}
```

### 6.10 Lockdown

**`GET /lockdown` — `view`.** Response: Lockdown (4.12).

```json
{"state": "active", "active": true, "engaged_at": "2026-01-01T10:00:00.000000Z", "engaged_by": "bob",
 "reason": "suspected intrusion", "expires_at": "2026-01-01T11:00:00.000000Z", "remaining_seconds": 3180,
 "renew_count": 0, "default_minutes": 60, "max_minutes": 1440}
```

**`POST /lockdown/engage` — `engage_lockdown`.** Blocks all removable storage and puts
the OS into default-deny for new devices, **in monitor mode too**. Protected devices are
never touched. It lifts itself at `expires_at` unless renewed. Request: `minutes` (int,
1–`max_minutes`, default `default_minutes`), `reason` (string, optional, at most 256
characters). Response 200: `lockdown` (Lockdown), `summary` ({`evaluated`, `changed`,
`blocked`, `read_only`, `released`, `failed`: int}), `default_deny`
(`"applied"` \| `"failed"` \| `"unsupported"`). Errors: 409 `lockdown_active` (use
renew), `invalid_duration`, `killswitch_active`, `enforcement_unavailable`.

```json
// request
{"minutes": 60, "reason": "suspected intrusion"}
// response 200
{"lockdown": {"state": "active", "active": true, "expires_at": "2026-01-01T11:00:00.000000Z", "...": "a Lockdown"},
 "summary": {"evaluated": 4, "changed": 1, "blocked": 1, "read_only": 0, "released": 0, "failed": 0},
 "default_deny": "applied"}
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
so). Errors: 401 `reauthentication_failed`, 429 `locked_out`, 409 `lockdown_not_active`.

```json
// request
{"password": "correct horse battery staple"}
// response 200
{"lockdown": {"state": "idle", "active": false, "expires_at": null, "...": "a Lockdown"},
 "summary": {"evaluated": 4, "changed": 1, "blocked": 0, "read_only": 0, "released": 1, "failed": 0}}
```

If the service is not running, the lockdown is lifted with `portlock recover`, which
needs operating-system administrator rights and no PortLock login.

### 6.11 Mode, doctor, settings

**`GET /mode` — `view`.** Response: ModeInfo (4.13).

```json
{"mode": "monitor", "effective_mode": "monitor", "source": "config", "killswitch": false, "can_enforce": true, "notes": []}
```

**`PUT /mode` — `change_mode`.** Request: `mode` (`"monitor"` \| `"enforce"`). Switching
to `enforce` applies every current decision; switching to `monitor` puts back everything
PortLock changed (an active lockdown excepted). Response 200: `mode` (ModeInfo),
`summary` (as lockdown engage). Errors: 409 `killswitch_active`,
`enforcement_unavailable`.

```json
// request
{"mode": "enforce"}
// response 200
{"mode": {"mode": "enforce", "effective_mode": "enforce", "source": "setting", "killswitch": false, "can_enforce": true, "notes": []},
 "summary": {"evaluated": 4, "changed": 0, "blocked": 1, "read_only": 0, "released": 0, "failed": 0}}
```

**`GET /doctor` — `view`.** What this machine can do right now. Response: Doctor (4.15).

```json
{"generated_at": "2026-01-01T09:00:00.000000Z", "platform": "linux", "version": "0.2.0",
 "backend": {"name": "linux", "event_driven": true, "healthy": true, "last_error": null, "notes": []},
 "enforcer": {"name": "linux", "privileged": true, "block": true, "read_only": true, "eject": true, "default_deny": true, "notes": []},
 "checks": [{"id": "guard.privilege", "status": "ok", "summary": "running with administrator rights", "detail": ""},
            {"id": "guard.detect", "status": "ok", "summary": "device arrival is event-driven", "detail": ""},
            {"id": "guard.enumerate", "status": "info", "summary": "4 USB devices present", "detail": ""},
            {"id": "service.audit", "status": "warn", "summary": "no HMAC key configured", "detail": "a fully rewritten log would not be detected locally"}]}
```

**`GET /settings` — `view`.** Response: Settings (4.16).

```json
{"config": {"mode": "monitor", "scope": "storage", "hid_enforcement": false, "...": "Config.to_dict()"},
 "runtime": {"protected_fingerprints": [], "scan.enabled": true, "lockdown.default_minutes": 60},
 "effective": {"scan_enabled": true, "lockdown_default_minutes": 60, "hid_enforcement_enabled": false,
               "scope": "storage", "fail_closed": false}}
```

**`PATCH /settings` — `edit_policy`.** Changes one or more of the three run-time
settings; each change is audited as `config.changed`. Request: any of
`protected_fingerprints` (array<fingerprint>, each a device PortLock has seen; replaces
the list), `scan.enabled` (bool), `lockdown.default_minutes` (int, 1–`max_minutes`).
Response 200: Settings plus `reevaluated` (array<int>). Everything else in `config`
(scope, HID enforcement, `fail_closed`, the API address, paths, authentication and audit
settings) can be changed only in the configuration file, by someone with
operating-system rights, followed by a restart: it is deliberately out of reach of the
web console. Errors: 400 `invalid_request`, 409 `unknown_device`.

```json
// request
{"protected_fingerprints": ["plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e"]}
// response 200
{"config": {"...": "unchanged"}, "runtime": {"protected_fingerprints": ["plk1:k7q2m4xw3n5p6r7s2t4v6y3a5b7c2d4e"],
 "scan.enabled": true, "lockdown.default_minutes": 60}, "effective": {"...": "as GET"}, "reevaluated": [42]}
```

### 6.12 Users

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
`password`, `role`. Response 201: `user`. Errors: 400 `invalid_request`,
`password_policy`; 409 `user_exists`.

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
**once** and stored only as digests. No body. Response 200: `username`, `codes`
(array<string>, 8 codes), `issued_at` (time).

```json
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
- The first frame is always `hello`.
- At most 8 streams are open at once (503 `too_many_streams`). A client that cannot keep
  up is disconnected and should reconnect.
- The stream ends when the session ends. It is not activity: an open stream does not
  keep a session alive. Before closing for that reason the server sends `session.ended`.
- `audit.appended` frames are sent only to sessions with `view_audit`.

### 7.2 Resuming

On reconnect the browser sends `Last-Event-ID`; a client may instead pass
`?since=<run_id>-<seq>`.

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

| Method | Path | Permission | CSRF |
| --- | --- | --- | --- |
| GET | `/ping` | public | — |
| POST | `/auth/login` | public | no |
| POST | `/auth/recovery` | public | no |
| POST | `/auth/logout` | session | yes |
| GET | `/auth/session` | session | — |
| POST | `/auth/password` | session | yes |
| GET | `/status` | `view` | — |
| GET | `/devices` | `view` | — |
| GET | `/devices/history` | `view` | — |
| GET | `/devices/known` | `view` | — |
| GET | `/devices/{fingerprint}` | `view` | — |
| GET | `/connections/{id}` | `view` | — |
| GET | `/decisions` | `view` | — |
| POST | `/connections/{id}/approve` | `approve_device` (+ `issue_temporary_grant` or `manage_trust` by kind) | yes |
| POST | `/connections/{id}/deny` | `approve_device` | yes |
| GET | `/trust` | `view` | — |
| POST | `/trust` | `manage_trust` | yes |
| DELETE | `/trust/{grant_id}` | `manage_trust` | yes |
| GET | `/grants` | `view` | — |
| POST | `/grants` | `issue_temporary_grant` | yes |
| DELETE | `/grants/{grant_id}` | `issue_temporary_grant` or `manage_trust` by kind | yes |
| GET | `/policy` | `view` | — |
| POST | `/policy/validate` | `view` | yes |
| PUT | `/policy` | `edit_policy` | yes |
| POST | `/policy/test` | `view` | yes |
| GET | `/audit` | `view_audit` | — |
| POST | `/audit/verify` | `view_audit` | yes |
| GET | `/audit/export` | `export_audit` | — |
| GET | `/audit/checkpoint` | `export_audit` | — |
| POST | `/scans` | `run_scan` | yes |
| GET | `/scans` | `view` | — |
| GET | `/scans/{id}` | `view` | — |
| GET | `/lockdown` | `view` | — |
| POST | `/lockdown/engage` | `engage_lockdown` | yes |
| POST | `/lockdown/renew` | `engage_lockdown` | yes |
| POST | `/lockdown/lift` | `lift_lockdown` + password or recovery code | yes |
| GET | `/mode` | `view` | — |
| PUT | `/mode` | `change_mode` | yes |
| GET | `/doctor` | `view` | — |
| GET | `/settings` | `view` | — |
| PATCH | `/settings` | `edit_policy` | yes |
| GET | `/users` | `manage_users` | — |
| POST | `/users` | `manage_users` | yes |
| PUT | `/users/{username}/role` | `manage_users` | yes |
| POST | `/users/{username}/disable` | `manage_users` | yes |
| POST | `/users/{username}/enable` | `manage_users` | yes |
| POST | `/users/{username}/password` | `manage_users` | yes |
| POST | `/users/{username}/recovery-codes` | `manage_users` or own account | yes |
| POST | `/users/{username}/unlock` | `manage_users` | yes |
| DELETE | `/users/{username}` | `manage_users` | yes |
| GET | `/events` | `view` | — |

Outside `/api/v1`: `GET /` and `GET /static/...` serve the web console's files without a
session (they contain no data); every other path is 404.
