# AuthOS security architecture

Status: implementation map, not a security or conformance guarantee

Reviewed: 2026-07-14

This document maps security-relevant behavior to the current repository. It
deliberately distinguishes source-visible mechanisms from verified controls.
See the [threat model](./threat-model.md) for abuse cases and open risks, and the
[authentication enumeration and context matrix](./auth-enumeration-and-context.md)
for public auth response policy, context binding, and timing qualification. The
[tenant-resource inventory](./tenant-resource-inventory.md) defines the
isolation surface.

## System and deployment boundary

The main process is a Rust/Axum HTTP API backed by one SeaORM database
connection configuration. Build features select SQLite, PostgreSQL, or MySQL.
The process also starts cleanup, refresh, metrics, event, webhook/email-job, and
buffered-audit work (`api/src/lib.rs`, `api/crates/authos-services/src/jobs/`, `api/crates/authos-services/src/services/`).

The API binds to `SERVER_HOST`/`SERVER_PORT`; `BASE_URL` supplies the public
issuer/origin. TLS termination, firewalling, database encryption, filesystem
permissions, container isolation, and reverse-proxy policy are outside the
Rust process and must be supplied by the deployment. HSTS,
`X-Content-Type-Options`, and `X-Frame-Options` response headers are set by the
application, but HSTS is effective only over HTTPS (`api/src/lib.rs`).

## Route security domains

| Domain | Authentication boundary | Source |
| --- | --- | --- |
| Public/authentication | No prior session; auth and device routes have IP rate-limit layers | `api/src/router.rs` |
| User and organization API | RS256 bearer JWT plus a matching non-expired database session | `api/src/middleware.rs` |
| Platform API | Authenticated user plus current database `is_platform_owner` | `api/src/router.rs`, `api/src/middleware.rs` |
| Service API | `X-Api-Key` resolved to a service principal and permission list | `api/src/middleware.rs` |
| SCIM API | Hashed bearer token resolved to one active, unexpired organization context | `api/src/middleware.rs` |
| SAML IdP endpoints | Public request initiation/metadata; protected service configuration and IdP-initiated route | `api/src/router.rs`, `api/src/handlers/saml.rs` |
| Webhooks from billing providers | Provider-specific verification in webhook handlers; no generic user session | `api/src/lib.rs`, `api/src/handlers/webhook.rs` |
| Health and metrics | Health probes are public; metrics are disabled by default and require a configured bearer token when enabled | `api/src/lib.rs`, `api/src/http_security.rs`, `api/src/router.rs` |

All routes receive a 30-second request timeout and a configurable streaming
request-body bound that defaults to 1 MiB. Dynamic CORS determines which browser
origins receive credentialed CORS headers; it is not relied on as server-side
authorization (`api/src/lib.rs`, `api/src/http_security.rs`,
`api/src/middleware.rs`).

## Identity, authorization, and tenant context

### Authenticated user

An ordinary access token contains `sub`, email, platform-owner flag, `jti`,
optional organization/service/resource/scope context, `iat`, and `exp`. The JWT
is signed with RS256. Middleware validates the JWT, hashes the exact token, and
requires a non-expired session row with that hash before loading the current
user and permissions from the database (`api/crates/authos-crypto/src/crypto/jwt.rs`,
`api/src/middleware.rs`, `api/crates/authos-store/src/store/sessions.rs`).

The platform-owner check uses the freshly loaded/cached user model rather than
only trusting the token's flag. The user cache has a 30-second TTL; permission
cache has a 60-second TTL. Some authorization changes explicitly invalidate
caches, but comprehensive invalidation evidence is not yet published
(`api/src/state.rs`, `api/src/lib.rs`).

### Platform authority and service-token boundaries

Platform authority requires all of the following at request time:

1. a management token minted for the platform context (`aud=platform`, no
   organization or service claim, and no actor claim);
2. a current, non-deleted `is_platform_owner` database row;
3. an enrolled TOTP factor; and
4. a signed `mfa_verified=true` marker proving that the current token came from
   the MFA completion flow, not merely from a session whose account has MFA
   enrolled.

Impersonation tokens always carry an actor claim and are never platform-context
management tokens. Tenant- and service-scoped tokens never carry platform
authority, even if the user row is later promoted. Promotion revokes every
session and refresh-token family and requires a fresh login; platform owners
must enroll MFA before the platform route boundary allows access. A passkey-only
login or an access-token refresh does not restore platform authority, so the
owner must complete password or magic-link sign-in and the MFA challenge again.
Tenant handlers that grant a platform owner implicit bypass use the same live
context, role, deletion, MFA-enrollment, and MFA-completion checks
(`api/src/middleware.rs`).

Service-login tokens are delivered to a relying party. They are accepted only
for `GET /api/user` and `GET /api/subscription`; all organization, privacy,
account-security, MFA, device, and platform routes reject them. Account email,
password, and MFA changes additionally require recent session authentication
plus the configured password/MFA factors. Magic-link verification honors
enrolled MFA. Platform-context browser logins are restricted to configured
platform origins so a tenant custom domain cannot receive a platform session.

The one-time bootstrap login is the deliberate exception. A browser bootstrap
link requires enrolled MFA when a factor is present; a no-Origin call from the
local standalone installer receives a bootstrap session that may perform
initial provisioning. The bootstrap token is a local one-time credential, the
session is revoked when MFA is enabled, and platform-owner password/OAuth
sessions still require an MFA-completed token.

### Tenant authorization

Organizations are the tenant root. Services belong to an organization; many
other records derive tenant context through a service or user. Handlers combine:

- membership rows with built-in roles such as owner/admin/member;
- relationship tuples stored as namespace/object/relation permissions;
- resource-specific checks that bind a service, role, webhook, SCIM token, or
  configuration record to the organization resolved from the route; and
- active-organization checks for selected feature routes.

The database is shared and no database row-level-security policy was found.
Isolation is therefore an application invariant: every lookup and mutation
must carry or derive the correct tenant predicate. The source contains many
specific checks and tests. The CI-checked
[tenant-isolation matrix](./tenant-isolation-matrix.json) now detects unrecorded
SeaORM entities and route paths and validates named local evidence, but it is
explicitly partial and does not establish complete method, actor, identifier,
database, or timing coverage.

### Service and provisioning principals

API keys contain a visible random prefix and a 32-byte random secret component.
Only SHA-256 of the full value is stored; verification compares hashes without
early byte exit. Middleware checks expiry, loads the bound service, rechecks
that its organization is currently active, and exposes the stored permission
list. Service-principal user and provider-token paths require the identity's
issuing organization and service plus the user's tenant row to match the
principal (`api/crates/authos-crypto/src/crypto/api_key.rs`, `api/src/middleware.rs`,
`api/crates/authos-store/src/store/identities.rs`).

SCIM tokens are random UUID-derived values stored as SHA-256 hashes with an
active flag and optional expiry. Middleware binds the request to the token's
`org_id` and rejects a conflicting `X-Organization-ID`. Handlers use that
context for user membership and group operations
(`api/crates/authos-store/src/store/scim_tokens.rs`, `api/src/handlers/scim/`).

Hashing is appropriate for high-entropy bearer values only if generation,
single display, transport, rotation, and database handling are also correct;
those lifecycle properties still need end-to-end evidence.

## Credential and secret storage

| Material | Current representation | Status |
| --- | --- | --- |
| User passwords | Argon2 password-hash string with random salt | Source-evidenced in `api/src/handlers/auth/password.rs`; parameter policy and upgrade strategy unverified. |
| MFA backup codes | Individual Argon2 hashes | Source-evidenced in `api/crates/authos-crypto/src/crypto/mfa.rs` and TOTP store paths. |
| TOTP secret | AES-256-GCM versioned envelope plus active key ID | Source-evidenced; previous-key reads and database-wide verification/rewrap are locally tested, but all-database and retirement evidence remain gaps. |
| Access-token session reference | SHA-256 hash of the complete JWT | Source-evidenced; the signed JWT itself remains bearer material at clients. |
| Refresh token | 256-bit opaque value represented only by a SHA-256 session hash and consumed-ancestor history | Local SQLite storage/replay evidence exists; PostgreSQL/MySQL runtime and multi-replica qualification remain. |
| Email verification, password reset, magic-link token | SHA-256 hash plus expiry and conditional-used/deletion state | SQLite races prove one winner for all three; handler/context, all-database, and multi-replica evidence remains incomplete. |
| API key / SCIM token | Prefix plus SHA-256 hash | Source-evidenced. |
| Service client secret | Hash in service record | Source-evidenced at schema level; issuance/rotation tests required. |
| Organization OAuth, billing, SMTP, upstream-provider credentials | Record/field-bound AES-256-GCM V2 envelope plus active key ID | Source-evidenced in entity/store/handler paths; legacy and V1 reads remain available only for migration through the active/previous keyring. |
| SAML signing private key | Record/field-bound AES-256-GCM V2 envelope; public certificate stored separately | Source-evidenced in `api/src/handlers/saml.rs`. |
| Connected-account provider tokens | Record/field-bound encrypted columns; legacy plaintext columns retained only as a migration bridge | Encrypted runtime rejects plaintext compatibility values and startup requires a complete maintenance rewrap first. Column removal still requires the documented all-database, backup-window, rollback, and retirement criteria. |
| Webhook signing secret | Record/field-bound ciphertext column; legacy plaintext column retained empty for migration compatibility | New writes and delivery reads require encryption. `rewrap-secrets` explicitly migrates old plaintext rows; plaintext runtime fallback is rejected. PostgreSQL/MySQL and restore qualification remain. |
| SIEM API key/auth header | Record/field-bound ciphertext encoded into compatibility text columns | New writes and reads require encryption and reject plaintext/damaged fallback. The rewrap inventory migrates unambiguous plaintext and stops on ambiguous base64 text. Dedicated key-ID columns are unnecessary because V2 embeds its authenticated key ID. |
| OAuth PKCE verifier and transaction state | Plaintext, expiring database state | Expected server-side transaction material, but database/backups must be protected and cleanup tested. |
| JWT private/public key and data-encryption keyrings | Environment variables | JWT issuance uses one active private key while active/previous public keys support verification overlap. The active data-encryption key is required for normal startup; a validated active ID and optional read-only previous keys support decryption overlap. Material remains operator-controlled; there is no integrated secret manager or completed key-retirement lifecycle. |

`EncryptionService` requires an active 32-byte hex key, validates its key ID,
and accepts an optional read-only previous-key registry. It generates a random
96-bit nonce and writes an AES-256-GCM envelope containing magic bytes, format
version, key ID, nonce, and ciphertext (`api/crates/authos-crypto/src/encryption/mod.rs`). V2
authenticates the header plus length-delimited physical table, record ID, and
field context. Legacy `nonce || ciphertext` and V1 values remain readable by
context-aware callers for staged migration and are rewritten as V2.
Missing referenced keys, malformed/unsupported envelopes, and authentication
failure fail closed; tests cover old/new reads, header tampering, missing keys,
and idempotent per-value rewrap.

This is a bounded rotation control, not closure of the storage control. The
default-dry-run `rewrap-secrets` command inventories 14 values across ten
tables, authenticates active values, and rewrites changed batches and sibling
key-ID metadata transactionally. Every write uses compare-and-swap predicates,
so a concurrent secret update aborts and rolls back the batch instead of being
overwritten. Local SQLite tests cover interruption/resume, idempotence,
context-swap rejection, conflicts, ambiguity, and tamper rollback.
PostgreSQL/MySQL plus key-retirement/restore drills remain unproved. Older
binaries cannot read the new envelope, so mixed-version writers and in-place
binary-only rollback are unsafe after the first new write.

Encrypted server startup performs the same complete inventory as a read-only
gate after schema migration but before platform bootstrap, workers, external
service checks, or HTTP routing. Any legacy/V1/previous-key ciphertext,
plaintext compatibility value, ambiguity, missing key, or authentication error
refuses startup with counts and record identifiers but never secret values.
Only the separately invoked, quiesced `rewrap-secrets --apply` maintenance
command can modify these rows. The startup inventory uses 100-row stable-ID
cursor pages and a five-minute deadline. It is race-safe against local writers
because none have started, but is not a cross-replica lock; all peer processes
must remain quiesced until multiwriter qualification exists. Local SQLite
restored-copy tests cover exact
identity/connected-account field context, four-token old-key reads, rewrap,
runtime reads after old-key removal, report canary redaction, and failure when
the old key is removed while an unrewrapped retained backup still needs it.

Server startup fails before database initialization when `ENCRYPTION_KEY` is
missing or malformed. The narrowly named
`AUTHOS_ALLOW_UNENCRYPTED_DEVELOPMENT=true` escape hatch permits only a missing
key and is limited to disposable development/test data. This startup control
does not by itself prove that every storage path is encrypted. The rewrap
command migrates unambiguous identity, connected-account, SIEM, and webhook
compatibility values. Ambiguous SIEM text stops safely. Runtime plaintext
fallback has been removed for SIEM, webhook, identity, and connected-account
secrets whenever encryption is configured; the older identity and
connected-account compatibility columns still need a final removal decision.

## Authentication transactions

### Password and account recovery

Password registration and changes hash with Argon2. Login performs an Argon2
verification even when no usable account password exists, reducing a direct
timing distinction. Request-time password and backup-code Argon2 operations are
offloaded to the blocking pool behind one CPU-scaled semaphore, reject inputs
over 1,024 UTF-8 bytes, and shed work that waits more than two seconds for a
permit. Verified-email, organization status/context, risk, MFA, and session
creation are applied in the handler flow. Reset tokens expire after an hour,
are conditionally marked used, and password reset deletes all user sessions
(`api/src/handlers/auth/password.rs`, `api/crates/authos-crypto/src/crypto/concurrency.rs`).

Deterministic handler tests cover the normalized response shapes, and the
bounded timing sampler described in the
[authentication enumeration and context matrix](./auth-enumeration-and-context.md)
can collect deployment observations without asserting constant-time behavior.
Seeded deployment timing evidence, password-policy documentation,
lockout/credential-stuffing analysis, compromised-password policy decisions,
and transaction-failure tests around token consumption and password update are
still required.

### MFA

TOTP uses six digits, a 30-second step, and a one-step skew window. Backup codes
are random alphanumeric values stored as Argon2 hashes. MFA login uses a
five-minute pre-auth JWT and consumes its `jti` under a database-backed
distributed lock before session creation (`api/crates/authos-crypto/src/crypto/mfa.rs`,
`api/src/handlers/auth/mfa.rs`). MFA verification and setup routes have tighter
IP rate limits.

Platform owners must enroll TOTP and complete the MFA challenge in the current
login before platform routes are available. Account factor changes require
recent authentication plus a current password and/or MFA code, revoke existing
sessions, and return a fresh session after the factor is proven. Magic links
challenge enrolled MFA rather than issuing a full session. Passkey-only and
refreshed platform sessions do not inherit platform authority. Recovery
assurance, factor-reset policy, backup-code atomicity, and pre-auth replay
across replicas remain release-evidence items.

### Magic links and passkeys

Magic-link tokens expire after 15 minutes, are stored hashed, and are deleted
before authentication continues. Stored context binds service and redirect
parameters in the reviewed flow (`api/crates/authos-store/src/store/magic_links.rs`,
`api/src/handlers/auth/magic.rs`).

Passkeys use `webauthn-rs`. Registration requires an authenticated user;
authentication begins from a scoped user lookup. Serialized ceremony state is
stored for five minutes and deleted before completion. RP configuration is
enabled only for localhost or a domain-backed HTTPS `BASE_URL`, and successful
authentication applies the library-validated result to the complete serialized
credential plus its denormalized counter/backup flags using an optimistic
compare-and-update. A SQLite race proves stale ceremony state cannot overwrite
the winning credential state (`api/src/lib.rs`, `api/crates/authos-services/src/services/webauthn.rs`,
`api/crates/authos-store/src/store/user_passkeys.rs`, `api/src/handlers/auth/passkeys.rs`).

SQLite also proves one-winner WebAuthn challenge deletion and expiry lookup.
Cross-origin/RP integration, cloned-authenticator behavior with real devices,
discoverable credentials, multi-replica replay, and deployment
account-enumeration timing still require dedicated evidence.

## Token and session model

| Token profile | Format and audience | Validation boundary |
| --- | --- | --- |
| Platform, organization, or service access token | RS256 `Claims`; `typ=authos-management+jwt`; `token_use=management_access`; `platform`, `org:<slug>`, or `service:<org>/<service>` | Exact active-or-previous verification-ring `kid`, issuer, derived audience, type/use, and absence of MFA/actor state at AuthOS authenticated API middleware. |
| Resource-scoped access token | RS256 `Claims`; `typ=at+jwt`; `token_use=external_resource_access`; registered absolute resource URI | Exact active-or-previous verification-ring `kid`, issuer, type/use, and exact resource at token exchange and each external resource server. Rejected by AuthOS authenticated API middleware. |
| MFA pre-authentication token | RS256 `Claims`; `typ=authos-mfa-preauth+jwt`; `token_use=mfa_preauth`; preserves the eventual access-token audience | Exact active-or-previous verification-ring `kid`, issuer, bounded internal/resource audience, five-minute expiry, exact MFA flags, no actor, and one-time `jti` consumption. |
| Impersonation token | RS256 `Claims`; `typ=authos-impersonation+jwt`; `token_use=impersonation`; `act`; `impersonation-session` | Exact active-or-previous verification-ring `kid`, issuer, fixed audience, type/use, 15-minute expiry, required actor, matching live session, and current actor/target tenant authority. |
| ID-JAG authorization grant | RS256 `IdJagClaims`; `typ=oauth-id-jag+jwt`; `token_use=id_jag`; AuthOS issuer URL audience | Separate validator enforces exact active-or-previous verification-ring `kid`, type/use, issuer, expected audience, expiry, and one-time database grant. |
| Refresh token | 256-bit opaque value stored only as a SHA-256 hash; no JWT audience | Transactional conditional family rotation, consumed-ancestor replay revocation, session context, and expiry checks. |

- Access-token lifetime is configured by `JWT_EXPIRATION_HOURS` (default 24).
- Refresh tokens are issued for 30 days in reviewed authentication paths and
  rotate using a compare-and-update operation.
- Impersonation tokens expire after 15 minutes, carry an `act` actor claim and
  the fixed `impersonation-session` audience, and require a live hash-matching
  session. Middleware bypasses user/permission caches for this profile and
  rechecks platform-owner authority or the actor's current owner/admin role,
  active organization, and target membership on every request. Logout and
  session deletion revoke the token immediately, and an impersonation context
  cannot mint another impersonation token.
- MFA pre-auth tokens expire after five minutes and carry `mfa_required` and
  `mfa_verified` state.
- ID-JAG authorization grants expire after five minutes and validate their
  custom type, issuer, and expected audience.

Every signed JWT profile carries both a distinct JOSE `typ` and signed
`token_use`. Profile validators fix the algorithm to RS256, require an exact
active-or-previous verification-ring `kid`, `exp`, `iss`, and `aud`, compare the
issuer, and enforce profile-specific audience, MFA, scope, and actor invariants
(`api/crates/authos-crypto/src/crypto/jwt.rs`). AuthOS authenticated API middleware accepts only
management and impersonation profiles; resource and MFA tokens are rejected.
OAuth token exchange validates only the external-resource profile with the
exact requested audience, while MFA completion accepts only the MFA pre-auth
profile. A table-driven local regression covers wrong `typ`, `token_use`,
audience, issuer, actor, `kid`, and algorithm, plus cross-validator rejection
for all five profiles. External resource servers remain responsible for using
the resource-audience validator and enforcing their own configured audience.

This is an intentional pre-1.0 token-format boundary: JWTs issued before these
profile fields existed are rejected and existing sessions require
reauthentication after upgrade. Release and upgrade notes must state that
behavior. End-to-end session revocation/replay coverage across all profiles and
databases remains part of the readiness gate.

Sessions store the access-token hash and expiry, the SHA-256 hash of an optional
256-bit opaque refresh token and its expiry, optional organization slug,
service ID, resource, user agent, and IP address. Raw refresh values are returned
only to the client. Rotation conditionally replaces the current hash and records
the consumed hash in the same transaction. The session row is the refresh-token
family: reuse of any recorded ancestor deletes that row and therefore revokes
the current access and refresh tokens. A concurrent SQLite regression proves
one rotation winner followed by family revocation when the losing request is
recognized as reuse (`api/crates/authos-crypto/src/crypto/refresh_tokens.rs`,
`api/crates/authos-store/src/store/sessions.rs`, `api/src/handlers/auth/session.rs`).

The refresh-token storage migration deliberately clears legacy plaintext
refresh values instead of attempting a backend-specific online conversion, so
existing refresh sessions must reauthenticate after upgrade. The compatibility
column remains nullable but new writes leave it empty. PostgreSQL/MySQL runtime
migration and distributed multi-replica race evidence are still required before
this control is complete. Cache staleness, logout across every token profile,
multi-device semantics and distributed revocation timing still require a
published contract.

The migration crate also has a local SQLite fixture that upgrades one
representative pre-hardening origin to head, checks preserved user/session/
webhook state and the deliberate refresh invalidation, and injects a migration
failure to prove runner rollback, unchanged data, unrecorded failure, and clean
retry. Its backend-neutral head-schema assertion is a hook for PostgreSQL/MySQL
CI; those runtime paths and a release-by-release supported-origin matrix remain
unqualified.

## OAuth integrations and device authorization

The authorization entry points persist a CSRF state plus flow context,
expiration, redirect URI, optional PKCE verifier, tenant/service context, and
requested resource/scopes. Callback paths retrieve and delete state before
upstream token exchange. PKCE is generated for upstream authorization and is
mandatory for service types treated as public. Service redirects are checked
against registered redirect URIs in reviewed paths
(`api/src/handlers/auth/oauth.rs`, `api/crates/authos-crypto/src/crypto/sso.rs`,
`api/crates/authos-store/src/store/oauth_states.rs`).

AuthOS publishes its active and explicitly retained previous JWT verification
keys and an AuthOS-specific runtime
capability document. That document identifies the implemented device-code,
token-exchange, JWT-bearer, and ID-JAG surfaces and explicitly marks OpenID
Connect authorization-code and ID-token provider behavior unsupported. The
standard OpenID Connect and RFC 8414 discovery paths return `404`
(`api/crates/authos-core/src/runtime_metadata.rs`, `api/src/lib.rs`). AuthOS does not currently
expose a standards authorization endpoint or issue ID tokens. There is no
committed OAuth conformance output. The local key-ring implementation provides
an overlap mechanism, but no release-candidate cache/rollover drill has yet
established a safe production overlap duration or retirement procedure.

Device authorization persists expiring device/user codes and status, applies a
separate IP rate limit, and exchanges authorized state for tokens. Polling,
slow-down behavior, concurrent exchange, client/resource binding, and expiry
need protocol tests.

## SAML architecture

The SAML IdP surface is service-scoped. Configuration and certificate
management require service-management authorization. Private signing keys are
generated per service and AES-GCM encrypted. The IdP validates configured
organization/service, active status, ACS equality, destination when supplied,
and issuer. AuthnRequest parsing rejects DTD declarations, unknown entity
references, malformed XML/attributes, and invalid or duplicate request roots;
HTTP-Redirect decoding accepts raw DEFLATE with or without an XML declaration,
rejects encoded requests above 262,144 bytes, and caps expanded or POST-binding
XML at 1,048,576 bytes. Focused unit regressions cover these checks, decompression
limits, and escaped-value decoding. The IdP stores 15-minute request state.
Generated metadata, assertions, responses, and logout responses use structural
XML writers that escape configuration, request, and user values. Assertions contain
`NotBefore`, `NotOnOrAfter`, audience, destination, and optional
`InResponseTo`, and may sign the assertion and/or response
(`api/src/handlers/saml.rs`).

Certificate rotation retains one valid active signer and publishes the former
certificate as verification-only for seven days, capped at two previous
certificates. Metadata orders the active certificate first and excludes expired
or manually retired material. Authenticated service managers can retire every
overlap immediately; deleting SAML retires all keys. The management status
classifies healthy, near-expiry, expired, and future certificates. These are
local controls; real SP caches, all-database concurrency, restored backups, and
alert delivery remain release-candidate evidence gaps.

Canonicalization now rejects malformed XML instead of signing partial output.
The XML-signature code remains an in-repository construction, and no committed
canonicalization/signature-wrapping/interoperability suite proves it. The
reviewed AuthnRequest receiver does not validate request signatures. Most
importantly, upstream SAML response processing rejects every response because
signature verification is explicitly unimplemented
(`api/src/handlers/auth/upstream_saml.rs`). Upstream SAML is therefore not an
implemented authentication path despite configuration and initiation code.

## SCIM architecture

SCIM routes are isolated behind organization-bound SCIM bearer-token
middleware. User operations filter/list by the token organization and verify
membership for specific IDs. Group behavior currently represents the
organization as a group and validates the group ID against token organization
(`api/src/handlers/scim/`).

The source contains parser and handler tests, but no public interoperability
matrix. Supported filter grammar, pagination, PATCH semantics, idempotency,
deprovisioning, group semantics, and error schemas must be documented from
tests rather than inferred from the route list.

## Browser, network, and outbound controls

- Dynamic CORS allows the platform/API origins, verified active organization
  domains, and registered service redirect origins. Localhost, `127.*`, and
  `192.168.*` origins are allowed for development. Cache TTL is five minutes.
- Proxy headers are ignored unless enabled and the socket peer is explicitly
  trusted. Operators must ensure the framework receives the real peer socket
  address and that the proxy strips attacker-supplied forwarding headers.
- `SafeHttpClient` permits HTTP/HTTPS, rejects resolved private/reserved
  addresses, disables redirects, sets timeouts, and pins the validated DNS
  addresses for the request. It is used by reviewed webhook, SIEM, and
  configurable provider paths.
- OAuth token refresh, GitHub/Google/Microsoft user-info, and configured
  Stripe/Polar billing API requests use the pinned-resolution safe client,
  disable redirects, bound response bodies at 64 KiB, and do not echo raw
  remote errors or response bodies. Domain verification retains a reviewed
  custom public-address policy and 4 KiB bound. GeoIP setup uses the safe client,
  permits one HTTPS redirect only to MaxMind's
  [documented R2 download host](https://dev.maxmind.com/geoip/release-notes/2024/#presigned-urls-for-database-downloads),
  never forwards the license-key parameter, caps the compressed response at
  128 MiB and decompressed/archive database work at 256/128 MiB, and installs
  through a restrictive atomic temporary file.

The machine-checked
[outbound HTTP inventory](./outbound-http-inventory.json) records every Rust
source file that constructs a raw Reqwest client, the credentials and response
bounds involved, and the remediation for remaining exceptions. CI fails when a
new raw-client file is not classified.
- Auth, device, MFA setup, and MFA verification routes use process-local IP
  rate limiting. Email/MFA helper limiters are also process-local. Multi-replica
  behavior is unverified.

## Audit and observability

AuthOS records login, organization, MFA, and platform audit entities and emits
bounded-label HTTP/authentication metrics. Login, organization, MFA, and platform actor
calls synchronously persist a typed JSON event in `audit_outbox` before
returning success. The channel is only a best-effort wake signal. A startup and
periodic reconciler scans durable pending rows in bounded batches, inserts the
target audit record and removes its outbox row in one database transaction,
and treats an identical target event ID as idempotent replay
(`api/crates/authos-audit/src/audit/actor.rs`). Delivery failures store only a bounded
error code, retry with bounded attempts/backoff, and become queryable
`dead_letter` rows. SQLite tests cover closed-channel/restart replay, enqueue
database failure, all four event kinds, paired domain/outbox rollback, late
failure ordering, duplicate replay, bounded draining, retry exhaustion, and
invalid-payload dead-lettering.

This is not yet a complete audit guarantee. API-key, member/role/ownership,
billing-credential, and impersonation-session mutations now share their domain
transaction with the success-event outbox insert, with the event ordered after
fallible domain work. The [remaining call/direct paths](./audit-transaction-inventory.md)
still require classification or conversion. Only one reconciler per database
is currently qualified; there is no claim/lease protocol or multi-replica
runtime test. The older direct audit services and platform helper remain outside
the actor outbox. PostgreSQL/MySQL runtime evidence,
multi-worker qualification, operator reconciliation/requeue tooling,
dead-letter alerting, completeness, tamper resistance, retention, export, and
authorization still need explicit tests.
CI rejects credential and email values passed to Rust tracing macros and
includes a failing negative-control fixture; runtime canaries must still cover
errors, audit records, metrics, webhooks, exports, and backups. `/metrics` is
disabled unless a metrics bearer token is
configured, then compares a fixed-length digest in constant time; production
network restriction remains an operator responsibility.

## Cryptographic lifecycle

| Function | Current mechanism | Missing lifecycle evidence |
| --- | --- | --- |
| Access-token signing | One environment-supplied active RSA private/public pair and `JWT_KID`; up to ten previous public keys keyed by `kid`; RS256; all verification keys published in JWKS | Generation policy, protected storage, release-candidate rollover, compromise, rollback, verifier caching, retirement/expiry alerting. |
| SAML signing | One active per-service RSA signer; AES-GCM-encrypted private key; seven-day metadata-only overlap capped at two previous certificates; immediate authenticated retirement; lifecycle status | Standards interoperability through real SP metadata caches, PostgreSQL/MySQL and multi-replica rotation, restored-backup behavior, emergency drill, and wired expiry alerting. |
| Application secret encryption | Active plus previous 32-byte keys; V2 AES-256-GCM envelope with random nonce and authenticated header/table/record/field context; CAS rewrap | PostgreSQL/MySQL qualification, old-key retirement, backup/restore drill, and secret-manager integration. |
| Password/backup-code hashing | Argon2 defaults with random salts | Parameter baseline, resource limits, periodic rehash, compatibility, breached-password decision. |
| High-entropy bearer lookup | SHA-256 hash | Entropy proof at every generator, constant-time verification where applicable, rotation and compromise response. |

No key-rotation or recovery guarantee should be made until the missing lifecycle
items are exercised against a release candidate and restored backup.

## Known gaps and unverified controls

1. Upstream SAML signature validation is not implemented and fails closed.
2. Explicit `typ` and signed `token_use` separation is implemented with a local
   confusion matrix. End-to-end session/revocation tests across all profiles and
   databases remain incomplete, and external resource servers must invoke the
   resource-audience validator with their own configured audience.
3. Webhook and SIEM credentials are written as context-bound V2 ciphertext and
   runtime plaintext fallback is rejected. The rewrap command migrates their
   legacy plaintext. Identity and connected-account plaintext compatibility
   columns remain, and all-database migration/rotation evidence is incomplete.
4. JWT/JWKS supports an active signing key plus previous verification keys, but
   still lacks a release-candidate rollover/cache/retirement drill. Application
   encryption does not yet have an equivalent proven lifecycle.
5. Tenant isolation is application-enforced with no database RLS defense in
   depth; comprehensive matrix evidence is incomplete. Service-login tokens are
   restricted to profile/subscription reads, and platform authority is bound to
   platform-context tokens with live MFA enrollment.
6. `/metrics` has no dedicated listener and still needs deployment-level network
   restriction even though application bearer authentication is implemented.
7. Rate limiting is process-local and may reset or multiply across replicas.
8. A 1 MiB default global streaming request-body bound is implemented. SAML
   Redirect input is separately bounded at 262,144 encoded bytes and 1,048,576
   expanded bytes, with focused regressions. Other compressed/archive inputs,
   XML-signature work, crypto concurrency, and broader resource-exhaustion
   evidence remain incomplete.
9. Buffered audit logging can lose records after retry exhaustion, channel
   closure, or abrupt termination.
10. Public OAuth qualification, SAML/SCIM interoperability, key-rotation,
    redaction, restore, and independent-review evidence is not yet committed.
    OpenID Connect conformance is not applicable while that provider behavior
    remains unsupported.

Canonical ownership, status, and closure evidence for these findings lives in
[the Phase 2 evidence index](../readiness/phase-2-evidence.md). These findings
are a review baseline, not a complete vulnerability list.
