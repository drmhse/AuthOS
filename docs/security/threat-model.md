# AuthOS threat model

Status: source-review baseline, not an independent assessment

Reviewed: 2026-07-14

Scope: the Rust API, its database records, background jobs, embedded web routes,
and first-party protocol endpoints in this repository

## How to read this document

This model records what the current source shows and what still requires proof.
It is not a security certification, conformance statement, penetration-test
result, or deployment guarantee. A control marked **source-evidenced** has an
identifiable implementation in the paths cited below; it has not necessarily
been tested end to end or assessed independently. **Partial** means the source
implements part of the control. **Unverified** means the review did not find
enough evidence to make the claim. **Gap** means the source exposes an explicit
missing control or a security-relevant design limitation.

The associated [security architecture](./security-architecture.md) describes
the implemented mechanisms. The
[authentication enumeration and context matrix](./auth-enumeration-and-context.md)
records public response policy and residual timing asymmetries. The
[tenant-resource inventory](./tenant-resource-inventory.md) defines the data
surface that isolation tests must cover.

## Security objectives

AuthOS is intended to preserve these properties:

1. A tenant user, tenant administrator, service principal, or provisioning
   client cannot read or mutate another organization's data.
2. A user cannot authenticate as another user, reuse a one-time credential, or
   extend a session beyond its documented lifetime.
3. Platform-owner authority is distinct from organization and service
   authority and cannot be obtained from tenant-controlled input.
4. OAuth/OIDC, SAML, SCIM, passkey, MFA, password, magic-link, and recovery
   flows bind responses to the initiating actor, client, tenant, destination,
   and transaction.
5. Passwords, signing keys, bearer credentials, provider credentials, and
   recovery material are not disclosed through storage, logs, APIs, or release
   artifacts.
6. Security-relevant actions remain attributable, while audit and telemetry do
   not become a second path for credential or personal-data disclosure.
7. Untrusted outbound destinations cannot use AuthOS to reach loopback,
   private, link-local, metadata, or otherwise reserved networks.
8. Operators can rotate or revoke credentials, recover data, and investigate
   incidents without relying on undocumented behavior.

Objectives 1 through 7 have implementation fragments in the repository, but
none should be treated as fully proven until the evidence requirements below
are satisfied. Objective 8 remains primarily an operational-readiness item.

## Assets

| Asset | Why it matters |
| --- | --- |
| User accounts, emails, identities, memberships, roles, and permissions | Control identity and tenant authority. |
| Password hashes, TOTP secrets, backup-code hashes, passkeys, reset links, magic links, and device credentials | Enable authentication or recovery. |
| Access tokens, refresh tokens, sessions, OAuth state, authorization grants, device codes, SAML state, and WebAuthn challenges | Bind and continue authentication transactions. |
| JWT private key and SAML signing private keys | Let a holder mint trusted assertions. |
| Organization OAuth, upstream-provider, billing, SMTP, SIEM, webhook, and service credentials | Authorize access to AuthOS or external systems. |
| Organization configuration, services, plans, subscriptions, domains, branding, webhooks, and provisioning state | Tenant data and security policy. |
| Organization, login, MFA, and platform audit data | Supports detection, attribution, and incident response. |
| Database contents, migrations, backups, environment variables, binaries, images, and installer artifacts | Define the integrity and recoverability of the system. |

## Actors and capabilities

| Actor | Expected authority | Adversarial cases |
| --- | --- | --- |
| Unauthenticated internet client | Public discovery, branding, authentication initiation, callbacks, health routes, and public protocol routes | Enumeration, credential stuffing, replay, parser abuse, resource exhaustion, malicious redirect/state input. |
| End user | Own profile, credentials, devices, sessions, linked accounts, and memberships granted to the user | Horizontal access to another user or tenant; recovery or linking abuse. |
| Organization member/admin/owner or custom role | Tenant resources permitted by membership/relationship tuples | Cross-tenant access, role escalation, confused-deputy requests using path IDs. |
| Platform owner | Platform governance and explicitly protected administrative operations | Account compromise, unsafe impersonation, abuse of bootstrap configuration. |
| Service principal | Service API operations allowed by an API key's permission list | Stolen key, permission bypass, access to another service or organization. |
| SCIM client | Provisioning operations for the organization bound to its token | Stolen token, forged organization header, cross-tenant resource IDs. |
| OAuth/OIDC or SAML identity provider | Supplies external identity assertions and tokens | Malicious/compromised provider, issuer confusion, unsigned or replayed response. |
| Service provider / relying party | Initiates OAuth/OIDC or SAML requests and consumes assertions | Redirect/ACS substitution, malicious client registration, assertion replay. |
| Email, billing, SIEM, webhook, DNS, GeoIP, and database dependencies | Deliver configured infrastructure functions | Dependency outage, malicious response, SSRF target, data exfiltration, stale data. |
| Host, database, and reverse-proxy operator | Controls deployment, secrets, storage, network, and process lifecycle | Misconfiguration or compromise; this actor is inside the deployment trust base. |
| Supply-chain participant | Contributes dependencies, CI workflows, images, and release inputs | Dependency compromise, workflow injection, artifact substitution. |

## Trust boundaries

1. **Internet to reverse proxy/API.** The application listens on a configured
   host/port. TLS termination and proxy correctness are deployment controls,
   not established by the Rust process. Proxy-derived client IPs are used only
   when `TRUST_PROXY_HEADERS` is enabled and the socket peer is listed in
   `TRUSTED_PROXY_IPS` (`api/src/middleware.rs`).
2. **Browser to public/authenticated routes.** Dynamic CORS checks platform and
   API origins, verified active custom domains, and registered service redirect
   origins. Local/private development origins receive an explicit exception
   (`api/src/middleware.rs`). CORS is not an authorization boundary.
3. **Bearer token to authenticated user.** RS256 verification and expiration
   checks are followed by a database lookup for a non-expired session on
   ordinary access-token requests (`api/crates/authos-crypto/src/crypto/jwt.rs`,
   `api/src/middleware.rs`, `api/crates/authos-store/src/store/sessions.rs`).
4. **User to organization/service.** Organization membership, built-in roles,
   relationship tuples, and resource-specific checks are performed in handlers
   and stores. The reviewed schema uses a shared database; no database
   row-level-security policy was found. Tenant isolation therefore depends on
   complete application query scoping.
5. **API/SCIM key to service/organization.** API keys resolve to one service;
   SCIM tokens resolve to one organization. Both are stored as hashes and
   checked by route middleware (`api/crates/authos-crypto/src/crypto/api_key.rs`,
   `api/src/middleware.rs`, `api/crates/authos-store/src/store/scim_tokens.rs`).
6. **AuthOS to external endpoints.** Webhook, SIEM, configurable OAuth/OIDC,
   and configured Stripe/Polar billing paths use `SafeHttpClient` in the
   reviewed call sites. It resolves and pins public addresses, disables
   redirects, and billing/OAuth response readers enforce 64 KiB bounds
   (`api/crates/authos-crypto/src/crypto/safe_http.rs`). GeoIP setup remains outside that shared
   policy and comprehensive proxy/DNS-rebinding integration evidence is not yet
   published.
7. **Process to database and secret material.** The database stores identity,
   tenant, session, and audit records. Normal API startup requires one valid
   environment-provided `ENCRYPTION_KEY`, used with AES-256-GCM for selected
   secrets. Only the explicit `AUTHOS_ALLOW_UNENCRYPTED_DEVELOPMENT=true`
   escape hatch permits a missing key, and it is unsafe for persistent data;
   JWT signing keys are supplied as environment variables
   (`api/crates/authos-crypto/src/encryption/mod.rs`, `api/src/lib.rs`).
8. **Foreground request to background work.** Email, webhook, refresh, cleanup,
   metrics, and audit work crosses asynchronous queues/tasks. Delivery,
   idempotency, shutdown, and failure handling require separate evidence.

## Major flows and threat decisions

### Password, recovery, magic-link, MFA, and passkey flows

- Passwords and MFA backup codes use Argon2 with per-secret salts
  (`api/src/handlers/auth/password.rs`, `api/crates/authos-crypto/src/crypto/mfa.rs`). Password login
  performs a dummy Argon2 verification for unknown/passwordless users to reduce
  a timing distinction. Deterministic handler tests qualify the response shape,
  and a bounded sampler supports deployment observations; neither is a
  constant-time or measured production enumeration-resistance claim.
- Password reset, email verification, and magic-link values are stored as
  SHA-256 hashes with expirations. Reset and verification consumption perform
  conditional one-time updates; magic-link and WebAuthn challenge consumption
  delete the record and check affected rows. SQLite races prove one winner for
  each (`api/crates/authos-store/src/store/password_reset.rs`, `api/crates/authos-store/src/store/email_verification.rs`,
  `api/crates/authos-store/src/store/magic_links.rs`, `api/crates/authos-store/src/store/webauthn_challenges.rs`).
- MFA pre-authentication tokens expire after five minutes. Consumption uses a
  distributed lock keyed by JWT `jti` (`api/crates/authos-crypto/src/crypto/jwt.rs`,
  `api/src/handlers/auth/mfa.rs`). Multi-node replay behavior is **unverified**.
- WebAuthn uses `webauthn-rs`, binds the RP to a domain-backed HTTPS
  `BASE_URL` (or localhost), stores five-minute ceremony state, checks the
  registering user, consumes challenges, and atomically applies the complete
  updated credential state without allowing stale ceremony state to overwrite a
  concurrent winner (`api/src/lib.rs`, `api/crates/authos-services/src/services/webauthn.rs`,
  `api/crates/authos-store/src/store/user_passkeys.rs`, `api/src/handlers/auth/passkeys.rs`). Full
  origin/RP, real cloned-authenticator, multi-replica, and deployment
  enumeration-timing tests remain required.

### Sessions and tokens

- Access tokens are RS256 JWTs. Ordinary authenticated requests also require a
  non-expired session matching the token's SHA-256 hash, enabling session
  deletion to revoke access (`api/crates/authos-crypto/src/crypto/jwt.rs`, `api/src/middleware.rs`).
- Refresh tokens are 256-bit opaque random values stored only as SHA-256 hashes.
  Rotation conditionally replaces the current hash and records the consumed
  ancestor in one transaction; the session row represents the family, and
  ancestor reuse deletes it. SQLite regressions cover hash-only storage,
  one-winner concurrent rotation, family revocation, expiry, and logout
  (`api/crates/authos-crypto/src/crypto/refresh_tokens.rs`, `api/src/handlers/auth/session.rs`,
  `api/crates/authos-store/src/store/sessions.rs`). PostgreSQL/MySQL runtime migration and
  distributed multi-replica race qualification remain **gaps**. The migration
  clears legacy plaintext refresh values and forces affected clients to
  reauthenticate.
- Every JWT profile now carries a distinct JOSE `typ` and signed `token_use`.
  Validators require RS256, a `kid` present in the configured verification-key
  ring, `exp`, `iss`, `aud`,
  expected type/use, and profile-specific audience/MFA/actor invariants. AuthOS
  management routes accept only management and impersonation profiles;
  resource and MFA tokens are rejected there. OAuth token exchange validates
  only the external-resource profile and exact requested resource audience
  (`api/crates/authos-crypto/src/crypto/jwt.rs`, `api/src/middleware.rs`,
  `api/src/handlers/auth/enterprise.rs`). A local confusion matrix covers wrong
  type/use/audience/issuer/actor/key/algorithm. External resource servers must
  still invoke the resource-audience validator with their configured audience;
  complete session/revocation evidence across profiles and databases remains a
  **gap**.
- JWT issuance uses only the active RSA private key and `kid`. Validators select
  the active or an explicitly configured previous public key by exact `kid`,
  and JWKS publishes the same complete verification set. Local regressions
  cover old/new overlap, active-only issuance, unknown and retired `kid`, wrong
  previous-key material, duplicate configuration, and multi-key JWKS
  (`api/crates/authos-crypto/src/crypto/jwt.rs`, `api/src/lib.rs`). A release-candidate rollover with
  downstream JWKS caches, retirement timing, restored keys, and emergency
  compromise response remains **unverified**.

### OAuth/OIDC and device flows

- OAuth state is persisted with an expiration and flow context; callbacks load
  and delete it before token exchange. PKCE is generated for upstream flows and
  enforced for public service types (`api/src/handlers/auth/oauth.rs`,
  `api/crates/authos-store/src/store/oauth_states.rs`). Concurrency and all error branches require
  replay tests.
- Registered service redirect URIs are revalidated before service redirects in
  reviewed callback paths. A complete open-redirect inventory remains
  **unverified** because several flows construct return locations.
- Device codes have separate rate limits and database state
  (`api/src/router.rs`, `api/crates/authos-store/src/store/device_codes.rs`). Polling interval,
  binding, expiry, and concurrent exchange require end-to-end evidence.
- AuthOS does not currently provide an OAuth authorization-code server or
  OpenID Connect provider and does not issue ID tokens. Standards discovery is
  disabled; the AuthOS-specific capability document limits its claims to the
  implemented device and enterprise extension grants. Those grant behaviors,
  client authentication, revocation, and error semantics remain **unverified
  for conformance**.

### SAML

- The IdP path checks organization status, service ownership/configuration,
  configured ACS URL, request destination when present, and request issuer. It
  rejects DTD declarations, unknown entity references, malformed XML and
  attributes, invalid request roots, encoded requests over 262,144 bytes, and
  decoded request XML over 1,048,576 bytes. Parsing additionally stops above 32
  element levels, 4,096 events, 64 attributes on one element, or 512 attributes
  total; it also creates expiring SAML state.
  Raw-DEFLATE Redirect requests do not require an XML declaration. Generated
  metadata, assertion, response, and logout XML structurally escapes request,
  configuration, and user values, and canonicalization rejects malformed input.
  Focused regressions cover those boundaries. Assertions include time conditions
  and may be signed with encrypted per-service keys (`api/src/handlers/saml.rs`).
- SAML certificate rotation signs only with one valid active key while metadata
  publishes at most two eligible previous certificates for seven days. Service
  managers can retire overlap immediately, deletion retires all material, and
  status exposes near-expiry/expiry. Remote SP cache refresh, emergency response,
  restored backups, and all-database/multi-replica behavior remain unqualified.
- The reviewed IdP AuthnRequest path does not verify a request signature. The
  XML-signature construction is custom and has no committed interoperability or
  signature-wrapping test evidence. These are **unverified controls**.
- Upstream SAML response processing explicitly returns an error because
  signature verification is not implemented
  (`api/src/handlers/auth/upstream_saml.rs`). This is a fail-closed **gap** and
  upstream SAML must not be represented as operational until it is implemented
  and tested.

### SCIM, service APIs, and tenant administration

- SCIM middleware binds a hashed, active, unexpired bearer token to its stored
  organization and rejects a conflicting optional `X-Organization-ID` header.
  SCIM user handlers additionally check organization membership; group handlers
  bind the only represented group to the token organization
  (`api/src/middleware.rs`, `api/src/handlers/scim/`).
- Service API middleware resolves a hashed API key by prefix, performs a
  constant-time hash comparison, checks expiration, and supplies the bound
  service plus serialized permissions (`api/crates/authos-crypto/src/crypto/api_key.rs`,
  `api/src/middleware.rs`). Every service handler still needs a negative test
  proving its permission and resource binding.
- Tenant administration handlers generally resolve an organization from the
  path and then require membership, built-in role, or a relationship-tuple
  capability. Service-login tokens are further restricted to profile and
  subscription reads. Platform owner bypasses require a platform-context token,
  a live owner row, enrolled MFA, and proof that the current login completed the
  MFA challenge; passkey-only and refreshed platform sessions are rejected. The
  inventory records the full surface; comprehensive negative tests remain a
  release requirement.

## Prioritized abuse cases

| Priority | Abuse case | Current control/evidence | Required disposition |
| --- | --- | --- | --- |
| Critical | Forge or accept an upstream SAML assertion | Processing fails closed; verification is explicitly unimplemented. | Keep feature unavailable; implement standards-based signature, issuer, audience, destination, time, `InResponseTo`, and replay validation before advertising support. |
| Critical | Tenant A supplies Tenant B's resource ID | Application-level org/service/user filters and handler checks exist; no DB RLS was found. A CI matrix covers current entity and route-path drift while explicitly retaining open gaps. SQLite regressions now cover billing-customer metadata binding, inconsistent service identity context, compound parent-scoped API-key/plan/domain/SCIM-token mutations, billing credential mutations, audit/billing custom capability revocation, suspended integration parents, session preservation, non-active service tenants, and live platform-owner demotion. | Complete method/actor/identifier/unchanged-state cases for every matrix row, remove all critical/high gaps, and repeat on PostgreSQL/MySQL and multiple replicas. |
| High | Reuse or redirect an OAuth transaction | Expiring stored state, PKCE, and redirect checks exist; callbacks require nonempty state and only the atomic state-deletion winner proceeds. File-backed SQLite covers concurrent state consumption. | Add handler-level mismatched-state/PKCE downgrade and every redirect-sink case, authorization-code reuse fixtures, and multi-replica evidence. |
| High | Use a valid JWT in the wrong issuer/audience/profile context | RS256, expiry, exact active-or-previous verification-ring `kid`, configured issuer, required audience, distinct JOSE `typ` plus signed `token_use`, profile invariants, and a local confusion matrix are enforced. | Enforce the configured resource audience at every external resource server and complete session/revocation tests for every profile on all databases. |
| High | Steal database contents and replay refresh/external credentials | Session refresh tokens are 256-bit opaque values stored only as SHA-256 hashes, with consumed-ancestor family revocation. Normal startup fails closed without the active application encryption key and performs a read-only full-inventory gate before any API/worker path. New secret writes use key-ID-bearing AES-GCM V2 envelopes authenticated to table/record/field context. A bounded CAS rewrap migrates legacy/V1, SIEM, webhook, identity, and connected-account values; encrypted runtime rejects every inventoried plaintext compatibility value. SQLite covers tampering, swapping, missing keys, resume, idempotence, restored identity/account reads, and backup-dependent old-key refusal. | Qualify refresh and encryption behavior on PostgreSQL/MySQL and multiple replicas; complete the compatibility-column retention window and release-candidate restore/retirement drill; integrate a production secret manager. |
| High | Replay MFA, magic-link, reset, verification, or WebAuthn state concurrently | Conditional update/delete and expirations exist; SQLite races prove one winner for reset, verification, magic-link, and WebAuthn challenge values. MFA uses a database-backed distributed lock. | Repeat on PostgreSQL/MySQL and multiple replicas; add real-authenticator origin/RP and clone/counter exercises. |
| High | Abuse platform-owner bootstrap or impersonation | Bootstrap token comparison is constant-time and a database-backed consumption record gives concurrent requests one winner before file `used_at` persistence. Impersonation requires a bounded reason, a live revocable session, and current actor/target tenant authority on every request; nested impersonation is rejected. Local tests cover actor demotion, target removal, org suspension, session deletion, and nesting. | Add bootstrap MFA policy and crash/file-write recovery, broader handler audit/non-escalation matrices on every database, multi-replica qualification, and operational revocation drills. |
| High | Redirect a webhook/SIEM/OIDC request to metadata or an internal host | Safe client rejects private/reserved resolutions, pins DNS results, and disables redirects in reviewed paths. The raw-client inventory has no unclassified gap; GeoIP has one credential-stripping, exact-host redirect exception. | Retain the inventory gate and add integration fixtures for IPv4/IPv6 encodings, DNS rebinding, proxy use, and redirect chains. |
| Medium | Evade rate limits behind spoofed proxy headers or across replicas | Trusted-proxy allowlist exists; route limiters are process-local. | Deployment tests for proxy topology and distributed/rate-limit behavior across replicas; document failover/reset semantics. |
| Medium | Exfiltrate through operational metrics or logs | Metrics use bounded labels; `/metrics` is disabled without a configured token and otherwise requires a constant-time bearer-token check. CI rejects credential/email values passed to tracing macros, but complete runtime redaction evidence does not exist. | Also network-restrict metrics, define allowed fields, and run error/audit/metric/webhook/export/backup secret canaries. |
| Medium | Exhaust CPU/memory with crypto, XML, JSON, request bodies, or high-cardinality input | Route rate limits, a 30-second timeout, and a configurable global streaming body limit (1 MiB default) exist. SAML Redirect input has encoded/expanded byte limits plus depth/event/attribute work budgets and deterministic boundary corpora. Request-time password and MFA backup-code Argon2 operations share a CPU-scaled semaphore, a two-second queue bound, a 1,024-byte input bound, and the blocking pool. GeoIP and offline release/npm archives have compressed, expanded, member-count, and selected-file limits. | Bound XML-signature verification and high-cardinality SCIM operations; add maintained fuzz targets and broader JSON/form/filter corpora; measure load-shedding thresholds on release hardware. |
| Medium | Lose or silently omit security audit events | Login, organization, MFA, and platform actor calls durably enqueue before returning; bounded startup/periodic reconciliation provides transactional target delivery, idempotent replay, coded retry, and observable dead letters. API-key, member/role/ownership, billing-credential, and impersonation-session mutations share their transaction with success enqueue. SQLite covers paired rollback, late failure ordering, restart, enqueue outage, duplicates, poison payloads, and retry bounds. | Classify and convert the [remaining caller/direct paths](./audit-transaction-inventory.md); qualify multi-worker PostgreSQL/MySQL behavior; add requeue/alerting, completeness reconciliation, retention, and runtime redaction canaries. |

## Deployment assumptions that are not application guarantees

- TLS is correctly terminated, HTTP is redirected to HTTPS, and forwarded
  headers are stripped/replaced by a trusted proxy.
- The database, backups, environment files, process account, and host are
  access-controlled and encrypted according to operator policy.
- JWT and encryption keys are generated securely, stored outside the image and
  repository, backed up safely, and rotated by an operator.
- System clocks, DNS, SMTP, external identity providers, and databases are
  trustworthy enough for the configured deployment.
- `/metrics`, readiness details, and administrative endpoints are restricted at
  the network/proxy layer where required; the metrics bearer token is supplied
  through a secret manager and never through a URL.
- `DISABLE_RATE_LIMITING` is not enabled in production.

These assumptions need deployment validation and runbooks before a production
claim. The application currently cannot prove them.

## Required security evidence

The following evidence is necessary to move controls from source review to a
release claim. Status, ownership, and artifact links are maintained in the
[Phase 2 evidence index](../readiness/phase-2-evidence.md):

1. A generated authorization matrix covering every resource in the tenant
   inventory, with owner/admin/member/non-member/platform/service/SCIM actors
   and same-tenant/cross-tenant IDs on SQLite, PostgreSQL, and MySQL.
2. OAuth device/enterprise qualification output plus negative tests for state,
   device-code and refresh replay, issuer, audience/resource, token type,
   algorithm, revocation, and signing-key rollover. PKCE, nonce, redirect,
   authorization-code, and ID-token evidence becomes required before an OpenID
   Connect/authorization-code provider is offered.
3. SAML interoperability and adversarial XML/signature tests. Upstream SAML
   remains unavailable until signed-response validation passes.
4. SCIM client interoperability, filtering/pagination/idempotency tests, and
   cross-tenant CRUD/group tests.
5. Concurrent one-time-token tests for reset, verification, magic link, OAuth,
   SAML, device, MFA, and WebAuthn state.
6. A cryptographic inventory and drill for JWT/SAML/encryption-key rotation,
   compromise, recovery, and overlapping verification windows.
7. Secret-at-rest and redaction tests using canary values across the database,
   backups, logs, errors, audit payloads, metrics, exports, and APIs.
8. Outbound-request inventory and SSRF tests for every caller, including DNS
   changes, IPv6, redirects, proxies, and internal address representations.
9. Fuzzing and bounded-resource tests for XML, SCIM filters, JWTs, request
   bodies, decompression, webhook payloads, and protocol parsers.
10. Independent review of the exact release candidate with a public scope and
    remediation status.

## Maintenance

The Security lead owns this model. Update it when a new route, token type,
tenant-scoped entity, external integration, credential store, cryptographic
primitive, trust boundary, deployment topology, or privileged role is added.
Each release review should link the exact commit and evidence artifacts used to
change any status in this document.
