# Changelog

This file records notable user-facing and project-level changes to AuthOS. The
project is pre-1.0; breaking changes are called out explicitly when known.

## [Unreleased]

No changes yet.

## 0.8.13 - 2026-09-29

### Security

- `rustls` 0.23.35 to 0.23.45 for RUSTSEC-2026-0285: TLS 1.3 handshake
  messages were accepted across encryption-level boundaries. `rustls` is linked
  into every shipped binary and image, for outbound HTTP and database TLS.
  `aws-lc-rs` and `rustls-webpki` move with it.
- Development and peer-test dependencies clear their advisories: `next`
  15.5.26 (GHSA-p293-qw3h-jr36, GHSA-2xp9-vwfh-vxw4), `sharp` 0.35.5,
  `vitest` 4.1.11, `undici` 7.30.0, and `qs` 6.16.0 via `express` 4.22.3 —
  the `qs` fix the 0.8.12 entry was waiting for. None of these ship in a
  published package; `npm audit` over the full tree now reports nothing.

### Fixed

- The weekly security scan passes again. It had failed since 2026-09-07,
  first on npm advisories and then on `rustls`.
- `api/migration/Cargo.lock` is removed. The migration crate has been a
  workspace member since 0.8.9, so cargo ignored that lockfile, yet the
  security, release, and npm-publish gates still audited it and Dependabot
  still tried to update it. It is now covered by `api/Cargo.lock`.

## 0.8.12 - 2026-09-06

### Fixed

- The release and publish workflows can complete. Both gated on
  `npm audit --audit-level=moderate` over the whole dependency tree, which fails
  on three moderate advisories in `qs` that are reachable only through `express`.
  `@drmhse/authos-node` declares `express` as a dev and a peer dependency, so a
  consumer installing the package never receives it and supplies its own — no
  shipped artifact is affected. There is also nowhere to move: `qs` 6.15.3 is the
  newest release and the advisory range covers it, and npm's advertised fix is
  `express` 5, a breaking change. Both gates now audit production dependencies,
  where the tree reports no vulnerabilities. `security.yml` still audits
  everything, so the advisory stays visible and will be acted on when `qs`
  publishes a fix. The v0.8.11 release failed at this gate and published no
  artifacts.

## 0.8.11 - 2026-09-06

### Fixed

- The API crate no longer rebuilds on every single build. `api/build.rs` emitted
  `cargo:rerun-if-changed` for `../lite-web-client/dist` before checking whether
  that path exists, and cargo treats a `rerun-if-changed` target that is missing
  as permanently stale — it says so directly, as
  `StaleItem(MissingFile { path: ".../lite-web-client/dist" })`. Because `dist`
  is gitignored, it is absent in every fresh clone and on every CI runner, so
  the build script re-ran and all three `sso` targets re-checked on every build,
  all 50,989 lines of the root package, whether or not anything had changed. The
  script now emits only for paths that exist, and tracks the
  `../lite-web-client` directory itself so that building the lite client for the
  first time still retriggers: creating `dist` moves the parent's mtime. Changes
  to an existing `dist` file retrigger as before. Measured on this workspace
  with `dist` absent: a no-op `cargo check --workspace` goes from 1.30s to
  0.18s, and from 6.00s to 0.47s with the target directory wiped against a warm
  build cache — one crate rebuilt becomes none, out of 444 units.

## 0.8.10 - 2026-09-02

### Changed

- The runtime image is 42% smaller: 19.67 MiB to 11.41 MiB compressed for
  `sqlite-amd64`, measured by building both Dockerfiles against the same
  release binary. Two causes. `RUN chmod 0555 /app/sso` ran after the binary
  was copied, and changing a file's mode rewrites the whole file into a new
  layer, so the 17.4 MiB binary was stored twice; the mode is now set by
  `COPY --chmod`. And the image installed `libgcc` and `ca-certificates`,
  neither of which it needs: the binaries are statically linked musl with no
  dynamic dependencies, and `alpine:3.20` already ships
  `ca-certificates-bundle`. Verified in the rebuilt image that the binary still
  executes and unwinds a panic without `libgcc`, that the entrypoint still runs
  at mode 0555, and that the trust store and the healthcheck's `wget` are
  present.

## 0.8.9 - 2026-09-02

### Changed

- `api/` is a cargo workspace instead of one crate. The root package `sso`
  keeps the HTTP layer and every lower layer moved to `api/crates/authos-*`:
  core, entities, crypto, db, audit, store, services, plus a dev-only testkit.
  Layers may only depend downward and cargo enforces it, because a cycle no
  longer compiles. Each crate re-exports the layers beneath it under their
  original module names, so `crate::error` and `crate::store` still resolve and
  almost no call site changed. Every existing command still works: the root
  package is also the workspace root, so `cargo run --bin sso_psql
  --no-default-features --features db_psql` and the `target/release/sso_*`
  paths the Dockerfile and benchmarks use are unaffected.
- `api/src/sso_sqlite.rs` was `include!("main.rs")`, so with `db_sqlite` as the
  default feature every `cargo build` compiled the whole crate twice, once as
  `sso` and once as `sso_sqlite`, and nothing consumed the bare `sso` binary.
  `main.rs` became `lib.rs` with `pub async fn run()` and all four binaries are
  three-line shims. Rebuilding after touching one handler went from 82s to
  roughly 4s, and one layer can now be tested on its own.
- Only crates with backend-conditional code carry `db_sqlite`/`db_psql`/
  `db_mysql`, and they forward to every dependency that also has such code,
  dev-dependencies included, with every internal dependency declared
  `default-features = false`. This is load-bearing rather than tidiness:
  `with_retrying_transaction` takes four arguments under `db_sqlite` and three
  otherwise, so a mixed-feature graph does not compile.
- Transaction machinery moved out of `error.rs` into `db/transaction.rs` and
  the `DB` connection enum out of `store/mod.rs` into `db/connection.rs`, which
  is what removed the last dependency cycles. `ensure_organization_active` moved
  from `handlers` into the store. The `auth` module is gone: its primitives
  (`jwt`, `api_key`, `mfa`, `refresh_tokens`, `sso`) are now `crypto`, and its
  orchestration (`device_flow`, `token_refresher`) moved up into `services`.
- The AuthOS CLI provisioning command talks to the API through the SDK instead
  of its own `fetch` wrapper, so it cannot drift from the published contract.
- `POST`, `PUT`, `PATCH` and `DELETE` in the SDK HTTP client accept `params`,
  matching `GET`.

### Added

- `npm run check:layers` fails the build when a module references a higher
  layer, and `npm run check:test-support` asserts the `test-support` features
  are absent from every production dependency graph and that the three database
  backends stay mutually exclusive. Both run in the release gate.

- Platform MFA metrics are real. `GET /api/platform/mfa/metrics` previously
  returned a fixed message and ignored every parameter, including the `org_id`
  its own note told callers to pass. It now serves the stored daily rollup,
  accepts `org_id` (omit it for the platform-wide row) and either a
  `start_date`/`end_date` range or a trailing `days` window. A background job
  writes the rollup hourly for the previous day, so the figures exist without
  anyone calling the generate endpoint by hand, and
  `/api/platform/mfa/metrics/generate` now also accepts `POST`.
- The SDK covers the upstream domain routing (Home Realm Discovery) endpoints
  through `sso.organizations.domainRoutes`, and the platform bootstrap, MFA
  metrics and suspicious-activity endpoints through `sso.platform.bootstrap`
  and `sso.platform.mfa`. Every API endpoint that is not a browser redirect or
  a machine protocol surface (SAML, SCIM) now has an SDK method.
- `PATCH /api/organizations/:org_slug/roles/:role_id` can clear a role
  description. The request DTO now distinguishes an absent field from an
  explicit `null`, which the store layer already supported.

### Changed

- The AuthOS CLI provisioning command talks to the API through the SDK instead
  of its own `fetch` wrapper, so it cannot drift from the published contract.
- `POST`, `PUT`, `PATCH` and `DELETE` in the SDK HTTP client accept `params`,
  matching `GET`.

### Removed

- `state` on the password login request. Login answers with tokens as JSON and
  has no redirect or emailed link to carry the value back, so the field could
  never do what it documented. Registration, password reset and verification
  resend still accept it, because those do continue through a link. Unknown
  fields are ignored, so clients still sending it are unaffected.

## 0.8.8 - 2026-08-17

### Changed

- The API no longer depends on OpenSSL. RSA key generation, the JWKS modulus
  and exponent, SAML signing and the vendored sqlx-mysql password path all use
  RustCrypto now, and webauthn-rs moved to a 0.6 prerelease for the same
  reason. The encodings OpenSSL emitted are preserved, because existing
  deployments have that PEM in their databases: PKCS#1 for the private key,
  PKCS#8 alongside it, and SPKI for the public key. SAML still signs
  RSASSA-PKCS1-v1_5 over SHA-256, and the MySQL handshake still encrypts with
  RSA OAEP using SHA-1 for digest and MGF1, which is what the server expects.
- Dropping it also makes release builds cacheable. OpenSSL was vendored and
  compiled from C on every checkout, and its static archives bake their own
  build directory into libcrypto.a and libssl.a, so no cache could reuse them.
  Priming the release dependency set is now noticeably cheaper for the same
  reason, 413s to 241s.
- The primed dependency store reaches the build matrix as a run artifact rather
  than an Actions cache. A cache is scoped to a ref and competes for a
  repository-wide ten gigabyte budget that is evicted least-recently-used, so a
  store written by priming could be displaced before the builds asked for it.

### Security

- RUSTSEC-2023-0071 is accepted rather than fixed, and recorded in
  `.cargo/audit.toml`. The `rsa` crate's private-key operations are not
  constant-time, so timing observable over the network may leak key material,
  and no fixed version exists: the advisory records no patched releases and the
  constant-time work is still a release candidate. The exposed path is SAML
  response signing; the MySQL handshake encrypts with the server's public key,
  the JWKS endpoint exports public material, and the API performs no RSA
  decryption. OpenSSL was originally affected by the same attack and has since
  mitigated it, so this release trades that hardening for a dependency that no
  longer compiles C on every build.

## 0.8.7 - 2026-08-17

### Changed

- Release builds compile the dependency set once per architecture instead of
  once per image. A priming job runs alongside release qualification and hands
  the third-party dependencies to the build matrix through a shared store, so
  each of the six image builds starts with them already built. Measured on CI,
  an image build goes from 556s and 404 crates compiled to 259s and 10.

## 0.8.6 - 2026-08-06

### Fixed

- Service MFA now completes inside the hosted login journey; the MFA challenge
  view resumes and finalizes the flow correctly.
- The device-flow MFA callback contract is aligned in the OAuth device
  endpoint so callback handling matches the SDK contract.
- SDK response types and secret serialization are hardened: invitation,
  organization, and upstream-provider models were aligned and the entity-secret
  serialization checks expanded.

### Changed

- The release finalizer binds `gh` to the triggering repository explicitly
  instead of relying on local `.git` metadata.

## 0.8.5 - 2026-07-25

### Changed

- The draft-release job now checks out the exact tagged source before creating
  release notes and attaching qualified artifacts.
- npm development dependencies and resolver overrides now select patched
  versions; the coordinated workspace audit reports no known vulnerabilities.

## 0.8.4 - 2026-07-18

### Changed

- The coordinated npm reusable-workflow caller now supplies the permission
  ceiling required to validate its publication job. Artifact preparation and
  source qualification remain explicitly read-only inside the called workflow.

## 0.8.3 - 2026-07-18

### Added

- Regression coverage for device-code expiry cleanup and a 30-minute budget-VM
  qualification case that crosses both code expiry and cleanup intervals.
- A CI-enforced, explicitly partial tenant-isolation matrix covering every
  current SeaORM entity and route path, with named SQLite evidence and
  categorized critical/high gaps.
- Cross-tenant unchanged-state regressions for billing credentials and
  webhooks, service identities and API keys, organization sessions,
  audit/billing capabilities, and platform/service authority.
- Pull-request CI for Rust quality, database-feature compilation, and
  TypeScript checks, tests, and builds.
- Dependency review, npm and Rust advisory audits, CodeQL analysis, and
  Dependabot update configuration.
- Release qualification for the exact annotated tag, SPDX SBOM generation,
  checksums, keyless artifact attestations, and container provenance.
- Manual npm workflow dispatches are dry-run-only; real publication requires a
  qualified annotated release tag.
- Public security, support, contribution, and project-status policies.
- An evidence-based production-readiness plan with explicit `v0.9` and `v1.0`
  gates.
- A release/versioning lifecycle and automated metadata consistency check.
- An online SQLite backup helper with restrictive output permissions,
  integrity and SHA-256 verification, overwrite protection, and a concurrent
  write regression.
- PostgreSQL 16 and MySQL 8.4 CI logical backup/restore qualification that
  preserves an existing login and tenant, then exercises new post-restore CRUD
  with the original protected key material.
- Exact npm publish tarballs, per-package SPDX SBOMs, SHA-256 manifests, GitHub
  artifact/SBOM attestations, and retention-aware verification instructions.
- Exact npm tarballs, SBOMs, checksums, and a source-bound package manifest are
  also attached to the GitHub release, with a clean verifier for package
  identity, version, digest, SPDX, and tar safety.
- Explicit disclosure of first-party paths that still require a maintainer
  licensing decision.
- SHA-256 verification of standalone release archives before installation.
- A machine-readable standalone release manifest binding the release tag, full
  source commit, workflow run, payload digests, and archive-to-SBOM mappings;
  the clean-environment verifier checks it before accepting the release set.
- Attested, release-attached container records for SQLite, PostgreSQL, and
  MySQL bind each multi-platform image digest to its release tag, source commit,
  workflow run, and registry SBOM/provenance expectations.

### Changed

- `DISABLE_RATE_LIMITING=true` now removes the route-level governors as its
  name states, keeping it suitable for isolated tests and benchmarks only.
- AuthOS Compose deployments now set the API container's open-file limit to
  65,535, matching the standalone systemd service and benchmark runner.
- Billing subscription webhooks now bind customer, organization, service,
  plan, and user membership; service-principal identity access binds both
  organization and service; inactive tenant service keys are denied; platform
  demotion is checked against current database state.
- Tenant administration now scopes plan, SCIM-token, domain-route,
  upstream-provider, and SIEM mutations by both parent and child identifiers;
  suspended tenants are denied across service, risk, integration, billing,
  webhook, and audit surfaces, including background webhook polling. Audit
  filter totals and target pagination now match the tenant-scoped query.
- Tenant login and risk analytics now combine explicit organization scope with
  compatible legacy service-derived scope, include legitimate service-less
  tenant events, and reject inconsistent organization/service pairs. Recent
  login responses represent a missing service explicitly.
- Invitation acceptance now claims pending state before side effects and
  requires a currently active parent; suspended tenants cannot create users or
  memberships through outstanding invitations. Invitation list responses no
  longer expose stored token verifiers.
- Conventional SQL-backed list endpoints now normalize non-positive limits to
  a one-item minimum and negative offsets to zero before unsigned conversion.
  SCIM retains RFC-compatible `count=0` behavior, and the organization service
  list retains its established in-memory `limit=0` empty-page behavior.
- The README now links to the project's maturity and trust documentation.
- Checked-in operator Compose topologies now align all AuthOS images with
  `v0.8.3` and the release-qualified PostgreSQL 16/MySQL 8.4 engines; the trust
  gate rejects stale or unclassified Compose pins.

### Security

- Rate-limit keys and request auditing now share one trusted-proxy-aware client
  IP resolver. Forwarding headers are accepted only from an explicitly
  allowlisted socket peer; direct clients cannot rotate spoofed headers to
  evade per-IP limits.
- Branding and custom-domain authorization now rechecks live platform-owner
  authority and active tenant state at request and transaction boundaries;
  OAuth callback/session completion similarly revalidates exact active
  organization, service, redirect, resource, and current user entitlement.
- SCIM deactivation and deletion now atomically revoke only the selected
  organization's memberships, permissions, sessions, identities, grants,
  provider requests, pending OAuth/SAML/device state, and enqueue the matching
  durable audit event while preserving other-organization and platform state.
- Provider token refresh jobs re-read live user/tenant/service authority before
  outbound I/O and use conditional transactional writeback so revocation,
  suspension, or token replacement wins. Email verification and password reset
  now commit one-time consumption with account mutation and session revocation
  in a single transaction.

- Application-secret writes now use AES-GCM V2 envelopes authenticated to the
  physical table, record ID, and field. The bounded `rewrap-secrets` command
  migrates legacy/V1, SIEM, webhook, identity, and connected-account values
  with compare-and-swap updates; webhook/SIEM runtime plaintext fallback is
  rejected. SQLite covers context swapping, migration, resume, and tampering.
- SIEM connection tests decrypt only the credential selected by the provider,
  require authentication for named providers, reject unsafe custom headers,
  bound downstream response bodies, and do not reflect downstream bodies or
  transport errors. Audit metadata redaction now covers nested credential keys
  with value suffixes and common passphrase/credential/recovery-code names
  while retaining explicitly non-secret identifiers and descriptors.
- JWT signing-key rotation now supports one active signing key plus an optional
  previous public-key ring keyed by `kid`. Validators accept only configured
  active/previous keys, issuance always uses the active key, and JWKS publishes
  the complete verification set for an overlap window. Unknown, retired,
  mismapped, duplicated, and malformed key configurations fail closed.

- Upgraded `quick-xml` to 0.41 and adapted SAML parsing to remediate
  `RUSTSEC-2026-0194` and `RUSTSEC-2026-0195` denial-of-service issues. Added
  regression coverage for escaped XML values, malformed XML/attributes,
  invalid roots, and external or unknown entity references.
- SAML Redirect decoding now accepts standards-shaped raw-DEFLATE requests
  without requiring an XML declaration, rejects encoded requests above 256 KiB,
  and caps expanded or POST-binding XML at 1 MiB. Metadata, assertion, response,
  and logout XML now structurally escapes configurable, request, and user values;
  canonicalization fails closed on malformed XML instead of signing partial output.
- Updated vulnerable or unsound Rust dependencies including `anyhow`,
  `crossbeam-epoch`, and the inactive `quinn-proto` lockfile entry.
- Updated transitive npm dependencies `undici` and `js-yaml`; `npm audit`
  reports no known vulnerabilities at the current development baseline.
- The standalone installer now verifies its selected archive against the
  release checksum manifest before extraction.
- Standalone archive extraction now rejects non-HTTPS redirects, oversized or
  non-exact checksum inputs, traversal, links, special files, duplicate
  members, unexpected inventory, and expansion/member-limit violations. API
  key output is confined beneath managed data using no-follow directory file
  descriptors, atomic replacement, and parent/target race checks; installed
  license, AGPL, and exact source-offer notices are retained atomically.
- Startup logging no longer prints database connection URLs that may contain
  PostgreSQL or MySQL credentials.
- OAuth token response bodies, access-token hashes, and registration email
  addresses are no longer written to application logs.
- Bootstrap-generated deployments now pin the current `v0.8.3` Docker image
  variants instead of the stale `v0.1.51` variants.
- Access-token validation now requires issuer and audience claims, enforces the
  configured issuer, rejects external-resource tokens at AuthOS management
  endpoints, and enforces the requested resource audience during token exchange.
- AuthOS-signed management, external-resource, MFA pre-authentication,
  impersonation, and ID-JAG tokens now carry distinct JOSE `typ` headers and a
  signed `token_use`; validators enforce the exact profile, issuer, audience,
  algorithm, configured key ID, and actor/MFA invariants. This is a breaking
  pre-1.0 session boundary: JWTs issued by earlier builds lack the required
  profile fields and users must reauthenticate after upgrading.
- Session refresh tokens are now 256-bit opaque values stored only as SHA-256
  hashes. Rotation atomically records consumed ancestors, and reuse revokes the
  entire session family. The migration clears legacy plaintext refresh values,
  so existing refresh sessions must reauthenticate after upgrading; a downgrade
  cannot reconstruct those cleared bearer values.
- `/metrics` is disabled by default and requires a configured bearer token when
  enabled; token digests are compared in constant time.
- A configurable global streaming request-body limit now rejects oversized
  requests with HTTP 413 and defaults to 1 MiB.
- Added SQLite tenant-isolation regressions for webhook listing, event
  selection, updates, and deletion, including cross-organization and missing-ID
  denial with unchanged-state assertions.
- Normal API startup now fails closed before database initialization unless
  `ENCRYPTION_KEY` is exactly 64 hexadecimal characters. A narrowly named
  development/test-only escape hatch permits a missing key for disposable data;
  it does not relax malformed-key validation or migrate legacy plaintext rows.
- Device-trust token signing now rejects a missing, malformed, or incorrectly
  sized `DEVICE_TRUST_SECRET` instead of silently using an all-zero production
  fallback. Managed installers continue to generate 32 bytes of hexadecimal
  key material.
- Release containers now run as UID/GID `10001`, keep application files
  non-writable, restrict new SQLite files to the service account, and ship a
  readiness health check. Generated Compose deployments also use a read-only
  root filesystem, a bounded `noexec` temporary directory, no Linux
  capabilities, and `no-new-privileges`.
- OAuth provider-token refresh now validates and pins resolved destinations,
  rejects additional special-purpose IPv4 and IPv4-mapped IPv6 ranges, disables
  redirects, bounds response bodies at 64 KiB, and avoids returning raw remote
  response bodies in errors.
- GitHub, Google, and Microsoft user-info requests now use the same pinned DNS,
  no-redirect SSRF policy and a 64 KiB response limit; provider error bodies and
  malformed profile data are not reflected to clients.
- GeoIP database setup now validates and pins both download destinations,
  permits only MaxMind's documented HTTPS R2 redirect without forwarding the
  license key, bounds compressed and expanded archive work, and atomically
  installs the bounded database file with restrictive permissions.
- Security audit events now use a database-backed durable outbox with bounded,
  idempotent reconciliation, retry/dead-letter state, and all four login,
  organization, MFA, and platform event kinds. High-risk API-key, membership,
  role/ownership, service-access, billing-credential, and impersonation
  mutations commit or roll back with their success event.
- Authentication, invitation, impersonation, organization-switch, cleanup, and
  bootstrap tracing now attributes events with opaque IDs instead of email
  addresses. CI rejects credential and email values passed to tracing macros
  and exercises a failing negative-control fixture.
- File-backed SQLite race regressions now prove single-winner consumption for
  password-reset tokens, magic links, OAuth callback state, and authorized
  client-bound device codes; a losing or wrong-client exchange cannot reuse the
  one-time value.
- OAuth and upstream-SAML callback handlers now require winning the atomic
  state deletion before they process a callback; concurrent losers fail closed,
  and OAuth callbacks reject missing or empty state.
- Bootstrap-login tokens now use constant-time comparison and a database-backed
  consumption record so concurrent processes have one winner before the managed
  state file records use. Missing expiry is rejected.
- Impersonation tokens now require a live revocable session. Each request
  bypasses identity/permission caches and rechecks the actor's current platform
  authority or tenant admin role, organization status, and target membership;
  reasons are mandatory and bounded, and nested impersonation is rejected.
- Email verification uses an expiry-aware conditional claim, and WebAuthn
  challenge deletion has explicit concurrent one-winner coverage. Successful
  WebAuthn authentication now persists the complete library-updated credential,
  counter, and backup state with optimistic concurrency so stale ceremonies
  cannot overwrite newer authenticator state.
- MFA device pre-authentication tokens now sign the exact device-code context;
  verification rejects missing, injected, or mismatched context before checking
  the MFA secret, and authorization still requires an exact pending, unexpired,
  user-bound row.
- Device authorization now atomically claims an unexpired pending row, prevents
  stale callbacks from replacing its principal, and permits token exchange
  after the browser has completed the bound MFA transition.
- SAML RSA certificate generation now runs off the async executor behind a
  bounded semaphore, uses unique random serial numbers, and encodes the same
  three-year validity period stored by AuthOS. Signing uses one active key while
  metadata publishes a bounded seven-day overlap, with explicit retirement,
  expiry status, deletion cleanup, and concurrent-rotation controls.
- Added CI-checked starter Prometheus recording/alert rules and a Grafana
  operations dashboard with a linked alert-response and drill procedure; the
  thresholds remain explicitly unqualified until measured failure exercises.
- Assigned AGPL-3.0-only to the lite web client, scripts, and installer, added
  a CI-enforced first-party license policy, and included the applicable license
  notices in standalone release bundles.
- Cross-version publication is serialized, prerelease tags are rejected until
  an isolated dist-tag policy exists, and every immutable and mutable Docker
  tag is verified against its prepared digest before a GitHub release becomes
  public. npm tarballs and OCI images now carry their complete license notices.

## 0.8.2 - 2026-06-20

- Published coordinated AuthOS packages using the release tag version.
- Published standalone SQLite bundles for Linux amd64 and arm64 with SHA-256
  checksums.
- Published backend-specific, multi-architecture Docker images through the
  release workflow.

Earlier pre-1.0 history is available from
[GitHub Releases](https://github.com/drmhse/AuthOS/releases).

[Unreleased]: https://github.com/drmhse/AuthOS/compare/v0.8.6...HEAD
[0.8.6]: https://github.com/drmhse/AuthOS/compare/v0.8.5...v0.8.6
[0.8.5]: https://github.com/drmhse/AuthOS/compare/v0.8.4...v0.8.5
[0.8.4]: https://github.com/drmhse/AuthOS/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/drmhse/AuthOS/compare/v0.8.2...v0.8.3
