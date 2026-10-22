# Remaining production-readiness gates

Status: canonical closure-classification summary  
Reviewed: 2026-10-22

This page separates work that can be implemented in the repository from gates
that require a protected release candidate, repository administration,
independent systems or people, production infrastructure, or elapsed operating
time. It prevents an external gate from being presented as a missing local code
change and prevents implemented code from being presented as qualified before
its required evidence exists.

The detailed Phase 2 control status remains in
[phase-2-evidence.md](./phase-2-evidence.md). The compact evidence snapshot is
[current-status.md](./current-status.md). The authoritative milestone rules
remain in [PRODUCTION_READINESS.md](../../PRODUCTION_READINESS.md).

Latest release evidence (`v0.8.16`): the coordinated standalone, npm, and
container workflow completed, and the standalone and npm release-evidence
verifiers pass. `main` and `v*` tags are now protected, and publication waits
for approval in the `release` environment. The first manually dispatched
restore-qualification run succeeded for SQLite, PostgreSQL 16, and MySQL 8.4;
the 30-consecutive-day window is open. These close part of the Phase 1 and
Phase 4 controls; they do not shorten the elapsed evidence windows below.

## Repository-local work still open

These are engineering backlogs, not external excuses:

- finish the tenant route/resource/actor matrix, including unchanged-state
  negative tests for every sensitive ID-bearing operation;
- qualify the closed local audit caller/direct-write inventory under
  multi-worker reconciliation, requeue/alerting, and live PostgreSQL/MySQL
  outage/recovery scenarios;
- complete application-secret lifecycle qualification under the documented
  temporary retention/removal criteria for identity/connected-account
  compatibility columns; qualify V2/CAS rewrap on PostgreSQL/MySQL and multiple
  writers, and publish a release-candidate restored-backup/retention-window
  drill before actual old-key retirement. Repository-local SQLite evidence now
  covers restored identity/connected-account reads, rewrap, backup-dependent
  old-key refusal, and a read-only startup gate that runs after schema migration
  but before any API/worker/bootstrap path; deployment qualification of the
  separate migration job plus quiesced rewrap sequence remains external;
- complete SAML signing-certificate external evidence: PostgreSQL/MySQL and
  multi-replica rotation, restored backups, wired expiry alerts, emergency
  retirement, and real SP metadata caches; keep upstream SAML disabled unless
  full signed-response validation is implemented;
- finish handler-level enumeration/timing matrices and qualify the implemented
  signed, exact MFA device-code pre-authentication binding across supported
  databases and multiple replicas;
- expand the new SAML structural corpus and bounded Argon2 request helpers into
  maintained fuzz targets and non-SAML JSON/form/filter/archive corpora; bound
  remaining archive and XML-signature work and publish measured load behavior;
- extend the local supported-origin SQLite upgrade and runner-failure/rollback
  fixtures to every declared source release and execute the reusable head-schema
  assertions in PostgreSQL/MySQL CI; add crash, disk-full, and restore drills;
- import and exercise the checked starter dashboard/alerts; execute the
  implemented bounded failure and capacity harnesses against exact release
  candidates; then publish measured thresholds and reference-architecture
  resource guidance with raw environment/result evidence;
- complete any deliberately chosen new protocol surface. The authorization-code
  OpenID Connect provider and upstream SAML SP are currently unsupported; they
  are not silently counted as implemented readiness work.

## Requires a committed release candidate or CI infrastructure

The local workspace cannot truthfully manufacture these results:

- execute the PostgreSQL 16.x and MySQL 8.4.x runtime, logical restore,
  migration, race, tenant, SCIM, and secret-rewrap suites in clean CI services;
- build, publish, and independently verify the exact standalone/npm/container
  manifests, digests, SBOMs, provenance, and attestations for a signed tag;
- boot-smoke the exact published `amd64` and `arm64` container images under
  QEMU (or native runners), and clean-install/smoke the published standalone
  archives in disposable hosts. The checked workflows do not yet perform these
  published-artifact release-run checks;
- qualify JWT rollover through real downstream JWKS caches and restored backup
  state; exercise retirement and emergency compromise against the candidate;
- exercise real proxies, DNS changes/rebinding, network failures, disk full,
  clock skew, database disconnect/exhaustion, process/host restart, and rolling
  deployment behavior in disposable infrastructure;
- run clean-install and upgrade/rollback drills from every declared supported
  source version using the exact published artifacts.

## Requires repository or organizational administration

- add a second maintainer for independent code review and document the
  emergency bypass; protected branches, required checks, conversation
  resolution, tag protection, and release-environment approval are now
  configured;
- record Product plus Security/Release approval of public claims, threat model,
  architecture, vulnerability disposition, and each release checklist;
- configure private vulnerability intake, maintainer/on-call ownership, signing
  identities, registry protections, support contacts, and retention locations;
- decide whether unsupported OIDC-provider/upstream-SAML features are roadmap
  commitments or remain explicitly out of scope;
- decide the license for the remaining unassigned root documentation and
  configuration before distributing those paths. The API and migration crates,
  lite web client, scripts, and installer are explicitly AGPL-3.0-only; CI must
  keep package metadata and shipped license notices aligned with that decision.

## Requires independent implementations or assessors

- applicable OAuth device/enterprise-extension qualification against the exact
  release candidate;
- SAML IdP interoperability with at least three independent service providers;
- SCIM interoperability with at least two independent clients;
- real-browser and independent-authenticator WebAuthn coverage;
- an independent security assessment, remediation, and retest with a
  disclosure-safe public scope and status; see the
  [assessment scope](./independent-assessment-scope.md).

## Requires elapsed evidence

- twenty consecutive protected security/quality runs with negative controls
  shown to block merge;
- thirty consecutive scheduled restore results plus two measured recovery
  drills for every deployment mode that receives an RPO/RTO claim; the daily
  workflow is configured, but the consecutive-result window has not completed;
- two consecutive production-candidate releases without undocumented repair;
- two independently operated reference deployments for ninety days, including
  one non-SQLite deployment and one SAML or SCIM deployment, each completing an
  upgrade and restore drill; see the
  [reference deployment evidence plan](./reference-deployment-plan.md);
- ninety days of public issue-triage and release-cadence metrics.

Until the explicit `v0.9` candidate gate passes, AuthOS should remain described
as pre-1.0 Beta software for controlled pilots, with the exact unsupported
boundaries in
[PROJECT_STATUS.md](../../PROJECT_STATUS.md), rather than as a universally
production-ready root identity system.
