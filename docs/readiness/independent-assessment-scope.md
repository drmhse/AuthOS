# Independent security assessment scope

Status: scoping template, not an assessment  
Target: the exact `v0.9` production candidate

This document defines the minimum scope for the independent security
assessment required by the `v1.0` gate. It is written so an assessor can price
and execute the work without relying on private context. The assessment is not
complete until the public report, remediation ledger, and retest statement are
linked from the release evidence.

## Candidate identity

The engagement must name:

- the annotated release tag and full commit;
- the standalone archive and container image digests;
- the database engines and versions tested;
- the deployment topology, reverse proxy, and TLS boundary; and
- the exact supported feature profile, including capabilities deliberately
  marked beta or unsupported.

The assessment does not apply to `v0.8.16` or any unreleased snapshot. If the
candidate changes materially after assessment starts, the changed surface must
be re-scoped or retested.

## Required scope

### Authentication and session security

- password, magic-link, passkey/WebAuthn, MFA, backup-code, OAuth, and device
  authorization journeys;
- login throttling, enumeration resistance, session fixation, refresh-token
  rotation and replay response, logout, revocation, and step-up authentication;
- bootstrap, recovery, impersonation, and platform-owner paths;
- session and authorization behavior across multiple API replicas.

### Authorization and tenant isolation

- every tenant-scoped resource family in the
  [tenant-resource inventory](../security/tenant-resource-inventory.md);
- owner, admin, custom-role, member, service, SCIM, and platform actors;
- cross-tenant resource identifiers, unchanged denied state, suspended and
  deleted parents, and selector confusion;
- service credentials, provider grants, webhooks, audit data, billing metadata,
  domain routing, and administrative APIs.

### Protocols and cryptography

- implemented OAuth device and enterprise-extension profiles;
- SAML identity-provider behavior, signed-response validation boundaries,
  metadata and certificate rollover;
- SCIM authentication, filtering, pagination, deprovisioning, and tenant
  isolation;
- JWT profile separation, signing-key rollover, JWKS behavior, encryption-key
  rotation, secret storage, and redaction;
- OIDC authorization-code and upstream SAML only if the candidate advertises
  them as supported.

### Deployment and supply chain

- secure defaults, bootstrap behavior, secret handling, file permissions,
  container runtime posture, proxy assumptions, and exposed operational
  endpoints;
- release manifests, checksums, SBOMs, provenance, attestations, and the
  clean-environment verifier;
- upgrade, rollback, backup, restore, and disaster-recovery assumptions that
  affect security.

### Abuse cases

- credential stuffing, account recovery bypass, MFA bypass, session theft,
  invitation abuse, open redirect, SSRF, parser and decompression bounds,
  audit redaction, and audit-loss scenarios.

## Explicitly out of scope

- managed services, operator-owned infrastructure, and third-party identity
  providers;
- availability or denial-of-service claims against systems the assessor does
  not own;
- high-availability claims, unless the candidate explicitly advertises HA;
- unsupported capabilities, which must fail closed and be documented as
  unsupported; and
- social engineering, physical access, and production data exfiltration.

## Method and access

The assessor should combine source review, configuration review, and
black-box testing against a disposable candidate deployment. Access must be
limited to test accounts, test data, and non-production secrets. The assessor
must not retain or publish live credentials, personal data, or operator
infrastructure details.

## Deliverables

- executive summary with the tested candidate identity and limitations;
- findings with severity, affected boundary, reproduction, impact, and
  remediation guidance;
- a remediation ledger with owner, disposition, and retest status;
- a retest statement for every critical/high finding;
- a disclosure-safe public report or public summary; and
- an explicit statement of residual risk and unsupported scope.

## Acceptance criteria

- zero unresolved critical or high findings against the candidate;
- every medium finding has an owner, mitigation, due date, and public
  disposition where disclosure is safe;
- the report names the exact candidate and the tested database/topology; and
- Product and Security approve the public summary and remediation status.

## Contact

Send scoping questions to [info@authos.dev](mailto:info@authos.dev) with the
subject `AuthOS independent assessment`. Do not send credentials or production
data in the initial message. Vulnerability handling follows
[SECURITY.md](../../SECURITY.md).
