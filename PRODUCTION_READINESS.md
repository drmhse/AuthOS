# AuthOS Production Readiness Plan

Status: active roadmap  
Baseline date: 2026-07-13  
Target sequence: trust foundation -> production candidate (`v0.9`) -> independently evidenced stable release (`v1.0`)

## Purpose

AuthOS should be described as production-ready only when that statement is supported by repeatable, public evidence. Feature breadth alone is not the gate. This plan covers the engineering, security, operational, release, and external-validation work needed to move AuthOS from a promising early-stage identity platform to a credible root identity system for production B2B and B2B2C applications.

The plan deliberately separates two milestones:

- `v0.9` is a production candidate suitable for controlled deployments with documented constraints and close operator involvement.
- `v1.0` is a stable release with a compatibility contract, tested recovery and upgrade paths, protocol evidence, supply-chain controls, an independent security review, and real-world operating evidence.

No date alone triggers either milestone. Each milestone is earned by satisfying its exit criteria.

The current backlog is classified by what can actually close it in
[docs/readiness/remaining-gates.md](./docs/readiness/remaining-gates.md); that
summary does not weaken the milestone criteria below.

## Pre-milestone evidence baseline

This baseline describes public commit `b1c0ed1` from 2026-06-20, before the
trust-foundation files in this change set. Counts use first-party source only:
`git grep -E '#\[(tokio::)?test\]' b1c0ed1 -- 'api/src/*.rs'
'api/src/**/*.rs'` and the equivalent tracked JavaScript test-file search.

The repository already contains substantial implementation work:

- A Rust/Axum API with SQLite, PostgreSQL, and MySQL feature variants.
- Standalone Linux bundles, multi-architecture Docker image builds, and published TypeScript packages.
- OAuth/OIDC, SAML, SCIM, passkey, MFA, organization, role, invitation, webhook, and audit-related code paths.
- 509 first-party Rust test functions across the `api/` workspace crates
  (`cargo test --workspace` executes 522 cases) and 13 JavaScript test files
  (37 JavaScript test cases). Vendored dependency tests are excluded.
- Tag-triggered release workflows for Linux `amd64` and `arm64`, three database image variants, checksums for standalone bundles, and npm provenance.
- Database test-environment scripts and migration history.

Before this trust-foundation change set, the public repository did not provide
enough evidence for a strong maturity claim:

- There is no pull-request CI workflow enforcing Rust format, Clippy, tests, frontend tests, or the three-database matrix.
- Release workflows build and publish artifacts, but do not first enforce the complete test and migration suite.
- There is no repository `SECURITY.md`, `SUPPORT.md`, `CONTRIBUTING.md`, changelog, public roadmap, threat model, conformance report, or production operations runbook.
- Existing authorization tests cover individual tenant boundaries, but there is
  no comprehensive tenant-resource inventory, coverage matrix, or published
  isolation report. There is likewise no committed public evidence for
  OIDC/OAuth conformance, SAML/SCIM interoperability, backup restoration,
  upgrade/rollback behavior, key rotation, or high availability.
- Releases do not yet include SBOMs or signed attestations; Docker provenance is explicitly disabled in the current workflow.
- Version references are inconsistent across the README, Rust crate, bootstrap defaults, and workspace metadata.

This change set begins closing the policy, roadmap, changelog, and baseline-CI
gaps. The remaining items stay open until their evidence is committed and, for
public settings, verified on GitHub. These are evidence gaps, not a claim that
the corresponding implementation is absent or defective.

## Roles and accountability

Names may change; accountability must not. Every tracked item has one directly responsible role and one reviewer role.

| Role | Accountability |
| --- | --- |
| Product maintainer | Product positioning, maturity labels, roadmap, support promises, and milestone approval. |
| Backend maintainer | Rust API correctness, database behavior, migrations, protocol implementation, and tenant isolation. |
| SDK maintainer | TypeScript SDK and framework adapter compatibility, tests, and release coordination. |
| Security lead | Threat model, abuse cases, vulnerability handling, cryptographic lifecycle, and security-review remediation. |
| QA lead | Test strategy, interoperability fixtures, release qualification, and evidence retention. |
| Operations lead | Deployment guidance, observability, backup/restore, upgrade/rollback, HA, and incident runbooks. |
| Release engineer | CI policy, artifact integrity, versioning, signing, SBOMs, provenance, and release reproducibility. |
| Documentation maintainer | Public policies, operator and developer documentation, evidence index, and claim accuracy. |
| Independent assessor | External security assessment and confirmation that reported remediation matches tested behavior. |

## Evidence rules

Every readiness claim must follow these rules:

1. Evidence is generated by a documented command or automated workflow.
2. Evidence identifies the commit, AuthOS version, environment, database, and tool version.
3. Raw machine-readable results are retained alongside a concise human-readable summary.
4. Failures and exceptions are published with an owner, severity, disposition, and target milestone.
5. Release evidence is immutable and linked from the release notes.
6. Marketing claims about scale, compatibility, security, or availability link to reproducible evidence and state their limits.

The documentation maintainer owns a release evidence index. A suitable eventual layout is `docs/trust/` for policies and summaries and release-attached artifacts for raw results. The exact layout may change without weakening these rules.

## Phase 0 — Public trust foundation

Goal: remove contradictory signals and make the project's actual support boundary explicit.

Primary owner: Product maintainer  
Reviewers: Documentation maintainer, Security lead, Release engineer

### Work

- Publish `SECURITY.md` with supported versions, private reporting instructions,
  honest response expectations, disclosure process, and security-advisory policy.
- Publish `SUPPORT.md` with community versus commercial support boundaries and expected response levels without promising capacity that does not exist.
- Publish `CONTRIBUTING.md`, a changelog, a public roadmap, and a documented release lifecycle.
- Publish a capability maturity matrix using `stable`, `beta`, `experimental`,
  and `unsupported`; cover protocols, databases, deployment modes, SDKs, and HA.
- Reconcile version sources so the API, packages, bootstrap defaults, images, documentation, and release tags have one documented versioning scheme.
- State database and deployment limitations explicitly, especially SQLite concurrency/HA boundaries and the supported PostgreSQL/MySQL versions.
- Audit every public performance, protocol, security, and availability claim. Remove it, qualify it, or link it to reproducible evidence.
- Ensure repository description, topics, website language, README, package metadata, container metadata, and release notes use the same positioning and maturity terms.
- Make the AGPL API and MIT SDK/package licensing boundary visible to repository hosts and downstream consumers.

### Exit criteria

- All listed policy and lifecycle documents are present and linked from the README.
- The maturity matrix covers 100% of publicly advertised features and deployment variants.
- A version-consistency check passes in CI and no release-relevant file contains an unexplained hard-coded stale version.
- Every quantitative public claim links to a reproducible benchmark or is removed/qualified.
- One Product maintainer and one Security or Release reviewer sign off on the release evidence review.

### Evidence artifacts

- Public policy documents and maturity matrix.
- Claim-audit checklist with links and dispositions.
- Version-consistency CI report.
- Release lifecycle and support matrix.

## Phase 1 — Mandatory CI and change control

Goal: make every merged change prove that it preserves the supported product surface.

Primary owner: Release engineer  
Reviewers: Backend maintainer, SDK maintainer, QA lead

### Work

- Add pull-request and protected-branch CI for Rust formatting, Clippy with warnings denied, compilation, unit tests, and documentation checks.
- Run backend tests against SQLite, supported PostgreSQL versions, and supported MySQL versions. Use the exact feature and binary combinations shipped to users.
- Run TypeScript typechecking, builds, linting, SDK tests, lite-client tests, and package tests.
- Add clean-install smoke tests for standalone bundles and each Docker database variant.
- Exercise the AuthOS capability document, confirm unsupported standards discovery returns `404`, and smoke-test every supported device/enterprise grant plus token validation, refresh, logout/revocation, and a basic organization-isolation scenario. Add authorization-code/PKCE/ID-token smoke tests only after that provider surface is implemented and supported.
- Test migrations from every supported upgrade origin to the proposed release on all supported databases. Verify failed-migration behavior and data preservation.
- Make release publication depend on the same required checks plus release-specific qualification; tag builds must not bypass branch checks.
- Enable dependency, secret, and static-analysis scanning with a documented severity policy.
- Configure branch protection: required checks, reviewed changes, resolved conversations, no direct pushes to the stable branch, and no administrator bypass except a documented emergency procedure.
- Define flaky-test handling. A retry may gather diagnostic evidence but may not turn a failing required check green without recording the original failure.

### Exit criteria

- A pull request cannot merge unless all required Rust, TypeScript, database, migration, security-scan, and smoke-test checks pass.
- The required matrix passes on 20 consecutive stable-branch runs without an unresolved flaky failure.
- A deliberately broken format check, tenant-isolation test, migration, frontend test, and install smoke test each block a test pull request.
- All release jobs depend on a successful qualification workflow for the exact commit being released.
- Median required-CI duration and the 95th percentile are published so maintainers can keep the gate usable.

### Evidence artifacts

- Required-check and branch-protection configuration export or screenshots.
- CI matrix definition and 20-run stability report.
- Negative-control pull requests demonstrating that failures block merge.
- Test result, coverage trend, lint, dependency, static-analysis, and smoke-test reports.
- Migration compatibility matrix by source version and database.

## Phase 2 — Identity security and protocol conformance

Goal: demonstrate that AuthOS handles hostile identity-system conditions, not only happy-path application behavior.

The canonical status, ownership, and evidence index for this phase is
[docs/readiness/phase-2-evidence.md](./docs/readiness/phase-2-evidence.md). This
section defines the gate; the evidence index tracks the remaining work without
duplicating it across status and architecture documents.

Primary owner: Security lead  
Reviewers: Backend maintainer, QA lead, Independent assessor when engaged

### Work

- Publish a threat model covering trust boundaries, tenants, administrators, service credentials, browser clients, upstream identity providers, webhooks, email, storage, cryptographic keys, and deployment infrastructure.
- Document the security architecture: token types and lifetimes, secret storage, password hashing, session model, audit model, encryption at rest, key hierarchy, rotation, and recovery.
- Create automated cross-tenant authorization tests for users, organizations, roles, invitations, SCIM, SAML, OAuth clients, service tokens, webhooks, audit data, billing metadata, and administrative APIs.
- Test the implemented OAuth device and enterprise extension surfaces for state/code reuse, polling and client binding, refresh-token replay and rotation, revocation, audience/issuer confusion, algorithm confusion, JWKS caching, signing-key rollover, and logout behavior. If authorization-code/OpenID Connect provider behavior is implemented, add redirect URI, PKCE, nonce, authorization-code reuse, and ID-token tests before changing its unsupported label.
- Run an applicable OAuth conformance or independent protocol-qualification suite against a release candidate for the implemented device and enterprise extension profiles. Run OpenID Connect conformance only after that provider behavior exists. Publish the profile, configuration, results, failures, and justified exclusions; do not make a generic compliance claim beyond tested profiles.
- Build SAML interoperability fixtures for the AuthOS IdP against at least three independent service-provider implementations. Separately, keep upstream SAML unsupported until its SP implementation validates signed responses and passes the same adversarial conditions against at least three independent identity providers. Cover signature validation, assertion conditions, replay, audience, destination, clock skew, metadata rollover, and certificate rotation.
- Build SCIM interoperability fixtures for at least two independent clients and cover create/read/update/delete, filtering, pagination, group membership, idempotency, deprovisioning, and tenant isolation.
- Test passkey/WebAuthn ceremonies, MFA enrollment and recovery, magic-link reuse/expiry, credential stuffing controls, enumeration resistance, rate limits, session fixation, CSRF, open redirects, SSRF-relevant integrations, and account-recovery bypasses.
- Test signing-key rotation with overlapping verification windows and an emergency compromise procedure. Prove that rotation does not invalidate valid sessions outside the documented policy.
- Add security logging tests that confirm sensitive values are redacted while security-relevant events remain attributable.
- Establish a severity rubric and remediation service levels. No release may hide accepted risk; exceptions are time-bound and public where disclosure is safe.

### Exit criteria

- The threat model and security architecture receive Security lead and Backend maintainer approval and are updated for every material architecture change.
- Automated tenant-isolation tests cover every tenant-scoped resource identified in the threat model, with zero open critical or high-severity failures.
- The selected OIDC/OAuth conformance profile passes, or every non-pass is explicitly documented and the affected capability is marked beta/unsupported.
- The AuthOS SAML IdP passes against at least three independent SPs. If upstream SAML is offered, the AuthOS SAML SP also passes against at least three independent IdPs. SCIM tests pass against at least two independent clients.
- Key rotation, compromised-key response, token replay, revocation, recovery, and audit-redaction scenarios pass in CI or a release qualification environment.
- There are zero unresolved critical or high security findings at release; medium findings require a documented owner, mitigation, and due date.

### Evidence artifacts

- Versioned [threat model](./docs/security/threat-model.md) and
  [security architecture](./docs/security/security-architecture.md).
- [Tenant-resource inventory](./docs/security/tenant-resource-inventory.md) and
  authorization test matrix.
- Raw and summarized OIDC/OAuth conformance results.
- SAML and SCIM interoperability matrix with sanitized fixtures.
- Abuse-case test report and security regression suite results.
- Key-rotation exercise report and cryptographic inventory.
- Vulnerability register with disclosure-safe remediation status.

## Phase 3 — Operational maturity and recoverability

Goal: prove that operators can safely deploy, observe, upgrade, recover, and scale AuthOS.

Primary owner: Operations lead  
Reviewers: Backend maintainer, Security lead, QA lead

### Work

- Publish production reference architectures for standalone SQLite and externally managed PostgreSQL/MySQL. State which are single-node, fault-tolerant, or HA-capable.
- Document supported platforms, resource sizing, capacity signals, reverse-proxy requirements, TLS boundaries, time synchronization, email dependencies, DNS/custom-domain behavior, and storage durability.
- Define metrics, health/readiness semantics, structured logs, traces where supported, audit export, dashboards, and alert thresholds. Verify secrets and personal data are not exposed by default.
- Write and exercise runbooks for install, backup, full restore, point-in-time recovery where supported, upgrade, rollback, failed migration, key rotation, expired certificate, upstream IdP outage, SMTP outage, database saturation, and credential compromise.
- Test backups by restoring into an isolated environment and performing authenticated and administrative journeys against restored data.
- Define RPO and RTO per deployment mode based on measured drills, not aspiration.
- Run failure injection for process crash, host restart, database disconnect, connection exhaustion, partial dependency failure, clock skew, and disk-full conditions.
- For HA claims, test multiple API replicas with the documented load balancer and external database topology. Cover session consistency, job duplication, cache invalidation, migrations, and rolling upgrades.
- Publish capacity tests for representative authentication, token, organization, SAML, and SCIM workloads. Include hardware, topology, data volume, latency percentiles, error rate, warm-up, duration, and bottlenecks.
- Document data retention, deletion, export, audit retention, and privacy-operation behavior.

### Exit criteria

- A clean operator can deploy each supported production topology from documentation without undocumented maintainer intervention.
- Automated nightly or scheduled restore tests succeed for 30 consecutive days; the release-candidate restore drill is observed by QA.
- Upgrade tests pass from every supported source version on all supported databases; rollback behavior and irreversible boundaries are explicit.
- At least two disaster-recovery drills meet the published RPO/RTO for each deployment mode claimed as production-ready.
- All documented critical alerts are triggered in a controlled exercise and link to a runbook that restores service.
- HA is not advertised until rolling-upgrade and failure-injection tests demonstrate the published availability behavior.
- Performance claims are reproducible within a documented tolerance and include raw results.

### Evidence artifacts

- Reference architectures and deployment support matrix.
- Operator guide, dashboards, alerts, and runbooks.
- Backup/restore, disaster-recovery, and failed-migration drill reports.
- Upgrade/rollback matrix and rolling-upgrade report.
- Failure-injection results.
- Reproducible benchmark harness, environment manifest, raw data, and report.

## Phase 4 — Release contract and software supply chain

Goal: make releases predictable, verifiable, upgradeable, and supportable.

Primary owner: Release engineer  
Reviewers: Product maintainer, Security lead, Operations lead, SDK maintainer

### Work

- Adopt semantic versioning across API, images, installers, SDKs, and framework packages, with an explicit policy for coordinated and independently versioned components.
- Publish compatibility and deprecation policies covering API behavior, database schema, configuration, tokens/claims, webhooks, SDKs, and supported upgrade paths.
- Generate changelogs from reviewed change categories and require migration, security, breaking-change, and rollback notes.
- Produce CycloneDX or SPDX SBOMs for standalone binaries, Docker images, and npm packages.
- Sign or keylessly attest binaries, checksums, images, npm packages, and provenance. Publish verification instructions and test them from a clean environment.
- Enable image provenance and use immutable base-image references. Record build toolchains and dependency locks.
- Make builds reproducible where practical; at minimum, rebuild the same commit in an isolated job and explain any non-reproducible fields.
- Define an emergency release and rollback procedure, including revoked artifacts, compromised signing identities, and customer notification.
- Publish end-of-life dates and supported patch branches. Security fixes must identify affected versions.
- Create a release checklist that links every required result and requires independent Release and Security approval.

### Exit criteria

- Every release artifact has an SBOM, digest, provenance/attestation, and documented verification path.
- A clean-environment verifier successfully validates every release artifact and records the result.
- Compatibility, deprecation, supported-version, and end-of-life policies are public and internally consistent.
- Upgrade and rollback notes exist for every release with a schema or configuration change.
- Two consecutive production-candidate releases complete the full release process without an undocumented manual repair.
- Emergency release and signing-identity compromise exercises complete successfully.

### Evidence artifacts

- Release manifest linking artifacts, digests, SBOMs, attestations, and test reports.
- Artifact-verification transcript.
- Compatibility, deprecation, version-support, and EOL policies.
- Reproducibility comparison report.
- Completed release checklists and emergency-release exercise report.

## Phase 5 — External evidence and ecosystem confidence

Goal: replace self-assessed maturity with evidence that independent people can reproduce.

Primary owner: Product maintainer  
Reviewers: Independent assessor, Security lead, Documentation maintainer

### Work

- Commission an independent security assessment covering authentication flows, authorization/tenant boundaries, protocols, cryptography, deployment defaults, and supply chain.
- Publish the assessment scope, date, tested version, executive summary, and remediation status. Withhold exploit detail only while coordinated remediation requires it.
- Recruit at least two independently operated production reference deployments with different operators; one should use a non-SQLite database and one should exercise enterprise federation or provisioning.
- Track deployment duration, upgrades, incidents, restore drills, support requests, and operator feedback for a meaningful operating window.
- Publish case studies only with operator approval, and distinguish measured results from testimonials.
- Invite reproducibility of benchmarks and protocol tests. Record independent confirmations and disagreements.
- Publish an accurate comparison page that focuses on architecture and use-case fit, cites sources, states tradeoffs, and avoids unsupported competitor claims.
- Establish a public release cadence and issue triage process with visible response and closure metrics.

### Exit criteria

- An independent assessment is complete, with zero unresolved critical/high findings and public remediation status for all other material findings.
- At least two independent production deployments have operated for 90 consecutive days and completed one upgrade and one restore drill each.
- At least one reference deployment uses PostgreSQL or MySQL, and at least one exercises SAML or SCIM in production.
- Public issue-triage and release metrics cover at least 90 days and match the support policy.
- Published case studies and benchmark/conformance claims link to evidence and disclose relevant limitations.

### Evidence artifacts

- Independent assessment report and remediation ledger, scoped using the
  [assessment scope](./docs/readiness/independent-assessment-scope.md).
- Sanitized reference-deployment scorecards and approved case studies, using
  the [reference deployment evidence plan](./docs/readiness/reference-deployment-plan.md).
- Independent reproduction links or reports.
- Public project-health and release-cadence metrics.
- Evidence-backed architecture comparison.

## `v0.9` production-candidate gate

`v0.9` may be called a production candidate only when Phases 0 and 1 are complete and the following minimum subset is complete:

- Threat model, tenant-isolation inventory, OAuth/OIDC abuse suite, signing-key rotation test, and security disclosure process.
- Documented production topology and limitations for every variant labeled supported.
- Backup/restore and upgrade tests for every supported database, with measured preliminary RPO/RTO.
- Compatibility/deprecation policy, changelog, SBOMs, artifact verification, and release checklist.
- Zero unresolved critical/high security defects; all exceptions are documented.

The `v0.9` release notes must still say that independent security review, long-running reference deployments, or HA evidence remain incomplete where that is true. “Production candidate” must not be shortened to “production-ready.”

## `v1.0` stable-release gate

`v1.0` is a pass/fail decision. All of the following are mandatory:

- Phases 0 through 5 satisfy their exit criteria for the exact release candidate or an explicitly traceable equivalent commit.
- All required CI checks pass for the release commit, and the 20-run stability criterion remains satisfied.
- The supported database migration matrix, clean-install tests, backup restore, disaster recovery, and upgrade/rollback exercises pass.
- The declared OIDC/OAuth conformance profile passes. SAML and SCIM interoperability meet the published matrices for any capability labeled stable.
- Cross-tenant isolation coverage is complete for the resource inventory, with zero known critical/high authorization failures.
- Signing-key rotation and compromise response are exercised successfully.
- An independent security review is complete, with zero unresolved critical/high findings and disclosed status for material findings.
- Each artifact is accompanied by a digest, SBOM, provenance/attestation, verification instructions, and a passing verification record.
- Compatibility, deprecation, support, EOL, and vulnerability-response contracts are public.
- Two independently operated production deployments have completed the 90-day, upgrade, and restore criteria.
- Every scale, availability, protocol, and security claim in `v1.0` materials links to evidence and states the tested boundary.
- Product, Security, Operations, QA, and Release roles each record approval of the completed release checklist.

The following are not acceptable substitutes for the gate:

- Feature count, test count, download count, stars, or elapsed development time.
- A successful build without protocol, recovery, and isolation evidence.
- A private assessment with no scope or remediation status.
- A customer deployment that has not exercised upgrade and restore.
- Calling unsupported behavior “known limitations” while still advertising the capability as stable.

If any mandatory item fails, the release remains `v0.x` or the affected capability remains beta/unsupported. The project should prefer an honest delayed `v1.0` over a stable label that transfers unmeasured risk to operators.

## Ongoing requirements after `v1.0`

Production readiness is maintained, not completed once.

- Run the full qualification suite for every stable release and the security-critical subset for every patch.
- Exercise restore monthly and disaster recovery at least quarterly for maintained reference environments.
- Review the threat model at least quarterly and after every material architecture or protocol change.
- Repeat independent security assessment annually and after high-risk architectural changes.
- Re-run conformance when protocol behavior, relevant dependencies, or supported profiles change.
- Publish security advisories, release evidence, support/EOL changes, and regression status promptly.
- Revoke or qualify a maturity claim when its evidence becomes stale or a regression invalidates it.

## Progress reporting

Track each exit criterion as `not started`, `in progress`, `blocked`, or `verified`. An item is `verified` only when its evidence link and reviewer are recorded. Publish a concise monthly readiness update containing:

- criteria completed and evidence links;
- new risks or regressions;
- open security findings by severity;
- CI stability and flaky-test trend;
- upgrade, restore, and incident exercises completed;
- claims added, removed, or qualified; and
- the current reason AuthOS is or is not eligible for `v0.9` or `v1.0`.

This report should make the maturity assessment derivable from evidence rather than dependent on project confidence or marketing language.
