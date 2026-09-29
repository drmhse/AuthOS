# AuthOS project status

AuthOS is under active development in the pre-1.0 release series. The project
may be evaluated for integration work and controlled production pilots whose
operators independently validate the features and deployment model they depend
on. It is not presented as a universally production-ready root identity system.

This distinction is deliberate. Identity infrastructure earns trust through
repeatable tests, protocol conformance, secure release engineering, and tested
recovery procedures. The work required to publish that evidence is tracked in
[PRODUCTION_READINESS.md](./PRODUCTION_READINESS.md).

## Current support statement

The labels used here mean:

- **Stable:** covered by a compatibility commitment and published readiness
  evidence.
- **Beta:** implemented and available, but compatibility or readiness evidence
  is not complete.
- **Experimental:** available for evaluation without a support commitment.
- **Unsupported:** not currently offered as a supported AuthOS configuration.

| Area | Current status |
| --- | --- |
| Rust API and database schema | **Beta.** Breaking changes remain possible before 1.0. |
| Organizations, teams, roles, and permissions | **Beta.** Tenant-isolation evidence is being expanded. |
| OAuth 2.0 device authorization | **Beta.** Device-code issuance and exchange are implemented; public end-to-end and abuse-case evidence is incomplete. |
| Enterprise managed authorization extensions | **Beta.** Token exchange, JWT bearer exchange, and the ID-JAG profile are implemented; public interoperability evidence is incomplete. |
| OAuth authorization-code server and OpenID Connect provider | **Unsupported.** AuthOS does not currently expose a standards authorization endpoint or issue ID tokens. The OpenID Connect and RFC 8414 discovery paths return `404` rather than advertise unimplemented behavior. |
| Social OAuth and upstream OIDC identity providers | **Beta.** Public interoperability results are not yet published. |
| SAML identity-provider SSO | **Beta.** The public interoperability suite is planned. |
| Upstream SAML identity providers | **Unsupported.** Response signature verification is not implemented; processing fails closed. |
| SCIM provisioning | **Beta.** The public client interoperability suite is planned. |
| Password, magic-link, MFA, and passkey journeys | **Beta.** Security abuse-case evidence is being expanded. |
| Service credentials, webhooks, and audit export | **Beta.** Compatibility and delivery/replay evidence is being expanded. |
| Custom domains, branding, and upstream domain routing | **Beta.** Deployment and interoperability boundaries are not yet fully published. |
| Metrics, structured logs, and operational jobs | **Beta.** CI checks starter Prometheus rules and a Grafana dashboard; bounded local failure and capacity runners have schema, safety, and redaction tests. One pinned SQLite budget-VM experiment publishes its harness and raw evidence, but supported resource guidance across releases, databases, production hosts, and journeys remains incomplete, as do live monitoring import/firing, broader runtime redaction, and external failure-exercise evidence. |
| Application secret encryption | **Beta.** Normal startup requires an active 32-byte key. New writes use record/field-bound AES-GCM V2 envelopes; active/previous keyrings read V2, V1, and legacy ciphertext. A default-dry-run, bounded ten-table CAS rewrap includes webhook/SIEM plaintext migration and SQLite interruption/tamper/swap coverage. PostgreSQL/MySQL, restored-backup reads, secret-manager integration, and old-key retirement evidence remain incomplete. |
| TypeScript, React, Vue, Node, and CLI packages | **Beta.** Published in the pre-1.0 series; consumers should pin versions. |
| SQLite standalone bundles on Linux amd64/arm64 | **Beta, single-node.** `v0.8.13` includes the checksum-verifying installer; release attestations become evidence only after the coordinated workflow succeeds. No multi-writer or HA guarantee is made. |
| PostgreSQL Docker deployments | **Beta.** PostgreSQL 16.x is the sole configured CI runtime qualification target for migration, login/tenant CRUD, and logical restore; link a successful protected run before treating that configuration as evidence. Other major versions and managed services are unqualified. |
| MySQL Docker deployments | **Beta.** MySQL 8.4.x is the sole configured CI runtime qualification target for migration, login/tenant CRUD, and logical restore; link a successful protected run before treating that configuration as evidence. Other series and managed services are unqualified. |
| Multi-node/high-availability operation | **Unsupported as a general guarantee.** HA behavior and topology constraints have not yet been evidenced publicly. |
| Independent security assessment | **Not yet evidenced.** No independent audit report has been published. |
| Upgrade, rollback, and recovery guarantees | **Not yet stable.** Procedures and automated evidence are being formalized. |

The canonical Phase 2 gap and evidence tracker is
[docs/readiness/phase-2-evidence.md](./docs/readiness/phase-2-evidence.md).
This table states current support; it does not duplicate that implementation
backlog. The separate
[remaining-gates classification](./docs/readiness/remaining-gates.md) shows
which open items are local engineering, release-candidate/infrastructure,
administrative, independent, or time-based work.

## Versioning expectations

- Pre-1.0 releases may contain breaking API, configuration, SDK, or migration
  changes. Changes must be called out in release notes.
- Production users should pin an exact AuthOS version and test upgrades in a
  representative environment.
- Security fixes may require upgrading to the latest release in the current
  series.
- A 1.0 release will not be declared solely because the feature set is broad.
  It must satisfy the evidence gates in the production-readiness plan.

## Choosing AuthOS today

AuthOS can be evaluated when an application needs native organizations,
enterprise federation, provisioning, and application SDKs in a self-hosted
platform. Operators considering AuthOS for critical workloads should review the
limitations above, the [security policy](./SECURITY.md), and the
production-readiness plan before deployment.

Questions about deployment suitability can be raised using the channels in
[SUPPORT.md](./SUPPORT.md). Security-sensitive questions must follow
[SECURITY.md](./SECURITY.md) instead of being posted publicly.
