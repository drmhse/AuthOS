# Current readiness status

Status: evidence snapshot, updated 2026-10-22  
Source of truth: [tenant-isolation matrix](../security/tenant-isolation-matrix.json), [phase-2 evidence](./phase-2-evidence.md), and [remaining gates](./remaining-gates.md)

This page is a compact snapshot for maintainers. It does not replace the
authoritative milestone rules in [PRODUCTION_READINESS.md](../../PRODUCTION_READINESS.md).

## Release position

- Latest public release: **v0.8.16**, published and verified.
- Latest public npm packages: `0.8.16` for all five `@drmhse/*` packages.
- Docker tags: `v0.8.16`, backend-version tags, and `latest` pointers verified.
- No `v0.9` production candidate has been declared.

## Local evidence

| Measure | Current |
| --- | --- |
| Tenant-isolation tracked critical gaps | **0** |
| Tenant-isolation tracked high gaps | **19** |
| Rust test cases | **305** in the `sso` suite plus workspace suites |
| Strict Clippy / formatting | Passing |
| Release metadata, docs, tenant, backup, audit, redaction, and related checks | Passing |
| Protected `main` CI/Security runs | **20** consecutive green runs |
| Daily restore-qualification workflow | Configured; first manual run passed for SQLite, PostgreSQL 16, and MySQL 8.4 |
| 30-day restore window | Open; starts with scheduled runs |
| PostgreSQL/MySQL matrix parity | Not complete |
| Multi-replica timing | Not complete |

## External and time-based gates

These cannot be completed by repository code changes alone:

- independent security assessment and retest;
- two independently operated reference deployments for 90 days, each with an
  upgrade and restore drill;
- 30 consecutive scheduled restore results and two disaster-recovery drills;
- 90 days of public issue-triage and release metrics;
- two consecutive production-candidate releases without undocumented repair;
- a second maintainer for independent review and release approval.

## Current gap classes

- **Local high gaps:** distributed cache revocation, multi-replica one-time
  consumption, parent/child races, provider callback concurrency, metadata
  policy, and background delivery concurrency.
- **Database parity:** most matrix rows still require PostgreSQL/MySQL runtime
  evidence rather than compile checks.
- **Operational:** upgrade/rollback drills, failure injection, capacity,
  alert-firing exercises, and HA/rolling-upgrade qualification remain open.
- **External:** assessment, reference deployments, interoperability matrices,
  and long-running public metrics remain open.

## Next actions

1. Add PostgreSQL/MySQL parity execution for the closed local matrices.
2. Add multi-replica timing and one-time-consumption tests.
3. Complete the remaining high-gap tests and operational drills.
4. Start the independent assessment and reference-deployment outreach.
5. Keep the protected-run and restore clocks moving, then prepare v0.9.
