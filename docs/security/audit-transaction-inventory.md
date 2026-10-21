# Audit transaction inventory

Status: active engineering inventory  
Reviewed: 2026-07-14

AuthOS has a durable database outbox for login, organization, MFA, and platform
audit events. `AuditHandle::log_*_with_db` accepts the store-layer `DB` wrapper,
so a handler can insert its domain mutation and success event through the same
database transaction. The wake message is only a delivery hint; the committed
outbox row remains discoverable by startup and periodic reconciliation.

## Transaction-coupled security-sensitive flows

The following mutations now commit or roll back with their success audit row:

- API-key create and service-scoped delete (`handlers/api_keys.rs`);
- member role and permission change, including the ownership-transfer branch;
- member removal and organization-permission revocation;
- direct per-service member grant replacement;
- explicit organization ownership transfer;
- custom organization-role create, update, and delete;
- billing-credential create/update and provider-scoped delete; and
- impersonation session creation with its high-severity platform event.

The role-change flow writes `member.role_changed` only after its role,
permission, and optional ownership work succeeds. The ownership event is last in
the same transaction. Response models needed by these handlers are also loaded
before the audit row is inserted, so a later fallible database read cannot turn
an already-audited success into an error response.

SQLite regression tests in `services/audit_actor.rs` prove that an outbox insert
failure rolls back the paired domain mutation and that a later domain failure
rolls back an earlier success event. The four supported event kinds are also
covered by durable enqueue and replay.

## Closed transaction boundary inventory

The original remaining inventory contained 39 `AuditHandle` calls. Every call
is now classified: 35 success events accompany a database mutation and use the
same transaction; four events describe a rejected attempt or conflict without a
paired domain mutation and use the standalone durable enqueue.
There are zero unclassified calls.

Across the complete current production tree, the structural checker finds 54
physical `AuditHandle` call expressions: 50 use a caller-supplied transaction
and four are the allowlisted standalone result/rejection events below. The
earlier 35+4 figures describe the original remaining-inventory baseline, not
the whole tree. Two OAuth completion routes intentionally share one coupled
session/audit helper, so route-flow counts need not equal physical call-expression
counts. The additional coupled expression is the provider-token request store
helper: it rejects non-transaction callers, conditionally consumes the
user-bound request, upserts the exact service/account grant, and enqueues every
caller-supplied success event through the same transaction. The SCIM
deprovision expression is also coupled: selected-organization membership,
permissions, sessions, identities, grants, provider requests, and pending auth
state are revoked before its success event is enqueued in that same
transaction; an enqueue failure rolls every revocation back. Separately, five
generic-connection enqueue expressions cover the
service/store compatibility APIs, and ten platform mutation routes call the
transaction-preserving platform audit helper.

The original conversion tranche and subsequently closed coupled flows cover:

- SAML configuration and signing-key lifecycle (4), branding/custom-domain
  lifecycle (4), SIEM configuration lifecycle (3), and service create/secret
  rotation (2);
- MFA setup/enable/disable/backup-code generation (5), one-time backup-code
  consumption (1), and GDPR anonymization across every affected organization
  (2);
- connected-account grant, transfer, revoke, provider-token refresh/issue, and
  provider-token-request completion flows (9); and
- OAuth, device-flow, passkey, and MFA challenge success persistence (4), where
  the session/one-winner state change and login/MFA event share one transaction;
- organization deletion (1), recorded as a platform event with preserved
  organization identity so deleting/cascading the organization cannot make the
  audit event permanently unreplayable.

Response models and other fallible database reads are completed before the
success event is enqueued. One-time backup-code consumption uses a conditional
`used = false` update; exactly one claimant can commit the code-use audit.
Custom-domain set, verification, and deletion similarly compare the exact
domain, verification token, and verification state observed by the request.
A concurrent replacement fails without changing the replacement or enqueuing a
stale success event. Domain and branding mutations also recheck current
management authority (and the applicable tier entitlement) inside that same
transaction.

The four intentionally standalone durable events are:

| Path | Classification |
| --- | --- |
| `handlers/user.rs` | rejected TOTP enable verification |
| `handlers/user.rs` | account-security MFA step-up success (result-only) |
| `handlers/auth/mfa.rs` | rejected MFA verification result |
| `handlers/auth/oauth.rs` | rejected provider-account conflict |

`handlers/auth/utils.rs` previously held a fourth: a shared result-only login
helper that nothing called. It was removed with the file, taking the count from
four to three.

Standalone does not mean best-effort: `AuditHandle::log_*` returns only after
the outbox row is durable. It merely means there is no domain mutation whose
transaction must be shared.

## Direct-write disposition

All five formerly identified production bypasses now route through the common
outbox:

- `MfaAuditService` and `OrganizationAuditService` use
  generic-connection durable enqueue;
- platform `create_audit_log` uses the platform outbox payload and preserves its
  caller's transaction;
- both `LoginEventStore` create APIs enqueue login payloads durably in every
  build.

Organization-audit pagination and login analytics tests exercise the same
durable outbox and reconciliation path as production. Tests that require a
historical timestamp still insert an explicit final-table fixture directly;
there is no `cfg(test)` branch that changes a production audit-write API.

The structural checks remain useful because line numbers move:

```bash
rg -n '\.log_(org|login|mfa|platform)\(' api/src --glob '*.rs'
rg -n 'audit_log.*\.insert|new_event\.insert' \
  api/crates/authos-services/src/services/audit.rs api/src/handlers/platform/mod.rs api/crates/authos-store/src/store/login_events.rs
npm run check:audit-policy
```

The second search should return no matches.

## Qualification boundary

SQLite regression tests cover mutation rollback on enqueue failure, rollback of
an earlier audit when a later domain operation fails, durable restart replay,
all four payload kinds, deleted-organization replay, and one-winner backup-code
consumption. OAuth and device-flow regressions also inject outbox failure and
prove the paired session/code-consumption mutation rolls back. PostgreSQL and
MySQL are compile-checked only; backend-specific
failure/replay testing is still required before claiming equivalent operational
qualification. The reconciler's qualified topology remains one worker per
database. Multi-worker claiming/lease semantics are not claimed by this work.
