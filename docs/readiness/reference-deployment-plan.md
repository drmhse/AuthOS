# Reference deployment evidence plan

Status: recruitment and evidence template, not completed evidence  
Target window: 90 consecutive days, with one upgrade and one restore drill

The `v1.0` gate requires two independently operated production deployments.
This plan defines the minimum evidence so the window can start before `v0.9`
is published and still support an honest `v1.0` decision.

## Deployment selection

At least two deployments must be operated by people other than the AuthOS
release builder. Together they must include:

- one deployment using PostgreSQL or MySQL rather than SQLite;
- one deployment exercising SAML or SCIM in production; and
- one completed upgrade from a published source release to the next candidate,
  with rollback notes and observed duration.

A controllable pilot or design-partner deployment counts only when it runs real
authentication workloads for real users, has an named operator, and can retain
the evidence below. A demo environment does not count.

## Suggested starting point

Start on `v0.8.16`, the current published release, and upgrade to `v0.9.0` when
it becomes available. That makes the upgrade drill part of the 90-day window
instead of serializing it after the candidate release. If the operator cannot
start on `v0.8.16`, start on the earliest published release that supports the
deployment and record why.

## Evidence to retain

For each deployment, retain sanitized records of:

- operator, environment, region, database engine/version, topology, and reverse
  proxy/TLS boundary;
- exact AuthOS version, standalone archive or container digest, and config
  change history;
- authentication, token, organization, SAML, and SCIM journeys exercised;
- uptime and error-rate signals, alert firing, and incident timeline;
- upgrade start/end, observed downtime, migration result, rollback decision,
  and post-upgrade verification;
- backup schedule, restore drill start/end, measured RPO/RTO, and post-restore
  login and administrative checks;
- support requests, defects, security concerns, and their resolution; and
- operator feedback on documentation gaps and operational friction.

Do not retain live credentials, access tokens, personal data, production
database contents, or private infrastructure details in public evidence.

## Cadence

- Record a short weekly scorecard: version, uptime, incidents, open defects, and
  upcoming changes.
- Record the exact upgrade and restore drill date and duration.
- Publish a sanitized 90-day summary only with operator approval.
- Report material incidents or security concerns immediately through the
  private security channel, not in the public scorecard.

## Exit criteria mapping

The two deployments close the Phase 5 operating-evidence gate only when:

- each operated for 90 consecutive days;
- each completed one upgrade and one restore drill;
- at least one used PostgreSQL or MySQL;
- at least one exercised SAML or SCIM in production; and
- the sanitized records above are linked from the release evidence index.

## Scorecard template

| Field | Value |
| --- | --- |
| Operator | |
| Deployment start / end | |
| AuthOS versions | |
| Artifact digest | |
| Database / topology | |
| SAML or SCIM in production | |
| Upgrade date and duration | |
| Restore date and measured RPO/RTO | |
| Incidents and disposition | |
| Open defects / support requests | |
| Public evidence link | |

## Contact

Operators interested in hosting a reference deployment can email
[info@authos.dev](mailto:info@authos.dev) with the subject
`AuthOS reference deployment`. Include the intended topology and database, but
do not send credentials or production data.
