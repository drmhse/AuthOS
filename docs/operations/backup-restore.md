# Backup and restore

AuthOS includes an integrity-checked SQLite database snapshot helper, but it
does not yet have a complete deployment-state backup command, point-in-time
recovery guarantee, RPO, or RTO. The procedures below match the repository's
current storage layout and database containers. CI runs SQLite
snapshot/restored-runtime checks and PostgreSQL/MySQL logical dump-and-restore
journeys on pull requests. The scheduled `Restore qualification` workflow runs
the same three journeys daily and retains each log for 90 days. Those source
definitions are not evidence until successful runs accumulate; the
30-consecutive-day window, complete deployment-state coverage, and repeated
disaster-recovery drills have not yet produced the evidence required for a
recovery guarantee.

## What a recoverable backup must contain

A database dump or SQLite file alone is not a complete AuthOS backup. Retain,
encrypt, and access-control all of the following together:

- the database;
- the JWT signing key pair and key ID;
- the active `ENCRYPTION_KEY`, its `ENCRYPTION_KEY_ID`, every configured
  `ENCRYPTION_PREVIOUS_KEYS` entry, and `DEVICE_TRUST_SECRET`;
- AuthOS configuration and integration credentials;
- the exact AuthOS release version and artifact digest;
- external proxy/TLS configuration when AuthOS does not manage it.

For a default standalone install, `/var/lib/authos/state.json` contains the JWT
and encryption material, `/var/lib/authos/config.json` contains managed
configuration, `/var/lib/authos/data/authos.db` is the SQLite database, and
`/etc/authos` contains install state plus the rendered environment. A custom
`standalone.dataDir` moves the managed files to that directory; read
`/etc/authos/install-state.json` before using the example below.

Backups contain authentication secrets and personal data. Store them encrypted
outside the AuthOS host, limit readers, and test deletion/retention controls.
Normal API startup rejects malformed active/previous encryption configuration,
but it cannot know whether the keyring covers every ciphertext in a restored
database. A restore must therefore use the exact protected active and previous
keys captured with that database and exercise decryption-dependent journeys
before it is considered successful. Do not retire a previous key while retained
backups may still reference it.

## Standalone SQLite: cold backup

**Operator procedure — repository-aligned, live drill not yet published.** This
example applies only to the default `/var/lib/authos` data directory. A cold
copy avoids separating the SQLite database from its WAL state.

```bash
BACKUP_DIR=/srv/backups/authos/$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "${BACKUP_DIR}"
sudo systemctl stop authos.service
sudo tar --numeric-owner -C / -czf "${BACKUP_DIR}/authos-state.tar.gz" \
  var/lib/authos etc/authos
sudo sha256sum "${BACKUP_DIR}/authos-state.tar.gz" \
  | sudo tee "${BACKUP_DIR}/SHA256SUMS" >/dev/null
sudo systemctl start authos.service
curl -fsS http://127.0.0.1:3001/health/ready
```

If Caddy or a non-default port is configured, use the configured local/public
readiness URL. Record the release version returned by `/health`, the checksum,
backup location, start/end time, and whether the service restarted cleanly.

## SQLite: online database snapshot

`scripts/authos-sqlite-backup.py` uses SQLite's online backup API instead of a
filesystem copy, so the source can remain in WAL mode while writes continue.
It refuses to overwrite an existing backup, restricts new output and manifest
files to mode `0600`, runs `PRAGMA integrity_check`, and records the size and
SHA-256 digest in a JSON manifest. CI exercises a concurrent writer and proves
that the restored snapshot is internally coherent.

Run it as the account that can read the database and write the protected
backup directory:

```bash
umask 077
scripts/authos-sqlite-backup.py \
  --database /var/lib/authos/data/authos.db \
  --output /srv/backups/authos/REPLACE_WITH_BACKUP_ID/authos.db
scripts/authos-sqlite-backup.py \
  --database /srv/backups/authos/REPLACE_WITH_BACKUP_ID/authos.db \
  --verify-manifest \
  /srv/backups/authos/REPLACE_WITH_BACKUP_ID/authos.db.manifest.json
```

This snapshots only the database. A recoverable AuthOS backup must also capture
the exact key/configuration state and release identity listed above. Store the
database and state bundle together; restoring either from a different point in
time can make tokens or encrypted integration credentials unusable.

## Standalone SQLite: isolated restore

**Planned validation procedure — do not treat as a proven disaster-recovery
runbook yet.** Practice on an isolated host and never overwrite the only copy.

1. Verify the archive checksum and obtain the exact release that produced it.
2. Install that release with `--no-start` so the matching binary and systemd
   integration exist.
3. Stop `authos.service` and `authos-apply.path`.
4. Extract the archive at `/`, preserving its protected permissions.
5. Re-render the service environment from the restored managed state.
6. Start AuthOS and verify data and authentication journeys.

For the default data directory, steps 3–6 are:

```bash
BACKUP_DIR=/srv/backups/authos/REPLACE_WITH_BACKUP_ID
sudo sha256sum --check "${BACKUP_DIR}/SHA256SUMS"
sudo systemctl stop authos.service authos-apply.path
sudo tar --numeric-owner -C / -xzf "${BACKUP_DIR}/authos-state.tar.gz"
sudo chown -R authos:authos /var/lib/authos
sudo authos-apply apply --bundle-dir /opt/authos --skip-start --no-print-link
sudo systemctl start authos-apply.path authos.service
curl -fsS http://127.0.0.1:3001/health/ready
```

The standalone install step must use the restored release rather than
`latest`. Confirm `/health` reports the intended version. Then test at least an
existing user login, token refresh, organization access, the AuthOS capability
document/JWKS, the expected `404` for OpenID Connect discovery, and one
configured enterprise or provisioning journey before accepting the restore.

## Docker SQLite

The bootstrap-generated Compose project stores SQLite in a named volume and
secrets/configuration in its output directory (normally `.authos/`). Back up
both. Discover the actual volume name with `docker volume ls`; do not assume a
name when the Compose project was renamed.

**Operator procedure — live drill not yet published:**

```bash
docker compose -f .authos/docker-compose.yml stop authos
docker volume ls
docker run --rm \
  -v REPLACE_WITH_SQLITE_VOLUME:/source:ro \
  -v "${PWD}/backups:/backup" \
  alpine:3.20 tar -C /source -czf /backup/authos-sqlite-volume.tar.gz .
sudo tar -C . -czf backups/authos-bootstrap-state.tar.gz .authos authos.config.json
docker compose -f .authos/docker-compose.yml start authos
curl -fsS http://127.0.0.1:3001/health/ready
```

Restore into a new named volume and an isolated Compose project first. The
project has not yet committed a safe automated volume-restore command because
volume naming and storage drivers vary by operator.

## PostgreSQL and MySQL

Use the database vendor's supported physical backup or logical dump tooling,
and back up the AuthOS bootstrap output directory separately. The repository's
generated Compose services can produce logical dumps after stopping AuthOS:

```bash
docker compose -f .authos/docker-compose.yml stop authos
docker compose -f .authos/docker-compose.yml exec -T postgres \
  sh -c 'pg_dump --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --format=custom' \
  > authos-postgres.dump
docker compose -f .authos/docker-compose.yml start authos
```

```bash
docker compose -f .authos/docker-compose.yml stop authos
docker compose -f .authos/docker-compose.yml exec -T mysql \
  sh -c 'mysqldump --single-transaction --user="$MYSQL_USER" --password="$MYSQL_PASSWORD" "$MYSQL_DATABASE"' \
  > authos-mysql.sql
docker compose -f .authos/docker-compose.yml start authos
```

These examples match the generated service/environment names. They are not a
substitute for vendor-specific backup policy, managed-database snapshots, WAL
archiving/binlogs, encryption, retention, or restore testing. No AuthOS claim
is currently made for PostgreSQL PITR or MySQL point-in-time recovery.

`scripts/qualify-logical-backup-restore.sh` is the CI qualification wrapper for
PostgreSQL 16 and MySQL 8.4. It creates a tenant through a running candidate,
stops the candidate, makes a vendor logical dump, restores it with the same
protected JWT/encryption/device keys, then proves existing login and tenant
access plus new post-restore CRUD. Before restore it renames a canary tenant and
after restore proves the original returned and the destroyed value did not,
preventing a no-op restore from passing. It requires `DATABASE_URL` and explicit
`AUTHOS_DB_*` inputs to identify the same database and keeps passwords in client
environment variables rather than command arguments. The wrapper is destructive to the selected test
database during restore and must never be pointed at a production database.

## Restore acceptance record

A restore is evidence only when the record includes:

- AuthOS source and target versions, artifact digests, database engine/version,
  topology, and host/storage details;
- backup start/end, restore start/end, and measured data-loss window;
- checksum verification and access-control checks;
- readiness plus representative login, refresh, tenant, admin, SAML/SCIM (when
  configured), and audit/event checks;
- failures, manual interventions, and the disposition of every gap.

Only measured, repeated drills can establish RPO or RTO values.
