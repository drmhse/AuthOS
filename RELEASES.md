# AuthOS releases and versioning

AuthOS uses one public release identity for coordinated artifacts: an annotated
Git tag in the exact form `vMAJOR.MINOR.PATCH`. Prerelease and build
metadata tags are rejected because the current publication path advances npm,
GitHub, and Docker `latest` pointers. The latest published release at this
document's baseline is `v0.8.13`.

## Version sources

The release tag is authoritative for shipped artifacts:

- standalone binaries embed the tag through `AUTHOS_BUILD_VERSION`;
- Docker images receive `backend-vX.Y.Z`, `backend-X.Y.Z`, and
  `backend-latest` tags;
- the npm publication workflow stamps every public `@drmhse/*` package from
  the release tag and aligns internal SDK dependency versions; and
- `install.sh` uses the latest GitHub release unless an operator supplies
  `AUTHOS_RELEASE_TAG`.

Some checked-in manifests are development metadata rather than public release
identities. The private workspace root remains `0.0.0`, the private embedded
web client has its own source version, and the Rust crate version is the local
fallback when a build has neither an exact Git tag nor
`AUTHOS_BUILD_VERSION`. Public packages keep a common checked-in development
version and are stamped during publication.

`npm run check:trust` verifies the relationships that must remain consistent:
the public package source versions, their internal SDK dependencies, the
documented current release, and bootstrap Docker pins.

## Current release lifecycle

1. Changes are reviewed through a pull request and the baseline CI workflow.
2. The maintainer verifies the release commit, changelog, migrations, and
   public support labels before creating a release tag.
3. A `vX.Y.Z` tag starts one orchestrated release workflow. Read-only jobs
   prepare every standalone, OCI, and npm artifact; one cross-channel preflight
   then requires all immutable npm and Docker versions to be absent and the
   candidate to be newer than the current GitHub/npm `latest` versions.
4. Only after that gate succeeds does the workflow create a draft GitHub
   release and invoke small artifact-only publication jobs. Source builds do
   not receive registry credentials, a contents-write token, or OIDC authority.
5. The draft becomes public only after standalone assets, all three Docker
   variants, all five npm packages, attestations, and durable evidence succeed.
6. The maintainer verifies the GitHub release assets and checksums, Docker
   variant tags, npm package versions/provenance, and embedded build version.
7. Failures are corrected with a new commit and tag; published artifacts are
   not silently replaced with different bytes under the same version.

The orchestrated release and the reusable npm preparation/manual path qualify
the exact tagged commit before building publishable artifacts. They require an
annotated, stable v-prefixed semantic-version tag whose commit is reachable
from `main`, run the tenant-isolation gate, and exercise runtime plus logical
restore against PostgreSQL 16 and MySQL 8.4. The npm publish-mode job only
consumes checksummed artifacts prepared by that qualified caller; it never
checks out source. The npm workflow has no independent tag trigger, while a
direct manual dispatch is unconditionally dry-run-only and receives no npm
credential. Immutable npm and Docker version tags must all be absent before
publication, and existing GitHub release assets are never overwritten.

These are configured candidate controls, not completed release evidence. They
become evidence only after the workflow is committed, protected, and succeeds
for an exact release tag with its retained logs, manifests, and attestations.

Registry publication is deliberately sequenced, but it is not transactional.
An npm or Docker outage can leave a strict subset public after the first write.
Never rerun or fill in that version: preserve the failed draft and logs, mark
the partial versions withdrawn/deprecated where supported, and recover only
with a reviewed commit and a new annotated version according to the emergency
procedure.

## Pre-1.0 compatibility

Pre-1.0 releases may change APIs, configuration, SDK behavior, or migrations.
Breaking and migration-relevant changes belong in [CHANGELOG.md](./CHANGELOG.md)
and the GitHub release notes. Operators should pin an exact version, back up
state, and exercise upgrades in a representative environment.

Only the latest published release receives routine security support. See
[SECURITY.md](./SECURITY.md) and [PROJECT_STATUS.md](./PROJECT_STATUS.md) for
the current support boundary.

## Release contracts and procedures

- [Compatibility and deprecation policy](./docs/release/compatibility.md)
- [Emergency release and signing-compromise procedure](./docs/release/emergency-release.md)
- [Release qualification checklist](./docs/release/release-checklist.md)
