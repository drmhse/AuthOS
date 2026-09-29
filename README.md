# AuthOS

Open-source API and SDK infrastructure for B2B and B2B2C authentication.

AuthOS ships a Rust API, standalone Linux bundles, Docker images, TypeScript
SDKs, framework adapters, and an embedded lightweight web client for setup and
end-user journeys.

AuthOS is currently in the pre-1.0 release series. Read the
[project status](./PROJECT_STATUS.md) for present support boundaries and the
[production-readiness plan](./PRODUCTION_READINESS.md) for the evidence required
before 1.0.

## Install

On a Linux host with `systemd`, `python3`, `curl`, `tar`, `mktemp`,
`sha256sum`, and `openssl`:

```bash
curl -fsSL -o install.sh https://github.com/drmhse/AuthOS/releases/latest/download/install.sh
chmod +x install.sh
sudo ./install.sh
```

The installer selects the matching SQLite standalone bundle for `linux/amd64`
or `linux/arm64`, verifies its checksum, starts AuthOS, and prints a one-time
bootstrap link.

To install a specific release:

```bash
AUTHOS_VERSION=v0.8.13
curl -fsSL -o install.sh "https://github.com/drmhse/AuthOS/releases/download/${AUTHOS_VERSION}/install.sh"
chmod +x install.sh
sudo AUTHOS_RELEASE_TAG="${AUTHOS_VERSION}" ./install.sh
```

## Packages

Install only the package your app needs:

```bash
npm install @drmhse/sso-sdk
npm install @drmhse/authos-react
npm install @drmhse/authos-vue
npm install @drmhse/authos-node
npm install @drmhse/authos-cli
```

## Repository

| Path | Description |
|------|-------------|
| [api/](./api) | Rust API and backend binaries. |
| [api/benchmarks/](./api/benchmarks) | Reproducible API benchmark harnesses and dated evidence. |
| [lite-web-client/](./lite-web-client) | Embedded setup and end-user journey UI. |
| [sso-sdk/](./sso-sdk) | Framework-agnostic TypeScript SDK. |
| [packages/](./packages) | React, Vue, Node, and CLI packages. |
| [scripts/](./scripts) | Installer and release bundle tooling. |

## Docs

- [Getting started](https://authos.dev/docs/api/getting-started/)
- [Authentication API](https://authos.dev/docs/api/reference/authentication/)
- [SDK packages](https://authos.dev/docs/packages/)
- [SCIM provisioning](https://authos.dev/docs/sdk/guides/scim-provisioning/)

Project trust and community resources:

- [Project status](./PROJECT_STATUS.md)
- [Production-readiness plan](./PRODUCTION_READINESS.md)
- [Security threat model](./docs/security/threat-model.md)
- [Security architecture](./docs/security/security-architecture.md)
- [Tenant-resource inventory](./docs/security/tenant-resource-inventory.md)
- [Release and versioning lifecycle](./RELEASES.md)
- [Release artifact verification](./docs/release-verification.md)
- [Supported deployment topologies](./docs/operations/supported-topologies.md)
- [Backup and restore](./docs/operations/backup-restore.md)
- [Upgrade and rollback](./docs/operations/upgrade-rollback.md)
- [Cryptographic key rotation](./docs/operations/key-rotation.md)
- [Monitoring and operational signals](./docs/operations/monitoring.md)
- [SQLite budget-VM benchmark](./api/benchmarks/sqlite-budget-vm/README.md)
- [Changelog](./CHANGELOG.md)
- [Security policy](./SECURITY.md)
- [Support](./SUPPORT.md)
- [Contributing](./CONTRIBUTING.md)

AuthOS also maintains source-verified Agent Skills for integration and
operations workflows:

- [github.com/drmhse/authos_skill](https://github.com/drmhse/authos_skill)
- [skills.sh/drmhse/authos_skill](https://skills.sh/drmhse/authos_skill)

## Development

Install workspace dependencies:

```bash
npm ci
npm run build:sdk
```

Common checks:

```bash
npm run lint
npm run typecheck
npm run test --workspaces --if-present
npm run build
npm run check:trust
cargo check --manifest-path api/Cargo.toml
```

For direct API work:

```bash
cd api
cp .env.example .env
# Replace the ENCRYPTION_KEY placeholder with this generated value:
openssl rand -hex 32
cargo run --release
```

Normal API startup requires a valid 64-character hexadecimal
`ENCRYPTION_KEY`. Store it through your secret-management workflow and retain
it with database backups; do not copy generated secret material into source
control. Optional `ENCRYPTION_KEY_ID` and `ENCRYPTION_PREVIOUS_KEYS` settings
provide active/previous key overlap. Follow the maintenance-window and rollback
limits in [the key-rotation runbook](./docs/operations/key-rotation.md) before
changing them.

## License

AuthOS currently assigns licenses to these first-party source paths:

- API, lite web client, scripts, and installer: [AGPL-3.0-only](./LICENSES/AGPL-3.0.txt)
- SDKs and packages: [MIT](./LICENSES/MIT.txt)

Vendored third-party code keeps its upstream notices in place under its own
directory. The current map does not yet assign a license to remaining root
documentation and configuration; do not assume an unlisted path uses either
license. See [LICENSE](./LICENSE) for the authoritative repository map.
