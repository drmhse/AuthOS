const fs = require('node:fs/promises');
const path = require('node:path');
const { run } = require('./process');
const { resolvePlatformTarget } = require('./targets');

const backends = {
  sqlite: { binary: 'sso_sqlite', feature: 'db_sqlite' },
  postgres: { binary: 'sso_psql', feature: 'db_psql' },
  mysql: { binary: 'sso_mysql', feature: 'db_mysql' },
};

/// Fail fast with actionable messages before a 10-minute build does:
/// workspace deps (A2), the SDK bundle (A3), and the zig musl toolchain
/// (A4) are all required up front.
async function checkBuildPrerequisites(root, target) {
  const missing = [];
  const exists = (p) => {
    try {
      require('node:fs').accessSync(require('node:path').join(root, p));
      return true;
    } catch {
      return false;
    }
  };
  if (!exists('node_modules') || !exists('lite-web-client/node_modules')) {
    missing.push('workspace dependencies — run `npm ci` from the repo root');
  }
  if (!exists('sso-sdk/dist/index.js')) {
    missing.push('the SDK bundle — run `npm --workspace @drmhse/sso-sdk run build`');
  }
  if (missing.length > 0) {
    throw new Error(`Cannot build the web client yet:\n- ${missing.join('\n- ')}`);
  }
  try {
    await run('cargo', ['zigbuild', '--version'], root, { quiet: true });
  } catch {
    throw new Error('`cargo-zigbuild` is not installed — run `cargo install cargo-zigbuild`');
  }
  try {
    await run('zig', ['version'], root, { quiet: true });
  } catch {
    throw new Error('`zig` is not installed — see https://ziglang.org/download');
  }
  const muslTarget = target.rustTarget.includes('musl') ? target.rustTarget : null;
  if (muslTarget) {
    const { stdout } = await run('rustup', ['target', 'list', '--installed'], root, {
      quiet: true,
    });
    if (!stdout.split('\n').some((line) => line.trim() === muslTarget)) {
      throw new Error(
        `Rust target ${muslTarget} is not installed — run \`rustup target add ${muslTarget}\``,
      );
    }
  }
}

async function buildLocalImage(root, config) {
  const backend = backends[config.deployment.backend];
  if (!backend) {
    throw new Error(`Unsupported local image backend: ${config.deployment.backend}`);
  }
  const target = resolvePlatformTarget(config.deployment.platform);
  await checkBuildPrerequisites(root, target);

  const apiDir = path.join(root, 'api');
  console.log(`\nBuilding local AuthOS image ${config.deployment.image} (${config.deployment.backend})...`);
  await run('npm', ['--workspace', 'lite-web-client', 'run', 'build'], root);
  await run(
    'cargo',
    [
      'zigbuild',
      '--release',
      '--target',
      target.rustTarget,
      '--no-default-features',
      '--features',
      backend.feature,
      '--bin',
      backend.binary,
    ],
    apiDir,
  );

  const distDir = path.join(apiDir, 'target', 'dist', `linux-${target.archiveArch}`);
  await fs.mkdir(distDir, { recursive: true });
  await fs.copyFile(
    path.join(apiDir, `target/${target.rustTarget}/release/${backend.binary}`),
    path.join(distDir, backend.binary),
  );

  await run(
    'docker',
    [
      'build',
      '-f',
      'Dockerfile',
      '--platform',
      config.deployment.platform,
      '--build-arg',
      `BINARY_NAME=${backend.binary}`,
      '-t',
      config.deployment.image,
      '.',
    ],
    apiDir,
  );
}

module.exports = {
  buildLocalImage,
  checkBuildPrerequisites,
};
