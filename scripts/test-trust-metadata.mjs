import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const checker = path.join(root, 'scripts/check-trust-metadata.mjs');
const fixtureFiles = [
  'README.md',
  'CHANGELOG.md',
  'CONTRIBUTING.md',
  'PRODUCTION_READINESS.md',
  'PROJECT_STATUS.md',
  'RELEASES.md',
  'SECURITY.md',
  'SUPPORT.md',
  'package.json',
  'LICENSE',
  'LICENSES/AGPL-3.0.txt',
  'LICENSES/MIT.txt',
  'install.sh',
  'sso-sdk/package.json',
  'sso-sdk/README.md',
  'packages/authos-cli/package.json',
  'packages/authos-cli/README.md',
  'packages/authos-node/package.json',
  'packages/authos-node/README.md',
  'packages/authos-react/package.json',
  'packages/authos-react/README.md',
  'packages/authos-vue/package.json',
  'packages/authos-vue/README.md',
  'scripts/authos-bootstrap/config.js',
  'api/docker-compose.dev.yml',
  'api/docker-compose.mysql.yml',
  'api/docker-compose.postgres.yml',
  'api/docker-compose.sqlite.yml',
  'api/docker-compose.test.yml',
  'api/docker-compose.yml',
];

function fixture() {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'authos-trust-'));
  for (const relative of fixtureFiles) {
    const destination = path.join(fixtureRoot, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(root, relative), destination);
  }
  // README links are checked for existence; symlinks are sufficient for the
  // referenced trees because this fixture mutates only copied trust inputs.
  for (const directory of ['docs', 'lite-web-client', 'api/benchmarks']) {
    fs.mkdirSync(path.dirname(path.join(fixtureRoot, directory)), { recursive: true });
    fs.symlinkSync(path.join(root, directory), path.join(fixtureRoot, directory), 'dir');
  }
  return fixtureRoot;
}

function check(fixtureRoot) {
  return execFileSync(process.execPath, [checker], {
    cwd: root,
    env: { ...process.env, AUTHOS_TRUST_ROOT: fixtureRoot },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

test('trust gate accepts the aligned release and database pins', () => {
  const fixtureRoot = fixture();
  try {
    assert.match(check(fixtureRoot), /release v0\.8\.13/);
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
});

test('trust gate rejects a stale AuthOS Compose pin', () => {
  const fixtureRoot = fixture();
  try {
    const composePath = path.join(fixtureRoot, 'api/docker-compose.sqlite.yml');
    fs.writeFileSync(
      composePath,
      fs.readFileSync(composePath, 'utf8').replace('sqlite-v0.8.13', 'sqlite-v0.8.12'),
    );
    assert.throws(
      () => check(fixtureRoot),
      (error) => error?.status === 1 && /does not pin editoredit\/sso:sqlite-v0\.8\.13/.test(error.stderr),
    );
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
});

test('trust gate rejects an unclassified Compose topology', () => {
  const fixtureRoot = fixture();
  try {
    fs.writeFileSync(path.join(fixtureRoot, 'api/docker-compose.extra.yml'), 'services: {}\n');
    assert.throws(
      () => check(fixtureRoot),
      (error) => error?.status === 1 && /explicit trust-pin classification/.test(error.stderr),
    );
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
});
