const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { checkBuildPrerequisites } = require('./local-image');

function emptyRoot() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'authos-prereq-'));
}

test('missing workspace deps fail fast with an npm ci hint', async () => {
  await assert.rejects(
    checkBuildPrerequisites(emptyRoot(), { rustTarget: 'x86_64-unknown-linux-musl' }),
    /npm ci/,
  );
});

test('missing SDK bundle is named', async () => {
  const root = emptyRoot();
  fs.mkdirSync(path.join(root, 'node_modules'), { recursive: true });
  fs.mkdirSync(path.join(root, 'lite-web-client', 'node_modules'), { recursive: true });
  await assert.rejects(
    checkBuildPrerequisites(root, { rustTarget: 'x86_64-unknown-linux-musl' }),
    /sso-sdk/,
  );
});
