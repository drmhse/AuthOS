const fs = require('node:fs');
const path = require('node:path');
const { DEFAULT_CONFIG, initConfig, parseArgs, printHelp } = require('./cli');
const { buildCompose, composeCmd } = require('./compose');
const { normalizeConfig, readJson, resolveOutputPaths } = require('./config');
const {
  buildContainerEnv,
  buildHostEnv,
  buildSdkEnv,
  ownerEnv,
  sdkPlatformEnvs,
  writeEnv,
  writeJson,
  writeText,
} = require('./env');
const { waitForReadiness } = require('./http');
const { buildLocalImage } = require('./local-image');
const { ensureMaterial, loadState, serializeState } = require('./material');
const { assertCommand } = require('./process');
const { provisionResources } = require('./provision');

const ROOT = path.resolve(__dirname, '../..');

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const configPath = path.resolve(ROOT, args.config || DEFAULT_CONFIG);
  if (args.init) {
    await initConfig(ROOT, configPath, args.force);
    return;
  }
  if (!fs.existsSync(configPath)) {
    throw new Error(
      `Missing ${path.relative(ROOT, configPath)}. Run "npm run authos:bootstrap -- --init" first.`,
    );
  }

  const config = normalizeConfig(readJson(ROOT, configPath));
  const paths = resolveOutputPaths(ROOT, config);
  const statePath = path.join(paths.outputDir, 'state.json');
  const state = loadState((file) => readJson(ROOT, file), statePath);
  const material = ensureMaterial(config, state);

  await writeOutputs(config, paths, material, statePath);

  if (args.up || args.reset || args.wait || args.provision) {
    await assertCommand('docker', ['version'], ROOT);
  }
  if (args.up && config.deployment.buildLocalImage) {
    await buildLocalImage(ROOT, config);
  }
  if (args.reset) await composeCmd(ROOT, paths, ['down', '-v', '--remove-orphans']);
  if (args.up) {
    const upArgs = ['up', '-d', '--remove-orphans'];
    if (config.deployment.buildLocalImage) {
      upArgs.push('--force-recreate');
    }
    await composeCmd(ROOT, paths, upArgs);
  }
  if (args.wait || args.provision) {
    await waitForReadiness(config.deployment.baseUrl, args.timeout || 120000);
  }

  const provisionReport = args.provision
    ? await provisionResources(ROOT, config, material)
    : null;
  renderSummary(configPath, config, paths, material, provisionReport);
}

async function writeOutputs(config, paths, material, statePath) {
  const platform = sdkPlatformEnvs(config);
  const hostEnv = buildHostEnv(config, material);
  await writeText(paths.composeFile, buildCompose(config, material), 0o600);
  await writeEnv(paths.containerEnvFile, buildContainerEnv(config, material));
  await writeEnv(paths.hostEnvFile, hostEnv);
  await writeEnv(paths.sdkEnvFile, buildSdkEnv(config));
  await writeEnv(paths.nextEnvFile, platform.next);
  await writeEnv(paths.viteEnvFile, platform.vite);
  await writeEnv(paths.nuxtEnvFile, platform.nuxt);
  await writeEnv(paths.nodeEnvFile, platform.node);
  await writeEnv(paths.ownerEnvFile, ownerEnv(config, material));
  await writeEnv(path.resolve(ROOT, config.outputs.apiEnv), hostEnv);
  await writeJson(statePath, serializeState(material));
}

function renderSummary(configPath, config, paths, material, provisionReport) {
  console.log('\nAuthOS bootstrap complete\n');
  console.log(`Config: ${path.relative(ROOT, configPath)}`);
  console.log(`Outputs: ${path.relative(ROOT, paths.outputDir)}`);
  console.log(`Compose: ${path.relative(ROOT, paths.composeFile)}`);
  console.log(`Backend: ${config.deployment.backend}`);
  console.log(`API: ${config.deployment.baseUrl}`);
  console.log(`Owner credentials: ${path.relative(ROOT, paths.ownerEnvFile)}`);
  console.log(`JWT key id: ${material.jwt.kid}`);

  if (!provisionReport) return;
  console.log('\nProvisioned resources:');
  for (const item of provisionReport) {
    console.log(
      `- ${item.org}/${item.service}: org=${item.organizationStatus}, admin=${item.adminInvite}, service=${item.serviceStatus}, client=${item.clientId || '(none)'}`,
    );
    for (const key of item.apiKeys) {
      console.log(`  api key ${key.name}: ${key.status}${key.writtenTo ? ` -> ${key.writtenTo}` : ''}`);
    }
  }
}

module.exports = {
  main,
};
