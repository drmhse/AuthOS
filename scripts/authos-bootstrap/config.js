const fs = require('node:fs');
const path = require('node:path');
const { resolvePlatformTarget } = require('./targets');

function readJson(root, filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`Could not read ${path.relative(root, filePath)}: ${error.message}`);
  }
}

function normalizeConfig(input) {
  const deployment = input.deployment || {};
  const backend = deployment.backend || 'sqlite';
  if (!['sqlite', 'postgres', 'mysql'].includes(backend)) {
    throw new Error('deployment.backend must be one of sqlite, postgres, or mysql');
  }

  const apiPort = Number(deployment.apiPort || 3001);
  const baseUrl = normalizeUrl(deployment.baseUrl || `http://localhost:${apiPort}`);
  const platformBaseUrl = normalizeUrl(deployment.platformBaseUrl || baseUrl);
  const platform = deployment.platform || 'linux/amd64';
  resolvePlatformTarget(platform);

  return {
    deployment: {
      project: deployment.project || 'authos',
      backend,
      image: deployment.image || defaultImage(backend),
      buildLocalImage: deployment.buildLocalImage === true,
      platform,
      apiPort,
      baseUrl,
      platformBaseUrl,
      fullWebClientBaseUrl: deployment.fullWebClientBaseUrl || '',
      trustProxyHeaders: deployment.trustProxyHeaders === true,
      trustedProxyIps: deployment.trustedProxyIps || '',
      rustLog: deployment.rustLog || 'info',
      disableRateLimiting: deployment.disableRateLimiting !== false,
      geoipDisabled: deployment.geoipDisabled !== false,
      maxMindLicenseKey: deployment.maxMindLicenseKey || '',
      jobProcessorIntervalSecs: Number(deployment.jobProcessorIntervalSecs || 10),
      jobProcessorBatchSize: Number(deployment.jobProcessorBatchSize || 10),
    },
    database: input.database || {},
    platformOwner: {
      email: input.platformOwner?.email || 'admin@example.com',
      password: input.platformOwner?.password || '',
    },
    billing: normalizeBilling(input.billing || {}),
    smtp: normalizeSmtp(input.smtp || {}),
    oauth: normalizeOAuth(input.oauth || {}, baseUrl),
    services: Array.isArray(input.services) ? input.services.map(normalizeService) : [],
    outputs: {
      directory: input.outputs?.directory || '.authos',
      apiEnv: input.outputs?.apiEnv || 'api/.env',
    },
  };
}

function normalizeBilling(billing) {
  const normalized = {
    provider: billing.provider || 'none',
    stripeSecretKey: billing.stripeSecretKey || '',
    stripeWebhookSecret: billing.stripeWebhookSecret || '',
    stripeApiBaseUrl: billing.stripeApiBaseUrl || '',
    stripeWebhookTestMode: billing.stripeWebhookTestMode !== false,
    polarApiKey: billing.polarApiKey || '',
    polarWebhookSecret: billing.polarWebhookSecret || '',
    polarApiBaseUrl: billing.polarApiBaseUrl || '',
  };
  if (!['none', 'stripe', 'polar'].includes(normalized.provider)) {
    throw new Error('billing.provider must be one of none, stripe, or polar');
  }
  if (normalized.provider === 'stripe' && (!normalized.stripeSecretKey || !normalized.stripeWebhookSecret)) {
    throw new Error('Stripe billing requires billing.stripeSecretKey and billing.stripeWebhookSecret');
  }
  if (normalized.provider === 'polar' && (!normalized.polarApiKey || !normalized.polarWebhookSecret)) {
    throw new Error('Polar billing requires billing.polarApiKey and billing.polarWebhookSecret');
  }
  return normalized;
}

function normalizeSmtp(smtp) {
  return {
    mode: smtp.mode || 'mailpit',
    host: smtp.host || '',
    port: Number(smtp.port || 1025),
    username: smtp.username || '',
    password: smtp.password || '',
    fromEmail: smtp.fromEmail || 'noreply@authos.local',
    fromName: smtp.fromName || 'AuthOS',
  };
}

function normalizeOAuth(oauth, baseUrl) {
  const providers = {};
  for (const provider of ['github', 'google', 'microsoft']) {
    const cfg = oauth[provider] || {};
    providers[provider] = {
      clientId: cfg.clientId || '',
      clientSecret: cfg.clientSecret || '',
      redirectUri: cfg.redirectUri || `${baseUrl}/auth/admin/${provider}/callback`,
      authUrl: cfg.authUrl || '',
      tokenUrl: cfg.tokenUrl || '',
      userApiUrl: cfg.userApiUrl || '',
    };
  }
  return providers;
}

function normalizeService(service) {
  if (!service.org || !service.service) {
    throw new Error('Each services[] entry needs org and service slugs');
  }
  return {
    org: service.org,
    orgName: service.orgName || service.org,
    service: service.service,
    name: service.name || service.service,
    type: service.type || 'web',
    redirectUris: unique((service.redirectUris || []).map(String).filter(Boolean)),
    githubScopes: unique((service.githubScopes || []).map(String).filter(Boolean)),
    oauthCredentials: service.oauthCredentials || {},
    apiKeys: Array.isArray(service.apiKeys)
      ? service.apiKeys.map((key) => ({
          name: key.name,
          permissions: key.permissions || [],
          writeTo: key.writeTo || '',
          forceNew: key.forceNew === true,
        }))
      : [],
  };
}

function resolveOutputPaths(root, config) {
  const outputDir = path.resolve(root, config.outputs.directory);
  return {
    outputDir,
    composeFile: path.join(outputDir, 'docker-compose.yml'),
    containerEnvFile: path.join(outputDir, 'authos.env'),
    hostEnvFile: path.join(outputDir, 'api.host.env'),
    sdkEnvFile: path.join(outputDir, 'sdk.env'),
    nextEnvFile: path.join(outputDir, 'next.env'),
    viteEnvFile: path.join(outputDir, 'vite.env'),
    nuxtEnvFile: path.join(outputDir, 'nuxt.env'),
    nodeEnvFile: path.join(outputDir, 'node.env'),
    ownerEnvFile: path.join(outputDir, 'owner.env'),
  };
}

function defaultImage(backend) {
  if (backend === 'postgres') return 'editoredit/sso:psql-v0.8.13';
  if (backend === 'mysql') return 'editoredit/sso:mysql-v0.8.13';
  return 'editoredit/sso:sqlite-v0.8.13';
}

function normalizeUrl(value) {
  const url = new URL(String(value));
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

function unique(values) {
  return [...new Set(values)];
}

module.exports = {
  readJson,
  normalizeConfig,
  resolveOutputPaths,
};
