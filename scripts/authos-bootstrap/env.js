const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');

function buildContainerEnv(config, material) {
  const smtp = resolveSmtp(config, true);
  return compactEnv({
    DATABASE_URL: databaseUrl(config, material, true),
    RUST_LOG: config.deployment.rustLog,
    JWT_PRIVATE_KEY_BASE64: material.jwt.privateKeyBase64,
    JWT_PUBLIC_KEY_BASE64: material.jwt.publicKeyBase64,
    JWT_KID: material.jwt.kid,
    JWT_PREVIOUS_PUBLIC_KEYS_JSON: JSON.stringify(material.jwt.previousPublicKeys || {}),
    JWT_EXPIRATION_HOURS: '24',
    PLATFORM_GITHUB_CLIENT_ID: config.oauth.github.clientId,
    PLATFORM_GITHUB_CLIENT_SECRET: config.oauth.github.clientSecret,
    PLATFORM_GITHUB_REDIRECT_URI: config.oauth.github.redirectUri,
    PLATFORM_GITHUB_AUTH_URL: config.oauth.github.authUrl,
    PLATFORM_GITHUB_TOKEN_URL: config.oauth.github.tokenUrl,
    PLATFORM_GITHUB_USER_API_URL: config.oauth.github.userApiUrl,
    PLATFORM_GOOGLE_CLIENT_ID: config.oauth.google.clientId,
    PLATFORM_GOOGLE_CLIENT_SECRET: config.oauth.google.clientSecret,
    PLATFORM_GOOGLE_REDIRECT_URI: config.oauth.google.redirectUri,
    PLATFORM_GOOGLE_AUTH_URL: config.oauth.google.authUrl,
    PLATFORM_GOOGLE_TOKEN_URL: config.oauth.google.tokenUrl,
    PLATFORM_GOOGLE_USER_API_URL: config.oauth.google.userApiUrl,
    PLATFORM_MICROSOFT_CLIENT_ID: config.oauth.microsoft.clientId,
    PLATFORM_MICROSOFT_CLIENT_SECRET: config.oauth.microsoft.clientSecret,
    PLATFORM_MICROSOFT_REDIRECT_URI: config.oauth.microsoft.redirectUri,
    PLATFORM_MICROSOFT_AUTH_URL: config.oauth.microsoft.authUrl,
    PLATFORM_MICROSOFT_TOKEN_URL: config.oauth.microsoft.tokenUrl,
    PLATFORM_MICROSOFT_USER_API_URL: config.oauth.microsoft.userApiUrl,
    BILLING_PROVIDER: config.billing.provider,
    STRIPE_SECRET_KEY: config.billing.stripeSecretKey,
    STRIPE_WEBHOOK_SECRET: config.billing.stripeWebhookSecret,
    STRIPE_API_BASE_URL: config.billing.stripeApiBaseUrl,
    STRIPE_WEBHOOK_TEST_MODE: String(config.billing.stripeWebhookTestMode),
    POLAR_API_KEY: config.billing.polarApiKey,
    POLAR_WEBHOOK_SECRET: config.billing.polarWebhookSecret,
    POLAR_API_BASE_URL: config.billing.polarApiBaseUrl,
    SMTP_HOST: smtp?.host,
    SMTP_PORT: smtp ? String(smtp.port) : '',
    SMTP_USERNAME: smtp?.username,
    SMTP_PASSWORD: smtp?.password,
    SMTP_FROM_EMAIL: smtp?.fromEmail,
    SMTP_FROM_NAME: smtp?.fromName,
    SERVER_HOST: '0.0.0.0',
    SERVER_PORT: '3000',
    BASE_URL: config.deployment.baseUrl,
    PLATFORM_BASE_URL: config.deployment.platformBaseUrl,
    FULL_WEB_CLIENT_BASE_URL: config.deployment.fullWebClientBaseUrl,
    TRUST_PROXY_HEADERS: String(config.deployment.trustProxyHeaders),
    TRUSTED_PROXY_IPS: config.deployment.trustedProxyIps,
    PLATFORM_OWNER_EMAIL: config.platformOwner.email,
    PLATFORM_OWNER_PASSWORD: material.platformOwnerPassword,
    ENCRYPTION_KEY: material.encryptionKey,
    ENCRYPTION_KEY_ID: material.encryptionKeyId,
    ENCRYPTION_PREVIOUS_KEYS: Object.entries(material.encryptionPreviousKeys || {})
      .map(([keyId, key]) => `${keyId}=${key}`)
      .join(','),
    DISABLE_RATE_LIMITING: String(config.deployment.disableRateLimiting),
    FAST_HASHING: 'true',
    GEOIP_DISABLED: String(config.deployment.geoipDisabled),
    GEOIP_DATABASE_PATH: '/app/geoip/GeoLite2-City.mmdb',
    MAXMIND_LICENSE_KEY: config.deployment.maxMindLicenseKey,
    DEVICE_TRUST_SECRET: material.deviceTrustSecret,
    JOB_PROCESSOR_INTERVAL_SECS: String(config.deployment.jobProcessorIntervalSecs),
    JOB_PROCESSOR_BATCH_SIZE: String(config.deployment.jobProcessorBatchSize),
  });
}

function buildHostEnv(config, material) {
  const smtp = resolveSmtp(config, false);
  return compactEnv({
    ...buildContainerEnv(config, material),
    DATABASE_URL: databaseUrl(config, material, false),
    SERVER_PORT: String(config.deployment.apiPort),
    SMTP_HOST: smtp?.host,
    SMTP_PORT: smtp ? String(smtp.port) : '',
  });
}

function buildSdkEnv(config) {
  return {
    AUTHOS_BASE_URL: config.deployment.baseUrl,
    AUTHOS_JWKS_URL: `${config.deployment.baseUrl}/.well-known/jwks.json`,
  };
}

function sdkPlatformEnvs(config) {
  return {
    next: {
      AUTHOS_BASE_URL: config.deployment.baseUrl,
      NEXT_PUBLIC_AUTHOS_URL: config.deployment.baseUrl,
    },
    vite: {
      VITE_AUTHOS_BASE_URL: config.deployment.baseUrl,
      VITE_API_BASE_URL: config.deployment.baseUrl,
    },
    nuxt: {
      NUXT_PUBLIC_AUTHOS_BASE_URL: config.deployment.baseUrl,
    },
    node: {
      AUTHOS_URL: config.deployment.baseUrl,
      AUTHOS_BASE_URL: config.deployment.baseUrl,
    },
  };
}

function ownerEnv(config, material) {
  return {
    AUTHOS_BASE_URL: config.deployment.baseUrl,
    AUTHOS_PLATFORM_OWNER_EMAIL: config.platformOwner.email,
    AUTHOS_PLATFORM_OWNER_PASSWORD: material.platformOwnerPassword,
  };
}

function resolveSmtp(config, container) {
  if (config.smtp.mode === 'disabled') return null;
  if (config.smtp.mode === 'mailpit') {
    return {
      host: container ? 'mailpit' : 'localhost',
      port: 1025,
      username: '',
      password: '',
      fromEmail: config.smtp.fromEmail,
      fromName: config.smtp.fromName,
    };
  }
  return config.smtp;
}

function compactEnv(values) {
  return Object.fromEntries(
    Object.entries(values).filter(([, value]) => value !== undefined && value !== null && value !== ''),
  );
}

function databaseUrl(config, material, container) {
  const db = config.database;
  if (config.deployment.backend === 'postgres') {
    const host = container ? 'postgres' : 'localhost';
    const port = container ? 5432 : Number(db.postgresHostPort || 5433);
    return `postgres://${db.postgresUser || 'authos'}:${material.database.postgresPassword}@${host}:${port}/${db.postgresDb || 'authos'}`;
  }
  if (config.deployment.backend === 'mysql') {
    const host = container ? 'mysql' : 'localhost';
    const port = container ? 3306 : Number(db.mysqlHostPort || 3307);
    return `mysql://${db.mysqlUser || 'authos'}:${material.database.mysqlPassword}@${host}:${port}/${db.mysqlDatabase || 'authos'}`;
  }
  // `?mode=rwc`: a first host run must create the database file instead
  // of failing with "unable to open database file" (A5).
  return container ? 'sqlite:/app/data/data.db?mode=rwc' : 'sqlite:./data/data.db?mode=rwc';
}

async function writeEnv(filePath, values) {
  await writeText(filePath, envString(values), 0o600);
}

async function writeJson(filePath, value) {
  await writeText(filePath, `${JSON.stringify(value, null, 2)}\n`, 0o600);
}

async function writeText(filePath, content, mode) {
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  const current = fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : null;
  if (current === content) {
    await fsp.chmod(filePath, mode);
    return false;
  }
  await fsp.writeFile(filePath, content, { mode });
  await fsp.chmod(filePath, mode);
  return true;
}

function envString(values) {
  const lines = ['# Generated by scripts/authos-bootstrap.js. Rerun the bootstrap command to update.'];
  for (const [key, value] of Object.entries(values)) {
    lines.push(`${key}=${envValue(value)}`);
  }
  return `${lines.join('\n')}\n`;
}

function envValue(value) {
  const text = String(value ?? '');
  if (text === '') return '';
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(text)) return text;
  return JSON.stringify(text);
}

module.exports = {
  buildContainerEnv,
  buildHostEnv,
  buildSdkEnv,
  sdkPlatformEnvs,
  ownerEnv,
  writeEnv,
  writeJson,
  writeText,
};
