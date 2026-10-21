const fsp = require('node:fs/promises');
const path = require('node:path');
const { HttpError, requestJson } = require('./http');
const { writeText } = require('./env');

async function provisionResources(root, config, material) {
  const token = await loginPlatformOwner(
    config.deployment.baseUrl,
    config.platformOwner.email,
    material.platformOwnerPassword,
  );
  const client = new AuthOsClient(config.deployment.baseUrl, token);
  const report = [];

  for (const service of config.services) {
    const organizationStatus = await ensureOrganization(client, service.org, service.orgName);
    const adminInvite = await ensureOrgAdminInvite(client, service, config.platformOwner.email);
    const serviceResult = await ensureService(client, service);
    const providerCredentials = await ensureOAuthCredentials(client, service);
    const apiKeys = [];
    for (const apiKey of service.apiKeys) {
      apiKeys.push(await ensureApiKey(root, client, service, apiKey));
    }
    report.push({
      org: service.org,
      organizationStatus,
      adminInvite,
      service: service.service,
      serviceStatus: serviceResult.status,
      clientId: serviceResult.clientId,
      providerCredentials,
      apiKeys,
    });
  }

  return report;
}

async function loginPlatformOwner(baseUrl, email, password) {
  const response = await requestJson(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!response.access_token) {
    throw new Error('Platform owner login did not return an access token');
  }
  if (!response.refresh_token) {
    throw new Error(
      'Platform owner MFA is enabled. Complete MFA or use the standalone installer/bootstrap recovery flow before provisioning.',
    );
  }
  return response.access_token;
}

class AuthOsClient {
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async request(pathname, init = {}) {
    try {
      return await requestJson(`${this.baseUrl}${pathname}`, {
        method: init.method || 'GET',
        headers: {
          accept: 'application/json',
          authorization: `Bearer ${this.token}`,
          ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
      });
    } catch (error) {
      if (error instanceof HttpError) error.path = pathname;
      throw error;
    }
  }
}

async function ensureOrganization(client, orgSlug, orgName) {
  let organization;
  let status = 'unchanged';
  try {
    const response = await client.request(`/api/organizations/${encodeURIComponent(orgSlug)}`);
    organization = response.organization || response;
  } catch (error) {
    if (!(error instanceof HttpError) || error.status !== 404) throw error;
  }

  if (!organization) {
    const response = await client.request('/api/organizations', {
      method: 'POST',
      body: { slug: orgSlug, name: orgName },
    });
    organization = response.organization || response;
    status = 'created';
  }

  if (organization.status === 'pending') {
    await client.request(`/api/platform/organizations/${encodeURIComponent(organization.id)}/approve`, {
      method: 'POST',
      body: { tier_id: organization.tier_id || 'tier_free' },
    });
    return status === 'created' ? 'created+approved' : 'approved';
  }

  if (organization.status === 'suspended') {
    await client.request(`/api/platform/organizations/${encodeURIComponent(organization.id)}/activate`, {
      method: 'POST',
    });
    return 'activated';
  }

  return status;
}

/// The platform owner is a global identity, but service sign-in needs an
/// org membership: invite them as admin when they have neither (A6). The
/// invite is idempotent (already-member / already-sent are fine), and the
/// summary tells the owner where to accept it.
async function ensureOrgAdminInvite(client, service, ownerEmail) {
  if (!ownerEmail) return 'skipped (no platform owner email)';
  try {
    await client.request(
      `/api/organizations/${encodeURIComponent(service.org)}/invitations`,
      { method: 'POST', body: { email: ownerEmail, role: 'admin' } },
    );
    return 'invited';
  } catch (error) {
    const message = error instanceof HttpError ? `${error.status} ${error.message}` : `${error}`;
    if (/already a member|already sent/i.test(message)) return 'existing';
    return `failed: ${message}`;
  }
}

async function ensureService(client, service) {
  const existing = await findService(client, service.org, service.service);
  const desired = {
    slug: service.service,
    name: service.name,
    service_type: service.type,
    redirect_uris: service.redirectUris,
    github_scopes: service.githubScopes,
  };
  if (!existing) {
    const response = await client.request(
      `/api/organizations/${encodeURIComponent(service.org)}/services`,
      { method: 'POST', body: desired },
    );
    return { status: 'created', clientId: response.service?.client_id || '' };
  }

  const needsUpdate =
    existing.name !== desired.name ||
    existing.service_type !== desired.service_type ||
    !sameStringSet(existing.redirect_uris || [], desired.redirect_uris) ||
    !sameStringSet(existing.github_scopes || [], desired.github_scopes);
  if (!needsUpdate) {
    return { status: 'unchanged', clientId: existing.client_id || '' };
  }
  const updated = await client.request(
    `/api/organizations/${encodeURIComponent(service.org)}/services/${encodeURIComponent(service.service)}`,
    { method: 'PATCH', body: desired },
  );
  return { status: 'updated', clientId: updated.client_id || existing.client_id || '' };
}

async function findService(client, orgSlug, serviceSlug) {
  const response = await client.request(
    `/api/organizations/${encodeURIComponent(orgSlug)}/services`,
  );
  return (response.services || []).find((candidate) => candidate.slug === serviceSlug) || null;
}

async function ensureOAuthCredentials(client, service) {
  const result = {};
  for (const provider of ['github', 'google', 'microsoft']) {
    const creds = service.oauthCredentials?.[provider];
    if (!creds?.clientId || !creds?.clientSecret) {
      result[provider] = 'skipped';
      continue;
    }
    await client.request(
      `/api/organizations/${encodeURIComponent(service.org)}/oauth-credentials/${provider}`,
      {
        method: 'POST',
        body: { client_id: creds.clientId, client_secret: creds.clientSecret },
      },
    );
    result[provider] = 'configured';
  }
  return result;
}

async function ensureApiKey(root, client, service, apiKey) {
  if (!apiKey.name) {
    throw new Error(`Service ${service.org}/${service.service} has an apiKeys[] entry without name`);
  }
  const list = await client.request(
    `/api/organizations/${encodeURIComponent(service.org)}/services/${encodeURIComponent(service.service)}/api-keys`,
  );
  const existing = (list.api_keys || []).find((candidate) => candidate.name === apiKey.name);
  if (existing && !apiKey.forceNew) {
    return { name: apiKey.name, status: 'existing', prefix: existing.prefix };
  }
  if (!apiKey.writeTo) {
    throw new Error(`API key ${apiKey.name} needs writeTo because new API key secrets are shown once`);
  }
  const created = await client.request(
    `/api/organizations/${encodeURIComponent(service.org)}/services/${encodeURIComponent(service.service)}/api-keys`,
    { method: 'POST', body: { name: apiKey.name, permissions: apiKey.permissions } },
  );
  const target = path.resolve(root, apiKey.writeTo);
  await fsp.mkdir(path.dirname(target), { recursive: true });
  await writeText(target, `AUTHOS_API_KEY=${created.key}\n`, 0o600);
  return {
    name: apiKey.name,
    status: 'created',
    prefix: created.prefix,
    writtenTo: path.relative(root, target),
  };
}

function sameStringSet(left, right) {
  if (left.length !== right.length) return false;
  const rightSet = new Set(right);
  return left.every((item) => rightSet.has(item));
}

module.exports = {
  provisionResources,
};
