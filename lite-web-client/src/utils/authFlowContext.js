export function firstQueryValue(value) {
  if (Array.isArray(value)) return value[0] || '';
  return typeof value === 'string' ? value : '';
}

export function getAuthFlowContext(route) {
  const org = firstQueryValue(route?.query?.org);
  const service = firstQueryValue(route?.query?.service);
  const redirectUri = firstQueryValue(route?.query?.redirect_uri);
  const redirect = firstQueryValue(route?.query?.redirect);
  const returnTo = firstQueryValue(route?.query?.return_to);
  const state = firstQueryValue(route?.query?.state);
  const isPlatformFlow = (!org || org === 'authos') && (!service || service === 'platform');
  const isServiceFlow = Boolean(org && service && !isPlatformFlow);

  return {
    org,
    service,
    redirectUri,
    redirect,
    returnTo,
    state,
    isServiceFlow,
    serviceLabel: service || 'this application',
    orgLabel: org || 'your organization',
  };
}

export function hasServiceAuthContext(route) {
  return getAuthFlowContext(route).isServiceFlow;
}

export function authRouteWithContext(route, path, extra = {}) {
  const ctx = getAuthFlowContext(route);
  const params = new URLSearchParams();

  if (ctx.org) params.set('org', ctx.org);
  if (ctx.service) params.set('service', ctx.service);
  if (ctx.redirectUri) params.set('redirect_uri', ctx.redirectUri);
  if (ctx.redirect) params.set('redirect', ctx.redirect);
  if (ctx.returnTo) params.set('return_to', ctx.returnTo);
  if (ctx.state) params.set('state', ctx.state);
  for (const [key, value] of Object.entries(extra)) {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value));
    }
  }

  const query = params.toString();
  return query ? `${path}?${query}` : path;
}

export function appendTokensToRedirectUri(redirectUri, accessToken, refreshToken, extras = {}) {
  const url = new URL(redirectUri, window.location.origin);
  const hashParams = new URLSearchParams(url.hash.replace(/^#/, ''));

  hashParams.set('access_token', accessToken);
  hashParams.set('refresh_token', refreshToken);

  for (const [key, value] of Object.entries(extras)) {
    if (value !== undefined && value !== null && value !== '') {
      hashParams.set(key, String(value));
    }
  }

  url.hash = hashParams.toString();
  return url.toString();
}

export function getDirectMfaChallenge(route, locationHash = '') {
  const fragment = new URLSearchParams(String(locationHash).replace(/^#/, ''));
  const preauthToken = fragment.get('preauth_token') || firstQueryValue(route?.query?.preauth_token);
  if (!preauthToken) return null;

  return {
    preauthToken,
    redirectUri: firstQueryValue(route?.query?.redirect_uri),
    state: firstQueryValue(route?.query?.state),
  };
}
