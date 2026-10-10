import { describe, expect, it } from 'vitest';
import { authRouteWithContext, getAuthFlowContext, getDirectMfaChallenge, hasServiceAuthContext } from '@/utils/authFlowContext';

describe('auth flow context helpers', () => {
  it('detects service-auth query context on hosted entry routes', () => {
    const route = {
      query: {
        org: 'indie-blog',
        service: 'blog-app',
        redirect_uri: 'http://app.example.com/callback',
        return_to: 'http://app.example.com/settings',
        state: 'caller-state',
      },
    };

    expect(hasServiceAuthContext(route)).toBe(true);
    expect(getAuthFlowContext(route)).toMatchObject({
      org: 'indie-blog',
      service: 'blog-app',
      redirectUri: 'http://app.example.com/callback',
      returnTo: 'http://app.example.com/settings',
      state: 'caller-state',
      isServiceFlow: true,
    });
  });

  it('carries the full flow context plus extras across hops', () => {
    const route = {
      query: {
        org: 'lab',
        service: 'servos',
        redirect_uri: 'http://localhost:18081/cb',
        state: 'caller-state',
      },
    };
    const next = authRouteWithContext(route, '/', { verified: '1' });
    expect(next).toContain('org=lab');
    expect(next).toContain('service=servos');
    expect(next).toContain('redirect_uri=');
    expect(next).toContain('state=caller-state');
    expect(next).toContain('verified=1');
  });

  it('does not treat platform routes as service-auth context', () => {
    expect(hasServiceAuthContext({ query: {} })).toBe(false);
    expect(hasServiceAuthContext({ query: { org: 'authos', service: 'platform' } })).toBe(false);
  });

  it('restores a hosted MFA continuation from a token-bearing fragment', () => {
    expect(getDirectMfaChallenge(
      {
        query: {
          redirect_uri: 'https://admin.servos.dev/auth/callback',
          state: 'caller-state',
        },
      },
      '#preauth_token=preauth-secret',
    )).toEqual({
      preauthToken: 'preauth-secret',
      redirectUri: 'https://admin.servos.dev/auth/callback',
      state: 'caller-state',
    });
  });
});
