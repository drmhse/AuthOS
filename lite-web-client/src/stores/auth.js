import { defineStore } from 'pinia';
import router from '@/router';
import { sso } from '@/lib/api';
import { useAuthFlowStore } from '@/stores/authFlow';
import { clearPostLoginRedirect, storePostLoginRedirect } from '@/utils/redirects';
import { decodeJwt, isTokenExpired } from '@/utils/jwt';

function canUseLocalStorage(method = 'getItem') {
  return typeof localStorage !== 'undefined' && typeof localStorage[method] === 'function';
}

function storageGet(key, fallback = null) {
  if (!canUseLocalStorage('getItem')) {
    return fallback;
  }

  const value = localStorage.getItem(key);
  return value ?? fallback;
}

function storageSet(key, value) {
  if (!canUseLocalStorage('setItem')) {
    return;
  }

  localStorage.setItem(key, value);
}

function storageRemove(key) {
  if (!canUseLocalStorage('removeItem')) {
    return;
  }

  localStorage.removeItem(key);
}

function storageJsonGet(key, fallback) {
  const raw = storageGet(key);
  if (!raw) {
    return fallback;
  }

  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    token: storageGet('sso_access_token'),
    refreshToken: storageGet('sso_refresh_token'),
    user: storageJsonGet('sso_user', null),
    claims: storageJsonGet('sso_claims', null),
    status: storageGet('sso_status', 'idle'),
    permissions: storageJsonGet('sso_permissions', []),
    plan: storageGet('sso_plan'),
    features: storageJsonGet('sso_features', []),
    activeOrgRole: storageGet('sso_active_org_role'),
  }),

  getters: {
    isAuthenticated: (state) => (
      state.status === 'authenticated' && Boolean(state.token) && !isTokenExpired(state.token)
    ),
    isPlatformOwner: (state) => state.claims?.is_platform_owner === true,
    isPlatformContext: (state) =>
      Boolean(state.claims) &&
      !state.claims.org &&
      !state.claims.service &&
      state.claims.aud === 'platform',
    isMfaVerified: (state) => state.claims?.mfa_verified === true,
    currentOrgSlug: (state) => state.claims?.org || null,
    currentOrgId: (state) => state.claims?.org_id || null,
    userEmail: (state) => state.user?.email || state.claims?.email || null,
    userId: (state) => state.user?.id || state.claims?.sub || null,
  },

  actions: {
    async initializeAuth() {
      const token = storageGet('sso_access_token');
      if (!token || isTokenExpired(token)) {
        this.clearAuth();
        this.status = 'idle';
        storageSet('sso_status', 'idle');
        return;
      }

      this.token = token;
      this.claims = decodeJwt(token);
      sso.setAuthToken(token);

      const cachedStatus = storageGet('sso_status');
      const cachedUser = storageGet('sso_user');
      if (cachedStatus === 'authenticated' && cachedUser) {
        this.user = storageJsonGet('sso_user', null);
        this.status = 'authenticated';
        return;
      }

      this.status = 'loading';
      storageSet('sso_status', 'loading');

      try {
        const userData = await sso.user.getProfile();
        this.user = userData;
        this.permissions = userData.permissions || [];
        this.plan = userData.plan || null;
        this.features = userData.features || [];
        storageSet('sso_user', JSON.stringify(userData));
        storageSet('sso_permissions', JSON.stringify(this.permissions));
        storageSet('sso_plan', this.plan || '');
        storageSet('sso_features', JSON.stringify(this.features));
        this.status = 'authenticated';
        storageSet('sso_status', 'authenticated');
      } catch (error) {
        this.handleAuthError(error);
      }
    },

    async handleLoginCallback(accessToken, refreshToken) {
      if (!accessToken || !refreshToken) {
        throw new Error('Both access token and refresh token are required');
      }

      this.status = 'loading';
      storageSet('sso_status', 'loading');
      this.token = accessToken;
      this.refreshToken = refreshToken;
      this.claims = decodeJwt(accessToken);
      this.activeOrgRole = null;

      storageSet('sso_access_token', accessToken);
      storageSet('sso_refresh_token', refreshToken);
      storageSet('sso_claims', JSON.stringify(this.claims));
      storageRemove('sso_active_org_role');

      await sso.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });

      const userData = await sso.user.getProfile();
      this.user = userData;
      this.permissions = userData.permissions || [];
      this.plan = userData.plan || null;
      this.features = userData.features || [];
      storageSet('sso_user', JSON.stringify(userData));
      storageSet('sso_permissions', JSON.stringify(this.permissions));
      storageSet('sso_plan', this.plan || '');
      storageSet('sso_features', JSON.stringify(this.features));
      this.status = 'authenticated';
      storageSet('sso_status', 'authenticated');
    },

    async completeMfaChallenge(preauthToken, code, deviceCodeId = null) {
      const response = await sso.auth.verifyMfa(preauthToken, code, deviceCodeId);
      await this.handleLoginCallback(response.access_token, response.refresh_token);
      return response;
    },

    async refreshUser() {
      const userData = await sso.user.getProfile();
      this.user = userData;
      this.permissions = userData.permissions || [];
      this.plan = userData.plan || null;
      this.features = userData.features || [];
      storageSet('sso_user', JSON.stringify(userData));
      storageSet('sso_permissions', JSON.stringify(this.permissions));
      storageSet('sso_plan', this.plan || '');
      storageSet('sso_features', JSON.stringify(this.features));
    },

    async updateTokens(accessToken, refreshToken, role = null) {
      this.token = accessToken;
      this.refreshToken = refreshToken;
      this.claims = decodeJwt(accessToken);
      this.activeOrgRole = role;
      storageSet('sso_access_token', accessToken);
      storageSet('sso_refresh_token', refreshToken);
      storageSet('sso_claims', JSON.stringify(this.claims));
      if (role) storageSet('sso_active_org_role', role);
      sso.setAuthToken(accessToken);
      await sso.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });
      await this.refreshUser();
    },

    async refreshAccessToken() {
      if (!this.refreshToken) throw new Error('No refresh token available');
      const response = await sso.auth.refreshToken(this.refreshToken);
      this.token = response.access_token;
      this.refreshToken = response.refresh_token;
      this.claims = decodeJwt(response.access_token);
      storageSet('sso_access_token', response.access_token);
      storageSet('sso_refresh_token', response.refresh_token);
      storageSet('sso_claims', JSON.stringify(this.claims));
      sso.setAuthToken(response.access_token);
      return response;
    },

    clearAuth() {
      const authFlowStore = useAuthFlowStore();
      storageRemove('sso_access_token');
      storageRemove('sso_refresh_token');
      storageRemove('sso_user');
      storageRemove('sso_claims');
      storageRemove('sso_status');
      storageRemove('sso_permissions');
      storageRemove('sso_plan');
      storageRemove('sso_features');
      storageRemove('sso_active_org_role');
      this.token = null;
      this.refreshToken = null;
      this.user = null;
      this.claims = null;
      this.permissions = [];
      this.plan = null;
      this.features = [];
      this.activeOrgRole = null;
      authFlowStore.clearMfaChallenge();
      clearPostLoginRedirect();
      sso.setAuthToken(null);
    },

    async logout() {
      try {
        await sso.auth.logout();
      } catch (error) {
        console.warn('Logout request failed:', error);
      } finally {
        this.clearAuth();
        this.status = 'idle';
        storageSet('sso_status', 'idle');
      }
    },

    handleAuthError(error) {
      console.error('Auth error:', error);
      this.clearAuth();
      this.status = 'idle';
      storageSet('sso_status', 'idle');

      if (router.currentRoute.value.path !== '/') {
        storePostLoginRedirect(router.currentRoute.value.fullPath);
        router.push({
          path: '/',
          query: {
            error: 'session_expired',
          },
        });
      }

      throw error;
    },
  },
});
