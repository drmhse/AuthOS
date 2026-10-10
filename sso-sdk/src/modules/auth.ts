import { HttpClient } from '../http';
import { SessionManager } from '../session';
import {
  OAuthProvider,
  DeviceCodeRequest,
  DeviceCodeResponse,
  DeviceVerifyResponse,
  TokenRequest,
  TokenResponse,
  IdJagBearerExchangeRequest,
  IdJagBearerExchangeResponse,
  IdJagTokenExchangeRequest,
  IdJagTokenExchangeResponse,
  LoginUrlParams,
  AdminLoginUrlParams,
  ProviderToken,
  RefreshTokenResponse,
  RegisterRequest,
  RegisterResponse,
  LoginRequest,
  ForgotPasswordRequest,
  ForgotPasswordResponse,
  ResetPasswordRequest,
  ResetPasswordResponse,
  MfaVerificationResponse,
  LookupEmailResponse,
  ResendVerificationRequest,
  ResendVerificationResponse,
  AuthorizeUrlParams,
  AccountSecurityUrlParams,
  AuthContextRequest,
  AuthContextResponse,
} from '../types';

/**
 * Authentication and OAuth flow methods
 */
export class AuthModule {
  constructor(
    private http: HttpClient,
    private session: SessionManager
  ) { }

  /**
   * Constructs the hosted AuthOS login URL for an end-user application.
   * AuthOS owns provider selection, HRD, password, magic-link, passkey, MFA,
   * recovery, and callback token delivery for this flow.
   *
   * @param params Hosted authorize parameters (org, service, redirect_uri)
   * @returns The full URL to redirect the user to
   *
   * @example
   * ```typescript
   * window.location.href = sso.auth.getAuthorizeUrl({
   *   org: 'acme-corp',
   *   service: 'main-app',
   *   redirect_uri: 'https://app.acme.com/callback'
   * });
   * ```
   */
  public getAuthorizeUrl(params: AuthorizeUrlParams): string {
    const baseURL = (this.http.defaults.baseURL || '').replace(/\/+$/, '');
    const searchParams = new URLSearchParams({
      org: params.org,
      service: params.service,
      redirect_uri: params.redirect_uri,
    });
    if (params.state) searchParams.append('state', params.state);

    return `${baseURL}/authorize?${searchParams.toString()}`;
  }

  /**
   * Constructs the hosted account-security URL for managing user factors.
   * Use this for AuthOS-owned MFA, passkeys, backup codes, and trusted devices.
   *
   * @param params Optional tenant/application context and return URL
   * @returns The full URL to open for account security management
   */
  public getAccountSecurityUrl(params: AccountSecurityUrlParams = {}): string {
    const baseURL = (this.http.defaults.baseURL || '').replace(/\/+$/, '');
    const searchParams = new URLSearchParams();

    if (params.org) searchParams.append('org', params.org);
    if (params.service) searchParams.append('service', params.service);
    if (params.return_to) searchParams.append('return_to', params.return_to);

    const query = searchParams.toString();
    return `${baseURL}/app/account-security${query ? `?${query}` : ''}`;
  }

  /**
   * Constructs the OAuth login URL for end-users.
   * This does not perform the redirect; the consuming application
   * should redirect the user's browser to this URL.
   *
   * @param provider The OAuth provider to use
   * @param params Login parameters (org, service, redirect_uri, connection_id)
   * @returns The full URL to redirect the user to
   *
   * @example
   * ```typescript
   * // Standard OAuth login
   * const url = sso.auth.getLoginUrl('github', {
   *   org: 'acme-corp',
   *   service: 'main-app',
   *   redirect_uri: 'https://app.acme.com/callback'
   * });
   * window.location.href = url;
   *
   * // Enterprise IdP login (after HRD lookup)
   * const hrd = await sso.auth.lookupEmail('user@enterprise.com');
   * if (hrd.connection_id) {
   *   const url = sso.auth.getLoginUrl('github', {
   *     org: 'acme-corp',
   *     service: 'main-app',
   *     connection_id: hrd.connection_id
   *   });
   *   window.location.href = url;
   * }
   * ```
   */
  public getLoginUrl(provider: OAuthProvider, params: LoginUrlParams): string {
    const baseURL = this.http.defaults.baseURL || '';
    const searchParams = new URLSearchParams({
      org: params.org,
      service: params.service,
    });

    if (params.redirect_uri) {
      searchParams.append('redirect_uri', params.redirect_uri);
    }
    if (params.state) {
      searchParams.append('state', params.state);
    }

    if (params.user_code) {
      searchParams.append('user_code', params.user_code);
    }

    if (params.connection_id) {
      searchParams.append('connection_id', params.connection_id);
    }

    return `${baseURL}/auth/${provider}?${searchParams.toString()}`;
  }

  /**
   * Constructs the OAuth login URL for platform/organization admins.
   * This uses the platform's dedicated OAuth credentials.
   *
   * @param provider The OAuth provider to use
   * @param params Optional admin login parameters
   * @returns The full URL to redirect the admin to
   *
   * @example
   * ```typescript
   * const url = sso.auth.getAdminLoginUrl('github', {
   *   org_slug: 'acme-corp'
   * });
   * window.location.href = url;
   * ```
   */
  public getAdminLoginUrl(provider: OAuthProvider, params?: AdminLoginUrlParams): string {
    const baseURL = this.http.defaults.baseURL || '';
    const searchParams = new URLSearchParams();

    if (params?.org_slug) {
      searchParams.append('org_slug', params.org_slug);
    }

    if (params?.user_code) {
      searchParams.append('user_code', params.user_code);
    }

    if (params?.return_to) {
      searchParams.append('return_to', params.return_to);
    }

    const queryString = searchParams.toString();
    return `${baseURL}/auth/admin/${provider}${queryString ? `?${queryString}` : ''}`;
  }

  /**
   * Device Flow: Request a device code for CLI/device authentication.
   *
   * @param payload Device code request payload
   * @returns Device code response with user code and verification URI
   *
   * @example
   * ```typescript
   * const response = await sso.auth.deviceCode.request({
   *   client_id: 'service-client-id',
   *   org: 'acme-corp',
   *   service: 'acme-cli'
   * });
   * console.log(`Visit ${response.verification_uri} and enter code: ${response.user_code}`);
   * ```
   */
  public deviceCode = {
    /**
     * Request a device code
     */
    request: async (payload: DeviceCodeRequest): Promise<DeviceCodeResponse> => {
      const response = await this.http.post<DeviceCodeResponse>('/auth/device/code', payload);
      return response.data;
    },

    /**
     * Verify a user code and get the context (org_slug, service_slug)
     * needed for the UI to initiate the appropriate OAuth flow.
     *
     * @param userCode The user-friendly code displayed on the device
     * @returns Context with organization and service information
     *
     * @example
     * ```typescript
     * const context = await sso.auth.deviceCode.verify('ABCD-1234');
     * // Use context.org_slug and context.service_slug to determine which OAuth flow to initiate
     * ```
     */
    verify: async (userCode: string): Promise<DeviceVerifyResponse> => {
      const response = await this.http.post<DeviceVerifyResponse>('/auth/device/verify', {
        user_code: userCode
      });
      return response.data;
    },

    /**
     * Exchange a device code for a JWT token.
     * This should be polled by the device/CLI after displaying the user code.
     * Note: This returns a TokenResponse (not RefreshTokenResponse) and typically
     * only includes access_token. For device flows that need persistence,
     * manually call sso.session.setSession() if needed.
     *
     * @param payload Token request payload
     * @returns Token response with JWT
     *
     * @example
     * ```typescript
     * // Poll every 5 seconds
     * const interval = setInterval(async () => {
     *   try {
     *     const token = await sso.auth.deviceCode.exchangeToken({
     *       grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
     *       device_code: deviceCode,
     *       client_id: 'service-client-id'
     *     });
     *     clearInterval(interval);
     *     // Session is automatically configured
     *   } catch (error) {
     *     if (error.errorCode !== 'authorization_pending') {
     *       clearInterval(interval);
     *       throw error;
     *     }
     *   }
     * }, 5000);
     * ```
     */
    exchangeToken: async (payload: TokenRequest): Promise<TokenResponse> => {
      const response = await this.http.post<TokenResponse>('/auth/token', payload);
      return response.data;
    },
  };

  /**
   * Enterprise-managed authorization helpers for MCP/Cross-App Access.
   */
  public enterprise = {
    /**
     * Exchange an AuthOS service-scoped JWT for a short-lived ID-JAG.
     */
    requestIdJag: async (
      payload: IdJagTokenExchangeRequest
    ): Promise<IdJagTokenExchangeResponse> => {
      const response = await this.http.postForm<IdJagTokenExchangeResponse>('/oauth/token', {
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
        audience: payload.audience,
        resource: payload.resource,
        scope: payload.scope,
        subject_token: payload.subject_token,
        subject_token_type:
          payload.subject_token_type || 'urn:ietf:params:oauth:token-type:access_token',
        client_id: payload.client_id,
        client_secret: payload.client_secret,
      });
      return response.data;
    },

    /**
     * Exchange an ID-JAG for a resource-scoped AuthOS bearer token.
     */
    exchangeIdJag: async (
      payload: IdJagBearerExchangeRequest
    ): Promise<IdJagBearerExchangeResponse> => {
      const response = await this.http.postForm<IdJagBearerExchangeResponse>('/oauth/token', {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: payload.assertion,
        client_id: payload.client_id,
        client_secret: payload.client_secret,
      });
      return response.data;
    },
  };

  /**
   * Logout the current user by revoking their JWT.
   * Automatically clears the session and tokens from storage.
   *
   * @example
   * ```typescript
   * await sso.auth.logout();
   * // Session is automatically cleared - no need for manual cleanup
   * ```
   */
  public async logout(): Promise<void> {
    try {
      await this.http.post('/api/auth/logout');
    } finally {
      // MAGIC HAPPENS HERE: Auto-clear tokens
      await this.session.clearSession();
    }
  }

  /**
   * Refresh an expired JWT access token using a refresh token.
   * This implements token rotation - both the access token and refresh token
   * will be renewed with each call.
   *
   * The refresh token must be stored securely on the client side.
   * After a successful refresh, update both tokens in storage and call
   * `sso.setAuthToken(newAccessToken)`.
   *
   * @param refreshToken The refresh token obtained during login
   * @returns New access token and refresh token pair
   *
   * @example
   * ```typescript
   * try {
   *   const tokens = await sso.auth.refreshToken(storedRefreshToken);
   *   sso.setAuthToken(tokens.access_token);
   *   localStorage.setItem('sso_access_token', tokens.access_token);
   *   localStorage.setItem('sso_refresh_token', tokens.refresh_token);
   * } catch (error) {
   *   // Refresh failed - redirect to login
   *   window.location.href = '/login';
   * }
   * ```
   */
  public async refreshToken(refreshToken: string): Promise<RefreshTokenResponse> {
    const response = await this.http.post<RefreshTokenResponse>('/api/auth/refresh', {
      refresh_token: refreshToken,
    });
    return response.data;
  }

  /**
   * Get a fresh provider access token for the authenticated user.
   * This will automatically refresh the token if it's expired.
   *
   * @param provider The OAuth provider
   * @returns Fresh provider token
   *
   * @example
   * ```typescript
   * const token = await sso.auth.getProviderToken('github');
   * // Use token.access_token to make GitHub API calls
   * ```
   */
  public async getProviderToken(provider: OAuthProvider): Promise<ProviderToken> {
    const response = await this.http.get<ProviderToken>(`/api/provider-token/${provider}`);
    return response.data;
  }

  // ============================================================================
  // PASSWORD AUTHENTICATION
  // ============================================================================

  /**
   * Register a new user with email and password.
   * After registration, the user will receive a verification email.
   *
   * @param payload Registration details (email and password)
   * @returns Registration confirmation message
   *
   * @example
   * ```typescript
   * const response = await sso.auth.register({
   *   email: 'user@example.com',
   *   password: 'SecurePassword123!'
   * });
   * console.log(response.message);
   * ```
   */
  public async register(payload: RegisterRequest): Promise<RegisterResponse> {
    const response = await this.http.post<RegisterResponse>('/api/auth/register', payload);
    return response.data;
  }

  /**
   * Which email-dependent flows this instance can complete, so clients
   * disable them up front instead of failing after submit.
   */
  public async availability(): Promise<AvailabilityResponse> {
    const response = await this.http.get<AvailabilityResponse>('/api/auth/availability');
    return response.data;
  }

  /**
   * Verify an email address using the token from the verification email.
   *
   * @param token Verification token
   * @returns HTML success page string
   *
   * @example
   * ```typescript
   * const html = await sso.auth.verifyEmail('token-from-email');
   * ```
   */
  public async verifyEmail(token: string): Promise<string> {
    const response = await this.http.get<string>('/auth/verify-email', {
      params: { token }
    });
    return response.data;
  }

  /**
   * Resend verification email to a user.
   * Returns success regardless of whether the email exists (to prevent email enumeration).
   *
   * @param payload Resend verification request (email address)
   * @returns Confirmation message
   *
   * @example
   * ```typescript
   * const response = await sso.auth.resendVerification({
   *   email: 'user@example.com'
   * });
   * console.log(response.message);
   * ```
   */
  public async resendVerification(payload: ResendVerificationRequest): Promise<ResendVerificationResponse> {
    const response = await this.http.post<ResendVerificationResponse>('/api/auth/resend-verification', payload);
    return response.data;
  }

  /**
   * Login with email and password.
   * Automatically persists the session once authentication is complete.
   *
   * @param payload Login credentials (email and password)
   * @returns Access token, refresh token, and expiration info
   *
   * @example
   * ```typescript
   * const tokens = await sso.auth.login({
   *   email: 'user@example.com',
   *   password: 'SecurePassword123!'
   * });
   * // Session is automatically saved unless MFA is required
   * ```
   */
  public async login(payload: LoginRequest): Promise<RefreshTokenResponse> {
    const response = await this.http.post<RefreshTokenResponse>('/api/auth/login', payload);

    if (response.data.refresh_token) {
      await this.session.setSession({
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token,
      });
    }

    return response.data;
  }

  /**
   * Verify MFA code and complete authentication.
   * This method should be called after login when the user has MFA enabled.
   * The login will return a pre-auth token with a short expiration (5 minutes).
   * Exchange the pre-auth token and TOTP code for a full session.
   * Automatically persists the session after successful MFA verification.
   *
   * @param preauthToken The pre-authentication token received from login
   * @param code The TOTP code from the user's authenticator app or a backup code
   * @returns Full session tokens (access_token and refresh_token)
   *
   * @example
   * ```typescript
   * // After login, if MFA is enabled:
   * const loginResponse = await sso.auth.login({
   *   email: 'user@example.com',
   *   password: 'password'
   * });
   *
   * // Check if this is a pre-auth token (expires_in will be 300 seconds = 5 minutes)
   * if (loginResponse.expires_in === 300) {
   *   // User needs to provide MFA code
   *   const mfaCode = prompt('Enter your 6-digit code from authenticator app');
   *   const tokens = await sso.auth.verifyMfa(loginResponse.access_token, mfaCode);
   *   // Session is automatically saved - no need for manual token management
   * }
   * ```
   */
  public async verifyMfa(
    preauthToken: string,
    code: string,
    deviceCodeId?: string
  ): Promise<MfaVerificationResponse> {
    const response = await this.http.post<MfaVerificationResponse>('/api/auth/mfa/verify', {
      preauth_token: preauthToken,
      code,
      ...(deviceCodeId && { device_code_id: deviceCodeId }),
    });

    // Auto-save tokens after MFA verification
    await this.session.setSession({
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token,
    });

    return response.data;
  }

  /**
   * Request a password reset for a user account.
   * If the email exists, a reset link will be sent to the user.
   * Returns success regardless of whether the email exists (to prevent email enumeration).
   *
   * @param payload Forgot password request (email address)
   * @returns Confirmation message
   *
   * @example
   * ```typescript
   * const response = await sso.auth.requestPasswordReset({
   *   email: 'user@example.com'
   * });
   * console.log(response.message);
   * ```
   */
  public async requestPasswordReset(payload: ForgotPasswordRequest): Promise<ForgotPasswordResponse> {
    const response = await this.http.post<ForgotPasswordResponse>('/api/auth/forgot-password', payload);
    return response.data;
  }

  /**
   * Reset a user's password using a reset token from email.
   * The token is obtained from the password reset email link.
   *
   * @param payload Reset password request (token and new password)
   * @returns Confirmation message
   *
   * @example
   * ```typescript
   * const response = await sso.auth.resetPassword({
   *   token: 'reset-token-from-email',
   *   new_password: 'NewSecurePassword123!'
   * });
   * console.log(response.message);
   * ```
   */
  public async resetPassword(payload: ResetPasswordRequest): Promise<ResetPasswordResponse> {
    const response = await this.http.post<ResetPasswordResponse>('/api/auth/reset-password', payload);
    return response.data;
  }

  // ============================================================================
  // HOME REALM DISCOVERY (HRD)
  // ============================================================================

  /**
   * Lookup an email address to determine which authentication method to use.
   * This implements Home Realm Discovery (HRD), allowing users to simply enter
   * their email address and be automatically routed to the correct identity provider.
   *
   * The system will:
   * 1. Extract the domain from the email address
   * 2. Check if the domain is verified and mapped to an enterprise IdP
   * 3. Return routing information (connection_id) if found
   * 4. Otherwise, indicate to use default authentication (password or OAuth)
   *
   * @param email The user's email address
   * @returns HRD response with routing information
   *
   * @example
   * ```typescript
   * // Lookup email to determine authentication flow
   * const result = await sso.auth.lookupEmail('john@acmecorp.com');
   *
   * if (result.auth_method === 'upstream' && result.connection_id) {
   *   // Route to enterprise IdP
   *   console.log(`Redirecting to ${result.provider_name}`);
   *   const url = sso.auth.getLoginUrl('github', {
   *     org: 'acme-corp',
   *     service: 'main-app',
   *     connection_id: result.connection_id
   *   });
   *   window.location.href = url;
   * } else if (result.auth_method === 'password') {
   *   // Show password login form
   *   showPasswordForm();
   * } else {
   *   // Show default OAuth provider buttons (GitHub, Google, Microsoft)
   *   showOAuthButtons();
   * }
   * ```
   */
  public async lookupEmail(email: string): Promise<LookupEmailResponse> {
    const response = await this.http.post<LookupEmailResponse>('/api/auth/lookup-email', {
      email
    });
    return response.data;
  }

  /**
   * Fetch public hosted-auth context for an organization/service login.
   */
  public async getContext(params: AuthContextRequest = {}): Promise<AuthContextResponse> {
    const searchParams = new URLSearchParams();
    if (params.org) searchParams.append('org', params.org);
    if (params.service) searchParams.append('service', params.service);
    if (params.redirect_uri) searchParams.append('redirect_uri', params.redirect_uri);

    const query = searchParams.toString();
    const response = await this.http.get<AuthContextResponse>(
      `/api/auth/context${query ? `?${query}` : ''}`
    );
    return response.data;
  }
}
