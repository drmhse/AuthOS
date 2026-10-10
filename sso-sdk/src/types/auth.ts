import { OAuthProvider } from './common';

/**
 * Device code request payload
 */
export interface DeviceCodeRequest {
  client_id: string;
  org: string;
  service: string;
}

/**
 * Device code response
 */
export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

/**
 * Device verify response - returns context for initiating OAuth flow
 */
export interface DeviceVerifyResponse {
  org_slug: string;
  service_slug: string;
  available_providers: string[];
}

/**
 * Token request payload for device flow
 */
export interface TokenRequest {
  grant_type: 'urn:ietf:params:oauth:grant-type:device_code';
  device_code: string;
  client_id: string;
  resource?: string;
}

/**
 * Token response
 */
export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
}

export interface IdJagTokenExchangeRequest {
  client_id: string;
  audience: string;
  resource: string;
  subject_token: string;
  subject_token_type?: 'urn:ietf:params:oauth:token-type:access_token';
  scope?: string;
  client_secret?: string;
}

export interface IdJagTokenExchangeResponse {
  issued_token_type: 'urn:ietf:params:oauth:token-type:id-jag';
  access_token: string;
  token_type: 'N_A';
  expires_in: number;
  scope?: string;
}

export interface IdJagBearerExchangeRequest {
  client_id: string;
  client_secret: string;
  assertion: string;
}

export interface IdJagBearerExchangeResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope?: string;
}

/**
 * Parameters for constructing login URL
 */
export interface LoginUrlParams {
  /**
   * Organization slug
   */
  org: string;

  /**
   * Service slug
   */
  service: string;

  /**
   * Optional redirect URI (must be registered with the service)
   */
  redirect_uri?: string;

  /**
   * Optional caller state to return to the service callback.
   */
  state?: string;

  /**
   * Optional user code for device flow authorization
   */
  user_code?: string;

  /**
   * Optional connection ID for enterprise IdP routing (from HRD lookup).
   * When provided, routes user to specific upstream provider instead of using default OAuth.
   * Example: "azure-ad-connection", "okta-enterprise"
   */
  connection_id?: string;
}

/**
 * Parameters for constructing the hosted AuthOS login URL.
 */
export interface AuthorizeUrlParams {
  /**
   * Organization slug
   */
  org: string;

  /**
   * Service slug
   */
  service: string;

  /**
   * Callback URI registered with the service
   */
  redirect_uri: string;

  /**
   * Optional caller state to return to the service callback.
   */
  state?: string;
}

/**
 * Parameters for constructing the hosted account-security URL.
 */
export interface AccountSecurityUrlParams {
  /**
   * Optional organization slug for tenant-aware branding/context
   */
  org?: string;

  /**
   * Optional service slug for application context
   */
  service?: string;

  /**
   * Optional URL to return to after managing account security
   */
  return_to?: string;
}

/**
 * Parameters for constructing admin login URL
 */
export interface AdminLoginUrlParams {
  /**
   * Optional organization slug to manage
   */
  org_slug?: string;
  /**
   * Optional user code for device flow authorization
   */
  user_code?: string;
  /**
   * Optional internal Lite client path to return to after admin OAuth.
   */
  return_to?: string;
}

/**
 * Provider token response
 */
export interface ProviderToken {
  access_token: string;
  refresh_token?: string;
  expires_at: string;
  scopes: string[];
  provider: OAuthProvider;
}

/**
 * Refresh token request payload
 */
export interface RefreshTokenRequest {
  refresh_token: string;
}

/**
 * Refresh token response
 */
export interface RefreshTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/**
 * Registration request payload
 */
export interface RegisterRequest {
  email: string;
  password: string;
  /**
   * Organization slug for tenant context.
   * When provided, the user is attributed to this organization.
   */
  org_slug?: string;
  /**
   * Service slug for service attribution.
   * When provided with org_slug, creates a scoped identity.
   * This ensures password users are tracked the same as OAuth users.
   */
  service_slug?: string;
  /**
   * Optional service callback URI to preserve the original app return path in the verification link.
   */
  redirect_uri?: string;

  /**
   * Optional caller state to return to hosted service callbacks.
   */
  state?: string;
}

/**
 * Registration response
 */
export interface RegisterResponse {
  message: string;
}

/**
 * Which email-dependent flows this instance can complete.
 */
export interface AvailabilityResponse {
  password_registration: boolean;
  magic_link: boolean;
  password_reset: boolean;
}

/**
 * Login request payload
 */
export interface LoginRequest {
  email: string;
  password: string;
  /**
   * Organization slug for context.
   * When provided, scopes the session to this organization.
   */
  org_slug?: string;
  /**
   * Service slug for service-scoped access.
   * When provided with org_slug, limits access to this specific service.
   * Only required for regular members; org owners/admins can omit.
   */
  service_slug?: string;
  /**
   * Optional service callback URI for hosted password login.
   * When supplied with org_slug and service_slug, the API validates it
   * against the service before tokens are returned to the hosted UI.
   */
  redirect_uri?: string;
  /** Internal SAML relay state when completing a hosted SAML login. */
  saml_state?: string;
}

/**
 * Forgot password request payload
 */
export interface ForgotPasswordRequest {
  email: string;
  org_slug?: string; // Optional: use organization-specific SMTP
  service_slug?: string;
  redirect_uri?: string;
  state?: string;
}

/**
 * Forgot password response
 */
export interface ForgotPasswordResponse {
  message: string;
}

/**
 * Reset password request payload
 */
export interface ResetPasswordRequest {
  token: string;
  new_password: string;
}

/**
 * Reset password response
 */
export interface ResetPasswordResponse {
  message: string;
}

/**
 * Resend verification request payload
 */
export interface ResendVerificationRequest {
  email: string;
  org_slug?: string;
  service_slug?: string;
  redirect_uri?: string;
  state?: string;
}

/**
 * Resend verification response
 */
export interface ResendVerificationResponse {
  message: string;
}

/**
 * MFA verification request payload
 */
export interface MfaVerificationRequest {
  preauth_token: string;
  code: string;
}

/**
 * MFA verification response (same as refresh token response)
 */
export interface MfaVerificationResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/**
 * Home Realm Discovery (HRD) request payload
 */
export interface LookupEmailRequest {
  /**
   * Email address to lookup
   */
  email: string;
}

/**
 * Home Realm Discovery (HRD) response
 */
export interface LookupEmailResponse {
  /**
   * The connection ID to use for authentication, if any.
   * If present, use this to route the user to their enterprise IdP.
   */
  connection_id: string | null;

  /**
   * The name of the upstream provider, for display purposes.
   * Example: "Acme Corp Azure AD", "Partner Okta"
   */
  provider_name: string | null;

  /**
   * Whether the email domain is verified.
   * true = domain is verified and owned by an organization
   * false = domain is not verified, use default auth flow
   */
  domain_verified: boolean;

  /**
   * The authentication method to use:
   * - "upstream": Route to enterprise IdP via connection_id
   * - "password": Use email/password authentication
   * - "oauth": Use default OAuth providers (GitHub, Google, Microsoft)
   */
  auth_method: 'upstream' | 'password' | 'oauth';
}

/**
 * Public hosted-auth context request.
 */
export interface AuthContextRequest {
  org?: string;
  service?: string;
  redirect_uri?: string;
}

/**
 * Public hosted-auth organization context.
 */
export interface AuthOrganizationContext {
  slug: string;
  name: string;
  logo_url?: string | null;
  primary_color?: string | null;
  status: string;
}

/**
 * Public hosted-auth service context.
 */
export interface AuthServiceContext {
  slug: string;
  name: string;
  service_type: string;
  redirect_uri_valid?: boolean | null;
}

/**
 * Public hosted-auth context response.
 */
export interface AuthContextResponse {
  organization: AuthOrganizationContext | null;
  service: AuthServiceContext | null;
  available_providers: string[];
  auth_methods: string[];
  support_available: boolean;
}
