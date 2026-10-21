/**
 * User subscription details
 */
export interface Subscription {
  service: string;
  plan: string;
  features: string[];
  status: string;
  current_period_end?: string;
}

/**
 * Update user profile payload
 */
export interface UpdateUserProfilePayload {
  email?: string;
  /** Required when the account has a password. */
  current_password?: string;
  /** Required when MFA is enabled. */
  mfa_code?: string;
}

/**
 * Social identity linked to the user
 */
export interface Identity {
  provider: string;
}

/**
 * Response when starting a social account link
 */
export interface StartLinkResponse {
  authorization_url: string;
}

export interface ProviderDefinition {
  provider: string;
  display_name: string;
  provider_type: string;
  scopes: string[];
  connect_supported: boolean;
}

export interface LinkedAccountGrant {
  id: string;
  service_id: string;
  scopes: string[];
  granted_at: string;
  last_used_at?: string;
}

export interface LinkedAccount {
  id: string;
  provider: string;
  provider_user_id: string;
  email?: string;
  display_name?: string;
  scopes: string[];
  expires_at?: string;
  status: string;
  grants: LinkedAccountGrant[];
}

export interface LinkedAccountsResponse {
  accounts: LinkedAccount[];
  available_providers: ProviderDefinition[];
}

export interface GrantLinkedAccountRequest {
  service_id?: string;
  scopes: string[];
}

export interface ProviderTokenRequestDetails {
  state: string;
  provider: string;
  requested_scopes: string[];
  service_id: string;
  service_name: string;
  expires_at: string;
  accounts: LinkedAccount[];
}

export interface CompleteProviderTokenRequestPayload {
  connected_account_id?: string;
}

export interface CompleteProviderTokenRequestResponse {
  redirect_url: string;
}

/**
 * Change password request payload
 */
export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
  /** Required when MFA is enabled. */
  mfa_code?: string;
}

/**
 * Change password response
 */
export interface ChangePasswordResponse {
  message: string;
}

/**
 * Set password request payload (for OAuth users without a password)
 */
export interface SetPasswordRequest {
  new_password: string;
  /** Required when MFA is enabled. */
  mfa_code?: string;
}

/**
 * Set password response
 */
export interface SetPasswordResponse {
  message: string;
}

/**
 * MFA status response
 */
export interface MfaStatusResponse {
  enabled: boolean;
  has_backup_codes: boolean;
}

/**
 * MFA setup response
 */
export interface MfaSetupResponse {
  secret: string;
  qr_code_svg: string;
  qr_code_uri: string;
}

/**
 * MFA verify request
 */
export interface MfaVerifyRequest {
  code: string;
}

export interface MfaSetupRequest {
  /** Required when the account already has a password. */
  current_password?: string;
}

export interface MfaConfirmationRequest {
  /** Current TOTP or backup code. */
  mfa_code: string;
}

/**
 * MFA verify response
 */
export interface MfaVerifyResponse {
  enabled: boolean;
  backup_codes: string[];
  /** Fresh session credentials after the factor change. */
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
}

export interface MfaDisableResponse {
  success: boolean;
  message: string;
  /** Fresh session credentials after the factor change. */
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
}

/**
 * Backup codes response
 */
export interface BackupCodesResponse {
  backup_codes: string[];
}

/**
 * User device information
 */
export interface UserDevice {
  /** Unique device identifier */
  id: string;
  /** Device name/description */
  device_name: string;
  /** When the device was first seen */
  first_seen_at: string;
  /** When the device was last used */
  last_used_at: string;
  /** When the device trust expires */
  expires_at: string;
  /** IP address when device was registered */
  registration_ip?: string;
  /** Risk score for this device */
  risk_score: number;
  /** Whether this device is currently trusted */
  is_trusted: boolean;
}

/**
 * List devices response
 */
export interface ListDevicesResponse {
  /** Array of user devices */
  devices: UserDevice[];
  /** Total number of devices */
  total: number;
  /** Current one-based page */
  page: number;
  /** Applied page size */
  limit: number;
}

/**
 * Revoke device request
 */
export interface RevokeDeviceRequest {
  /** Optional reason for revocation */
  reason?: string;
}

/**
 * Revoke device response
 */
export interface RevokeDeviceResponse {
  /** Success message */
  message: string;
  /** Whether revocation was successful */
  success: boolean;
}
