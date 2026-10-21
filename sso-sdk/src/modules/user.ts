import { HttpClient } from '../http';
import { UserProfile, UpdateUserProfilePayload, Subscription, Identity, StartLinkResponse, ChangePasswordRequest, ChangePasswordResponse, SetPasswordRequest, SetPasswordResponse, MfaStatusResponse, MfaSetupResponse, MfaVerifyResponse, MfaSetupRequest, MfaConfirmationRequest, MfaDisableResponse, BackupCodesResponse, UserDevice, ListDevicesResponse, RevokeDeviceResponse, LinkedAccountsResponse, GrantLinkedAccountRequest, LinkedAccountGrant, ProviderTokenRequestDetails, CompleteProviderTokenRequestPayload, CompleteProviderTokenRequestResponse } from '../types';

/**
 * Identity (social account linking) methods
 */
class IdentitiesModule {
  constructor(private http: HttpClient) {}

  /**
   * List all social accounts linked to the authenticated user.
   *
   * @returns Array of linked identities
   *
   * @example
   * ```typescript
   * const identities = await sso.user.identities.list();
   * console.log(identities); // [{ provider: 'github' }, { provider: 'google' }]
   * ```
   */
  public async list(): Promise<Identity[]> {
    const response = await this.http.get<Identity[]>('/api/user/identities');
    return response.data;
  }

  /**
   * Start linking a new social account to the authenticated user.
   * Returns an authorization URL that the user should be redirected to.
   *
   * @param provider The OAuth provider to link (e.g., 'github', 'google', 'microsoft')
   * @returns Object containing the authorization URL
   *
   * @example
   * ```typescript
   * const { authorization_url } = await sso.user.identities.startLink('github');
   * window.location.href = authorization_url; // Redirect user to complete OAuth
   * ```
   */
  public async startLink(provider: string): Promise<StartLinkResponse> {
    const response = await this.http.post<StartLinkResponse>(`/api/user/identities/${provider}/link`, {});
    return response.data;
  }

  /**
   * Unlink a social account from the authenticated user.
   * Note: Cannot unlink the last remaining identity to prevent account lockout.
   *
   * @param provider The OAuth provider to unlink (e.g., 'github', 'google', 'microsoft')
   *
   * @example
   * ```typescript
   * await sso.user.identities.unlink('google');
   * ```
   */
  public async unlink(provider: string): Promise<void> {
    await this.http.delete(`/api/user/identities/${provider}`);
  }
}

class LinkedAccountsModule {
  constructor(private http: HttpClient) {}

  public async list(): Promise<LinkedAccountsResponse> {
    const response = await this.http.get<LinkedAccountsResponse>('/api/user/linked-accounts');
    return response.data;
  }

  public async startLink(provider: string): Promise<StartLinkResponse> {
    const response = await this.http.post<StartLinkResponse>(`/api/user/linked-accounts/${provider}/link`, {});
    return response.data;
  }

  public async grant(accountId: string, payload: GrantLinkedAccountRequest): Promise<LinkedAccountGrant> {
    const response = await this.http.post<LinkedAccountGrant>(`/api/user/linked-accounts/${accountId}/grants`, payload);
    return response.data;
  }

  public async revokeGrant(accountId: string, serviceId: string): Promise<void> {
    await this.http.delete(`/api/user/linked-accounts/${accountId}/grants/${serviceId}`);
  }

  public async unlink(accountId: string): Promise<void> {
    await this.http.delete(`/api/user/linked-accounts/${accountId}`);
  }

  public async getProviderTokenRequest(state: string): Promise<ProviderTokenRequestDetails> {
    const response = await this.http.get<ProviderTokenRequestDetails>(`/api/user/provider-token-requests/${state}`);
    return response.data;
  }

  public async completeProviderTokenRequest(
    state: string,
    payload: CompleteProviderTokenRequestPayload = {},
  ): Promise<CompleteProviderTokenRequestResponse> {
    const response = await this.http.post<CompleteProviderTokenRequestResponse>(`/api/user/provider-token-requests/${state}/complete`, payload);
    return response.data;
  }

  public async startProviderTokenRequestLink(state: string): Promise<StartLinkResponse> {
    const response = await this.http.post<StartLinkResponse>(`/api/user/provider-token-requests/${state}/link`, {});
    return response.data;
  }
}

/**
 * Multi-Factor Authentication (MFA) methods
 */
class MfaModule {
  constructor(private http: HttpClient) {}

  /**
   * Get the current MFA status for the authenticated user.
   *
   * @returns MFA status
   *
   * @example
   * ```typescript
   * const status = await sso.user.mfa.getStatus();
   * console.log(status.enabled); // false
   * ```
   */
  public async getStatus(): Promise<MfaStatusResponse> {
    const response = await this.http.get<MfaStatusResponse>('/api/user/mfa/status');
    return response.data;
  }

  /**
   * Initiate MFA setup. Generates a TOTP secret and QR code.
   * The user must complete setup by calling verify() with a code from their authenticator app.
   *
   * @returns MFA setup details including QR code
   *
   * @example
   * ```typescript
   * const setup = await sso.user.mfa.setup({
   *   current_password: 'account-password-if-present',
   * });
   * console.log(setup.qr_code_svg); // Display this QR code to the user
   * // User scans QR code with authenticator app and enters code to verify
   * ```
   */
  public async setup(payload: MfaSetupRequest = {}): Promise<MfaSetupResponse> {
    const response = await this.http.post<MfaSetupResponse>('/api/user/mfa/setup', payload);
    return response.data;
  }

  /**
   * Verify TOTP code and enable MFA.
   * Returns backup codes that must be stored securely by the user.
   *
   * @param code TOTP code from authenticator app
   * @returns Verification response with backup codes
   *
   * @example
   * ```typescript
   * const result = await sso.user.mfa.verify('123456');
   * console.log(result.backup_codes); // Store these securely!
   * ```
   */
  public async verify(code: string): Promise<MfaVerifyResponse> {
    const response = await this.http.post<MfaVerifyResponse>('/api/user/mfa/verify', { code });
    return response.data;
  }

  /**
   * Disable MFA for the authenticated user.
   *
   * @example
   * ```typescript
   * await sso.user.mfa.disable({ mfa_code: '123456' });
   * ```
   */
  public async disable(payload: MfaConfirmationRequest): Promise<MfaDisableResponse> {
    const response = await this.http.delete<MfaDisableResponse>('/api/user/mfa', payload);
    return response.data;
  }

  /**
   * Regenerate backup codes.
   * Invalidates all previous backup codes and returns new ones.
   *
   * @returns New backup codes
   *
   * @example
   * ```typescript
   * const { backup_codes } = await sso.user.mfa.regenerateBackupCodes({
   *   mfa_code: '123456',
   * });
   * console.log(backup_codes); // Store these securely!
   * ```
   */
  public async regenerateBackupCodes(payload: MfaConfirmationRequest): Promise<BackupCodesResponse> {
    const response = await this.http.post<BackupCodesResponse>('/api/user/mfa/backup-codes/regenerate', payload);
    return response.data;
  }
}

/**
 * Device management methods
 */
class DevicesModule {
  constructor(private http: HttpClient) {}

  /**
   * List all devices associated with the authenticated user.
   *
   * @param options Optional query parameters for pagination
   * @returns Array of user devices
   *
   * @example
   * ```typescript
   * const { devices, total } = await sso.user.devices.list();
   * console.log(devices); // Array of trusted devices
   * ```
   */
  public async list(options?: {
    page?: number;
    limit?: number;
    sort_by?: 'first_seen_at' | 'last_used_at' | 'device_name';
    sort_order?: 'asc' | 'desc';
  }): Promise<ListDevicesResponse> {
    const params = new URLSearchParams();

    if (options?.page) params.append('page', options.page.toString());
    if (options?.limit) params.append('limit', options.limit.toString());
    if (options?.sort_by) params.append('sort_by', options.sort_by);
    if (options?.sort_order) params.append('sort_order', options.sort_order);

    const query = params.toString();
    const url = `/api/user/devices${query ? `?${query}` : ''}`;

    const response = await this.http.get<ListDevicesResponse>(url);
    return response.data;
  }

  /**
   * Get details for a specific device.
   *
   * @param deviceId The device ID to retrieve
   * @returns Device details
   *
   * @example
   * ```typescript
   * const device = await sso.user.devices.get('device-123');
   * console.log(device.device_name, device.is_trusted);
   * ```
   */
  public async get(deviceId: string): Promise<UserDevice> {
    const response = await this.http.get<UserDevice>(`/api/user/devices/${deviceId}`);
    return response.data;
  }

  /**
   * Revoke access for a specific device.
   * This will remove the device's trust and require re-authentication.
   *
   * @param deviceId The device ID to revoke
   * @param reason Optional reason for revocation
   * @returns Confirmation message
   *
   * @example
   * ```typescript
   * const result = await sso.user.devices.revoke('device-123', 'Device lost');
   * console.log(result.message);
   * ```
   */
  public async revoke(deviceId: string, reason?: string): Promise<RevokeDeviceResponse> {
    const payload = reason ? { reason } : {};
    const response = await this.http.post<RevokeDeviceResponse>(`/api/user/devices/${deviceId}/revoke`, payload);
    return response.data;
  }

  /**
   * Revoke all devices except the current one.
   * This is useful when you suspect account compromise or want to force re-authentication on all devices.
   *
   * @returns Confirmation message
   *
   * @example
   * ```typescript
   * const result = await sso.user.devices.revokeAll();
   * console.log(result.message); // "All other devices have been revoked"
   * ```
   */
  public async revokeAll(): Promise<RevokeDeviceResponse> {
    const response = await this.http.post<RevokeDeviceResponse>('/api/user/devices/revoke-all', {});
    return response.data;
  }

  /**
   * Update the name of a device.
   *
   * @param deviceId The device ID to update
   * @param deviceName New device name
   * @returns Updated device information
   *
   * @example
   * ```typescript
   * const device = await sso.user.devices.updateName('device-123', 'My Laptop');
   * console.log(device.device_name); // "My Laptop"
   * ```
   */
  public async updateName(deviceId: string, deviceName: string): Promise<UserDevice> {
    const response = await this.http.patch<UserDevice>(`/api/user/devices/${deviceId}`, {
      device_name: deviceName
    });
    return response.data;
  }

  /**
   * Mark a device as trusted manually.
   * This is useful for devices that you want to explicitly trust regardless of risk assessment.
   *
   * @param deviceId The device ID to trust
   * @returns Updated device information
   *
   * @example
   * ```typescript
   * const device = await sso.user.devices.trust('device-123');
   * console.log(device.is_trusted); // true
   * ```
   */
  public async trust(deviceId: string): Promise<UserDevice> {
    const response = await this.http.post<UserDevice>(`/api/user/devices/${deviceId}/trust`, {});
    return response.data;
  }
}

/**
 * User profile and subscription methods
 */
export class UserModule {
  public readonly identities: IdentitiesModule;
  public readonly linkedAccounts: LinkedAccountsModule;
  public readonly mfa: MfaModule;
  public readonly devices: DevicesModule;

  constructor(private http: HttpClient) {
    this.identities = new IdentitiesModule(http);
    this.linkedAccounts = new LinkedAccountsModule(http);
    this.mfa = new MfaModule(http);
    this.devices = new DevicesModule(http);
  }

  /**
   * Get the profile of the currently authenticated user.
   * The response includes context from the JWT (org, service).
   *
   * @returns User profile
   *
   * @example
   * ```typescript
   * const profile = await sso.user.getProfile();
   * console.log(profile.email, profile.org, profile.service);
   * ```
   */
  public async getProfile(): Promise<UserProfile> {
    const response = await this.http.get<UserProfile>('/api/user');
    return response.data;
  }

  /**
   * Update the authenticated user's profile.
   *
   * @param payload Update payload
   * @returns Updated user profile
   *
   * @example
   * ```typescript
   * const updated = await sso.user.updateProfile({
   *   email: 'newemail@example.com',
   *   current_password: 'current-password-if-present',
   *   mfa_code: '123456-if-enabled',
   * });
   * ```
   */
  public async updateProfile(payload: UpdateUserProfilePayload): Promise<UserProfile> {
    const response = await this.http.patch<UserProfile>('/api/user', payload);
    return response.data;
  }

  /**
   * Get the current user's subscription details for the service in their JWT.
   *
   * @returns Subscription details
   *
   * @example
   * ```typescript
   * const subscription = await sso.user.getSubscription();
   * console.log(subscription.plan, subscription.features);
   * ```
   */
  public async getSubscription(): Promise<Subscription> {
    const response = await this.http.get<Subscription>('/api/subscription');
    return response.data;
  }

  /**
   * Change the authenticated user's password.
   * Requires the current password for verification.
   *
   * @param payload Change password request (current and new password)
   * @returns Confirmation message
   *
   * @example
   * ```typescript
   * const response = await sso.user.changePassword({
   *   current_password: 'OldPassword123!',
   *   new_password: 'NewSecurePassword456!',
   *   mfa_code: '123456-if-enabled',
   * });
   * console.log(response.message);
   * ```
   */
  public async changePassword(payload: ChangePasswordRequest): Promise<ChangePasswordResponse> {
    const response = await this.http.post<ChangePasswordResponse>('/api/user/change-password', payload);
    return response.data;
  }

  /**
   * Set a password for the authenticated user (OAuth users only).
   * This endpoint is for OAuth users who don't have a password yet.
   * If a password is already set, this will return an error.
   *
   * @param payload Set password request (new password only)
   * @returns Confirmation message
   *
   * @example
   * ```typescript
   * const response = await sso.user.setPassword({
   *   new_password: 'MyNewSecurePassword123!',
   *   mfa_code: '123456-if-enabled',
   * });
   * console.log(response.message); // "Password set successfully"
   * ```
   */
  public async setPassword(payload: SetPasswordRequest): Promise<SetPasswordResponse> {
    const response = await this.http.post<SetPasswordResponse>('/api/user/set-password', payload);
    return response.data;
  }
}
