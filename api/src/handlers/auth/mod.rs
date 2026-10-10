pub mod device;
pub(crate) mod email_delivery;
pub mod enterprise;
pub mod hrd;
pub mod magic;
pub mod mfa;
pub mod oauth;
pub mod passkeys;
pub mod password;
pub mod session;
pub mod upstream_saml;

// Re-export all public handlers from sub-modules

// OAuth handlers
pub use oauth::{
    auth_admin_callback, auth_admin_provider, auth_callback, auth_provider, auth_saml_callback,
    get_authorization_url_for_client,
};
pub(crate) use oauth::{is_supported_upstream_oauth_type, resolve_upstream_oidc_config};

// Device flow handlers
pub use device::{device_code, device_verify, token_exchange};

// Enterprise-managed authorization token endpoint
pub use enterprise::enterprise_token;

// Session handlers
pub use session::{logout, refresh_token, revoke_token};

// Password authentication handlers
pub use password::{
    availability, forgot_password, login, register, resend_verification, reset_password,
    verify_email,
};

// MFA handlers
pub use mfa::{verify_mfa_login, verify_saml_mfa};

// HRD handlers
pub use hrd::{get_auth_context, lookup_email};

// Passkey handlers
pub use passkeys::{
    authenticate_finish, authenticate_start, delete_passkey, list_passkeys, register_finish,
    register_start, update_passkey_name,
};

// Magic link handlers
pub use magic::{request_magic_link, verify_magic_link};
