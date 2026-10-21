use crate::error::{AppError, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MANAGEMENT_ACCESS_TYP: &str = "authos-management+jwt";
const EXTERNAL_RESOURCE_ACCESS_TYP: &str = "at+jwt";
const MFA_PREAUTH_TYP: &str = "authos-mfa-preauth+jwt";
const IMPERSONATION_TYP: &str = "authos-impersonation+jwt";
const ID_JAG_TYP: &str = "oauth-id-jag+jwt";
pub const PREVIOUS_PUBLIC_KEYS_ENV: &str = "JWT_PREVIOUS_PUBLIC_KEYS_JSON";
const MAX_PREVIOUS_PUBLIC_KEYS: usize = 10;

/// The intended security context for an AuthOS-signed JWT.
///
/// This signed claim is deliberately redundant with the JOSE `typ` header.
/// Validators require both values so a token minted for one flow cannot be
/// accepted by another merely because its issuer, audience, and key are valid.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TokenUse {
    ManagementAccess,
    ExternalResourceAccess,
    MfaPreauth,
    Impersonation,
    IdJag,
}

impl TokenUse {
    fn jose_type(self) -> &'static str {
        match self {
            Self::ManagementAccess => MANAGEMENT_ACCESS_TYP,
            Self::ExternalResourceAccess => EXTERNAL_RESOURCE_ACCESS_TYP,
            Self::MfaPreauth => MFA_PREAUTH_TYP,
            Self::Impersonation => IMPERSONATION_TYP,
            Self::IdJag => ID_JAG_TYP,
        }
    }
}

/// Actor claim for impersonation (RFC 8693)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Actor {
    pub sub: String,   // admin user_id who is performing the impersonation
    pub email: String, // admin email
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>, // reason for impersonation
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub token_use: TokenUse,
    pub sub: String,             // user_id (required) - the user being impersonated
    pub email: String,           // user email (required) - the user being impersonated
    pub is_platform_owner: bool, // platform owner flag (required)
    pub jti: String,             // JWT ID - unique identifier for this token (required)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>, // org_slug (optional, for service-specific JWTs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>, // service_slug (optional)

    // REMOVED: plan, features, permissions - these are now fetched from cache
    // This reduces token size from 5-10KB to ~300-500 bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_required: Option<bool>, // MFA challenge required (pre-auth token)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_verified: Option<bool>, // MFA has been verified in this session
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saml_state: Option<String>, // SAML state ID for SAML authentication flows
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_code_id: Option<String>, // Bound device authorization context for MFA
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>, // Actor claim for impersonation (RFC 8693)
    /// Marks the one-time platform-bootstrap session that may perform initial
    /// provisioning before an owner has enrolled MFA. Never set on tenant or
    /// service tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>, // Audience - used for impersonation sessions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>, // Issuer - AuthOS API base URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>, // OAuth scope string for resource-scoped access tokens
    pub exp: i64, // expiration timestamp
    pub iat: i64, // issued at timestamp
}

impl Claims {
    /// Platform authority is only valid for a token minted without tenant or
    /// service context. The signed audience makes this explicit as well.
    pub fn is_platform_context(&self) -> bool {
        self.act.is_none()
            && self.org.is_none()
            && self.service.is_none()
            && self.aud.as_deref() == Some("platform")
    }

    /// Service-login tokens are user tokens delivered to a relying party. They
    /// must not be treated as platform or organization-management authority.
    pub fn is_service_context(&self) -> bool {
        self.service.is_some()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdJagClaims {
    pub token_use: TokenUse,
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub resource: String,
    pub client_id: String,
    pub jti: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_keys: BTreeMap<String, DecodingKey>,
    public_key_pems: BTreeMap<String, Vec<u8>>,
    expiration_hours: i64,
    key_id: String,
    issuer: String,
}

impl JwtService {
    pub fn new(
        private_key_base64: &str,
        public_key_base64: &str,
        expiration_hours: i64,
        key_id: &str,
        issuer: &str,
    ) -> Result<Self> {
        Self::new_with_previous_keys(
            private_key_base64,
            public_key_base64,
            expiration_hours,
            key_id,
            issuer,
            &BTreeMap::new(),
        )
    }

    pub fn new_with_previous_keys(
        private_key_base64: &str,
        public_key_base64: &str,
        expiration_hours: i64,
        key_id: &str,
        issuer: &str,
        previous_public_keys: &BTreeMap<String, String>,
    ) -> Result<Self> {
        let key_id = key_id.trim();
        if key_id.is_empty() {
            return Err(AppError::InternalServerError(
                "JWT_KID cannot be empty".to_string(),
            ));
        }
        if previous_public_keys.len() > MAX_PREVIOUS_PUBLIC_KEYS {
            return Err(AppError::InternalServerError(format!(
                "At most {MAX_PREVIOUS_PUBLIC_KEYS} previous JWT public keys may be configured"
            )));
        }
        if previous_public_keys.contains_key(key_id) {
            return Err(AppError::InternalServerError(
                "The active JWT kid must not also appear in the previous-key ring".to_string(),
            ));
        }

        let private_key_pem = STANDARD.decode(private_key_base64).map_err(|e| {
            AppError::InternalServerError(format!("Failed to decode private key: {}", e))
        })?;
        let public_key_pem = STANDARD.decode(public_key_base64).map_err(|e| {
            AppError::InternalServerError(format!("Failed to decode public key: {}", e))
        })?;

        let encoding_key = EncodingKey::from_rsa_pem(&private_key_pem).map_err(|e| {
            AppError::InternalServerError(format!("Failed to create encoding key: {}", e))
        })?;
        let active_decoding_key = DecodingKey::from_rsa_pem(&public_key_pem).map_err(|e| {
            AppError::InternalServerError(format!("Failed to create decoding key: {}", e))
        })?;

        let mut decoding_keys = BTreeMap::new();
        decoding_keys.insert(key_id.to_string(), active_decoding_key);
        let mut public_key_pems = BTreeMap::new();
        public_key_pems.insert(key_id.to_string(), public_key_pem);

        for (previous_kid, previous_public_key_base64) in previous_public_keys {
            let previous_kid = previous_kid.trim();
            if previous_kid.is_empty() {
                return Err(AppError::InternalServerError(
                    "Previous JWT key identifiers cannot be empty".to_string(),
                ));
            }
            if decoding_keys.contains_key(previous_kid) {
                return Err(AppError::InternalServerError(format!(
                    "JWT key identifier is configured more than once ({previous_kid})"
                )));
            }
            let previous_public_key_pem =
                STANDARD.decode(previous_public_key_base64).map_err(|_| {
                    AppError::InternalServerError(format!(
                        "Failed to decode previous JWT public key for kid {previous_kid}"
                    ))
                })?;
            if public_key_pems
                .values()
                .any(|configured| configured == &previous_public_key_pem)
            {
                return Err(AppError::InternalServerError(format!(
                    "JWT public key material is assigned to more than one kid ({previous_kid})"
                )));
            }
            let decoding_key =
                DecodingKey::from_rsa_pem(&previous_public_key_pem).map_err(|_| {
                    AppError::InternalServerError(format!(
                        "Failed to create previous JWT decoding key for kid {previous_kid}"
                    ))
                })?;
            decoding_keys.insert(previous_kid.to_string(), decoding_key);
            public_key_pems.insert(previous_kid.to_string(), previous_public_key_pem);
        }

        Ok(Self {
            encoding_key,
            decoding_keys,
            public_key_pems,
            expiration_hours,
            key_id: key_id.to_string(),
            issuer: issuer.trim_end_matches('/').to_string(),
        })
    }

    pub fn parse_previous_public_keys_json(
        value: Option<&str>,
    ) -> Result<BTreeMap<String, String>> {
        let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
            return Ok(BTreeMap::new());
        };
        let keys: BTreeMap<String, String> = serde_json::from_str(value).map_err(|_| {
            AppError::InternalServerError(format!(
                "{PREVIOUS_PUBLIC_KEYS_ENV} must be a JSON object mapping kid to base64 public key"
            ))
        })?;
        if keys.len() > MAX_PREVIOUS_PUBLIC_KEYS {
            return Err(AppError::InternalServerError(format!(
                "At most {MAX_PREVIOUS_PUBLIC_KEYS} previous JWT public keys may be configured"
            )));
        }
        Ok(keys)
    }

    /// Return the active verification key first, followed by previous keys in
    /// stable kid order. Only the active key is ever used for issuance.
    pub fn verification_public_keys(&self) -> Vec<(&str, &[u8])> {
        let active = self
            .public_key_pems
            .get(&self.key_id)
            .expect("active JWT public key must be retained");
        let mut keys = vec![(self.key_id.as_str(), active.as_slice())];
        keys.extend(
            self.public_key_pems
                .iter()
                .filter(|(kid, _)| kid.as_str() != self.key_id)
                .map(|(kid, pem)| (kid.as_str(), pem.as_slice())),
        );
        keys
    }

    pub(crate) fn audience_for(
        org_slug: Option<&str>,
        service_slug: Option<&str>,
    ) -> Option<String> {
        match (org_slug, service_slug) {
            (Some(org), Some(service)) => Some(format!("service:{}/{}", org, service)),
            (Some(org), None) => Some(format!("org:{}", org)),
            (None, Some(service)) => Some(format!("service:{}", service)),
            (None, None) => Some("platform".to_string()),
        }
    }

    pub fn create_token(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
    ) -> Result<String> {
        self.create_token_with_resource(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            None,
        )
    }

    pub fn create_token_with_resource(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        resource: Option<&str>,
    ) -> Result<String> {
        self.create_token_with_resource_and_scope(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            resource,
            None,
        )
    }

    /// Mint a management token after the current request proved the account's
    /// second factor. The signed marker lets platform routes distinguish an
    /// MFA-completed login from a passkey-only session that merely has MFA
    /// enrolled on the account.
    pub fn create_mfa_verified_token(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
    ) -> Result<String> {
        self.create_management_token_inner(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            None,
            None,
            false,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_mfa_verified_token_with_resource(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        resource: Option<&str>,
    ) -> Result<String> {
        self.create_management_token_inner(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            resource,
            None,
            false,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_token_with_resource_and_scope(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        resource: Option<&str>,
        scope: Option<&str>,
    ) -> Result<String> {
        self.create_management_token_inner(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            resource,
            scope,
            false,
            false,
        )
    }

    /// Mint the one-time bootstrap management session. It carries a signed
    /// marker so the platform route boundary can permit initial provisioning
    /// before the owner has enrolled MFA. The marker is never valid on tenant
    /// or service tokens, and enabling MFA revokes this session.
    pub fn create_bootstrap_management_token(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
    ) -> Result<String> {
        self.create_management_token_inner(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            None,
            None,
            true,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_management_token_inner(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        resource: Option<&str>,
        scope: Option<&str>,
        bootstrap_requested: bool,
        mfa_verified: bool,
    ) -> Result<String> {
        use uuid::Uuid;

        if let Some(resource) = resource {
            crate::utils::resource_indicators::validate_resource_uri(resource)?;
            if org_slug.is_none() || service_slug.is_none() {
                return Err(AppError::BadRequest(
                    "External resource tokens require organization and service context".to_string(),
                ));
            }
        }

        let now = Utc::now();
        let exp = now + Duration::hours(self.expiration_hours);
        let aud = resource
            .map(std::string::ToString::to_string)
            .or_else(|| Self::audience_for(org_slug, service_slug));
        let token_use = if resource.is_some() {
            TokenUse::ExternalResourceAccess
        } else {
            TokenUse::ManagementAccess
        };
        let platform_context = org_slug.is_none() && service_slug.is_none() && resource.is_none();
        // Never advertise platform authority in a tenant- or service-scoped
        // token. Platform routes also verify the signed context, but dropping
        // the claim prevents relying parties from misinterpreting the token.
        let is_platform_owner = is_platform_owner && platform_context;
        let bootstrap = (bootstrap_requested && platform_context).then_some(true);

        let claims = Claims {
            token_use,
            sub: user_id.to_string(),
            email: email.to_string(),
            is_platform_owner,
            jti: Uuid::new_v4().to_string(),
            org: org_slug.map(std::string::ToString::to_string),
            service: service_slug.map(std::string::ToString::to_string),
            // Removed: plan, features, permissions - fetched from cache
            mfa_required: None,
            mfa_verified: mfa_verified.then_some(true),
            saml_state: None,
            device_code_id: None,
            act: None,
            bootstrap,
            aud,
            iss: Some(self.issuer.clone()),
            scope: scope.map(std::string::ToString::to_string),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());
        header.typ = Some(token_use.jose_type().to_string());

        encode(&header, &claims, &self.encoding_key).map_err(AppError::Jwt)
    }

    /// Create a pre-authentication token for MFA challenges
    /// This token is short-lived (5 minutes) and requires MFA verification
    pub fn create_mfa_preauth_token(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        saml_state: Option<&str>,
    ) -> Result<String> {
        self.create_mfa_preauth_token_with_resource(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            saml_state,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_mfa_preauth_token_with_resource(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        saml_state: Option<&str>,
        resource: Option<&str>,
    ) -> Result<String> {
        self.create_mfa_preauth_token_with_context(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            saml_state,
            resource,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_mfa_preauth_token_for_device(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        device_code_id: &str,
    ) -> Result<String> {
        self.create_mfa_preauth_token_for_device_with_resource(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            None,
            device_code_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_mfa_preauth_token_for_device_with_resource(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        resource: Option<&str>,
        device_code_id: &str,
    ) -> Result<String> {
        if device_code_id.is_empty() {
            return Err(AppError::BadRequest(
                "Device authorization context is invalid".to_string(),
            ));
        }
        self.create_mfa_preauth_token_with_context(
            user_id,
            email,
            is_platform_owner,
            org_slug,
            service_slug,
            None,
            resource,
            Some(device_code_id),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_mfa_preauth_token_with_context(
        &self,
        user_id: &str,
        email: &str,
        is_platform_owner: bool,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        saml_state: Option<&str>,
        resource: Option<&str>,
        device_code_id: Option<&str>,
    ) -> Result<String> {
        use uuid::Uuid;

        if let Some(resource) = resource {
            crate::utils::resource_indicators::validate_resource_uri(resource)?;
            if org_slug.is_none() || service_slug.is_none() {
                return Err(AppError::BadRequest(
                    "External resource MFA requires organization and service context".to_string(),
                ));
            }
        }

        let now = Utc::now();
        let exp = now + Duration::minutes(5);
        let aud = resource
            .map(std::string::ToString::to_string)
            .or_else(|| Self::audience_for(org_slug, service_slug));
        let is_platform_owner =
            is_platform_owner && org_slug.is_none() && service_slug.is_none() && resource.is_none();

        let claims = Claims {
            token_use: TokenUse::MfaPreauth,
            sub: user_id.to_string(),
            email: email.to_string(),
            is_platform_owner,
            jti: Uuid::new_v4().to_string(),
            org: org_slug.map(std::string::ToString::to_string),
            service: service_slug.map(std::string::ToString::to_string),
            mfa_required: Some(true),
            mfa_verified: Some(false),
            saml_state: saml_state.map(std::string::ToString::to_string),
            device_code_id: device_code_id.map(str::to_string),
            act: None,
            bootstrap: None,
            aud,
            iss: Some(self.issuer.clone()),
            scope: None,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());
        header.typ = Some(MFA_PREAUTH_TYP.to_string());

        encode(&header, &claims, &self.encoding_key).map_err(AppError::Jwt)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        self.validate_management_token(token)
    }

    /// Validate an ordinary AuthOS management-session access token.
    pub fn validate_management_token(&self, token: &str) -> Result<Claims> {
        self.validate_claims_profile(token, TokenUse::ManagementAccess, None)
    }

    /// Validate a token presented to AuthOS's own authenticated API.
    ///
    /// Resource-scoped access tokens are deliberately rejected here: a token
    /// minted for an external resource server must not be usable as a
    /// management-session token at AuthOS itself.
    pub fn validate_authos_token(&self, token: &str) -> Result<Claims> {
        let header = decode_header(token).map_err(AppError::Jwt)?;
        match header.typ.as_deref() {
            Some(MANAGEMENT_ACCESS_TYP) => self.validate_management_token(token),
            Some(IMPERSONATION_TYP) => self.validate_impersonation_token(token),
            _ => Err(AppError::Unauthorized(
                "Token profile is not valid for the AuthOS API".to_string(),
            )),
        }
    }

    /// Validate an access token for one specific resource audience.
    pub fn validate_token_for_audience(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<Claims> {
        self.validate_claims_profile(
            token,
            TokenUse::ExternalResourceAccess,
            Some(expected_audience),
        )
    }

    /// Validate the short-lived token accepted only by the MFA completion flow.
    pub fn validate_mfa_preauth_token(&self, token: &str) -> Result<Claims> {
        self.validate_claims_profile(token, TokenUse::MfaPreauth, None)
    }

    /// Validate an impersonation session and require its actor and audience.
    pub fn validate_impersonation_token(&self, token: &str) -> Result<Claims> {
        self.validate_claims_profile(
            token,
            TokenUse::Impersonation,
            Some("impersonation-session"),
        )
    }

    fn validate_claims_profile(
        &self,
        token: &str,
        expected_token_use: TokenUse,
        expected_audience: Option<&str>,
    ) -> Result<Claims> {
        let decoding_key = self.validation_key(token, expected_token_use.jose_type())?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[self.issuer.as_str()]);
        if let Some(audience) = expected_audience {
            validation.set_audience(&[audience]);
        } else {
            // Management and MFA audiences depend on signed tenant/flow
            // context and are checked by `validate_profile_invariants` below.
            validation.validate_aud = false;
        }

        let token_data =
            decode::<Claims>(token, decoding_key, &validation).map_err(AppError::Jwt)?;

        let claims = token_data.claims;
        if claims.token_use != expected_token_use {
            return Err(AppError::Unauthorized(
                "JWT token_use does not match the expected token profile".to_string(),
            ));
        }
        self.validate_profile_invariants(&claims, expected_token_use)?;

        Ok(claims)
    }

    fn validation_key(&self, token: &str, expected_type: &str) -> Result<&DecodingKey> {
        let header = decode_header(token).map_err(AppError::Jwt)?;
        if header.alg != Algorithm::RS256 {
            return Err(AppError::Unauthorized(
                "JWT algorithm is not valid for this token profile".to_string(),
            ));
        }
        if header.typ.as_deref() != Some(expected_type) {
            return Err(AppError::Unauthorized(
                "JWT type does not match the expected token profile".to_string(),
            ));
        }
        let key_id = header.kid.as_deref().ok_or_else(|| {
            AppError::Unauthorized("JWT key identifier is not recognized".to_string())
        })?;
        self.decoding_keys.get(key_id).ok_or_else(|| {
            AppError::Unauthorized("JWT key identifier is not recognized".to_string())
        })
    }

    fn validate_profile_invariants(&self, claims: &Claims, token_use: TokenUse) -> Result<()> {
        let valid = match token_use {
            TokenUse::ManagementAccess => {
                let bootstrap_valid = claims.bootstrap.is_none()
                    || (claims.bootstrap == Some(true)
                        && claims.org.is_none()
                        && claims.service.is_none()
                        && claims.aud.as_deref() == Some("platform"));
                claims.act.is_none()
                    && claims.device_code_id.is_none()
                    && claims.mfa_required.is_none()
                    && matches!(claims.mfa_verified, None | Some(true))
                    && claims.scope.is_none()
                    && bootstrap_valid
                    && claims.aud
                        == Self::audience_for(claims.org.as_deref(), claims.service.as_deref())
            }
            TokenUse::ExternalResourceAccess => {
                claims.act.is_none()
                    && claims.bootstrap.is_none()
                    && claims.device_code_id.is_none()
                    && claims.mfa_required.is_none()
                    && matches!(claims.mfa_verified, None | Some(true))
            }
            TokenUse::MfaPreauth => {
                let expected_management_audience =
                    Self::audience_for(claims.org.as_deref(), claims.service.as_deref());
                let is_management_audience = claims.aud == expected_management_audience;
                let is_resource_audience =
                    crate::utils::resource_indicators::resource_from_audience(
                        claims.aud.as_deref(),
                    )
                    .is_some();
                claims.act.is_none()
                    && claims.bootstrap.is_none()
                    && claims.mfa_required == Some(true)
                    && claims.mfa_verified == Some(false)
                    && claims.scope.is_none()
                    && (is_management_audience || is_resource_audience)
            }
            TokenUse::Impersonation => {
                claims.act.is_some()
                    && claims.bootstrap.is_none()
                    && claims.device_code_id.is_none()
                    && claims.mfa_required.is_none()
                    && claims.mfa_verified.is_none()
                    && claims.scope.is_none()
                    && claims.aud.as_deref() == Some("impersonation-session")
            }
            TokenUse::IdJag => false,
        };

        if !valid {
            return Err(AppError::Unauthorized(
                "JWT claims do not match the expected token profile".to_string(),
            ));
        }
        Ok(())
    }

    /// Create an impersonation token (RFC 8693)
    /// This allows an admin to impersonate another user
    #[allow(clippy::too_many_arguments)]
    pub fn create_impersonation_token(
        &self,
        target_user_id: &str,       // user being impersonated
        target_user_email: &str,    // email of user being impersonated
        admin_user_id: &str,        // admin performing impersonation
        admin_user_email: &str,     // email of admin
        reason: Option<&str>,       // reason for impersonation
        org_slug: Option<&str>,     // organization context
        service_slug: Option<&str>, // service context
        is_target_platform_owner: bool,
    ) -> Result<String> {
        use uuid::Uuid;

        let now = Utc::now();
        // Impersonation tokens have shorter TTL (15 minutes)
        let exp = now + Duration::minutes(15);
        let is_platform_owner =
            is_target_platform_owner && org_slug.is_none() && service_slug.is_none();

        let claims = Claims {
            token_use: TokenUse::Impersonation,
            sub: target_user_id.to_string(),
            email: target_user_email.to_string(),
            is_platform_owner,
            jti: Uuid::new_v4().to_string(),
            org: org_slug.map(std::string::ToString::to_string),
            service: service_slug.map(std::string::ToString::to_string),
            mfa_required: None,
            mfa_verified: None,
            saml_state: None,
            device_code_id: None,
            act: Some(Actor {
                sub: admin_user_id.to_string(),
                email: admin_user_email.to_string(),
                reason: reason.map(std::string::ToString::to_string),
            }),
            bootstrap: None,
            aud: Some("impersonation-session".to_string()),
            iss: Some(self.issuer.clone()),
            scope: None,
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());
        header.typ = Some(IMPERSONATION_TYP.to_string());

        encode(&header, &claims, &self.encoding_key).map_err(AppError::Jwt)
    }

    /// Check if a token is an impersonation token
    pub fn is_impersonation_token(&self, token: &str) -> Result<bool> {
        let header = decode_header(token).map_err(AppError::Jwt)?;
        if header.typ.as_deref() != Some(IMPERSONATION_TYP) {
            return Ok(false);
        }
        self.validate_impersonation_token(token).map(|_| true)
    }

    /// Extract impersonation context from a token
    pub fn extract_impersonation_context(&self, token: &str) -> Result<Option<(Actor, Claims)>> {
        let header = decode_header(token).map_err(AppError::Jwt)?;
        if header.typ.as_deref() != Some(IMPERSONATION_TYP) {
            return Ok(None);
        }

        let mut claims = self.validate_impersonation_token(token)?;

        if let Some(actor) = claims.act.take() {
            return Ok(Some((actor, claims)));
        }

        Err(AppError::Unauthorized(
            "Impersonation token is missing its actor".to_string(),
        ))
    }

    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn create_id_jag(
        &self,
        subject: &str,
        email: Option<&str>,
        audience: &str,
        resource: &str,
        client_id: &str,
        scope: Option<&str>,
    ) -> Result<String> {
        use uuid::Uuid;

        let now = Utc::now();
        let exp = now + Duration::minutes(5);
        let claims = IdJagClaims {
            token_use: TokenUse::IdJag,
            iss: self.issuer.clone(),
            sub: subject.to_string(),
            aud: audience.trim_end_matches('/').to_string(),
            resource: resource.to_string(),
            client_id: client_id.to_string(),
            jti: Uuid::new_v4().to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            scope: scope.map(std::string::ToString::to_string),
            email: email.map(std::string::ToString::to_string),
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());
        header.typ = Some(ID_JAG_TYP.to_string());

        encode(&header, &claims, &self.encoding_key).map_err(AppError::Jwt)
    }

    pub fn validate_id_jag(&self, token: &str, expected_audience: &str) -> Result<IdJagClaims> {
        let decoding_key = self.validation_key(token, ID_JAG_TYP)?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[expected_audience.trim_end_matches('/')]);

        let token_data =
            decode::<IdJagClaims>(token, decoding_key, &validation).map_err(AppError::Jwt)?;

        let claims = token_data.claims;
        if claims.token_use != TokenUse::IdJag {
            return Err(AppError::Unauthorized(
                "JWT authorization grant token_use is invalid".to_string(),
            ));
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_creation_and_validation() {
        let private_key = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQ0dlSHhCSHJkRE9wR3cKLzNOcGhkK2JhRTNEaGNac3F3cE83Tm0rZUxsMGNkWERINUc2eXBURW1oS25LLzYrRmM4UE95SnB1R0ZORll5NAoyUUd4VVBiekJyeTZ3ay80TWMwV09mNXlKOFh6djlLRGcyM0pObk1OLys1cExLT0UzTS9BbSs2aVpYd1ZUMGJ0ClR4aU9nNlppajlLS3hZck9ZSitqWEE3aE1xWHFwc1h5b2t4d3pKLzM3eG96QktpRnVycGtad2tGZzQ0cldHSTYKalovN0pxRWszSHM0djdUcGZiWUovWnRzcndhYnduMWdzZDA4enpLVXNQTURGelpuWTJwTGorUG5tNWJTd1ZuTgpWSDRxTjBMNWtYUWxQMVZmQ1VhTTV1YnVxenE0c3FPeVJ0aTFRYTI0dG1qMS9jeXJKRno2OFhtT1RyZm1Cbmc3CmZMa0IzdHM3QWdNQkFBRUNnZ0VBRCtLMlJHMGxWNUd1T2h1R0hna0hndnVkOVlOZFpHTmZzRFk3MGt3VWEwU3kKd2o1OXFwN3ZBZVlmczZtM1g1WlhvK1FucXhkSFFMZDkxeTBsRFl1cE9NbVZkeUg5d2k0dW5ROFVna0RmbWtMbQowc3d1ZStSQ1VGSSttYzhyc1hEeWhyMnZ3Y3M5RHVRUzFzc095c1hwQnpZWURjdkxjTzVVNkQ2M3IvUHZTaS9tCkFTM051VlMycWNYOFd1RGt0Q3hKRFRxQjREa2ZWRnpoUFV2NWJmaThHWVUwZ2Z3TmZMYUpHdmcyUTdSQzl6eC8KejBncVNZTnZaMllWem8zY3Jvckh2S2F1M0RhcVZpRG1sVTBubEtncFJxbXZCNG9IeHRYcVgxNnY0OEs4WGwxRAo5V3lFNUZYanJEUWhPZWNWazJ6NDJDdWp1TjZlVlppeUk5blpBV2JBM1FLQmdRQzV6eVZCMHE0bkNrNm9pWitSCnNkWkkvb3k1ajY3VkJ0T0ZhNUpzS092UGtYMjlQclA1ZlN0dXFNNklDUFNmMWVwTmI5REZrN2gwVENqbmhuRHEKYWpJeDZUMk5GWWJMTEo0L05iS0RnNDI3UHdzTzcrbFAxM0l1eDdvUi94R2RpZFExcUwzdVdVSlB5cFZKM2xXTgpPWkk2U1Z2dU4wY0wzNnFaUkdhREExWGFSd0tCZ1FDNVJKbGF1emx5MndpTUNxVFRlSUV6TGNibHV3eHFROVN1CkFQUDFoWkVxMVdMOERvbitqZUIyTkxwRTNUWG9QRzRncVNxSTFxS05vSTE0ekNVWjlyMTkvcjg2eEkvaGZ1UXYKRkxJZjQ2TnJ0MzdMZnNNTGxGL3dIQWxrc05JYU9TQTFkZ3ZORC80Rm9BNkwzeldYNGdyTFZjQVIvK2c4ZmlIKwpJTWNJelVJOWJRS0JnRGhWQ2VtYjB2cTVFRUhlZjRjdlVGVU8vMkVlbzVXb0hTYTlCMFpOWGJpdlZseXlqdVBiCncvZ25xMzNvb1NsNE5ESEg3WmFKQTRvV3NPd0lnV0ZBVXZsNHloVms2bG5jckJsajBUdzMvUmRBdEx5UmxiMkUKQnZVUnptSzRYd0hSRUlvNEgyVU1vS01LT3hxTEVvcmZZbXJUWk5DaTU2STg3RDdOVXZyelh1cnZBb0dBVk5tZApIcGZHdk5xaDlIbGZlZGFqM1l1bW4wcG1hamk4ckNDVm1xbmNqWENEVUF0Y21lL2lrR0NmdXJCUll4WmlIYVU4CmJNVllWMkxqeUNJL0Q4QVlreDdiK0E5VUVpTnFZRUdyUHIyajk4NW5UTTIyaUpRZ3lEZ2UrVFdlVkJJN3RTQm0KVVRsMHpxQzZhTWNHcFpRSis0dy9WajhNM3IrcDA5aXhMMC9LZVpVQ2dZRUFnTGQyeEJROE1Cam9POG44ci8ycgptTTl3cWpzTXpqa1JzN3l1Vi9tMEZEOXFEemI2aGlMMmpGZHBpeXh6Yzg4NzNmdmVkaGxZSGg0T2svN0JpdDk3CjV3Wjh0TVFaZ3BCUzBZMkZ5dGE3cnZzeXNQclhKRmk5bXZSSnNsWk9DZmtjaXdLYU03S1BXM2c1cktsWk1JV08KSzFGeXBzOXpRS1ZvSkRWdkJlQ3BaV289Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K";
        let public_key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFobmg4UVI2M1F6cVJzUDl6YVlYZgptMmhOdzRYR2JLc0tUdXpadm5pNWRISFZ3eCtSdXNxVXhKb1NweXYrdmhYUER6c2lhYmhoVFJXTXVOa0JzVkQyCjh3YTh1c0pQK0RITkZqbitjaWZGODcvU2c0TnR5VFp6RGYvdWFTeWpoTnpQd0p2dW9tVjhGVTlHN1U4WWpvT20KWW8vU2lzV0t6bUNmbzF3TzRUS2w2cWJGOHFKTWNNeWY5KzhhTXdTb2hicTZaR2NKQllPT0sxaGlPbzJmK3lhaApKTng3T0wrMDZYMjJDZjJiYks4R204SjlZTEhkUE04eWxMRHpBeGMyWjJOcVM0L2o1NXVXMHNGWnpWUitLamRDCitaRjBKVDlWWHdsR2pPYm03cXM2dUxLanNrYll0VUd0dUxabzlmM01xeVJjK3ZGNWprNjM1Z1o0TzN5NUFkN2IKT3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
        let jwt_service = JwtService::new(
            private_key,
            public_key,
            24,
            "test-key-id",
            "https://auth.example.com",
        )
        .unwrap();

        let token = jwt_service
            .create_token(
                "user_123",
                "user@example.com",
                false,
                Some("acme-corp"),
                Some("analytics"),
            )
            .unwrap();

        let claims = jwt_service.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "user_123");
        assert_eq!(claims.email, "user@example.com");
        assert!(!claims.is_platform_owner);
        assert_eq!(claims.org, Some("acme-corp".to_string()));
        assert_eq!(claims.service, Some("analytics".to_string()));
        assert_eq!(claims.iss, Some("https://auth.example.com".to_string()));
        assert_eq!(claims.aud, Some("service:acme-corp/analytics".to_string()));

        let other_issuer = JwtService::new(
            private_key,
            public_key,
            24,
            "test-key-id",
            "https://other-issuer.example.com",
        )
        .unwrap();
        let wrong_issuer_token = other_issuer
            .create_token("user_123", "user@example.com", false, None, None)
            .unwrap();
        assert!(matches!(
            jwt_service.validate_token(&wrong_issuer_token),
            Err(AppError::Jwt(error))
                if matches!(error.kind(), jsonwebtoken::errors::ErrorKind::InvalidIssuer)
        ));

        let mut missing_audience_claims = claims;
        missing_audience_claims.aud = None;
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-id".to_string());
        header.typ = Some(MANAGEMENT_ACCESS_TYP.to_string());
        let missing_audience_token =
            encode(&header, &missing_audience_claims, &jwt_service.encoding_key).unwrap();
        assert!(matches!(
            jwt_service.validate_token(&missing_audience_token),
            Err(AppError::Jwt(error))
                if matches!(
                    error.kind(),
                    jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claim)
                        if claim == "aud"
                )
        ));

        assert!(jwt_service.validate_authos_token(&token).is_ok());

        let impersonation_token = jwt_service
            .create_impersonation_token(
                "target-user",
                "target@example.com",
                "admin-user",
                "admin@example.com",
                Some("support request"),
                Some("acme-corp"),
                Some("analytics"),
                false,
            )
            .unwrap();
        assert!(jwt_service
            .validate_authos_token(&impersonation_token)
            .is_ok());
    }

    #[test]
    fn platform_authority_is_only_claimed_in_platform_context() {
        let service = generated_test_service();
        let platform = service
            .create_token("user", "user@example.com", true, None, None)
            .expect("platform token");
        let platform_claims = service.validate_management_token(&platform).unwrap();
        assert!(platform_claims.is_platform_context());
        assert!(platform_claims.is_platform_owner);

        for (org, svc) in [
            (Some("acme"), None),
            (Some("acme"), Some("portal")),
            (None, Some("portal")),
        ] {
            let token = service
                .create_token("user", "user@example.com", true, org, svc)
                .expect("tenant token");
            let claims = service.validate_management_token(&token).unwrap();
            assert!(!claims.is_platform_context(), "{org:?}/{svc:?}");
            assert!(!claims.is_platform_owner, "{org:?}/{svc:?}");
        }
    }

    #[test]
    fn mfa_verified_marker_is_only_set_by_the_mfa_completion_flow() {
        let service = generated_test_service();
        let ordinary = service
            .create_token("user", "user@example.com", true, None, None)
            .expect("ordinary token");
        let ordinary_claims = service.validate_management_token(&ordinary).unwrap();
        assert_eq!(ordinary_claims.mfa_verified, None);

        let verified = service
            .create_mfa_verified_token("user", "user@example.com", true, None, None)
            .expect("mfa-verified token");
        let verified_claims = service.validate_management_token(&verified).unwrap();
        assert_eq!(verified_claims.mfa_verified, Some(true));
        assert!(verified_claims.is_platform_context());
        assert!(verified_claims.is_platform_owner);

        let resource = service
            .create_mfa_verified_token_with_resource(
                "user",
                "user@example.com",
                false,
                Some("acme"),
                Some("portal"),
                Some("https://resource.example.test"),
            )
            .expect("mfa-verified resource token");
        let resource_claims = service
            .validate_token_for_audience(&resource, "https://resource.example.test")
            .expect("resource token validates");
        assert_eq!(resource_claims.mfa_verified, Some(true));
    }

    #[test]
    fn bootstrap_marker_is_platform_only() {
        let service = generated_test_service();
        let bootstrap = service
            .create_bootstrap_management_token("user", "user@example.com", true, None, None)
            .expect("bootstrap token");
        let claims = service.validate_management_token(&bootstrap).unwrap();
        assert_eq!(claims.bootstrap, Some(true));
        assert!(claims.is_platform_context());
        assert!(claims.is_platform_owner);

        let tenant = service
            .create_bootstrap_management_token("user", "user@example.com", true, Some("acme"), None)
            .expect("tenant bootstrap attempt");
        let claims = service.validate_management_token(&tenant).unwrap();
        assert_eq!(claims.bootstrap, None);
        assert!(!claims.is_platform_context());
        assert!(!claims.is_platform_owner);
    }

    #[test]
    fn test_jwt_resource_audience_override() {
        let private_key = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktjd2dnU2pBZ0VBQW9JQkFRQ0dlSHhCSHJkRE9wR3cKLzNOcGhkK2JhRTNEaGNac3F3cE83Tm0rZUxsMGNkWERINUc2eXBURW1oS25LLzYrRmM4UE95SnB1R0ZORll5NAoyUUd4VVBiekJyeTZ3ay80TWMwV09mNXlKOFh6djlLRGcyM0pObk1OLys1cExLT0UzTS9BbSs2aVpYd1ZUMGJ0ClR4aU9nNlppajlLS3hZck9ZSitqWEE3aE1xWHFwc1h5b2t4d3pKLzM3eG96QktpRnVycGtad2tGZzQ0cldHSTYKalovN0pxRWszSHM0djdUcGZiWUovWnRzcndhYnduMWdzZDA4enpLVXNQTURGelpuWTJwTGorUG5tNWJTd1ZuTgpWSDRxTjBMNWtYUWxQMVZmQ1VhTTV1YnVxenE0c3FPeVJ0aTFRYTI0dG1qMS9jeXJKRno2OFhtT1RyZm1Cbmc3CmZMa0IzdHM3QWdNQkFBRUNnZ0VBRCtLMlJHMGxWNUd1T2h1R0hna0hndnVkOVlOZFpHTmZzRFk3MGt3VWEwU3kKd2o1OXFwN3ZBZVlmczZtM1g1WlhvK1FucXhkSFFMZDkxeTBsRFl1cE9NbVZkeUg5d2k0dW5ROFVna0RmbWtMbQowc3d1ZStSQ1VGSSttYzhyc1hEeWhyMnZ3Y3M5RHVRUzFzc095c1hwQnpZWURjdkxjTzVVNkQ2M3IvUHZTaS9tCkFTM051VlMycWNYOFd1RGt0Q3hKRFRxQjREa2ZWRnpoUFV2NWJmaThHWVUwZ2Z3TmZMYUpHdmcyUTdSQzl6eC8KejBncVNZTnZaMllWem8zY3Jvckh2S2F1M0RhcVZpRG1sVTBubEtncFJxbXZCNG9IeHRYcVgxNnY0OEs4WGwxRAo5V3lFNUZYanJEUWhPZWNWazJ6NDJDdWp1TjZlVlppeUk5blpBV2JBM1FLQmdRQzV6eVZCMHE0bkNrNm9pWitSCnNkWkkvb3k1ajY3VkJ0T0ZhNUpzS092UGtYMjlQclA1ZlN0dXFNNklDUFNmMWVwTmI5REZrN2gwVENqbmhuRHEKYWpJeDZUMk5GWWJMTEo0L05iS0RnNDI3UHdzTzcrbFAxM0l1eDdvUi94R2RpZFExcUwzdVdVSlB5cFZKM2xXTgpPWkk2U1Z2dU4wY0wzNnFaUkdhREExWGFSd0tCZ1FDNVJKbGF1emx5MndpTUNxVFRlSUV6TGNibHV3eHFROVN1CkFQUDFoWkVxMVdMOERvbitqZUIyTkxwRTNUWG9QRzRncVNxSTFxS05vSTE0ekNVWjlyMTkvcjg2eEkvaGZ1UXYKRkxJZjQ2TnJ0MzdMZnNNTGxGL3dIQWxrc05JYU9TQTFkZ3ZORC80Rm9BNkwzeldYNGdyTFZjQVIvK2c4ZmlIKwpJTWNJelVJOWJRS0JnRGhWQ2VtYjB2cTVFRUhlZjRjdlVGVU8vMkVlbzVXb0hTYTlCMFpOWGJpdlZseXlqdVBiCncvZ25xMzNvb1NsNE5ESEg3WmFKQTRvV3NPd0lnV0ZBVXZsNHloVms2bG5jckJsajBUdzMvUmRBdEx5UmxiMkUKQnZVUnptSzRYd0hSRUlvNEgyVU1vS01LT3hxTEVvcmZZbXJUWk5DaTU2STg3RDdOVXZyelh1cnZBb0dBVk5tZApIcGZHdk5xaDlIbGZlZGFqM1l1bW4wcG1hamk4ckNDVm1xbmNqWENEVUF0Y21lL2lrR0NmdXJCUll4WmlIYVU4CmJNVllWMkxqeUNJL0Q4QVlreDdiK0E5VUVpTnFZRUdyUHIyajk4NW5UTTIyaUpRZ3lEZ2UrVFdlVkJJN3RTQm0KVVRsMHpxQzZhTWNHcFpRSis0dy9WajhNM3IrcDA5aXhMMC9LZVpVQ2dZRUFnTGQyeEJROE1Cam9POG44ci8ycgptTTl3cWpzTXpqa1JzN3l1Vi9tMEZEOXFEemI2aGlMMmpGZHBpeXh6Yzg4NzNmdmVkaGxZSGg0T2svN0JpdDk3CjV3Wjh0TVFaZ3BCUzBZMkZ5dGE3cnZzeXNQclhKRmk5bXZSSnNsWk9DZmtjaXdLYU03S1BXM2c1cktsWk1JV08KSzFGeXBzOXpRS1ZvSkRWdkJlQ3BaV289Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K";
        let public_key = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFobmg4UVI2M1F6cVJzUDl6YVlYZgptMmhOdzRYR2JLc0tUdXpadm5pNWRISFZ3eCtSdXNxVXhKb1NweXYrdmhYUER6c2lhYmhoVFJXTXVOa0JzVkQyCjh3YTh1c0pQK0RITkZqbitjaWZGODcvU2c0TnR5VFp6RGYvdWFTeWpoTnpQd0p2dW9tVjhGVTlHN1U4WWpvT20KWW8vU2lzV0t6bUNmbzF3TzRUS2w2cWJGOHFKTWNNeWY5KzhhTXdTb2hicTZaR2NKQllPT0sxaGlPbzJmK3lhaApKTng3T0wrMDZYMjJDZjJiYks4R204SjlZTEhkUE04eWxMRHpBeGMyWjJOcVM0L2o1NXVXMHNGWnpWUitLamRDCitaRjBKVDlWWHdsR2pPYm03cXM2dUxLanNrYll0VUd0dUxabzlmM01xeVJjK3ZGNWprNjM1Z1o0TzN5NUFkN2IKT3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";
        let jwt_service = JwtService::new(
            private_key,
            public_key,
            24,
            "test-key-id",
            "https://auth.example.com",
        )
        .unwrap();

        let token = jwt_service
            .create_token_with_resource(
                "user_123",
                "user@example.com",
                false,
                Some("acme-corp"),
                Some("analytics"),
                Some("https://api.example.com/mcp"),
            )
            .unwrap();

        let claims = jwt_service
            .validate_token_for_audience(&token, "https://api.example.com/mcp")
            .unwrap();

        assert_eq!(claims.org, Some("acme-corp".to_string()));
        assert_eq!(claims.service, Some("analytics".to_string()));
        assert_eq!(claims.aud, Some("https://api.example.com/mcp".to_string()));

        assert!(jwt_service.validate_authos_token(&token).is_err());
        assert!(jwt_service
            .validate_token_for_audience(&token, "https://api.example.com/mcp")
            .is_ok());
        assert!(matches!(
            jwt_service.validate_token_for_audience(&token, "https://api.example.com/other"),
            Err(AppError::Jwt(error))
                if matches!(error.kind(), jsonwebtoken::errors::ErrorKind::InvalidAudience)
        ));
    }

    fn generated_key_pair() -> (String, String) {
        let rsa = crate::rsa_keys::GeneratedKey::generate().expect("generate test RSA key");
        let private_key = rsa.private_key_pem().expect("private key PEM");
        let public_key = rsa.public_key_pem().expect("public key PEM");

        (STANDARD.encode(private_key), STANDARD.encode(public_key))
    }

    fn generated_test_service() -> JwtService {
        let (private_key, public_key) = generated_key_pair();

        JwtService::new(
            &private_key,
            &public_key,
            24,
            "matrix-key",
            "https://auth.example.com",
        )
        .expect("test JWT service")
    }

    #[test]
    fn device_mfa_preauth_token_binds_exact_device_context() {
        let service = generated_test_service();
        let token = service
            .create_mfa_preauth_token_for_device(
                "user",
                "user@example.com",
                false,
                Some("acme"),
                None,
                "device-code-id",
            )
            .expect("device MFA preauth token");
        let claims = service
            .validate_mfa_preauth_token(&token)
            .expect("validate device MFA preauth token");

        assert_eq!(claims.device_code_id.as_deref(), Some("device-code-id"));
        assert_eq!(claims.aud.as_deref(), Some("org:acme"));
        let resource_token = service
            .create_mfa_preauth_token_for_device_with_resource(
                "user",
                "user@example.com",
                false,
                Some("acme"),
                Some("portal"),
                Some("https://api.example.com/resource"),
                "device-code-id",
            )
            .expect("resource-bound device MFA preauth token");
        assert_eq!(
            service
                .validate_mfa_preauth_token(&resource_token)
                .expect("validate resource-bound token")
                .aud
                .as_deref(),
            Some("https://api.example.com/resource")
        );
        assert!(service
            .create_mfa_preauth_token_for_device(
                "user",
                "user@example.com",
                false,
                Some("acme"),
                None,
                "",
            )
            .is_err());
    }

    #[test]
    fn signing_key_rotation_accepts_overlap_and_rejects_unknown_or_retired_keys() {
        let issuer = "https://auth.example.com";
        let (old_private, old_public) = generated_key_pair();
        let old_service = JwtService::new(&old_private, &old_public, 24, "old-key", issuer)
            .expect("old JWT service");
        let old_management = old_service
            .create_token("user", "user@example.com", false, None, None)
            .expect("old management token");
        let old_id_jag = old_service
            .create_id_jag(
                "user",
                Some("user@example.com"),
                issuer,
                "https://api.example.com",
                "client-id",
                None,
            )
            .expect("old ID-JAG");

        let (active_private, active_public) = generated_key_pair();
        let previous = BTreeMap::from([("old-key".to_string(), old_public)]);
        let rotated = JwtService::new_with_previous_keys(
            &active_private,
            &active_public,
            24,
            "active-key",
            issuer,
            &previous,
        )
        .expect("rotated JWT service");

        assert!(rotated.validate_management_token(&old_management).is_ok());
        assert!(rotated.validate_id_jag(&old_id_jag, issuer).is_ok());
        let active_token = rotated
            .create_token("user", "user@example.com", false, None, None)
            .expect("active token");
        assert_eq!(
            decode_header(&active_token).unwrap().kid.as_deref(),
            Some("active-key")
        );
        assert_eq!(
            rotated
                .verification_public_keys()
                .into_iter()
                .map(|(kid, _)| kid)
                .collect::<Vec<_>>(),
            vec!["active-key", "old-key"]
        );

        let claims = rotated
            .validate_management_token(&active_token)
            .expect("active claims");
        let mut unknown_header = Header::new(Algorithm::RS256);
        unknown_header.kid = Some("unknown-key".to_string());
        unknown_header.typ = Some(MANAGEMENT_ACCESS_TYP.to_string());
        let unknown_kid_token =
            encode(&unknown_header, &claims, &rotated.encoding_key).expect("unknown-kid token");
        assert!(matches!(
            rotated.validate_management_token(&unknown_kid_token),
            Err(AppError::Unauthorized(message)) if message.contains("not recognized")
        ));

        let retired = JwtService::new(&active_private, &active_public, 24, "active-key", issuer)
            .expect("retired old key");
        assert!(retired.validate_management_token(&old_management).is_err());

        let (_, unrelated_public) = generated_key_pair();
        let wrong_previous = BTreeMap::from([("old-key".to_string(), unrelated_public)]);
        let wrong_ring = JwtService::new_with_previous_keys(
            &active_private,
            &active_public,
            24,
            "active-key",
            issuer,
            &wrong_previous,
        )
        .expect("wrong previous-key mapping is structurally valid");
        assert!(wrong_ring
            .validate_management_token(&old_management)
            .is_err());
    }

    #[test]
    fn previous_key_ring_configuration_fails_closed() {
        let (private_key, public_key) = generated_key_pair();
        let active_collision = BTreeMap::from([("active-key".to_string(), public_key.clone())]);
        assert!(JwtService::new_with_previous_keys(
            &private_key,
            &public_key,
            24,
            "active-key",
            "https://auth.example.com",
            &active_collision,
        )
        .is_err());

        let (_, unrelated_public) = generated_key_pair();
        let trimmed_active_collision =
            BTreeMap::from([(" active-key ".to_string(), unrelated_public)]);
        assert!(JwtService::new_with_previous_keys(
            &private_key,
            &public_key,
            24,
            "active-key",
            "https://auth.example.com",
            &trimmed_active_collision,
        )
        .is_err());

        let duplicate_material = BTreeMap::from([("old-key".to_string(), public_key.clone())]);
        assert!(JwtService::new_with_previous_keys(
            &private_key,
            &public_key,
            24,
            "active-key",
            "https://auth.example.com",
            &duplicate_material,
        )
        .is_err());
        assert!(JwtService::parse_previous_public_keys_json(Some("not-json")).is_err());
        assert_eq!(
            JwtService::parse_previous_public_keys_json(Some("  ")).unwrap(),
            BTreeMap::new()
        );
    }

    #[test]
    fn token_profiles_accept_only_their_intended_validators() {
        let service = generated_test_service();

        let management = service
            .create_token("user", "user@example.com", true, None, None)
            .expect("management token");
        let management_claims = service
            .validate_management_token(&management)
            .expect("validate management token");
        assert_eq!(management_claims.token_use, TokenUse::ManagementAccess);
        assert_eq!(management_claims.aud.as_deref(), Some("platform"));
        assert_eq!(
            decode_header(&management).unwrap().typ.as_deref(),
            Some(MANAGEMENT_ACCESS_TYP)
        );
        assert!(service.validate_authos_token(&management).is_ok());
        assert!(service.validate_mfa_preauth_token(&management).is_err());
        assert!(service
            .validate_token_for_audience(&management, "platform")
            .is_err());

        let resource = "https://api.example.com/mcp";
        let external = service
            .create_token_with_resource(
                "user",
                "user@example.com",
                false,
                Some("acme"),
                Some("portal"),
                Some(resource),
            )
            .expect("external-resource token");
        let external_claims = service
            .validate_token_for_audience(&external, resource)
            .expect("validate external-resource token");
        assert_eq!(external_claims.token_use, TokenUse::ExternalResourceAccess);
        assert_eq!(
            decode_header(&external).unwrap().typ.as_deref(),
            Some(EXTERNAL_RESOURCE_ACCESS_TYP)
        );
        assert!(service.validate_authos_token(&external).is_err());
        assert!(service.validate_management_token(&external).is_err());
        for reserved in ["platform", "org:acme", "service:acme/portal"] {
            assert!(service
                .create_token_with_resource(
                    "user",
                    "user@example.com",
                    false,
                    Some("acme"),
                    Some("portal"),
                    Some(reserved),
                )
                .is_err());
        }
        assert!(service
            .create_token_with_resource(
                "user",
                "user@example.com",
                false,
                Some("acme"),
                Some("portal"),
                Some("urn:example:custom-resource"),
            )
            .is_ok());

        let mfa = service
            .create_mfa_preauth_token_with_resource(
                "user",
                "user@example.com",
                false,
                Some("acme"),
                Some("portal"),
                None,
                Some(resource),
            )
            .expect("MFA preauth token");
        let mfa_claims = service
            .validate_mfa_preauth_token(&mfa)
            .expect("validate MFA preauth token");
        assert_eq!(mfa_claims.token_use, TokenUse::MfaPreauth);
        assert_eq!(
            decode_header(&mfa).unwrap().typ.as_deref(),
            Some(MFA_PREAUTH_TYP)
        );
        assert!(service.validate_authos_token(&mfa).is_err());
        assert!(service.validate_token_for_audience(&mfa, resource).is_err());

        let impersonation = service
            .create_impersonation_token(
                "target",
                "target@example.com",
                "admin",
                "admin@example.com",
                Some("support"),
                Some("acme"),
                Some("portal"),
                false,
            )
            .expect("impersonation token");
        let impersonation_claims = service
            .validate_impersonation_token(&impersonation)
            .expect("validate impersonation token");
        assert_eq!(impersonation_claims.token_use, TokenUse::Impersonation);
        assert!(impersonation_claims.act.is_some());
        assert!(service.validate_authos_token(&impersonation).is_ok());
        assert!(service.validate_management_token(&impersonation).is_err());

        let id_jag = service
            .create_id_jag(
                "user",
                Some("user@example.com"),
                "https://auth.example.com",
                resource,
                "client-id",
                Some("read"),
            )
            .expect("ID-JAG");
        let id_jag_claims = service
            .validate_id_jag(&id_jag, "https://auth.example.com")
            .expect("validate ID-JAG");
        assert_eq!(id_jag_claims.token_use, TokenUse::IdJag);
        assert_eq!(
            decode_header(&id_jag).unwrap().typ.as_deref(),
            Some(ID_JAG_TYP)
        );
        assert!(service.validate_authos_token(&id_jag).is_err());
    }

    #[test]
    fn management_token_confusion_matrix_rejects_mismatched_security_context() {
        #[derive(Clone, Copy)]
        enum Mutation {
            Type,
            TokenUse,
            Audience,
            Issuer,
            Actor,
            KeyId,
            Algorithm,
        }

        let service = generated_test_service();
        let valid = service
            .create_token(
                "user",
                "user@example.com",
                false,
                Some("acme"),
                Some("portal"),
            )
            .expect("management token");
        let baseline = service
            .validate_management_token(&valid)
            .expect("baseline management claims");

        let cases = [
            ("wrong typ", Mutation::Type),
            ("wrong token_use", Mutation::TokenUse),
            ("wrong audience", Mutation::Audience),
            ("wrong issuer", Mutation::Issuer),
            ("unexpected actor", Mutation::Actor),
            ("wrong kid", Mutation::KeyId),
            ("wrong algorithm", Mutation::Algorithm),
        ];

        for (name, mutation) in cases {
            let mut claims = baseline.clone();
            let mut token_type = MANAGEMENT_ACCESS_TYP;
            let mut key_id = "matrix-key";
            let mut algorithm = Algorithm::RS256;

            match mutation {
                Mutation::Type => token_type = EXTERNAL_RESOURCE_ACCESS_TYP,
                Mutation::TokenUse => claims.token_use = TokenUse::ExternalResourceAccess,
                Mutation::Audience => {
                    claims.aud = Some("https://api.example.com/not-management".to_string())
                }
                Mutation::Issuer => {
                    claims.iss = Some("https://other-issuer.example.com".to_string())
                }
                Mutation::Actor => {
                    claims.act = Some(Actor {
                        sub: "unexpected-admin".to_string(),
                        email: "admin@example.com".to_string(),
                        reason: None,
                    })
                }
                Mutation::KeyId => key_id = "unknown-key",
                Mutation::Algorithm => algorithm = Algorithm::HS256,
            }

            let mut header = Header::new(algorithm);
            header.kid = Some(key_id.to_string());
            header.typ = Some(token_type.to_string());
            let token = if algorithm == Algorithm::RS256 {
                encode(&header, &claims, &service.encoding_key).expect("sign matrix token")
            } else {
                encode(
                    &header,
                    &claims,
                    &EncodingKey::from_secret(b"not-the-rsa-key"),
                )
                .expect("sign wrong-algorithm token")
            };

            assert!(
                service.validate_management_token(&token).is_err(),
                "accepted confusion case: {name}"
            );
        }
    }

    #[test]
    fn test_token_hash() {
        let token = "test_token_123";
        let hash = JwtService::hash_token(token);
        assert!(!hash.is_empty());
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex chars
    }
}
