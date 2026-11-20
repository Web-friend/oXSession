//! N-API exports for oXSession's framework-independent authentication APIs.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use oxsession_core::{Credentials, Error as CoreError, Pairs, SessionId, resolve};
use oxsession_session::{
    Error as SessionError, ErrorCategory as SessionErrorCategory, MAX_SUBJECT_BYTES, MemoryStore,
    Policy, SessionManager,
};
use oxsession_sign::{CookieSigner as RustCookieSigner, Error as SignError, KeyId, SecretKey};

fn js_error(code: &str, message: impl AsRef<str>) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("OXSESSION_{code}: {}", message.as_ref()),
    )
}

fn core_error(error: CoreError) -> Error {
    match error {
        CoreError::Unauthenticated => {
            js_error("MISSING_CREDENTIAL", "no usable credential was supplied")
        }
        CoreError::Ambiguous(_) => {
            js_error("AMBIGUOUS_CREDENTIAL", "credential cookie is ambiguous")
        }
        _ => js_error("INVALID_INPUT", "credential input is invalid"),
    }
}

fn sign_error(error: SignError) -> Error {
    match error {
        SignError::BadMac | SignError::UnknownKey => {
            js_error("SIGNATURE_FAILURE", "cookie signature verification failed")
        }
        SignError::InvalidKeyId
        | SignError::KeySize
        | SignError::InvalidKeyEncoding
        | SignError::TooManyKeys
        | SignError::DuplicateKeyId => js_error("CONFIGURATION", error.to_string()),
        _ => js_error("INVALID_INPUT", error.to_string()),
    }
}

fn session_error(error: SessionError) -> Error {
    let code = match error.category() {
        SessionErrorCategory::InvalidSubject => "INVALID_SUBJECT",
        SessionErrorCategory::SubjectTooLong => "SUBJECT_TOO_LONG",
        SessionErrorCategory::MissingSession => "MISSING_SESSION",
        SessionErrorCategory::ExpiredSession => "EXPIRED_SESSION",
        SessionErrorCategory::EntropyFailure => "ENTROPY_FAILURE",
        SessionErrorCategory::StorageFailure => "STORAGE_FAILURE",
    };
    js_error(code, error.to_string())
}

fn parse_session_id(value: &str) -> Result<SessionId> {
    SessionId::new(value).map_err(|_| js_error("INVALID_INPUT", "session id has an invalid format"))
}

/// A cookie name and value returned from a parsed request header.
#[napi(object)]
pub struct CookiePair {
    /// Cookie name.
    pub name: String,
    /// Cookie value after quote removal.
    pub value: String,
}

/// Cookie parser counters and limits.
#[napi(object)]
pub struct CookieStats {
    /// Accepted name/value pairs.
    pub pairs: u32,
    /// Non-empty malformed segments ignored by the parser.
    pub skipped: u32,
    /// True when the pair limit stopped the scan.
    pub truncated: bool,
    /// True when the header exceeded the parser's byte limit.
    pub too_long: bool,
}

/// Parsed cookie header, including scan statistics.
#[napi(object)]
pub struct ParsedCookies {
    /// Accepted cookie pairs in header order.
    pub pairs: Vec<CookiePair>,
    /// Parser scan statistics.
    pub stats: CookieStats,
}

/// Parse one `Cookie` header using the core parser's byte and pair limits.
#[napi(js_name = "parseCookies")]
pub fn parse_cookies(header: String) -> ParsedCookies {
    let parsed = Pairs::parse(header.as_bytes());
    let pairs = parsed
        .iter()
        .map(|pair| CookiePair {
            name: pair.name().to_owned(),
            value: pair.value().to_owned(),
        })
        .collect();
    let stats = parsed.stats();
    ParsedCookies {
        pairs,
        stats: CookieStats {
            pairs: stats.pairs as u32,
            skipped: stats.skipped as u32,
            truncated: stats.truncated,
            too_long: stats.too_long,
        },
    }
}

/// A resolved bearer or cookie credential.
#[napi(object)]
pub struct ResolvedCredential {
    /// Credential token. Treat it as a bearer secret.
    pub token: String,
    /// Source of the token: `bearer` or `cookie`.
    pub source: String,
}

/// Resolve a credential from optional authorization and cookie headers.
#[napi(js_name = "resolveCredential")]
pub fn resolve_credential(
    authorization: Option<String>,
    cookie_header: String,
    cookie_name: Option<String>,
) -> Result<ResolvedCredential> {
    let pairs = Pairs::parse(cookie_header.as_bytes());
    let credential = resolve(
        authorization.as_deref(),
        &pairs,
        cookie_name.as_deref().unwrap_or("session"),
    )
    .map_err(core_error)?;
    let (token, source) = match credential {
        Credentials::Bearer(value) => (value, "bearer"),
        Credentials::Cookie(value) => (value, "cookie"),
    };
    Ok(ResolvedCredential {
        token: token.to_owned(),
        source: source.to_owned(),
    })
}

/// HMAC signer and verifier with a bounded rotating key ring.
#[napi(js_name = "CookieSigner")]
pub struct NodeCookieSigner {
    inner: RustCookieSigner,
}

#[napi]
impl NodeCookieSigner {
    /// Create a signer. Keys must be 32 bytes encoded as unpadded base64url.
    #[napi(constructor)]
    pub fn new(key_id: String, key_base64url: String) -> Result<Self> {
        let inner = RustCookieSigner::new(
            KeyId::new(&key_id).map_err(sign_error)?,
            SecretKey::from_base64url(&key_base64url).map_err(sign_error)?,
        );
        Ok(Self { inner })
    }

    /// Retain a previous key for verification.
    #[napi(js_name = "addPrevious")]
    pub fn add_previous(&mut self, key_id: String, key_base64url: String) -> Result<()> {
        self.inner
            .add_previous(
                KeyId::new(&key_id).map_err(sign_error)?,
                SecretKey::from_base64url(&key_base64url).map_err(sign_error)?,
            )
            .map_err(sign_error)
    }

    /// Promote a new current key, retaining the old key for verification.
    #[napi]
    pub fn rotate(&mut self, key_id: String, key_base64url: String) -> Result<()> {
        self.inner
            .rotate(
                KeyId::new(&key_id).map_err(sign_error)?,
                SecretKey::from_base64url(&key_base64url).map_err(sign_error)?,
            )
            .map_err(sign_error)
    }

    /// Current signing key identifier.
    #[napi(getter, js_name = "keyId")]
    pub fn key_id(&self) -> String {
        self.inner.key_id().to_owned()
    }

    /// Sign a cookie payload.
    #[napi]
    pub fn sign(&self, name: String, payload: String) -> Result<String> {
        self.inner.sign(&name, &payload).map_err(sign_error)
    }

    /// Verify a cookie value and return its payload.
    #[napi]
    pub fn verify(&self, name: String, wire: String) -> Result<String> {
        self.inner
            .verify(&name, &wire)
            .map(str::to_owned)
            .map_err(sign_error)
    }
}

/// A session returned to JavaScript. Its id is a bearer credential.
#[napi(object)]
pub struct SessionRecord {
    /// Opaque bearer session id. Do not log or expose it unnecessarily.
    pub id: String,
    /// Application-defined subject.
    pub subject: String,
    /// Creation time in Unix seconds.
    pub issued_at: f64,
    /// Current expiry time in Unix seconds.
    pub expires_at: f64,
}

impl From<oxsession_core::Session> for SessionRecord {
    fn from(session: oxsession_core::Session) -> Self {
        Self {
            id: session.id().as_str().to_owned(),
            subject: session.subject().to_owned(),
            issued_at: session.issued_at() as f64,
            expires_at: session.expires_at() as f64,
        }
    }
}

/// Process-local session manager backed by a Rust-owned `MemoryStore`.
#[napi(js_name = "SessionManager")]
pub struct NodeSessionManager {
    inner: SessionManager<MemoryStore>,
}

#[napi]
impl NodeSessionManager {
    /// Create a manager with idle and absolute lifetimes in seconds.
    #[napi(constructor)]
    pub fn new(ttl_seconds: Option<u32>, absolute_ttl_seconds: Option<u32>) -> Result<Self> {
        let ttl = ttl_seconds.map_or(oxsession_session::DEFAULT_TTL_SECONDS, u64::from);
        let absolute_ttl =
            absolute_ttl_seconds.map_or(oxsession_session::DEFAULT_ABSOLUTE_TTL_SECONDS, u64::from);
        let policy = Policy::new(ttl, absolute_ttl)
            .map_err(|_| js_error("INVALID_INPUT", "invalid session lifetime policy"))?;
        Ok(Self {
            inner: SessionManager::new(MemoryStore::new(), policy),
        })
    }

    /// Create a session using the current system time.
    #[napi]
    pub async fn create(&self, subject: String) -> Result<SessionRecord> {
        if subject.len() > MAX_SUBJECT_BYTES {
            return Err(js_error(
                "SUBJECT_TOO_LONG",
                "subject exceeds the 1024-byte limit",
            ));
        }
        self.inner
            .create(&subject, oxsession_session::now())
            .await
            .map(Into::into)
            .map_err(session_error)
    }

    /// Validate a session and refresh its idle expiry.
    #[napi]
    pub async fn validate(&self, id: String) -> Result<SessionRecord> {
        let id = parse_session_id(&id)?;
        self.inner
            .validate(&id, oxsession_session::now())
            .await
            .map(Into::into)
            .map_err(session_error)
    }

    /// Revoke a session. Returns false if it did not exist.
    #[napi]
    pub async fn revoke(&self, id: String) -> Result<bool> {
        let id = parse_session_id(&id)?;
        self.inner.revoke(&id).await.map_err(session_error)
    }

    /// Replace a session id and invalidate the old id.
    #[napi]
    pub async fn rotate(&self, id: String) -> Result<SessionRecord> {
        let id = parse_session_id(&id)?;
        self.inner
            .rotate(&id, oxsession_session::now())
            .await
            .map(Into::into)
            .map_err(session_error)
    }
}
