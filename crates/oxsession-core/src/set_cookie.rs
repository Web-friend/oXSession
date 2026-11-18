//! Building and serializing `Set-Cookie` response headers.
//!
//! Values are not percent-encoded: a cookie value must already consist of
//! cookie-octets, which is exactly what [`SetCookie::new`] enforces and what
//! [`crate::Pairs`] accepts back. Tokens should be base64url so no encoding
//! layer is needed at all — that keeps the wire format identical across every
//! language that talks to this service.

use core::fmt::Write as _;

use crate::cookies::{is_cookie_octet, is_valid_name};
use crate::error::Error;

/// The `SameSite` attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SameSite {
    /// Never sent on cross-site requests.
    Strict,
    /// Sent on top-level cross-site navigations.
    Lax,
    /// Sent on all cross-site requests; requires `Secure`.
    None,
}

impl SameSite {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// The security prefix a cookie name declares (RFC 6265bis section 4.1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefix {
    /// `__Host-`: `Secure`, `Path=/`, and no `Domain`.
    Host,
    /// `__Secure-`: `Secure`.
    Secure,
    /// No prefix, no extra requirements.
    None,
}

impl Prefix {
    /// The prefix declared by `name`.
    #[must_use]
    pub fn of(name: &str) -> Self {
        if name.starts_with("__Host-") {
            Self::Host
        } else if name.starts_with("__Secure-") {
            Self::Secure
        } else {
            Self::None
        }
    }
}

/// A validated `Set-Cookie` header.
///
/// Construct with [`SetCookie::builder`] when the cookie carries attributes
/// (`Path`, `Domain`, `Max-Age`, ...), which is the normal case for a session
/// cookie. [`SetCookie::new`] only accepts cookies whose attributes are absent,
/// so a `__Host-` name always needs the builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetCookie<'a> {
    name: &'a str,
    value: &'a str,
    path: Option<&'a str>,
    domain: Option<&'a str>,
    max_age: Option<u64>,
    secure: bool,
    http_only: bool,
    same_site: Option<SameSite>,
}

impl<'a> SetCookie<'a> {
    /// A cookie with no attributes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCookieName`], [`Error::InvalidCookieValue`], or
    /// one of the prefix errors when `name` uses a `__Host-`/`__Secure-` prefix
    /// that the missing attributes cannot satisfy.
    pub fn new(name: &'a str, value: &'a str) -> Result<Self, Error> {
        let cookie = Self {
            name,
            value,
            path: None,
            domain: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        cookie.validate_grammar()?;
        cookie.validate_policy()?;
        Ok(cookie)
    }

    /// Start building a cookie with attributes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCookieName`] or [`Error::InvalidCookieValue`]
    /// when the name or value cannot be represented on the wire.
    pub fn builder(name: &'a str, value: &'a str) -> Result<SetCookieBuilder<'a>, Error> {
        SetCookieBuilder::new(name, value)
    }

    /// The cookie name.
    #[must_use]
    pub const fn name(&self) -> &'a str {
        self.name
    }

    /// The cookie value.
    #[must_use]
    pub const fn value(&self) -> &'a str {
        self.value
    }

    /// Serialize the header value.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(64 + self.name.len() + self.value.len());
        out.push_str(self.name);
        out.push('=');
        out.push_str(self.value);

        if let Some(path) = self.path {
            out.push_str("; Path=");
            out.push_str(path);
        }
        if let Some(domain) = self.domain {
            out.push_str("; Domain=");
            out.push_str(domain);
        }
        if let Some(max_age) = self.max_age {
            // Writing into a String cannot fail.
            let _ = write!(out, "; Max-Age={max_age}");
        }
        if self.secure {
            out.push_str("; Secure");
        }
        if self.http_only {
            out.push_str("; HttpOnly");
        }
        if let Some(same_site) = self.same_site {
            out.push_str("; SameSite=");
            out.push_str(same_site.as_str());
        }
        out
    }

    fn validate_grammar(&self) -> Result<(), Error> {
        if !is_valid_name(self.name) {
            return Err(Error::InvalidCookieName);
        }
        if !self.value.bytes().all(is_cookie_octet) {
            return Err(Error::InvalidCookieValue);
        }
        if let Some(path) = self.path {
            if !path.starts_with('/') {
                return Err(Error::InvalidAttribute("Path must start with '/'"));
            }
            validate_attribute_value(path)?;
        }
        if let Some(domain) = self.domain {
            validate_attribute_value(domain)?;
            if domain.is_empty() || !domain.is_ascii() {
                return Err(Error::InvalidAttribute(
                    "Domain must be a non-empty ASCII name",
                ));
            }
        }
        Ok(())
    }

    fn validate_policy(&self) -> Result<(), Error> {
        match Prefix::of(self.name) {
            Prefix::Host => {
                if !self.secure || self.path != Some("/") || self.domain.is_some() {
                    return Err(Error::HostPrefix);
                }
            }
            Prefix::Secure => {
                if !self.secure {
                    return Err(Error::SecurePrefix);
                }
            }
            Prefix::None => {}
        }

        if self.same_site == Some(SameSite::None) && !self.secure {
            return Err(Error::SameSiteNoneRequiresSecure);
        }
        Ok(())
    }
}

/// Builder for [`SetCookie`].
#[derive(Clone, Debug)]
pub struct SetCookieBuilder<'a> {
    cookie: SetCookie<'a>,
}

impl<'a> SetCookieBuilder<'a> {
    fn new(name: &'a str, value: &'a str) -> Result<Self, Error> {
        let cookie = SetCookie {
            name,
            value,
            path: None,
            domain: None,
            max_age: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        cookie.validate_grammar()?;
        Ok(Self { cookie })
    }

    /// Set the `Path` attribute. It must start with `/`.
    #[must_use]
    pub fn path(mut self, path: &'a str) -> Self {
        self.cookie.path = Some(path);
        self
    }

    /// Set the `Domain` attribute.
    #[must_use]
    pub fn domain(mut self, domain: &'a str) -> Self {
        self.cookie.domain = Some(domain);
        self
    }

    /// Set the `Max-Age` attribute.
    #[must_use]
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.cookie.max_age = Some(seconds);
        self
    }

    /// Add the `Secure` attribute.
    #[must_use]
    pub fn secure(mut self) -> Self {
        self.cookie.secure = true;
        self
    }

    /// Add the `HttpOnly` attribute.
    #[must_use]
    pub fn http_only(mut self) -> Self {
        self.cookie.http_only = true;
        self
    }

    /// Set the `SameSite` attribute.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.cookie.same_site = Some(same_site);
        self
    }

    /// Validate the assembled cookie, including the prefix and `SameSite` rules.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HostPrefix`], [`Error::SecurePrefix`],
    /// [`Error::SameSiteNoneRequiresSecure`], or an attribute error.
    pub fn build(self) -> Result<SetCookie<'a>, Error> {
        self.cookie.validate_grammar()?;
        self.cookie.validate_policy()?;
        Ok(self.cookie)
    }
}

fn validate_attribute_value(value: &str) -> Result<(), Error> {
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b',' | b' ' | b'\t'))
    {
        return Err(Error::InvalidAttribute(
            "attribute values cannot contain separators or control bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_a_minimal_cookie() {
        let cookie = SetCookie::new("theme", "dark").unwrap();
        assert_eq!(cookie.encode(), "theme=dark");
    }

    #[test]
    fn encodes_every_attribute() {
        let cookie = SetCookie::builder("theme", "dark")
            .unwrap()
            .path("/")
            .max_age(3600)
            .secure()
            .http_only()
            .same_site(SameSite::Lax)
            .build()
            .unwrap();
        assert_eq!(
            cookie.encode(),
            "theme=dark; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn rejects_names_and_values_that_cannot_be_sent() {
        assert_eq!(
            SetCookie::new("bad name", "x").unwrap_err(),
            Error::InvalidCookieName
        );
        assert_eq!(
            SetCookie::new("a", "1; Domain=evil.example").unwrap_err(),
            Error::InvalidCookieValue
        );
    }

    #[test]
    fn host_prefix_requires_secure_path_and_no_domain() {
        assert_eq!(
            SetCookie::builder("__Host-sid", "x")
                .unwrap()
                .build()
                .unwrap_err(),
            Error::HostPrefix
        );
        assert_eq!(
            SetCookie::builder("__Host-sid", "x")
                .unwrap()
                .secure()
                .build()
                .unwrap_err(),
            Error::HostPrefix
        );
        assert_eq!(
            SetCookie::builder("__Host-sid", "x")
                .unwrap()
                .secure()
                .path("/")
                .domain("example.com")
                .build()
                .unwrap_err(),
            Error::HostPrefix
        );
        assert!(
            SetCookie::builder("__Host-sid", "x")
                .unwrap()
                .secure()
                .path("/")
                .build()
                .is_ok()
        );
    }

    #[test]
    fn secure_prefix_requires_secure() {
        assert_eq!(
            SetCookie::new("__Secure-sid", "x").unwrap_err(),
            Error::SecurePrefix
        );
        assert!(
            SetCookie::builder("__Secure-sid", "x")
                .unwrap()
                .secure()
                .build()
                .is_ok()
        );
    }

    #[test]
    fn same_site_none_requires_secure() {
        assert_eq!(
            SetCookie::builder("sid", "x")
                .unwrap()
                .same_site(SameSite::None)
                .build()
                .unwrap_err(),
            Error::SameSiteNoneRequiresSecure
        );
    }

    #[test]
    fn path_must_be_absolute() {
        assert_eq!(
            SetCookie::builder("sid", "x")
                .unwrap()
                .path("app")
                .build()
                .unwrap_err(),
            Error::InvalidAttribute("Path must start with '/'")
        );
    }

    #[test]
    fn detects_prefixes() {
        assert_eq!(Prefix::of("__Host-sid"), Prefix::Host);
        assert_eq!(Prefix::of("__Secure-sid"), Prefix::Secure);
        assert_eq!(Prefix::of("__host-sid"), Prefix::None);
    }
}
