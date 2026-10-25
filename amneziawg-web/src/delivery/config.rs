// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

use super::*;
use lettre::message::Mailbox;
use url::Url;

/// Explicit security selection. Required STARTTLS never downgrades.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportSecurity {
    Starttls,
    Implicit,
    None,
}
impl TransportSecurity {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "starttls" => Ok(Self::Starttls),
            "implicit" => Ok(Self::Implicit),
            "none" => Ok(Self::None),
            _ => Err(DeliveryError("invalid_smtp_tls")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starttls => "starttls",
            Self::Implicit => "implicit",
            Self::None => "none",
        }
    }
    pub fn validate_credentials(
        self,
        authenticate: bool,
        username: &str,
        password: &str,
    ) -> Result<()> {
        if self == Self::None && (authenticate || !username.is_empty() || !password.is_empty()) {
            return Err(DeliveryError("plaintext_auth_forbidden"));
        }
        Ok(())
    }
}

/// Intentionally no Debug or Serialize; password never leaves this type.
#[derive(Clone)]
pub struct Settings {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub tls: TransportSecurity,
    pub from: String,
    pub reply_to: Option<String>,
    pub username: String,
    pub authenticate: bool,
    pub password: String,
    pub public_base: Option<Url>,
    pub ttl: i64,
}
pub fn mailbox(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 254
        || value.chars().any(char::is_control)
        || value.contains(['<', '>', ',', ';'])
    {
        return Err(DeliveryError("invalid_email"));
    }
    let parsed: Mailbox = value.parse().map_err(|_| DeliveryError("invalid_email"))?;
    if parsed.name.is_some() {
        return Err(DeliveryError("invalid_email"));
    }
    Ok(parsed.email.to_string())
}
pub fn public_base(value: &str) -> Result<Url> {
    let err = DeliveryError("invalid_public_base");
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) || value.contains('\\') {
        return Err(err);
    }
    let lower = value.to_ascii_lowercase();
    if ["%2f", "%5c", "%2e"].iter().any(|s| lower.contains(s))
        || value.split('/').any(|s| s == "." || s == "..")
    {
        return Err(err);
    }
    let mut url = Url::parse(value).map_err(|_| err)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.host(), Some(url::Host::Domain(_)))
    {
        return Err(err);
    }
    if url.path().contains('%') || url.path().contains("//") {
        return Err(err);
    }
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(&path);
    Ok(url)
}
impl Settings {
    pub fn from_env(auth_enabled: bool) -> Result<Self> {
        Self::parse(|name| std::env::var(name).ok(), auth_enabled)
    }
    pub fn parse(get: impl Fn(&str) -> Option<String>, auth_enabled: bool) -> Result<Self> {
        let enabled = match get("AWG_EMAIL_ENABLED").as_deref().unwrap_or("false") {
            "true" | "1" => true,
            "false" | "0" | "" => false,
            _ => return Err(DeliveryError("invalid_email_enabled")),
        };
        if enabled && !auth_enabled {
            return Err(DeliveryError("email_requires_auth"));
        }
        let mut s = Self {
            enabled,
            host: String::new(),
            port: 587,
            tls: TransportSecurity::Starttls,
            from: String::new(),
            reply_to: None,
            username: String::new(),
            authenticate: false,
            password: String::new(),
            public_base: None,
            ttl: 86400,
        };
        if !enabled {
            return Ok(s);
        }
        s.host = get("AWG_SMTP_HOST").unwrap_or_default();
        if s.host.is_empty()
            || s.host.len() > 253
            || s.host.chars().any(|c| c.is_whitespace() || c.is_control())
            || s.host.contains(['/', '\\', '@', '?', '#'])
            || url::Host::parse(&s.host).is_err()
        {
            return Err(DeliveryError("invalid_smtp_host"));
        }
        s.tls =
            TransportSecurity::parse(&get("AWG_SMTP_TLS").unwrap_or_else(|| "starttls".into()))?;
        if s.tls == TransportSecurity::None
            && get("AWG_SMTP_ALLOW_PLAINTEXT").as_deref() != Some("true")
        {
            return Err(DeliveryError("plaintext_ack_required"));
        }
        s.port = get("AWG_SMTP_PORT")
            .unwrap_or_else(|| {
                if s.tls == TransportSecurity::Implicit {
                    "465".into()
                } else {
                    "587".into()
                }
            })
            .parse()
            .map_err(|_| DeliveryError("invalid_smtp_port"))?;
        if s.port == 0 {
            return Err(DeliveryError("invalid_smtp_port"));
        }
        s.from = mailbox(&get("AWG_SMTP_FROM").unwrap_or_default())?;
        s.reply_to = get("AWG_SMTP_REPLY_TO")
            .filter(|value| !value.trim().is_empty())
            .map(|value| mailbox(&value))
            .transpose()?;
        s.username = get("AWG_SMTP_USERNAME").unwrap_or_default();
        s.authenticate = !s.username.is_empty();
        s.password = get("AWG_SMTP_PASSWORD").unwrap_or_default();
        if s.username.chars().any(char::is_control) {
            return Err(DeliveryError("invalid_smtp_username"));
        }
        s.tls
            .validate_credentials(s.authenticate, &s.username, &s.password)?;
        s.public_base = get("AWG_DELIVERY_PUBLIC_BASE_URL")
            .filter(|v| !v.is_empty())
            .map(|v| public_base(&v))
            .transpose()?;
        s.ttl = get("AWG_DELIVERY_TTL_SECS")
            .unwrap_or_else(|| "86400".into())
            .parse()
            .map_err(|_| DeliveryError("invalid_ttl"))?;
        if !(300..=604800).contains(&s.ttl) {
            return Err(DeliveryError("invalid_ttl"));
        }
        Ok(s)
    }
    pub fn fingerprint(&self) -> Vec<u8> {
        hash(
            serde_json::to_string(&(
                self.enabled,
                &self.host,
                self.port,
                &self.tls,
                &self.from,
                &self.reply_to,
                &self.username,
                self.authenticate,
                self.public_base.as_ref().map(Url::as_str),
                self.ttl,
            ))
            .unwrap()
            .as_bytes(),
        )
    }
    pub fn external_path(&self) -> String {
        format!(
            "{}/delivery/",
            self.public_base
                .as_ref()
                .map(|u| u.path().trim_end_matches('/'))
                .unwrap_or("")
        )
    }
    pub fn origin(&self) -> String {
        self.public_base
            .as_ref()
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default()
    }
    pub fn link(&self, token: &str) -> Result<String> {
        let base = self
            .public_base
            .as_ref()
            .ok_or(DeliveryError("link_unavailable"))?;
        Ok(format!(
            "{}/delivery/#{token}",
            base.as_str().trim_end_matches('/')
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn panel_smtp_host_cannot_smuggle_url_components() {
        for host in [
            "smtp.example.test/path",
            "user@smtp.example.test",
            "smtp.example.test?x=1",
            "smtp.example.test#x",
        ] {
            let result = Settings::parse(
                |name| match name {
                    "AWG_EMAIL_ENABLED" => Some("true".into()),
                    "AWG_SMTP_HOST" => Some(host.into()),
                    "AWG_SMTP_FROM" => Some("sender@example.test".into()),
                    _ => None,
                },
                true,
            );
            assert!(result.is_err(), "SMTP host accepted URL syntax");
        }
    }
    #[test]
    fn panel_reply_to_rejects_header_injection() {
        let result = Settings::parse(
            |name| match name {
                "AWG_EMAIL_ENABLED" => Some("true".into()),
                "AWG_SMTP_HOST" => Some("smtp.example.test".into()),
                "AWG_SMTP_FROM" => Some("sender@example.test".into()),
                "AWG_SMTP_REPLY_TO" => Some("a@example.test\r\nBcc: other@example.test".into()),
                _ => None,
            },
            true,
        );
        assert!(
            result.is_err(),
            "Reply-to must be validated as a single mailbox"
        );
    }
    #[test]
    fn delivery_rejects_mail_header_injection_and_multiple_recipients() {
        for bad in [
            "a@example.test\r\nBcc: x@example.test",
            "a@example.test,b@example.test",
            "Name <a@example.test>",
            "",
        ] {
            assert!(mailbox(bad).is_err(), "{bad:?}");
        }
        assert_eq!(mailbox(" a@example.test ").unwrap(), "a@example.test");
    }
    #[test]
    fn delivery_base_is_canonical_and_independent_of_host_headers() {
        for bad in [
            "http://example.test",
            "https://u:p@example.test",
            "https://example.test/a/../b",
            "https://example.test/%2f/a",
            "https://example.test?q=x",
            "https://example.test/#x",
            "https://127.0.0.1",
            "https://example.test\\x",
        ] {
            assert!(public_base(bad).is_err(), "{bad}");
        }
        assert_eq!(
            public_base("https://EXAMPLE.test:443/share/")
                .unwrap()
                .as_str(),
            "https://example.test/share"
        );
    }
    #[test]
    fn delivery_disabled_does_not_read_credentials_and_enabled_requires_auth() {
        assert!(
            !Settings::parse(
                |name| {
                    assert_eq!(name, "AWG_EMAIL_ENABLED");
                    None
                },
                false
            )
            .unwrap()
            .enabled
        );
        assert!(Settings::parse(|_| Some("true".into()), false).is_err());
    }
    #[test]
    fn panel_plaintext_environment_requires_explicit_opt_in_and_no_credentials() {
        for (ack, user, password, allowed) in [
            (false, "", "", false),
            (true, "", "", true),
            (true, "user", "", false),
            (true, "", "secret", false),
        ] {
            let result = Settings::parse(
                |name| match name {
                    "AWG_EMAIL_ENABLED" => Some("true".into()),
                    "AWG_SMTP_HOST" => Some("relay.example.test".into()),
                    "AWG_SMTP_FROM" => Some("sender@example.test".into()),
                    "AWG_SMTP_TLS" => Some("none".into()),
                    "AWG_SMTP_ALLOW_PLAINTEXT" => Some(ack.to_string()),
                    "AWG_SMTP_USERNAME" => Some(user.into()),
                    "AWG_SMTP_PASSWORD" => Some(password.into()),
                    _ => None,
                },
                true,
            );
            assert_eq!(result.is_ok(), allowed);
        }
    }
}
