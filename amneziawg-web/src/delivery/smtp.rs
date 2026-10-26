// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

use super::*;
use lettre::{
    message::{header::ContentType, Attachment, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    Accepted,
    DefiniteTransient,
    DefinitePermanent,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionCheck {
    Connected,
    TlsFailed,
    AuthenticationRejected,
    Timeout,
    Unavailable,
}
/// Immutable per-attempt input: deliberately not Debug/Serialize.
pub struct MailMessage {
    pub recipient: String,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<(Format, Vec<u8>)>,
}
pub trait Transport: Send + Sync {
    // Fail closed for transports without a connection-check capability.
    fn check<'a>(&'a self) -> BoxFuture<'a, ConnectionCheck> {
        Box::pin(async { ConnectionCheck::Unavailable })
    }
    fn submit<'a>(&'a self, mail: &'a MailMessage) -> BoxFuture<'a, Submission>;
}
pub struct Disabled;
impl Transport for Disabled {
    fn submit<'a>(&'a self, _: &'a MailMessage) -> BoxFuture<'a, Submission> {
        Box::pin(async { Submission::DefinitePermanent })
    }
}
pub struct Smtp {
    inner: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
    reply_to: Option<String>,
}
impl Smtp {
    pub fn new(settings: &super::config::Settings) -> Result<Self> {
        use super::config::TransportSecurity;
        settings.tls.validate_credentials(
            settings.authenticate,
            &settings.username,
            &settings.password,
        )?;
        let builder = match settings.tls {
            TransportSecurity::Implicit => {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&settings.host)
                    .map_err(|_| DeliveryError("smtp_configuration"))?
            }
            TransportSecurity::Starttls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&settings.host)
                    .map_err(|_| DeliveryError("smtp_configuration"))?
            }
            // Explicit, validated, acknowledged local relay mode only. No fallback.
            TransportSecurity::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&settings.host)
            }
        };
        let mut builder = builder
            .port(settings.port)
            .timeout(Some(std::time::Duration::from_secs(30)));
        if settings.authenticate {
            builder = builder.credentials(Credentials::new(
                settings.username.clone(),
                settings.password.clone(),
            ));
        }
        Ok(Self {
            inner: builder.build(),
            from: settings.from.clone(),
            reply_to: settings.reply_to.clone(),
        })
    }
}
impl Transport for Smtp {
    fn check<'a>(&'a self) -> BoxFuture<'a, ConnectionCheck> {
        Box::pin(async move {
            // No pool feature: a fresh configured TLS/auth connection, NOOP,
            // then QUIT. Never calls send(), MAIL FROM, RCPT TO or DATA.
            match self.inner.test_connection().await {
                Ok(true) => ConnectionCheck::Connected,
                Ok(false) => ConnectionCheck::Unavailable,
                Err(e) if e.is_timeout() => ConnectionCheck::Timeout,
                Err(e) if e.is_tls() => ConnectionCheck::TlsFailed,
                Err(e) if e.status().is_some_and(|code| code.to_string() == "535") => {
                    ConnectionCheck::AuthenticationRejected
                }
                Err(_) => ConnectionCheck::Unavailable,
            }
        })
    }
    fn submit<'a>(&'a self, mail: &'a MailMessage) -> BoxFuture<'a, Submission> {
        Box::pin(async move {
            let message = (|| -> Option<Message> {
                let mut parts = MultiPart::mixed().singlepart(SinglePart::plain(mail.body.clone()));
                for (format, bytes) in &mail.attachments {
                    let mime = if *format == Format::Qr {
                        "image/svg+xml"
                    } else {
                        "text/plain"
                    };
                    parts = parts.singlepart(
                        Attachment::new(format.filename().into())
                            .body(bytes.clone(), mime.parse::<ContentType>().ok()?),
                    );
                }
                let mut builder = Message::builder();
                if let Some(reply_to) = &self.reply_to {
                    builder = builder.reply_to(reply_to.parse().ok()?);
                }
                builder
                    .from(self.from.parse().ok()?)
                    .to(mail.recipient.parse().ok()?)
                    .subject(&mail.subject)
                    .multipart(parts)
                    .ok()
            })();
            let Some(message) = message else {
                return Submission::DefinitePermanent;
            };
            match self.inner.send(message).await {
                Ok(_) => Submission::Accepted,
                Err(e) if e.is_transient() => Submission::DefiniteTransient,
                Err(e) if e.is_permanent() => Submission::DefinitePermanent,
                Err(_) => Submission::Unknown,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    fn settings(port: u16, tls: &str) -> super::super::config::Settings {
        super::super::config::Settings::parse(
            |name| match name {
                "AWG_EMAIL_ENABLED" => Some("true".into()),
                "AWG_SMTP_HOST" => Some("127.0.0.1".into()),
                "AWG_SMTP_PORT" => Some(port.to_string()),
                "AWG_SMTP_TLS" => Some(tls.into()),
                "AWG_SMTP_FROM" => Some("test@example.test".into()),
                "AWG_SMTP_USERNAME" => Some("fixture-user".into()),
                "AWG_SMTP_PASSWORD" => Some("fixture-password".into()),
                _ => None,
            },
            true,
        )
        .unwrap()
    }
    fn mail() -> MailMessage {
        MailMessage {
            recipient: "recipient@example.test".into(),
            subject: "Fixture".into(),
            body: "synthetic test message".into(),
            attachments: vec![],
        }
    }
    #[tokio::test]
    async fn delivery_smtp_requires_starttls_before_auth_or_mail() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"220 fixture ESMTP\r\n").await.unwrap();
            let mut reader = BufReader::new(socket);
            let mut transcript = String::new();
            reader.read_line(&mut transcript).await.unwrap();
            assert!(transcript.starts_with("EHLO "));
            reader
                .get_mut()
                .write_all(b"250-fixture\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                reader.read_to_string(&mut transcript),
            )
            .await;
            transcript
        });
        let transport = Smtp::new(&settings(port, "starttls")).unwrap();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(4), transport.submit(&mail()))
                .await
                .unwrap();
        assert_eq!(result, Submission::Unknown);
        let transcript = server.await.unwrap();
        assert!(!transcript.contains("AUTH "));
        assert!(!transcript.contains("MAIL FROM"));
        assert!(!transcript.contains("DATA"));
        assert!(!transcript.contains("fixture-password"));
    }
    #[tokio::test]
    async fn delivery_smtp_rejects_untrusted_tls_certificate() {
        use tokio_rustls::{
            rustls::{
                self,
                pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
            },
            TlsAcceptor,
        };
        let certificate = CertificateDer::from(
            include_bytes!("../../tests/fixtures/delivery-tls/certificate.der").to_vec(),
        );
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../../tests/fixtures/delivery-tls/key.der").to_vec(),
        ));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, _) = listener.accept().await.unwrap();
                assert!(
                    acceptor.accept(socket).await.is_err(),
                    "client must refuse the untrusted certificate"
                );
            }
        });
        let transport = Smtp::new(&settings(port, "implicit")).unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(4), transport.submit(&mail()))
                .await
                .unwrap(),
            Submission::Unknown
        );
        // Some rustls connect failures are wrapped as a generic connection
        // error by lettre. Never invent a TLS stage from an error string.
        assert!(matches!(
            transport.check().await,
            ConnectionCheck::TlsFailed | ConnectionCheck::Unavailable
        ));
        tokio::time::timeout(std::time::Duration::from_secs(4), server)
            .await
            .unwrap()
            .unwrap();
    }
    #[tokio::test]
    async fn panel_smtp_plaintext_check_uses_only_ehlo_noop_quit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            reader
                .get_mut()
                .write_all(b"220 fixture ESMTP\r\n")
                .await
                .unwrap();
            let mut commands = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let reply = if line.starts_with("EHLO ") {
                    b"250-fixture\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n".as_slice()
                } else if line == "NOOP\r\n" {
                    b"250 OK\r\n".as_slice()
                } else if line == "QUIT\r\n" {
                    b"221 Bye\r\n".as_slice()
                } else {
                    panic!("unexpected SMTP command during connection check")
                };
                let quit = line.starts_with("QUIT");
                commands.push(line);
                reader.get_mut().write_all(reply).await.unwrap();
                if quit {
                    break;
                }
            }
            commands
        });
        let mut settings = settings(port, "starttls");
        settings.tls = super::super::config::TransportSecurity::None;
        settings.authenticate = false;
        settings.username.clear();
        settings.password.clear();
        let transport = Smtp::new(&settings).unwrap();
        assert_eq!(transport.check().await, ConnectionCheck::Connected);
        let commands = server.await.unwrap();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[1], "NOOP\r\n");
        assert_eq!(commands[2], "QUIT\r\n");
        settings.password = "retained-fixture-password".into();
        assert!(matches!(
            Smtp::new(&settings),
            Err(DeliveryError("plaintext_auth_forbidden"))
        ));
    }
    #[tokio::test]
    async fn panel_smtp_connection_failure_is_sanitized() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(
            Smtp::new(&settings(port, "starttls"))
                .unwrap()
                .check()
                .await,
            ConnectionCheck::Unavailable
        );
    }
    #[tokio::test]
    async fn panel_smtp_check_starttls_failure_never_downgrades_or_sends_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            reader
                .get_mut()
                .write_all(b"220 fixture ESMTP\r\n")
                .await
                .unwrap();
            let mut transcript = String::new();
            reader.read_line(&mut transcript).await.unwrap();
            assert!(transcript.starts_with("EHLO "));
            reader
                .get_mut()
                .write_all(b"250-fixture\r\n250 AUTH PLAIN\r\n")
                .await
                .unwrap();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                reader.read_to_string(&mut transcript),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!transcript.contains("AUTH "));
            assert!(!transcript.contains("MAIL"));
            assert!(!transcript.contains("RCPT"));
            assert!(!transcript.contains("DATA"));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "must not reconnect with plaintext fallback"
            );
        });
        let result = Smtp::new(&settings(port, "starttls"))
            .unwrap()
            .check()
            .await;
        assert_ne!(result, ConnectionCheck::Connected);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn panel_smtp_tls_auth_check_never_submits_and_classifies_rejection() {
        use lettre::transport::smtp::client::{Certificate, Tls, TlsParameters};
        use tokio_rustls::{
            rustls::{
                self,
                pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
            },
            TlsAcceptor,
        };
        let der = include_bytes!("../../tests/fixtures/delivery-tls/server.der").to_vec();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../../tests/fixtures/delivery-tls/key.der").to_vec(),
        ));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(der.clone())], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
        for accepted in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let acceptor = acceptor.clone();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(acceptor.accept(socket).await.unwrap());
                reader
                    .get_mut()
                    .write_all(b"220 fixture ESMTP\r\n")
                    .await
                    .unwrap();
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                assert!(line.starts_with("EHLO "));
                reader
                    .get_mut()
                    .write_all(b"250-fixture\r\n250 AUTH PLAIN\r\n")
                    .await
                    .unwrap();
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                assert!(line.starts_with("AUTH PLAIN "));
                reader
                    .get_mut()
                    .write_all(if accepted {
                        b"235 Authenticated\r\n"
                    } else {
                        b"535 fixture-secret-canary\r\n"
                    })
                    .await
                    .unwrap();
                if accepted {
                    line.clear();
                    reader.read_line(&mut line).await.unwrap();
                    assert_eq!(line, "NOOP\r\n");
                    reader.get_mut().write_all(b"250 OK\r\n").await.unwrap();
                    line.clear();
                    reader.read_line(&mut line).await.unwrap();
                    assert_eq!(line, "QUIT\r\n");
                    reader.get_mut().write_all(b"221 Bye\r\n").await.unwrap();
                } else {
                    line.clear();
                    if let Err(error) = reader.read_to_string(&mut line).await {
                        // Lettre aborts a rejected authentication connection;
                        // a TLS close_notify is not required for this failure.
                        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
                    }
                    assert!(!line.contains("MAIL"));
                    assert!(!line.contains("RCPT"));
                    assert!(!line.contains("DATA"));
                }
            });
            // Trust only this public disposable fixture, with normal hostname and
            // certificate verification. Production root selection is unchanged.
            let tls = TlsParameters::builder("localhost".into())
                .add_root_certificate(Certificate::from_der(der.clone()).unwrap())
                .build()
                .unwrap();
            let transport = Smtp {
                inner: AsyncSmtpTransport::<Tokio1Executor>::relay("127.0.0.1")
                    .unwrap()
                    .port(port)
                    .tls(Tls::Wrapper(tls))
                    .credentials(Credentials::new(
                        "fixture-user".into(),
                        "fixture-password".into(),
                    ))
                    .build(),
                from: "sender@example.test".into(),
                reply_to: None,
            };
            let outcome =
                tokio::time::timeout(std::time::Duration::from_secs(4), transport.check())
                    .await
                    .unwrap();
            assert_eq!(
                outcome,
                if accepted {
                    ConnectionCheck::Connected
                } else {
                    ConnectionCheck::AuthenticationRejected
                }
            );
            assert!(!serde_json::to_string(&outcome).unwrap().contains("canary"));
            server.await.unwrap();
        }
    }
}
