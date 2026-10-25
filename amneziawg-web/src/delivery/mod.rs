// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

//! Explicit delivery of immutable, freshly admitted exports. No SMTP under guards.
pub mod config;
pub mod exports;
#[cfg(test)]
mod panel_tests;
pub mod runtime;
pub mod service;
pub mod settings;
pub mod smtp;
pub mod smtp_check;
pub mod test_mail;
#[cfg(test)]
pub(crate) mod tests;
pub mod tokens;
pub mod worker;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{future::Future, pin::Pin};

pub type Result<T> = std::result::Result<T, DeliveryError>;
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Fixed public codes only. Underlying errors may contain secrets; never wrap them.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("{0}")]
pub struct DeliveryError(pub &'static str);
impl From<sqlx::Error> for DeliveryError {
    fn from(_: sqlx::Error) -> Self {
        Self("storage_unavailable")
    }
}
impl From<std::io::Error> for DeliveryError {
    fn from(_: std::io::Error) -> Self {
        Self("export_unavailable")
    }
}

pub fn random_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Direct,
    Link,
}
impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Link => "link",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Conf,
    Qr,
    VpnUri,
}
impl Format {
    pub fn render(self, text: &str) -> Result<Vec<u8>> {
        match self {
            Self::Conf => Ok(text.as_bytes().to_vec()),
            Self::VpnUri => crate::vpn_uri::encode(text.as_bytes())
                .map(String::into_bytes)
                .map_err(|_| DeliveryError("export_unavailable")),
            Self::Qr => qrcode::QrCode::new(text.as_bytes())
                .map(|qr| {
                    qr.render::<qrcode::render::svg::Color>()
                        .min_dimensions(256, 256)
                        .build()
                        .into_bytes()
                })
                .map_err(|_| DeliveryError("qr_too_large")),
        }
    }
    pub fn filename(self) -> &'static str {
        match self {
            Self::Conf => "client.conf",
            Self::Qr => "client.svg",
            Self::VpnUri => "vpn-uri.txt",
        }
    }
}

pub struct AdmissionGuards {
    _state: tokio::sync::MutexGuard<'static, ()>,
    _lifecycle: std::fs::File,
    _mapping: tokio::sync::MutexGuard<'static, ()>,
}
impl AdmissionGuards {
    pub async fn acquire(path: &std::path::Path) -> Result<Self> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let state = crate::admin::EXPIRATION_STATE_LOCK.lock().await;
            let lifecycle = loop {
                match crate::admin::client_manager::acquire_lifecycle_lock(path) {
                    Ok(file) => break file,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await
                    }
                    Err(_) => return Err(DeliveryError("lock_unavailable")),
                }
            };
            let mapping = crate::poller::acquire_config_mapping_lock().await;
            Ok(Self {
                _state: state,
                _lifecycle: lifecycle,
                _mapping: mapping,
            })
        })
        .await
        .map_err(|_| DeliveryError("busy"))?
    }
}
