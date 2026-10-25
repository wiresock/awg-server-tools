// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

use super::*;
use crate::{
    config_store::ClientConfig,
    db::{delivery::Client, Database},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// No Debug/Serialize: contents include a client private key.
pub struct ExportSnapshot {
    pub client: Client,
    pub digest: Vec<u8>,
    pub content: String,
}

pub trait Ownership: Send + Sync {
    fn verify<'a>(
        &'a self,
        peer_key: &'a str,
        name: &'a str,
        interface: &'a str,
        content: &'a str,
        config: &'a ClientConfig,
    ) -> BoxFuture<'a, Result<()>>;
}
pub struct ServerOwnership {
    pub override_name: Option<String>,
}
impl Ownership for ServerOwnership {
    fn verify<'a>(
        &'a self,
        peer_key: &'a str,
        name: &'a str,
        interface: &'a str,
        content: &'a str,
        config: &'a ClientConfig,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let params = crate::awg::delivery_read_params().await?;
            let params = crate::admin::client_manager::parse_params(&params)
                .map_err(|_| DeliveryError("ownership_unverified"))?;
            if params.server_awg_nic != interface
                || self
                    .override_name
                    .as_deref()
                    .is_some_and(|i| i != interface)
                || config.peer_public_key.as_ref().map(|k| k.0.as_str())
                    != Some(params.server_pub_key.as_str())
            {
                return Err(DeliveryError("ownership_unverified"));
            }
            let private =
                interface_private_key(content).ok_or(DeliveryError("ownership_unverified"))?;
            if crate::awg::delivery_pubkey(private).await? != peer_key {
                return Err(DeliveryError("ownership_unverified"));
            }
            let server = crate::awg::delivery_server_state(interface).await?;
            if !managed_block_matches(&server, name, peer_key, config) {
                return Err(DeliveryError("ownership_unverified"));
            }
            Ok(())
        })
    }
}

fn interface_private_key(text: &str) -> Option<&str> {
    let mut in_interface = false;
    let mut key = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_interface = line.eq_ignore_ascii_case("[Interface]");
        }
        if in_interface {
            if let Some((name, value)) = line.split_once('=') {
                if name.trim().eq_ignore_ascii_case("PrivateKey") {
                    if key.is_some() {
                        return None;
                    }
                    key = Some(value.trim());
                }
            }
        }
    }
    key.filter(|k| k.len() == 44 && !k.chars().any(char::is_control))
}

fn managed_block_matches(server: &str, name: &str, key: &str, config: &ClientConfig) -> bool {
    let start = format!("### Client {name}");
    let mut blocks = 0;
    let mut active = false;
    let mut public = None;
    let mut addresses = None;
    let mut matched = false;
    let mut peer_sections = 0;
    for line in server
        .lines()
        .map(str::trim)
        .chain(std::iter::once("### Client __end__"))
    {
        if line.starts_with("### Client ") && active {
            matched = peer_sections == 1
                && public == Some(key)
                && addresses.is_some_and(|a| config.matches_addresses(a));
            active = false;
        }
        if line == start {
            blocks += 1;
            active = true;
            public = None;
            addresses = None;
            peer_sections = 0;
        } else if active {
            if line.starts_with('[') {
                if line != "[Peer]" {
                    return false;
                }
                peer_sections += 1;
            }
            if let Some((field, value)) = line.split_once('=') {
                let slot = match field.trim() {
                    "PublicKey" => &mut public,
                    "AllowedIPs" => &mut addresses,
                    _ => continue,
                };
                if slot.replace(value.trim()).is_some() {
                    return false;
                }
            }
        }
    }
    blocks == 1 && !active && matched
}

pub struct ExportSource {
    pub db: Database,
    pub directory: PathBuf,
    pub lock_directory: PathBuf,
    pub ownership: Arc<dyn Ownership>,
}
impl ExportSource {
    pub async fn snapshot(
        &self,
        client_id: &str,
        _guards: &AdmissionGuards,
        deadline: i64,
    ) -> Result<ExportSnapshot> {
        let result = self.read(client_id, deadline).await;
        if result.is_err() {
            crate::db::delivery::invalidate(&self.db.pool, client_id).await?;
        }
        result
    }
    async fn read(&self, client_id: &str, deadline: i64) -> Result<ExportSnapshot> {
        let mut client = crate::db::delivery::client(&self.db.pool, client_id).await?;
        if client.retired_at.is_some() {
            return Err(DeliveryError("ineligible"));
        }
        let peer_id = client.peer_id.ok_or(DeliveryError("unbound"))?;
        let peer = crate::db::peers::find_by_id(&self.db.pool, peer_id)
            .await?
            .ok_or(DeliveryError("ineligible"))?;
        let pending: i64 = sqlx::query_scalar("SELECT removal_pending FROM peers WHERE id=?")
            .bind(peer_id)
            .fetch_one(&self.db.pool)
            .await?;
        if peer.disabled != 0
            || peer.archived != 0
            || pending != 0
            || peer.expires_at.as_deref().is_some_and(|t| {
                chrono::DateTime::parse_from_rfc3339(t).map_or(true, |t| t.timestamp() <= deadline)
            })
            || peer.public_key != client.last_public_key
            || peer.managed_client_name.as_deref() != Some(&client.managed_name)
        {
            return Err(DeliveryError("ineligible"));
        }
        let path = PathBuf::from(peer.config_path.ok_or(DeliveryError("missing_config"))?);
        let content = read_config(&self.directory, &path).await?;
        let config = ClientConfig::from_content(path, &content);
        if !config.matches_addresses(&peer.allowed_ips) {
            return Err(DeliveryError("ownership_unverified"));
        }
        self.ownership
            .verify(
                &peer.public_key,
                &client.managed_name,
                &client.interface,
                &content,
                &config,
            )
            .await?;
        let digest = hash(content.as_bytes());
        if client.export_digest.as_ref() != Some(&digest) {
            let changed=sqlx::query("UPDATE delivery_clients SET export_digest=?,binding_version=binding_version+1 WHERE id=? AND binding_version=?")
                .bind(&digest).bind(client_id).bind(client.binding_version).execute(&self.db.pool).await?.rows_affected();
            if changed != 1 {
                return Err(DeliveryError("changed"));
            }
            client = crate::db::delivery::client(&self.db.pool, client_id).await?;
        }
        Ok(ExportSnapshot {
            client,
            digest,
            content,
        })
    }
}

/// Both delivery and the existing admin exports use the same file boundary.
pub async fn read_config(directory: &Path, path: &Path) -> Result<String> {
    Ok(crate::config_store::export::read_config(directory, path).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn delivery_server_ownership_rejects_ambiguous_blocks() {
        let config = ClientConfig::from_content(
            "awg0-client-phone.conf".into(),
            "[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = server",
        );
        let valid = "### Client phone\n[Peer]\nPublicKey = client\nAllowedIPs = 10.0.0.2/32\n";
        assert!(managed_block_matches(valid, "phone", "client", &config));
        for bad in [
            format!("{valid}{valid}"),
            valid.replace(
                "PublicKey = client",
                "PublicKey = wrong\nPublicKey = client",
            ),
            format!("{valid}[Peer]\nPublicKey = client\nAllowedIPs = 10.0.0.2/32\n"),
            valid.replace("phone", "other"),
            valid.replace("client", "replacement"),
        ] {
            assert!(
                !managed_block_matches(&bad, "phone", "client", &config),
                "ambiguous/wrong ownership must fail"
            );
        }
    }
    #[tokio::test]
    async fn delivery_safe_reader_rejects_outside_symlink_and_oversize() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let outside = other.path().join("outside.conf");
        std::fs::write(&outside, "secret fixture").unwrap();
        assert!(read_config(root.path(), &outside).await.is_err());
        #[cfg(unix)]
        {
            let link = root.path().join("link.conf");
            std::os::unix::fs::symlink(&outside, &link).unwrap();
            assert!(read_config(root.path(), &link).await.is_err());
        }
        let large = root.path().join("large.conf");
        std::fs::write(
            &large,
            vec![b'x'; crate::config_store::export::MAX_EXPORT_BYTES + 1],
        )
        .unwrap();
        assert!(read_config(root.path(), &large).await.is_err());
        let normal = root.path().join("normal.conf");
        std::fs::write(&normal, "fixture contents").unwrap();
        assert_eq!(
            read_config(root.path(), &normal).await.unwrap(),
            "fixture contents"
        );
    }
}
