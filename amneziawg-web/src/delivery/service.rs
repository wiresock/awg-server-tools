// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

use super::{
    config::Settings,
    exports::{ExportSnapshot, ExportSource},
    smtp::Transport,
    *,
};
use crate::db::delivery::{self, Client};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[derive(Clone, Serialize)]
pub struct PreviewItem {
    pub client_id: String,
    pub recipient: String,
    pub version: i64,
    pub name: String,
    #[serde(skip)]
    pub digest: Vec<u8>,
}
#[derive(Clone, Serialize)]
pub struct Preview {
    pub skipped: Vec<SkippedItem>,
    pub id: String,
    pub expires_at: i64,
    pub settings_revision: i64,
    pub ttl_seconds: i64,
    pub mode: Mode,
    pub formats: Vec<Format>,
    pub items: Vec<PreviewItem>,
    #[serde(skip)]
    pub actor: String,
}
#[derive(Clone, Serialize)]
pub struct SkippedItem {
    pub client_id: String,
    pub reason: String,
}
pub struct DeliveryContext {
    pub(crate) admission_budget: std::time::Duration,
    pub(crate) quarantined: std::sync::atomic::AtomicBool,
    pub source: ExportSource,
    pub(crate) runtime: std::sync::RwLock<Arc<super::runtime::RuntimeConfiguration>>,
    pub(crate) transport_factory: Arc<dyn super::runtime::TransportFactory>,
    pub(crate) test_slot: Arc<tokio::sync::Semaphore>,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    previews: Mutex<HashMap<String, Preview>>,
    _worker_lock: Option<std::fs::File>,
}
impl DeliveryContext {
    pub fn new(
        source: ExportSource,
        settings: Settings,
        transport: Arc<dyn Transport>,
        worker_lock: Option<std::fs::File>,
        revision: i64,
    ) -> Self {
        Self {
            admission_budget: std::time::Duration::from_secs(2),
            quarantined: std::sync::atomic::AtomicBool::new(false),
            source,
            runtime: std::sync::RwLock::new(Arc::new(super::runtime::RuntimeConfiguration {
                revision,
                settings,
                transport,
            })),
            transport_factory: Arc::new(super::runtime::SmtpFactory),
            test_slot: Arc::new(tokio::sync::Semaphore::new(1)),
            clock: Arc::new(now),
            previews: Mutex::new(HashMap::new()),
            _worker_lock: worker_lock,
        }
    }
    pub fn time(&self) -> i64 {
        (self.clock)()
    }
    pub fn enabled(&self) -> Result<()> {
        if self.quarantined.load(std::sync::atomic::Ordering::Acquire) {
            return Err(DeliveryError("delivery_recovery_required"));
        }
        if self.runtime().settings.enabled {
            Ok(())
        } else {
            Err(DeliveryError("delivery_disabled"))
        }
    }
    pub async fn guards(&self) -> Result<AdmissionGuards> {
        AdmissionGuards::acquire(&self.source.lock_directory).await
    }
    pub async fn recover(&self) -> Result<()> {
        let mut tx = self.source.db.pool.begin().await?;
        sqlx::query("UPDATE email_jobs SET state='unknown',error_code='restart_unknown' WHERE state='sending'").execute(&mut *tx).await?;
        sqlx::query("UPDATE delivery_grants SET revoked_at=COALESCE(revoked_at,?) WHERE job_id IN (SELECT id FROM email_jobs WHERE state='unknown')").bind(self.time()).execute(&mut *tx).await?;
        sqlx::query("UPDATE email_test_attempts SET state='unknown',error_code='restart_unknown' WHERE state='sending'").execute(&mut *tx).await?;
        let fingerprint = self.runtime().settings.fingerprint();
        let old: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT config_fingerprint FROM delivery_settings WHERE id=1")
                .fetch_optional(&mut *tx)
                .await?;
        if old.as_ref() != Some(&fingerprint) || !self.runtime().settings.enabled {
            sqlx::query("UPDATE delivery_clients SET binding_version=binding_version+1")
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("INSERT INTO delivery_settings VALUES(1,?) ON CONFLICT(id) DO UPDATE SET config_fingerprint=excluded.config_fingerprint").bind(fingerprint).execute(&mut *tx).await?;
        tx.commit().await?;
        self.quarantined
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(())
    }
    pub async fn contacts(&self) -> Result<Vec<Client>> {
        let _guards = self.guards().await?;
        // Create blank contacts only; retained contacts are never matched by name/IP.
        for peer in crate::db::peers::list_all(&self.source.db.pool).await? {
            let Some(name) = peer.managed_client_name else {
                continue;
            };
            let Some(path) = peer.config_path else {
                continue;
            };
            let Some(stem) = std::path::Path::new(&path)
                .file_stem()
                .and_then(|s| s.to_str())
            else {
                continue;
            };
            let Some((interface, suffix)) = stem.split_once("-client-") else {
                continue;
            };
            if suffix != name || peer.archived != 0 {
                continue;
            }
            sqlx::query("INSERT INTO delivery_clients(id,peer_id,interface,managed_name,last_public_key) VALUES(?,?,?,?,?) ON CONFLICT(peer_id) DO NOTHING")
                .bind(random_id()).bind(peer.id).bind(interface).bind(name).bind(peer.public_key).execute(&self.source.db.pool).await?;
        }
        Ok(
            sqlx::query_as("SELECT * FROM delivery_clients ORDER BY managed_name,id")
                .fetch_all(&self.source.db.pool)
                .await?,
        )
    }
    pub async fn set_email(&self, id: &str, version: i64, email: Option<&str>) -> Result<()> {
        let email = email
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(config::mailbox)
            .transpose()?;
        let _guards = self.guards().await?;
        let count=sqlx::query("UPDATE delivery_clients SET email=?,binding_version=binding_version+1 WHERE id=? AND binding_version=?")
            .bind(email).bind(id).bind(version).execute(&self.source.db.pool).await?.rows_affected();
        if count != 1 {
            return Err(DeliveryError("changed"));
        }
        Ok(())
    }
    pub async fn revoke(&self, id: &str) -> Result<()> {
        let _guards = self.guards().await?;
        delivery::invalidate(&self.source.db.pool, id).await
    }
    pub async fn delete_contact(&self, id: &str, version: i64) -> Result<()> {
        let _guards = self.guards().await?;
        // Preserve in-flight outcomes rather than cascading them away.
        let changed=sqlx::query("UPDATE delivery_clients SET email=NULL,peer_id=NULL,retired_at=?,binding_version=binding_version+1 WHERE id=? AND binding_version=?")
            .bind(self.time()).bind(id).bind(version).execute(&self.source.db.pool).await?.rows_affected();
        if changed != 1 {
            return Err(DeliveryError("changed"));
        }
        Ok(())
    }
    pub async fn rebind(
        &self,
        id: &str,
        version: i64,
        target_id: &str,
        target_version: i64,
    ) -> Result<()> {
        let guards = self.guards().await?;
        let target = self
            .source
            .snapshot(target_id, &guards, self.time() + 30)
            .await?;
        let old = delivery::client(&self.source.db.pool, id).await?;
        if old.binding_version != version
            || old.peer_id.is_some()
            || old.retired_at.is_some()
            || target.client.binding_version != target_version
            || target.client.email.is_some()
            || old.interface != target.client.interface
            || id == target_id
        {
            return Err(DeliveryError("changed"));
        }
        let mut tx = self.source.db.pool.begin().await?;
        sqlx::query("UPDATE delivery_settings SET id=id WHERE id=1")
            .execute(&mut *tx)
            .await?;
        self.validate_transaction(&mut tx, &target, self.time() + 30)
            .await?;
        let detached=sqlx::query("UPDATE delivery_clients SET peer_id=NULL,retired_at=?,binding_version=binding_version+1 WHERE id=? AND binding_version=? AND email IS NULL")
            .bind(self.time()).bind(target_id).bind(target_version).execute(&mut *tx).await?.rows_affected();
        if detached != 1 {
            return Err(DeliveryError("changed"));
        }
        let changed=sqlx::query("UPDATE delivery_clients SET peer_id=?,managed_name=?,last_public_key=?,export_digest=?,binding_version=binding_version+1 WHERE id=? AND binding_version=? AND peer_id IS NULL")
            .bind(target.client.peer_id).bind(target.client.managed_name).bind(target.client.last_public_key).bind(target.digest).bind(id).bind(version).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(DeliveryError("changed"));
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn preview(
        &self,
        actor: &str,
        ids: &[String],
        mode: Mode,
        formats: &[Format],
    ) -> Result<Preview> {
        self.preview_with_ttl(actor, ids, mode, formats, None).await
    }
    pub async fn preview_with_ttl(
        &self,
        actor: &str,
        ids: &[String],
        mode: Mode,
        formats: &[Format],
        ttl: Option<i64>,
    ) -> Result<Preview> {
        // One deadline includes every lock/DB wait, helper and selected client.
        tokio::time::timeout(
            self.admission_budget,
            self.preview_inner(actor, ids, mode, formats, ttl),
        )
        .await
        .map_err(|_| DeliveryError("admission_timeout"))?
    }
    async fn preview_inner(
        &self,
        actor: &str,
        ids: &[String],
        mode: Mode,
        formats: &[Format],
        ttl: Option<i64>,
    ) -> Result<Preview> {
        self.enabled()?;
        if ids.is_empty() || ids.len() > 50 || formats.is_empty() || formats.len() > 3 {
            return Err(DeliveryError("selection_limit"));
        }
        let guards = self.guards().await?;
        self.enabled()?;
        let runtime = self.runtime();
        if mode == Mode::Link && runtime.settings.public_base.is_none() {
            return Err(DeliveryError("link_unavailable"));
        }
        let ttl_seconds = ttl.unwrap_or(runtime.settings.ttl);
        if !(300..=604800).contains(&ttl_seconds) {
            return Err(DeliveryError("invalid_ttl"));
        }
        let mut items = Vec::new();
        let mut skipped = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for id in ids {
            if !seen.insert(id) {
                return Err(DeliveryError("duplicate_client"));
            }
            let snapshot = match self.source.snapshot(id, &guards, self.time() + 30).await {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    skipped.push(SkippedItem {
                        client_id: id.clone(),
                        reason: error.0.into(),
                    });
                    continue;
                }
            };
            let recipient = match snapshot
                .client
                .email
                .as_deref()
                .ok_or(DeliveryError("email_missing"))
                .and_then(config::mailbox)
            {
                Ok(recipient) => recipient,
                Err(error) => {
                    skipped.push(SkippedItem {
                        client_id: id.clone(),
                        reason: error.0.into(),
                    });
                    continue;
                }
            };
            // Surface QR capacity errors before confirmation, without storing bytes.
            if let Some(error) = formats
                .iter()
                .find_map(|format| format.render(&snapshot.content).err())
            {
                skipped.push(SkippedItem {
                    client_id: id.clone(),
                    reason: error.0.into(),
                });
                continue;
            }
            items.push(PreviewItem {
                client_id: id.clone(),
                recipient,
                version: snapshot.client.binding_version,
                name: snapshot.client.managed_name,
                digest: snapshot.digest,
            });
        }
        let preview = Preview {
            skipped,
            id: random_id(),
            expires_at: self.time() + 300,
            settings_revision: runtime.revision,
            ttl_seconds,
            mode,
            formats: formats.to_vec(),
            items,
            actor: actor.into(),
        };
        let mut store = self.previews.lock().await;
        store.retain(|_, p| p.expires_at > self.time());
        if store.len() >= 100 {
            return Err(DeliveryError("preview_limit"));
        }
        store.insert(preview.id.clone(), preview.clone());
        Ok(preview)
    }
    pub async fn enqueue(
        &self,
        actor: &str,
        preview_id: &str,
        request: &str,
    ) -> Result<Vec<String>> {
        // On timeout/drop SQLx rolls back an unfinished transaction. A response
        // lost at commit is retried with this same ID and durably deduplicated.
        tokio::time::timeout(
            self.admission_budget,
            self.enqueue_inner(actor, preview_id, request),
        )
        .await
        .map_err(|_| DeliveryError("admission_timeout"))?
    }
    async fn enqueue_inner(
        &self,
        actor: &str,
        preview_id: &str,
        request: &str,
    ) -> Result<Vec<String>> {
        self.enabled()?;
        // Request identity is the immutable preview ID, preventing payload reuse.
        if request != preview_id {
            return Err(DeliveryError("invalid_request_id"));
        }
        let guards = self.guards().await?;
        self.enabled()?;
        let existing: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM email_jobs WHERE request_id=? AND actor=? ORDER BY id",
        )
        .bind(request)
        .bind(actor)
        .fetch_all(&self.source.db.pool)
        .await?;
        if !existing.is_empty() {
            return Ok(existing);
        }
        let preview = self
            .previews
            .lock()
            .await
            .get(preview_id)
            .cloned()
            .ok_or(DeliveryError("preview_expired"))?;
        if preview.actor != actor || preview.expires_at <= self.time() {
            return Err(DeliveryError("preview_expired"));
        }
        if preview.settings_revision != self.runtime().revision {
            return Err(DeliveryError("settings_changed"));
        }
        if preview.items.is_empty() {
            return Err(DeliveryError("no_eligible_clients"));
        }
        for item in &preview.items {
            let snapshot = self
                .source
                .snapshot(&item.client_id, &guards, self.time() + 30)
                .await?;
            if snapshot.client.binding_version != item.version
                || snapshot.digest != item.digest
                || snapshot.client.email.as_deref() != Some(&item.recipient)
            {
                return Err(DeliveryError("changed"));
            }
        }
        let mut tx = self.source.db.pool.begin().await?;
        sqlx::query("DELETE FROM delivery_send_budget WHERE at<=?")
            .bind(self.time() - 3600)
            .execute(&mut *tx)
            .await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM email_jobs WHERE state IN ('queued','sending')",
        )
        .fetch_one(&mut *tx)
        .await?;
        let admin_count: i64 =
            sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM delivery_send_budget WHERE actor='admin') + (SELECT COUNT(*) FROM email_jobs WHERE state='queued' AND attempts=0)")
                .fetch_one(&mut *tx)
                .await?;
        if count + preview.items.len() as i64 > 500
            || admin_count + preview.items.len() as i64 > 100
        {
            return Err(DeliveryError("send_limit"));
        }
        let mut ids = Vec::new();
        for item in &preview.items {
            let count: i64 =
                sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM delivery_send_budget WHERE client_id=?1) + (SELECT COUNT(*) FROM email_jobs WHERE client_id=?1 AND state='queued' AND attempts=0)")
                    .bind(&item.client_id)
                    .fetch_one(&mut *tx)
                    .await?;
            let valid:i64=sqlx::query_scalar("SELECT COUNT(*) FROM delivery_clients c JOIN peers p ON p.id=c.peer_id WHERE c.id=? AND c.binding_version=? AND c.email=? AND c.export_digest=? AND c.retired_at IS NULL AND p.public_key=c.last_public_key AND p.managed_client_name=c.managed_name AND p.disabled=0 AND p.archived=0 AND p.removal_pending=0 AND (p.expires_at IS NULL OR unixepoch(p.expires_at)>?)")
                .bind(&item.client_id).bind(item.version).bind(&item.recipient).bind(&item.digest).bind(self.time()+30).fetch_one(&mut *tx).await?;
            if count >= 5 {
                return Err(DeliveryError("send_limit"));
            }
            if valid != 1 {
                return Err(DeliveryError("changed"));
            }
            let id = random_id();
            sqlx::query("INSERT INTO email_jobs(id,client_id,request_id,actor,recipient,mode,formats,binding_version,export_digest,state,created_at,next_attempt_at,link_ttl_seconds) VALUES(?,?,?,?,?,?,?,?,?,'queued',?,?,?)")
                .bind(&id).bind(&item.client_id).bind(request).bind(actor).bind(&item.recipient).bind(preview.mode.as_str()).bind(serde_json::to_string(&preview.formats).unwrap()).bind(item.version).bind(&item.digest).bind(self.time()).bind(self.time()).bind(preview.ttl_seconds).execute(&mut *tx).await?;
            ids.push(id);
        }
        tx.commit().await?;
        Ok(ids)
    }
    pub async fn validate_transaction(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        snapshot: &ExportSnapshot,
        deadline: i64,
    ) -> Result<()> {
        let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM delivery_clients c JOIN peers p ON p.id=c.peer_id WHERE c.id=? AND c.binding_version=? AND c.export_digest=? AND c.retired_at IS NULL AND p.public_key=c.last_public_key AND p.disabled=0 AND p.archived=0 AND p.removal_pending=0 AND (p.expires_at IS NULL OR unixepoch(p.expires_at)>?)")
            .bind(&snapshot.client.id).bind(snapshot.client.binding_version).bind(&snapshot.digest).bind(deadline).fetch_one(&mut **tx).await?;
        if count != 1 {
            return Err(DeliveryError("changed"));
        }
        Ok(())
    }
    pub async fn jobs(&self) -> Result<Vec<delivery::Job>> {
        Ok(
            sqlx::query_as("SELECT * FROM email_jobs ORDER BY created_at DESC LIMIT 200")
                .fetch_all(&self.source.db.pool)
                .await?,
        )
    }
    pub async fn purge(&self) -> Result<()> {
        let mut tx = self.source.db.pool.begin().await?;
        sqlx::query(
            "DELETE FROM email_jobs WHERE state NOT IN ('queued','sending') AND created_at<?",
        )
        .bind(self.time() - 30 * 86400)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM delivery_sessions WHERE expires_at<=?")
            .bind(self.time())
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM delivery_grants WHERE expires_at<=?")
            .bind(self.time())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

#[cfg(unix)]
pub fn worker_lock(directory: &std::path::Path) -> Result<std::fs::File> {
    use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join("email-worker.lock"))?;
    if !file.metadata()?.is_file()
        || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err(DeliveryError("worker_already_running"));
    }
    Ok(file)
}
#[cfg(not(unix))]
pub fn worker_lock(_: &std::path::Path) -> Result<std::fs::File> {
    Err(DeliveryError("unix_required"))
}
