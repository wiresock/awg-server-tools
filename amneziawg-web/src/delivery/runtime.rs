// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

//! Immutable configuration snapshots and cancellation-safe configuration apply.
use super::{config::Settings, service::DeliveryContext, settings, smtp::Transport, *};
use std::sync::{atomic::Ordering, Arc};

#[derive(Clone)]
pub struct RuntimeConfiguration {
    pub revision: i64,
    pub settings: Settings,
    pub transport: Arc<dyn Transport>,
}

pub trait TransportFactory: Send + Sync {
    fn build(&self, settings: &Settings) -> Result<Arc<dyn Transport>>;
}
impl<F> TransportFactory for F
where
    F: Fn(&Settings) -> Result<Arc<dyn Transport>> + Send + Sync,
{
    fn build(&self, settings: &Settings) -> Result<Arc<dyn Transport>> {
        self(settings)
    }
}
pub struct SmtpFactory;
impl TransportFactory for SmtpFactory {
    fn build(&self, settings: &Settings) -> Result<Arc<dyn Transport>> {
        if settings.enabled {
            Ok(Arc::new(super::smtp::Smtp::new(settings)?))
        } else {
            Ok(Arc::new(super::smtp::Disabled))
        }
    }
}

#[derive(Serialize)]
pub struct SettingsView {
    pub revision: i64,
    pub source: &'static str,
    pub enabled: bool,
    pub operational: bool,
    pub host: String,
    pub port: u16,
    pub tls: super::config::TransportSecurity,
    pub authenticate: bool,
    pub username: String,
    pub credentials_present: bool,
    pub from: String,
    pub reply_to: Option<String>,
    pub public_base: Option<String>,
    pub link_enabled: bool,
    pub ttl_seconds: i64,
    pub storage_ready: bool,
    pub blocked_reason: Option<&'static str>,
}

impl DeliveryContext {
    /// Explicit admin-only tests may use an unsaved snapshot. Building a
    /// transport performs no network I/O and never changes the active runtime.
    pub(crate) fn test_configuration(
        &self,
        revision: i64,
        draft: Option<settings::PanelSettingsInput>,
    ) -> Result<Arc<RuntimeConfiguration>> {
        self.validate_test_revision(revision)?;
        let before = self.runtime();
        if before.revision != revision {
            return Err(DeliveryError("settings_changed"));
        }
        let Some(mut input) = draft else {
            self.enabled()?;
            return Ok(before);
        };
        if input.revision != revision {
            return Err(DeliveryError("settings_changed"));
        }
        // Enable only this transient transport, regardless of the form's
        // persisted sending toggle. The caller has already required admin auth.
        input.enabled = true;
        let candidate = input.resolve_change(&before.settings, true)?;
        let transport = self.transport_factory.build(&candidate)?;
        Ok(Arc::new(RuntimeConfiguration {
            revision,
            settings: candidate,
            transport,
        }))
    }

    /// Repeat under admission guards after resolving Keep against a snapshot.
    pub(crate) fn validate_test_revision(&self, revision: i64) -> Result<()> {
        self.startup_ready()?;
        if self.quarantined.load(Ordering::Acquire) {
            return Err(DeliveryError("delivery_recovery_required"));
        }
        if self.runtime().revision != revision {
            return Err(DeliveryError("settings_changed"));
        }
        Ok(())
    }

    pub fn runtime(&self) -> Arc<RuntimeConfiguration> {
        self.runtime.read().unwrap().clone()
    }
    pub fn settings_view(&self) -> SettingsView {
        let runtime = self.runtime();
        let s = &runtime.settings;
        SettingsView {
            blocked_reason: self.startup_blocked,
            revision: runtime.revision,
            source: if self.startup_blocked.is_some() {
                "unavailable"
            } else if runtime.revision == 0 {
                "environment"
            } else {
                "panel"
            },
            enabled: s.enabled,
            operational: s.enabled
                && self.startup_ready().is_ok()
                && !self.quarantined.load(Ordering::Acquire),
            host: s.host.clone(),
            port: s.port,
            tls: s.tls,
            authenticate: s.authenticate,
            username: s.username.clone(),
            credentials_present: !s.password.is_empty(),
            from: s.from.clone(),
            reply_to: s.reply_to.clone(),
            public_base: s.public_base.as_ref().map(|u| u.as_str().to_owned()),
            link_enabled: s.public_base.is_some(),
            ttl_seconds: s.ttl,
            storage_ready: self.startup_ready().is_ok()
                && settings::verify_private_database(&self.source.db.pool).is_ok(),
        }
    }

    // Only called with admission guards held. It does not perform crash recovery
    // on live sending jobs. Missing previously-saved state is not an env fallback.
    async fn reload_configuration(&self, auth_enabled: bool) -> Result<()> {
        self.startup_ready()?;
        let restored =
            if let Some(saved) = settings::load_saved(&self.source.db.pool, auth_enabled).await? {
                let transport = self.transport_factory.build(&saved.settings)?;
                Arc::new(RuntimeConfiguration {
                    revision: saved.revision,
                    settings: saved.settings,
                    transport,
                })
            } else if self.runtime().revision != 0 {
                return Err(DeliveryError("settings_recovery_required"));
            } else {
                self.runtime()
            };
        // Quarantine may also follow an uncertain worker completion. Before
        // reopening admission, durably revoke every old binding; merely reading
        // settings cannot prove an earlier grant revocation committed.
        let mut tx = self.source.db.pool.begin().await?;
        sqlx::query("UPDATE delivery_clients SET binding_version=binding_version+1")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        *self.runtime.write().unwrap() = restored;
        self.quarantined.store(false, Ordering::Release);
        Ok(())
    }

    pub async fn update_settings(
        self: &Arc<Self>,
        body: settings::PanelSettingsInput,
        auth_enabled: bool,
        admin_base: String,
    ) -> Result<SettingsView> {
        let ctx = self.clone();
        // A disconnected request cannot cancel SQLite commit between durable
        // invalidation and the in-memory pointer swap. No SMTP is done here.
        tokio::spawn(async move { ctx.apply_settings(body, auth_enabled, &admin_base).await })
            .await
            .map_err(|_| DeliveryError("settings_result_unknown"))?
    }
    async fn apply_settings(
        &self,
        body: settings::PanelSettingsInput,
        auth_enabled: bool,
        admin_base: &str,
    ) -> Result<SettingsView> {
        self.startup_ready()?;
        let before = self.runtime();
        if before.revision != body.revision {
            return Err(DeliveryError("settings_changed"));
        }
        let candidate = body.resolve_change(&before.settings, auth_enabled)?;
        crate::web::delivery_base_path(
            admin_base,
            candidate.enabled && candidate.public_base.is_some(),
        )
        .map_err(|_| DeliveryError("public_route_conflict"))?;
        let transport = self.transport_factory.build(&candidate)?;
        let (guards, tx, revision) = tokio::time::timeout(self.admission_budget, async {
            let guards = self.guards().await?;
            if self.quarantined.load(Ordering::Acquire) {
                self.reload_configuration(auth_enabled).await?;
                // Require a fresh read after recovery. A Keep password resolved
                // from the pre-recovery snapshot must never overwrite newer data.
                return Err(DeliveryError("settings_changed"));
            }
            if self.runtime().revision != body.revision {
                return Err(DeliveryError("settings_changed"));
            }
            let mut tx = self.source.db.pool.begin().await?;
            let revision =
                settings::write_saved(&self.source.db.pool, &mut tx, body.revision, &candidate)
                    .await?;
            Ok::<_, DeliveryError>((guards, tx, revision))
        })
        .await
        .map_err(|_| DeliveryError("admission_timeout"))??;
        self.quarantined.store(true, Ordering::Release);
        if tx.commit().await.is_err() {
            // A failed commit response is not proof it rolled back. Reload only
            // durable state; if unavailable, stay quarantined until retry/restart.
            let _ = self.reload_configuration(auth_enabled).await;
            return Err(DeliveryError("settings_result_unknown"));
        }
        *self.runtime.write().unwrap() = Arc::new(RuntimeConfiguration {
            revision,
            settings: candidate,
            transport,
        });
        self.quarantined.store(false, Ordering::Release);
        drop(guards);
        Ok(self.settings_view())
    }
}
