// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

//! Background polling task.
//!
//! Uses `tokio::time::interval` so that cycles are tick-aligned: the period
//! between the *start* of consecutive cycles is `interval` seconds, regardless
//! of how long each cycle takes.
//!
//! 0. Resolves the panel mode: which interface this instance follows
//!    (`AWG_INTERFACE`, else `SERVER_AWG_NIC` from the installer params) and
//!    whether it may manage it.  An override naming an interface the installer
//!    does not manage puts the panel into monitoring-only mode.
//! 1. Calls `awg::show_all_dump()` on a blocking thread – reads current AWG state
//!    and keeps only the followed interface.  Other interfaces on the host are
//!    ignored.
//! 2. Writes a snapshot row per peer into `snapshots`.
//! 3. Upserts each peer into the `peers` table.
//!    3b. Removes disabled peers from the running AWG interface
//!    (`awg set <iface> peer <key> remove`; management mode only).  This is a
//!    self-healing safety net; immediate removal also happens at toggle time.
//! 4. Scans the config directory for `*.conf` files.
//! 5. Applies config-to-peer mapping (sets `has_config`, `config_name`,
//!    `config_path` on matching peers).
//! 6. Removes stale peers – DB rows for non-disabled peers whose public
//!    keys no longer appear on the managed AWG interface.  This cleans up
//!    artifacts left when peers are removed outside the web panel, and rows
//!    recorded from other interfaces before the poller was scoped.
//!
//! Errors within a single cycle step are logged and the cycle continues;
//! the overall polling loop never stops due to a single-cycle failure.
//! In management mode, expired managed users are removed before each AWG
//! snapshot, including the poller's immediate first cycle at process startup.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use chrono::SecondsFormat;
use tokio::sync::{Mutex, MutexGuard};
use tracing::{debug, error, info, warn};

use crate::awg;
use crate::config_store;
use crate::db::Database;
use crate::domain::PublicKey;
use crate::managed_interface::{
    scope_to_interface, InterfaceSelector, PanelMode, ScopedInterfaces,
};

/// Serializes access to the clear-all + re-map sequence so that concurrent
/// calls from the poller and on-demand `rescan_configs` cannot interleave, and
/// archive eligibility checks cannot observe the transient cleared state.
static CONFIG_MAPPING_LOCK: Mutex<()> = Mutex::const_new(());

/// Serialize config discovery/mapping with newly-created peer persistence and
/// peer archival eligibility checks.
///
/// The guard deliberately covers the directory scan as well as the database
/// clear-and-remap sequence, so a scan cannot apply a pre-creation snapshot
/// after creation metadata has been stored.
pub(crate) async fn acquire_config_mapping_lock() -> MutexGuard<'static, ()> {
    CONFIG_MAPPING_LOCK.lock().await
}

#[derive(Clone)]
pub struct Poller {
    db: Database,
    interval: Duration,
    /// Directory to scan for `*.conf` client config files.
    config_dir: PathBuf,
    /// Persistent directory whose descriptor serializes client lifecycle work.
    lifecycle_lock_dir: PathBuf,
    /// Maximum age of snapshots in days before cleanup (0 = disabled).
    snapshot_retention_days: u32,
    /// Which AWG interface the poller records and enforces.
    interface: InterfaceSelector,
    /// Last reported interface scope, so changes are logged once rather than
    /// on every cycle.
    scope_log: std::sync::Arc<std::sync::Mutex<ScopeLog>>,
}

impl Poller {
    #[cfg(test)]
    pub fn new(db: Database, interval_secs: u64, config_dir: PathBuf) -> Self {
        Self::new_full(
            db,
            interval_secs,
            config_dir.clone(),
            config_dir,
            0,
            InterfaceSelector::from_params(),
        )
    }

    pub fn new_full(
        db: Database,
        interval_secs: u64,
        config_dir: PathBuf,
        lifecycle_lock_dir: PathBuf,
        snapshot_retention_days: u32,
        interface: InterfaceSelector,
    ) -> Self {
        Self {
            db,
            interval: Duration::from_secs(interval_secs),
            config_dir,
            lifecycle_lock_dir,
            snapshot_retention_days,
            interface,
            scope_log: std::sync::Arc::new(std::sync::Mutex::new(ScopeLog::default())),
        }
    }

    #[cfg(test)]
    pub fn with_retention_days(mut self, days: u32) -> Self {
        self.snapshot_retention_days = days;
        self
    }

    /// Run the polling loop and independent retention task forever.
    pub async fn run(&self) {
        match self.interface.override_name() {
            Some(interface) => info!(
                interface,
                "poller scoped to the AWG interface set by AWG_INTERFACE"
            ),
            None => info!(
                "poller scoped to SERVER_AWG_NIC from the installer params (set AWG_INTERFACE to override)"
            ),
        }

        if self.snapshot_retention_days > 0 {
            info!(
                interval_secs = self.interval.as_secs(),
                snapshot_retention_days = self.snapshot_retention_days,
                config_dir = %self.config_dir.display(),
                "poller started (snapshot retention enabled)"
            );
        } else {
            info!(
                interval_secs = self.interval.as_secs(),
                config_dir = %self.config_dir.display(),
                "poller started (snapshot retention disabled)"
            );
        }

        tokio::join!(self.run_poll_loop(), self.run_retention_loop());
    }

    async fn run_poll_loop(&self) {
        let mut ticker = tokio::time::interval(self.interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.poll_once().await {
                error!(error = %e, "poll cycle failed");
            }
        }
    }

    /// Independent retention loop that runs snapshot cleanup on startup and
    /// subsequently every hour. If a deletable (non-baseline) snapshot backlog
    /// remains, continues draining in bounded chunks with a 1-second pause
    /// between steps until fully cleared. AWG dump collection runs on the
    /// blocking pool, so a slow `awg` command does not stall this timer.
    pub async fn run_retention_loop(&self) {
        self.run_retention_loop_with_intervals(Duration::from_secs(3600), Duration::from_secs(1))
            .await;
    }

    pub async fn run_retention_loop_with_intervals(
        &self,
        interval: Duration,
        backlog_delay: Duration,
    ) {
        if self.snapshot_retention_days == 0 {
            return;
        }

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;

            let mut more_remaining = self.cleanup_expired_snapshots_step().await;
            while more_remaining {
                tokio::time::sleep(backlog_delay).await;
                more_remaining = self.cleanup_expired_snapshots_step().await;
            }

            ticker.reset();
        }
    }

    async fn poll_once(&self) -> anyhow::Result<()> {
        let start = std::time::Instant::now();
        debug!("poll cycle starting");

        // ── Step 0: Panel mode ───────────────────────────────────────────────
        // Resolve which interface this instance follows and whether it may
        // manage it.  This reads the installer params through the privileged
        // helper – a blocking `sudo` call, run off the async executor like the
        // dump itself.  Without a name there is nothing safe to scope the
        // dump to, so the cycle's AWG steps are skipped.
        let mode = match self.interface.resolve_mode_off_thread().await {
            Ok(mode) => mode,
            Err(e) => {
                error!(
                    error = %e,
                    "cannot determine the managed AWG interface – skipping poll cycle"
                );
                return Err(e.into());
            }
        };
        self.log_mode(&mode);
        let managed = mode.interface();

        // ── Step 0b: Expired-user cleanup ────────────────────────────────────
        // The first interval tick fires immediately, so this also catches
        // expirations missed while the web service was stopped. Running it
        // before AWG discovery means cleanup is still attempted if AWG status
        // collection fails later in the cycle.  Removal rewrites the
        // installer's server config, so it only runs in management mode.
        self.cleanup_expired_users_step(&mode).await;

        // ── Step 1–3: AWG data ───────────────────────────────────────────────
        // `awg show all dump` is a blocking process; run it off the async
        // executor so the independent retention timer (and HTTP tasks) can
        // still be polled while the command is in flight.
        let interfaces = match collect_awg_dump().await {
            Ok(ifaces) => ifaces,
            Err(awg::AwgError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("awg binary not found at /usr/bin/awg – skipping poll cycle");
                return Ok(());
            }
            Err(e) => {
                error!(error = %e, "awg show all dump failed");
                return Err(e.into());
            }
        };

        // Every other interface on the host is dropped here, so snapshots,
        // upserts, disabled-peer enforcement and stale-peer cleanup below only
        // ever see the managed interface.
        let ScopedInterfaces {
            matched: interfaces,
            ignored,
        } = scope_to_interface(interfaces, managed);
        self.log_scope(managed, !interfaces.is_empty(), &ignored);

        let peer_count: usize = interfaces.iter().map(|i| i.peers.len()).sum();
        info!(
            interface = %managed,
            interface_count = interfaces.len(),
            ignored_interface_count = ignored.len(),
            peer_count,
            "awg data retrieved"
        );

        let now = chrono::Utc::now();
        let snapshots_written = match self.record_poll_batch(&interfaces, now).await {
            Ok(count) => count,
            Err(e) => {
                error!(error = %e, "failed to record poll batch – continuing");
                0
            }
        };

        info!(
            snapshots_written,
            elapsed_ms = start.elapsed().as_millis(),
            "awg poll step complete"
        );

        // ── Step 3b: Enforce disabled peers ──────────────────────────────────
        // Remove peers that are flagged as disabled in the DB but still present
        // on the running AWG interface.  This is a self-healing safety net:
        // immediate removal also happens at toggle time (web/admin handlers),
        // but the poller ensures eventual consistency (e.g. after an AWG
        // restart that re-reads the on-disk config).  A monitoring-only
        // instance never changes the interface it follows.
        if mode.is_managing() {
            if let Err(e) = self.enforce_disabled_peers(&interfaces).await {
                error!(error = %e, "enforce-disabled step failed – continuing");
            }
        } else {
            debug!(
                interface = %managed,
                "monitoring-only mode – disabled peers are not removed from the interface"
            );
        }

        // ── Step 4–5: Config mapping ─────────────────────────────────────────
        if let Err(e) = self.apply_config_mapping_step().await {
            error!(error = %e, "config mapping step failed – continuing");
        }

        // ── Step 6: Remove stale peers ───────────────────────────────────────
        // Delete DB peers that no longer appear on any AWG interface and are
        // not administratively disabled.  This cleans up artifacts left when
        // a peer is removed outside the web panel (e.g. via the install
        // script's --remove-client flag).
        if let Err(e) = self.remove_stale_peers(&interfaces).await {
            error!(error = %e, "stale-peer cleanup failed – continuing");
        }

        info!(
            elapsed_ms = start.elapsed().as_millis(),
            "poll cycle complete"
        );
        Ok(())
    }

    /// Remove due managed users, unless this instance only monitors its
    /// interface: removal rewrites the installer's server config and
    /// reconciles the installer's interface, which may be a different one.
    async fn cleanup_expired_users_step(&self, mode: &PanelMode) {
        if !mode.is_managing() {
            debug!(
                interface = %mode.interface(),
                "monitoring-only mode – expired-user cleanup skipped"
            );
            return;
        }
        match crate::admin::cleanup_expired_users(
            &self.db,
            &self.config_dir,
            &self.lifecycle_lock_dir,
        )
        .await
        {
            Ok(removed) if removed > 0 => {
                info!(removed, "expired-user cleanup complete");
            }
            Ok(_) => {}
            Err(e) => {
                error!(error = %e, "expired-user cleanup query failed – continuing");
            }
        }
    }

    /// Log the panel mode once at startup and again whenever it changes.
    fn log_mode(&self, mode: &PanelMode) {
        let previous = match self.scope_log.lock() {
            Ok(mut state) => state.observe_mode(mode),
            Err(poisoned) => poisoned.into_inner().observe_mode(mode),
        };
        let Some(previous) = previous else {
            return;
        };
        match mode {
            PanelMode::MonitoringOnly {
                monitored,
                installer,
            } => warn!(
                monitored = %monitored,
                installer = installer.as_deref().unwrap_or("(params unreadable)"),
                "monitoring-only mode: this panel instance only records its interface; client, peer and protocol management are unavailable"
            ),
            PanelMode::Managing { interface } => {
                if previous.is_some() {
                    info!(
                        interface = %interface,
                        "management mode restored: the followed interface is the installer's"
                    );
                }
            }
        }
    }

    /// Report scope changes: the monitored interface (at startup and whenever
    /// it changes), whether it is present in the dump, and which other
    /// interfaces the host carries.  Logging only on change keeps a
    /// permanently present foreign interface from producing a warning on
    /// every cycle.
    fn log_scope(&self, managed: &str, present: bool, ignored: &[String]) {
        let changes = match self.scope_log.lock() {
            Ok(mut state) => state.observe(managed, present, ignored),
            Err(poisoned) => poisoned.into_inner().observe(managed, present, ignored),
        };

        if changes.interface {
            info!(
                interface = %managed,
                source = self.interface.source(),
                "monitoring AWG interface"
            );
        }
        if changes.presence {
            if present {
                info!(interface = %managed, "managed AWG interface is present again");
            } else {
                warn!(
                    interface = %managed,
                    "managed AWG interface is not present in the dump – peers are left untouched until it is up"
                );
            }
        }
        if changes.ignored {
            if ignored.is_empty() {
                info!(interface = %managed, "no other AWG interfaces present any more");
            } else {
                warn!(
                    interface = %managed,
                    ignored = ?ignored,
                    "AWG dump contains other interfaces – they are not monitored by this panel (set AWG_INTERFACE to choose a different one)"
                );
            }
        }
    }

    /// Remove peers that are disabled in the database but still present on the
    /// running AWG interface.
    ///
    /// Iterates over every peer reported by `awg show all dump`.  If a peer's
    /// public key is marked `disabled = 1` in the DB, it is removed from the
    /// interface via `awg set <iface> peer <pubkey> remove`.
    ///
    /// The actual removal commands are blocking (`std::process::Command`) and
    /// are offloaded to `tokio::task::spawn_blocking` so the poller task stays
    /// responsive.
    ///
    /// Errors on individual peer removals are logged but do not abort the
    /// remaining removals.
    async fn enforce_disabled_peers(&self, interfaces: &[awg::AwgInterface]) -> anyhow::Result<()> {
        let disabled_keys = crate::db::peers::list_disabled_public_keys(&self.db.pool).await?;

        if disabled_keys.is_empty() {
            return Ok(());
        }

        // Collect (interface_name, public_key) pairs that need removal.
        let to_remove: Vec<(String, String)> = interfaces
            .iter()
            .flat_map(|iface| {
                iface
                    .peers
                    .iter()
                    .filter(|p| disabled_keys.contains(&p.public_key.0))
                    .map(|p| (iface.name.clone(), p.public_key.0.clone()))
            })
            .collect();

        if to_remove.is_empty() {
            return Ok(());
        }

        // Offload the blocking awg commands to a dedicated thread.
        let result = tokio::task::spawn_blocking(move || {
            let mut removed: usize = 0;
            for (iface_name, public_key) in &to_remove {
                info!(
                    interface = %iface_name,
                    public_key = %public_key,
                    "removing disabled peer from interface"
                );
                match awg::remove_peer(iface_name, public_key) {
                    Ok(()) => removed += 1,
                    Err(e) => {
                        error!(
                            interface = %iface_name,
                            public_key = %public_key,
                            error = %e,
                            "failed to remove disabled peer – continuing"
                        );
                    }
                }
            }
            removed
        })
        .await;

        match result {
            Ok(removed) if removed > 0 => {
                info!(removed, "disabled peers removed from interface");
            }
            Err(e) if e.is_panic() => {
                error!(error = %e, "spawn_blocking for peer removal panicked");
            }
            Err(e) if e.is_cancelled() => {
                warn!(error = %e, "spawn_blocking for peer removal was cancelled");
            }
            Err(e) => {
                error!(error = %e, "spawn_blocking for peer removal failed");
            }
            _ => {}
        }
        Ok(())
    }

    /// Scan the config directory and update `has_config`, `config_name`,
    /// `config_path`, and `friendly_name` on every peer.
    ///
    /// This operation is idempotent:
    /// 1. All config-mapping fields are first reset to NULL / 0 for every peer.
    /// 2. Configs owned by the selected server are matched by client address.
    ///
    /// If the config directory cannot be read, a warning is logged and the
    /// step returns `Ok(())` — existing config-mapping fields are **not**
    /// cleared (they retain whatever values they had from the previous cycle).
    async fn apply_config_mapping_step(&self) -> anyhow::Result<()> {
        let _guard = acquire_config_mapping_lock().await;
        let config_dir = self.config_dir.clone();
        let configs =
            match tokio::task::spawn_blocking(move || config_store::scan(&config_dir)).await {
                Ok(scan_result) => scan_result,
                Err(e) => {
                    warn!(
                        config_dir = %self.config_dir.display(),
                        error = %e,
                        "config scan task failed – skipping config mapping"
                    );
                    return Ok(());
                }
            };

        let configs = match configs {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    config_dir = %self.config_dir.display(),
                    error = %e,
                    "config scan failed – skipping config mapping"
                );
                return Ok(());
            }
        };

        debug!(
            total_configs = configs.len(),
            config_dir = %self.config_dir.display(),
            "config scan complete"
        );

        let scope = self.interface.config_scope().await?;
        apply_config_mappings(&self.db, &configs, scope.as_ref()).await
    }

    /// Purge snapshots older than `snapshot_retention_days` (if configured > 0).
    ///
    /// Each peer keeps its newest pre-cutoff snapshot as a usage baseline.
    /// Returns the number of snapshots deleted.
    #[cfg(test)]
    pub async fn cleanup_expired_snapshots(&self) -> anyhow::Result<u64> {
        if self.snapshot_retention_days == 0 {
            return Ok(0);
        }

        let retention_duration = match chrono::Duration::try_days(
            self.snapshot_retention_days as i64,
        ) {
            Some(dur) if self.snapshot_retention_days <= 36_500 => dur,
            _ => {
                warn!(
                    days = self.snapshot_retention_days,
                    "snapshot retention days exceeds maximum supported range (36500); skipping cleanup"
                );
                return Ok(0);
            }
        };

        let cutoff = chrono::Utc::now() - retention_duration;
        let cutoff_str = cutoff.to_rfc3339_opts(SecondsFormat::Secs, true);
        let res =
            crate::db::peers::delete_expired_snapshots(&self.db.pool, &cutoff_str, 5000, None)
                .await?;
        Ok(res.deleted)
    }

    pub async fn cleanup_expired_snapshots_step(&self) -> bool {
        if self.snapshot_retention_days == 0 {
            return false;
        }

        let retention_duration = match chrono::Duration::try_days(
            self.snapshot_retention_days as i64,
        ) {
            Some(dur) if self.snapshot_retention_days <= 36_500 => dur,
            _ => {
                warn!(
                    days = self.snapshot_retention_days,
                    "snapshot retention days exceeds maximum supported range (36500); skipping cleanup"
                );
                return false;
            }
        };

        let cutoff = chrono::Utc::now() - retention_duration;
        let cutoff_str = cutoff.to_rfc3339_opts(SecondsFormat::Secs, true);

        // Cap to 2 batches (up to 10,000 rows) per step with 25ms pause between batches,
        // preventing prolonged lock contention and yielding the SQLite write lock.
        match crate::db::peers::delete_expired_snapshots(&self.db.pool, &cutoff_str, 5000, Some(2))
            .await
        {
            Ok(result) => {
                if result.deleted > 0 {
                    info!(
                        deleted = result.deleted,
                        more_remaining = result.more_remaining,
                        retention_days = self.snapshot_retention_days,
                        "expired snapshot cleanup progress"
                    );
                }
                result.more_remaining
            }
            Err(e) => {
                error!(error = %e, "expired snapshot cleanup failed – continuing");
                false
            }
        }
    }

    async fn record_poll_batch(
        &self,
        interfaces: &[awg::AwgInterface],
        now: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<usize> {
        self.interface.observe_interfaces(interfaces);
        let mut tx = self
            .db
            .pool
            .begin()
            .await
            .context("begin poll batch transaction")?;
        let mut snapshots_written = 0;

        for iface in interfaces {
            for peer in &iface.peers {
                match self
                    .store_snapshot_tx(&mut tx, &peer.public_key, peer, now)
                    .await
                {
                    Ok(true) => snapshots_written += 1,
                    Ok(false) => {
                        debug!(
                            public_key = %peer.public_key,
                            "snapshot skipped for archived peer"
                        );
                    }
                    Err(e) => {
                        error!(
                            public_key = %peer.public_key,
                            error = %e,
                            "failed to write snapshot in batch"
                        );
                        return Err(e);
                    }
                }

                if let Err(e) = self.upsert_peer_tx(&mut tx, &peer.public_key, peer).await {
                    error!(
                        public_key = %peer.public_key,
                        error = %e,
                        "failed to upsert peer in batch"
                    );
                    return Err(e);
                }
            }
        }

        tx.commit().await.context("commit poll batch transaction")?;
        Ok(snapshots_written)
    }

    async fn store_snapshot_tx(
        &self,
        tx: &mut sqlx::SqliteConnection,
        public_key: &PublicKey,
        peer: &awg::AwgPeer,
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let endpoint = peer.endpoint.as_deref();
        let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
        let rx = saturating_u64_to_i64(peer.rx_bytes);
        let tx_bytes = saturating_u64_to_i64(peer.tx_bytes);
        let captured_str = captured_at.to_rfc3339_opts(SecondsFormat::Secs, true);

        let result = sqlx::query(
            "INSERT INTO snapshots \
             (public_key, captured_at, endpoint, last_handshake_at, rx_bytes, tx_bytes) \
             SELECT ?, ?, ?, ?, ?, ? \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM peers WHERE public_key = ? AND archived = 1 \
             )",
        )
        .bind(&public_key.0)
        .bind(&captured_str)
        .bind(endpoint)
        .bind(last_handshake)
        .bind(rx)
        .bind(tx_bytes)
        .bind(&public_key.0)
        .execute(tx)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    #[cfg(test)]
    async fn store_snapshot(
        &self,
        public_key: &PublicKey,
        peer: &awg::AwgPeer,
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<bool> {
        let mut tx = self.db.pool.begin().await?;
        let res = self
            .store_snapshot_tx(&mut tx, public_key, peer, captured_at)
            .await?;
        tx.commit().await?;
        Ok(res)
    }

    async fn upsert_peer_tx(
        &self,
        tx: &mut sqlx::SqliteConnection,
        public_key: &PublicKey,
        peer: &awg::AwgPeer,
    ) -> anyhow::Result<()> {
        let endpoint = peer.endpoint.as_deref();
        let allowed_ips = peer.allowed_ips.join(",");
        let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
        let rx = saturating_u64_to_i64(peer.rx_bytes);
        let tx_bytes = saturating_u64_to_i64(peer.tx_bytes);

        sqlx::query(
            "INSERT INTO peers (public_key, endpoint, allowed_ips, last_handshake_at, rx_bytes, tx_bytes) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(public_key) DO UPDATE SET \
                 endpoint            = excluded.endpoint, \
                 allowed_ips         = excluded.allowed_ips, \
                 last_handshake_at   = excluded.last_handshake_at, \
                 rx_bytes            = excluded.rx_bytes, \
                 tx_bytes            = excluded.tx_bytes, \
                 sync_pending        = 0, \
                 updated_at          = CURRENT_TIMESTAMP \
             WHERE peers.archived = 0",
        )
        .bind(&public_key.0)
        .bind(endpoint)
        .bind(&allowed_ips)
        .bind(last_handshake)
        .bind(rx)
        .bind(tx_bytes)
        .execute(tx)
        .await?;

        Ok(())
    }

    #[cfg(test)]
    async fn upsert_peer(&self, public_key: &PublicKey, peer: &awg::AwgPeer) -> anyhow::Result<()> {
        let mut tx = self.db.pool.begin().await?;
        self.upsert_peer_tx(&mut tx, public_key, peer).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Delete DB peers that no longer appear on any AWG interface and are not
    /// administratively disabled.
    ///
    /// This cleans up artifacts left when a peer is removed outside the web
    /// panel (e.g. via the install script's `--remove-client` flag).  Disabled
    /// peers are preserved because they were intentionally marked via the UI.
    async fn remove_stale_peers(&self, interfaces: &[awg::AwgInterface]) -> anyhow::Result<()> {
        // If no interfaces were returned we cannot tell whether all peers are
        // truly gone or AWG is simply down / not configured.  Skip cleanup to
        // avoid accidentally deleting every non-disabled peer.
        if interfaces.is_empty() {
            warn!("no AWG interfaces found – skipping stale-peer cleanup");
            return Ok(());
        }

        let active_keys: std::collections::HashSet<String> = interfaces
            .iter()
            .flat_map(|iface| iface.peers.iter().map(|p| p.public_key.0.clone()))
            .collect();

        let now = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let stale = crate::db::peers::delete_stale_peers(&self.db.pool, &active_keys, &now).await?;

        if !stale.is_empty() {
            info!(removed = stale.len(), "stale peers removed from database");
        }

        Ok(())
    }
}

/// Tracks the last reported poll scope so changes are logged once.
#[derive(Debug, Default)]
struct ScopeLog {
    mode: Option<PanelMode>,
    interface: Option<String>,
    present: Option<bool>,
    ignored: Option<Vec<String>>,
}

/// Which parts of the poll scope changed since the previous observation.
#[derive(Debug, Default, PartialEq, Eq)]
struct ScopeChanges {
    /// The managed interface name is new or different.
    interface: bool,
    /// The managed interface appeared in or vanished from the dump.  On the
    /// first observation only an absent interface counts as a change.
    presence: bool,
    /// The set of other interfaces changed.  On the first observation only a
    /// non-empty set counts as a change.
    ignored: bool,
}

impl ScopeLog {
    fn observe(&mut self, managed: &str, present: bool, ignored: &[String]) -> ScopeChanges {
        let changes = ScopeChanges {
            interface: self.interface.as_deref() != Some(managed),
            presence: match self.present {
                None => !present,
                Some(previous) => previous != present,
            },
            ignored: match &self.ignored {
                None => !ignored.is_empty(),
                Some(previous) => previous.as_slice() != ignored,
            },
        };
        self.interface = Some(managed.to_string());
        self.present = Some(present);
        self.ignored = Some(ignored.to_vec());
        changes
    }

    /// Record the panel mode.  Returns the previous value when it changed
    /// (`Some(None)` on the first observation) and `None` when unchanged.
    fn observe_mode(&mut self, mode: &PanelMode) -> Option<Option<PanelMode>> {
        if self.mode.as_ref() == Some(mode) {
            return None;
        }
        Some(self.mode.replace(mode.clone()))
    }
}

/// Run blocking `awg show all dump` off the async executor.
///
/// A hung or slow AWG command still occupies a blocking-pool thread until it
/// returns, but it must not stall the Tokio worker that drives the retention
/// timer and HTTP tasks.
async fn collect_awg_dump() -> Result<Vec<awg::AwgInterface>, awg::AwgError> {
    collect_awg_dump_with(awg::show_all_dump).await
}

#[allow(clippy::io_other_error)] // Error::other requires Rust 1.83; crate MSRV is 1.75
async fn collect_awg_dump_with<F>(dump: F) -> Result<Vec<awg::AwgInterface>, awg::AwgError>
where
    F: FnOnce() -> Result<Vec<awg::AwgInterface>, awg::AwgError> + Send + 'static,
{
    match tokio::task::spawn_blocking(dump).await {
        Ok(result) => result,
        Err(e) if e.is_panic() => {
            error!(error = %e, "spawn_blocking for awg dump panicked");
            Err(awg::AwgError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "awg dump task panicked",
            )))
        }
        Err(e) if e.is_cancelled() => {
            error!(error = %e, "spawn_blocking for awg dump was cancelled");
            Err(awg::AwgError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "awg dump task was cancelled",
            )))
        }
        Err(e) => {
            error!(error = %e, "spawn_blocking for awg dump failed");
            Err(awg::AwgError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "awg dump task failed",
            )))
        }
    }
}

/// Perform a one-shot AWG peer snapshot into the `peers` table.
///
/// Unlike the full poller cycle, this helper does not write traffic snapshots
/// and does not touch config mapping; it only upserts the latest peer rows so
/// UI pages can reflect lifecycle changes immediately.  Like the poller, it
/// only reads the managed interface.
pub async fn sync_peers_from_awg(
    db: &crate::db::Database,
    interface: &InterfaceSelector,
) -> anyhow::Result<()> {
    let mode = interface
        .resolve_mode_off_thread()
        .await
        .context("cannot determine the managed AWG interface")?;
    let interfaces = match collect_awg_dump().await {
        Ok(ifaces) => ifaces,
        Err(awg::AwgError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            warn!("awg binary not found at /usr/bin/awg – skipping one-shot peer sync");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let interfaces = scope_to_interface(interfaces, mode.interface()).matched;
    interface.observe_interfaces(&interfaces);

    let mut tx = db.pool.begin().await.context("begin sync_peers tx")?;
    for iface in &interfaces {
        for peer in &iface.peers {
            let endpoint = peer.endpoint.as_deref();
            let allowed_ips = peer.allowed_ips.join(",");
            let last_handshake = peer.last_handshake.map(|ts| ts.timestamp());
            let rx = saturating_u64_to_i64(peer.rx_bytes);
            let tx_bytes = saturating_u64_to_i64(peer.tx_bytes);

            sqlx::query(
                "INSERT INTO peers (public_key, endpoint, allowed_ips, last_handshake_at, rx_bytes, tx_bytes) \
                 VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(public_key) DO UPDATE SET \
                     endpoint            = excluded.endpoint, \
                     allowed_ips         = excluded.allowed_ips, \
                     last_handshake_at   = excluded.last_handshake_at, \
                     rx_bytes            = excluded.rx_bytes, \
                     tx_bytes            = excluded.tx_bytes, \
                     updated_at          = CURRENT_TIMESTAMP \
                 WHERE peers.archived = 0",
            )
            .bind(&peer.public_key.0)
            .bind(endpoint)
            .bind(&allowed_ips)
            .bind(last_handshake)
            .bind(rx)
            .bind(tx_bytes)
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await.context("commit sync_peers tx")?;

    Ok(())
}

/// Convert a `u64` counter to `i64`, capping at [`i64::MAX`] instead of
/// silently wrapping.  Traffic counters from `awg show` can theoretically
/// exceed `i64::MAX` (~9.2 EiB), but saturating avoids writing incorrect
/// negative values into SQLite.
fn saturating_u64_to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Shared config-to-peer mapping logic used by both the poller cycle and
/// on-demand rescan. Requires server ownership before matching client addresses.
///
/// Callers hold [`CONFIG_MAPPING_LOCK`] across both their directory scan and
/// this clear-and-remap sequence.
async fn apply_config_mappings(
    db: &crate::db::Database,
    configs: &[config_store::ClientConfig],
    scope: Option<&crate::managed_interface::ConfigScope>,
) -> anyhow::Result<()> {
    // Reset all mapping fields so that removed configs don't persist.
    crate::db::peers::clear_all_config_mappings(&db.pool).await?;

    let Some(scope) = scope else { return Ok(()) };

    // Include disabled/offline managed peers; monitoring is restricted below
    // to peers observed on the selected interface.
    let all_peers = crate::db::peers::list_visible(&db.pool).await?;

    let mut mapped_by_ip: usize = 0;
    // Live peers of a monitoring-only interface cannot have an installer
    // lifecycle identity. Repair values assigned by older unscoped discovery
    // without touching operator labels, comments or unrelated retained rows.
    if !scope.mode.is_managing() {
        for peer in &all_peers {
            if scope.permits_peer(&peer.public_key) {
                sqlx::query("UPDATE peers SET managed_client_name = NULL WHERE id = ?")
                    .bind(peer.id)
                    .execute(&db.pool)
                    .await?;
            }
        }
    }
    for config in configs {
        if !config.belongs_to(scope) {
            continue;
        }
        let path_str = config.path.to_string_lossy();
        let managed_client_name = scope
            .mode
            .is_managing()
            .then(|| {
                crate::admin::script_bridge::managed_client_name_from_config(
                    &config.name,
                    &config.friendly_name,
                )
            })
            .flatten();

        // Attempt to match by comparing the config's Address field
        // with peer AllowedIPs.  Only match if unambiguous (exactly one).
        if !config.addresses.is_empty() {
            let candidates: Vec<_> = all_peers
                .iter()
                .filter(|p| {
                    scope.permits_peer(&p.public_key) && config.matches_addresses(&p.allowed_ips)
                })
                .collect();

            if candidates.len() == 1 {
                let peer = candidates[0];
                match crate::db::peers::apply_config_mapping(
                    &db.pool,
                    &peer.public_key,
                    &config.name,
                    &path_str,
                    &config.friendly_name,
                    managed_client_name,
                )
                .await
                {
                    Ok(true) => {
                        mapped_by_ip += 1;
                        info!(
                            config = %config.name,
                            friendly_name = %config.friendly_name,
                            public_key = %peer.public_key,
                            "owned config linked by client address"
                        );
                    }
                    Ok(false) => {
                        warn!(
                            config = %config.name,
                            public_key = %peer.public_key,
                            "AllowedIPs candidate peer vanished between query and update"
                        );
                    }
                    Err(e) => {
                        warn!(
                            config = %config.name,
                            error = %e,
                            "failed to apply AllowedIPs config mapping – skipping"
                        );
                    }
                }
            } else if candidates.len() > 1 {
                warn!(
                    config = %config.name,
                    candidate_count = candidates.len(),
                    "ambiguous AllowedIPs match – skipping config mapping"
                );
            } else {
                debug!(
                    config = %config.name,
                    "no matching peer address – skipping config mapping"
                );
            }
        } else {
            debug!(
                config = %config.name,
                "config has no client addresses – skipping config mapping"
            );
        }
    }

    info!(
        total_configs = configs.len(),
        mapped_by_ip = mapped_by_ip,
        "config mapping applied"
    );
    Ok(())
}

/// Perform a one-shot config-directory rescan and update peer mappings.
///
/// Uses `spawn_blocking` for the filesystem scan to avoid blocking the
/// Tokio runtime, then delegates to the shared `apply_config_mappings`
/// helper (same logic the poller uses every cycle).
pub async fn rescan_configs(
    db: &crate::db::Database,
    config_dir: &std::path::Path,
    interface: &InterfaceSelector,
) -> anyhow::Result<()> {
    let _guard = acquire_config_mapping_lock().await;
    let dir = config_dir.to_path_buf();
    let configs = match tokio::task::spawn_blocking(move || config_store::scan(&dir)).await {
        Ok(scan_result) => scan_result,
        Err(e) => {
            warn!(
                config_dir = %config_dir.display(),
                error = %e,
                "config scan task failed during rescan"
            );
            return Ok(());
        }
    };

    let configs = match configs {
        Ok(c) => c,
        Err(e) => {
            warn!(
                config_dir = %config_dir.display(),
                error = %e,
                "config scan failed during rescan"
            );
            return Ok(());
        }
    };

    let scope = interface.config_scope().await?;
    apply_config_mappings(db, &configs, scope.as_ref()).await?;
    info!("on-demand config rescan complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn config_scope_selector(monitored: &str) -> InterfaceSelector {
        InterfaceSelector::from_override(Some(monitored))
            .unwrap()
            .with_params_reader(|| {
                Ok(crate::managed_interface::test_params("awg0")
                    .replace("SERVER_PUB_KEY='PUB'", "SERVER_PUB_KEY='AWG0_SERVER='"))
            })
    }

    fn overlapping_interfaces() -> Vec<awg::AwgInterface> {
        awg::parse_dump(
            "awg0\tP0\tAWG0_SERVER=\t51820\toff\n\
             awg0\tALICE_KEY=\t(none)\t(none)\t10.66.66.2/32\t0\t0\t0\toff\n\
             awg1\tP1\tAWG1_SERVER=\t51821\toff\n\
             awg1\tBOB_KEY=\t(none)\t(none)\t10.66.66.2/32\t0\t0\t0\toff\n",
        )
        .unwrap()
    }

    fn scoped_client_config(server: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = PRIVATE_FIXTURE\nAddress = 10.66.66.2/32\n\
             [Peer]\nPublicKey = {server}\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n"
        )
    }

    async fn assert_config_exports(app: &axum::Router, id: i64, expected: axum::http::StatusCode) {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        for export in ["config", "vpn-uri", "qr"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/peers/{id}/{export}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{export}");
        }
    }

    #[tokio::test]
    async fn config_mapping_rejects_other_interfaces_and_repairs_monitoring_metadata() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("awg0-client-alice.conf"),
            scoped_client_config("AWG0_SERVER="),
        )
        .unwrap();
        let db = Database::connect_for_test().await.unwrap();
        let selector = config_scope_selector("awg1");
        selector.resolve_mode().unwrap();
        let poller = Poller::new_full(
            db.clone(),
            30,
            dir.path().into(),
            dir.path().into(),
            0,
            selector,
        );
        let scoped = scope_to_interface(overlapping_interfaces(), "awg1").matched;
        poller.record_poll_batch(&scoped, Utc::now()).await.unwrap();
        // Metadata left by an older poller must not give Bob Alice's lifecycle
        // identity. Operator-entered labels and notes remain Bob's own data.
        sqlx::query("UPDATE peers SET managed_client_name = 'alice', display_name = 'Bob', comment = 'keep note'")
            .execute(&db.pool).await.unwrap();
        poller.apply_config_mapping_step().await.unwrap();
        let bob = crate::db::peers::find_by_public_key(&db.pool, "BOB_KEY=")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            bob.has_config, 0,
            "same IP does not prove interface ownership"
        );
        assert_eq!(bob.config_path, None);
        assert_eq!(bob.managed_client_name, None);
        assert_eq!(bob.display_name.as_deref(), Some("Bob"));
        assert_eq!(bob.comment.as_deref(), Some("keep note"));
    }

    #[tokio::test]
    async fn config_exports_reject_stale_mapping_before_first_monitoring_poll() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("awg0-client-alice.conf");
        std::fs::write(&path, scoped_client_config("AWG0_SERVER=")).unwrap();
        let db = Database::connect_for_test().await.unwrap();
        sqlx::query(
            "INSERT INTO peers (public_key, allowed_ips) VALUES ('BOB_KEY=', '10.66.66.2/32')",
        )
        .execute(&db.pool)
        .await
        .unwrap();
        crate::db::peers::apply_config_mapping(
            &db.pool,
            "BOB_KEY=",
            "awg0-client-alice",
            path.to_str().unwrap(),
            "alice",
            Some("alice"),
        )
        .await
        .unwrap();
        let bob = crate::db::peers::find_by_public_key(&db.pool, "BOB_KEY=")
            .await
            .unwrap()
            .unwrap();
        let app = crate::web::router_with_lifecycle_lock_dir(
            db,
            crate::auth::AuthConfig::disabled(),
            dir.path().into(),
            dir.path().into(),
            dir.path().join("missing-sessions.json"),
            config_scope_selector("awg1"),
        );
        assert_config_exports(&app, bob.id, axum::http::StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn config_exports_invalidate_observed_key_when_installer_scope_changes() {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        let changed = Arc::new(AtomicBool::new(false));
        let reader_changed = changed.clone();
        let selector = InterfaceSelector::from_params().with_params_reader(move || {
            let (name, key) = if reader_changed.load(Ordering::SeqCst) {
                ("awg1", "AWG1_SERVER=")
            } else {
                ("awg0", "AWG0_SERVER=")
            };
            Ok(crate::managed_interface::test_params(name)
                .replace("SERVER_PUB_KEY='PUB'", &format!("SERVER_PUB_KEY='{key}'")))
        });
        selector.resolve_mode().unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("awg0-client-alice.conf"),
            scoped_client_config("AWG0_SERVER="),
        )
        .unwrap();
        let db = Database::connect_for_test().await.unwrap();
        let poller = Poller::new_full(
            db.clone(),
            30,
            dir.path().into(),
            dir.path().into(),
            0,
            selector.clone(),
        );
        poller
            .record_poll_batch(
                &scope_to_interface(overlapping_interfaces(), "awg0").matched,
                Utc::now(),
            )
            .await
            .unwrap();
        poller.apply_config_mapping_step().await.unwrap();
        let alice = crate::db::peers::find_by_public_key(&db.pool, "ALICE_KEY=")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alice.managed_client_name.as_deref(), Some("alice"));
        // Use a generic filename to ensure the key cache itself is invalidated,
        // independently of the installer filename ownership check.
        std::fs::rename(
            dir.path().join("awg0-client-alice.conf"),
            dir.path().join("custom.conf"),
        )
        .unwrap();
        poller.apply_config_mapping_step().await.unwrap();
        let app = crate::web::router_with_lifecycle_lock_dir(
            db,
            crate::auth::AuthConfig::disabled(),
            dir.path().into(),
            dir.path().into(),
            dir.path().join("missing-sessions.json"),
            selector.clone(),
        );
        assert_config_exports(&app, alice.id, axum::http::StatusCode::OK).await;
        changed.store(true, Ordering::SeqCst);
        selector.resolve_mode().unwrap();
        assert_config_exports(&app, alice.id, axum::http::StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn config_mapping_preserves_owned_exports_and_rejects_conflicting_filenames() {
        for monitored in ["awg0", "awg1"] {
            let dir = tempfile::tempdir().unwrap();
            let db = Database::connect_for_test().await.unwrap();
            let selector = config_scope_selector(monitored);
            selector.resolve_mode().unwrap();
            let poller = Poller::new_full(
                db.clone(),
                30,
                dir.path().into(),
                dir.path().into(),
                0,
                selector.clone(),
            );
            let scoped = scope_to_interface(overlapping_interfaces(), monitored).matched;
            poller.record_poll_batch(&scoped, Utc::now()).await.unwrap();
            if monitored == "awg1" {
                sqlx::query("INSERT INTO peers (public_key, allowed_ips, disabled, managed_client_name) VALUES ('OLD_ALICE=', '10.66.66.2/32', 1, 'historical-alice')")
                    .execute(&db.pool).await.unwrap();
            }
            let (key, server, foreign_name) = if monitored == "awg0" {
                ("ALICE_KEY=", "AWG0_SERVER=", "awg1-client-wrong")
            } else {
                ("BOB_KEY=", "AWG1_SERVER=", "awg0-client-wrong")
            };
            let path = dir.path().join(format!("{foreign_name}.conf"));
            std::fs::write(&path, scoped_client_config(server)).unwrap();
            poller.apply_config_mapping_step().await.unwrap();
            let row = crate::db::peers::find_by_public_key(&db.pool, key)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                row.has_config, 0,
                "a foreign filename must not override server ownership"
            );

            std::fs::rename(&path, dir.path().join("custom-client.conf")).unwrap();
            poller.apply_config_mapping_step().await.unwrap();
            let row = crate::db::peers::find_by_public_key(&db.pool, key)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.has_config, 1);
            let app = crate::web::router_with_lifecycle_lock_dir(
                db,
                crate::auth::AuthConfig::disabled(),
                dir.path().into(),
                dir.path().into(),
                dir.path().join("missing-sessions.json"),
                selector,
            );
            assert_config_exports(&app, row.id, axum::http::StatusCode::OK).await;
            // A stale DB link must not authorize replacement file contents.
            std::fs::write(
                dir.path().join("custom-client.conf"),
                scoped_client_config("FOREIGN_SERVER="),
            )
            .unwrap();
            assert_config_exports(&app, row.id, axum::http::StatusCode::NOT_FOUND).await;
            std::fs::write(
                dir.path().join("custom-client.conf"),
                scoped_client_config(server),
            )
            .unwrap();
            poller.record_poll_batch(&[], Utc::now()).await.unwrap();
            assert_config_exports(
                &app,
                row.id,
                if monitored == "awg0" {
                    axum::http::StatusCode::OK
                } else {
                    axum::http::StatusCode::NOT_FOUND
                },
            )
            .await;
            poller.apply_config_mapping_step().await.unwrap();
            let row = crate::db::peers::find_by_public_key(&poller.db.pool, key)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.has_config, i64::from(monitored == "awg0"));
            if monitored == "awg1" {
                let historical =
                    crate::db::peers::find_by_public_key(&poller.db.pool, "OLD_ALICE=")
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(
                    historical.managed_client_name.as_deref(),
                    Some("historical-alice")
                );
            }
        }
    }

    #[tokio::test]
    async fn collect_awg_dump_propagates_success() {
        let result = collect_awg_dump_with(|| Ok(Vec::new())).await;
        assert!(result.expect("success").is_empty());
    }

    #[tokio::test]
    async fn collect_awg_dump_propagates_awg_error() {
        let result = collect_awg_dump_with(|| Err(awg::AwgError::Parse("bad dump".into()))).await;
        assert!(matches!(result, Err(awg::AwgError::Parse(_))));
    }

    #[tokio::test]
    async fn collect_awg_dump_propagates_blocking_panic() {
        let result = collect_awg_dump_with(|| panic!("awg dump panicked")).await;
        match result {
            Err(awg::AwgError::Io(err)) => {
                assert!(err.to_string().contains("panicked"));
            }
            other => panic!("expected Io panic error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn collect_awg_dump_does_not_starve_async_work() {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();

        let dump = tokio::spawn(async move {
            collect_awg_dump_with(move || {
                let _ = entered_tx.send(());
                let _ = release_rx.recv();
                Ok(Vec::new())
            })
            .await
        });

        tokio::time::timeout(Duration::from_secs(2), entered_rx)
            .await
            .expect("blocking dump should start without occupying the async worker")
            .expect("oneshot");

        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::time::sleep(Duration::from_millis(30)),
        )
        .await
        .expect("retention/HTTP timers must fire while AWG collection is blocked");

        release_tx.send(()).expect("release blocking dump");
        dump.await.expect("join dump task").expect("dump result");
    }

    #[tokio::test]
    async fn poller_writes_cannot_repopulate_an_archived_peer() {
        let db = Database::connect_for_test().await.expect("test database");
        let public_key = PublicKey("KEY_ARCHIVED_POLLER=".to_string());
        let id = sqlx::query(
            "INSERT INTO peers (public_key, display_name, comment, allowed_ips, disabled) \
             VALUES (?, 'Old name', 'Old comment', '10.8.0.2/32', 1)",
        )
        .bind(&public_key.0)
        .execute(&db.pool)
        .await
        .expect("insert peer")
        .last_insert_rowid();

        let outcome = crate::db::peers::archive_peer_data(&db.pool, id, "admin")
            .await
            .expect("archive peer");
        assert!(matches!(
            outcome,
            crate::db::peers::ArchivePeerOutcome::Archived { .. }
        ));

        let observed = awg::AwgPeer {
            public_key: public_key.clone(),
            endpoint: Some("198.51.100.9:51820".to_string()),
            allowed_ips: vec!["10.8.0.2/32".to_string()],
            last_handshake: Some(Utc::now()),
            rx_bytes: 123,
            tx_bytes: 456,
        };
        let poller = Poller::new(db.clone(), 30, PathBuf::from("."));

        assert!(!poller
            .store_snapshot(&public_key, &observed, Utc::now())
            .await
            .expect("store guarded snapshot"));
        poller
            .upsert_peer(&public_key, &observed)
            .await
            .expect("guarded peer upsert");

        let row = crate::db::peers::find_by_id(&db.pool, id)
            .await
            .expect("find peer")
            .expect("archived tombstone");
        assert_eq!(row.archived, 1);
        assert_eq!(row.disabled, 1);
        assert!(row.display_name.is_none());
        assert!(row.comment.is_none());
        assert!(row.endpoint.is_none());
        assert!(row.allowed_ips.is_empty());
        assert_eq!(row.rx_bytes, 0);
        assert_eq!(row.tx_bytes, 0);

        let snapshots: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM snapshots WHERE public_key = ?")
                .bind(&public_key.0)
                .fetch_one(&db.pool)
                .await
                .expect("count snapshots");
        assert_eq!(snapshots, 0);
    }

    #[tokio::test]
    async fn record_poll_batch_writes_snapshots_and_upserts_peers() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk1 = PublicKey("KEY_BATCH_1=".to_string());
        let pk2 = PublicKey("KEY_BATCH_2=".to_string());

        let peer1 = awg::AwgPeer {
            public_key: pk1.clone(),
            endpoint: Some("198.51.100.10:51820".to_string()),
            allowed_ips: vec!["10.8.0.2/32".to_string()],
            last_handshake: Some(Utc::now()),
            rx_bytes: 1000,
            tx_bytes: 2000,
        };
        let peer2 = awg::AwgPeer {
            public_key: pk2.clone(),
            endpoint: Some("198.51.100.11:51820".to_string()),
            allowed_ips: vec!["10.8.0.3/32".to_string()],
            last_handshake: Some(Utc::now()),
            rx_bytes: 3000,
            tx_bytes: 4000,
        };

        let iface = awg::AwgInterface {
            name: "awg0".to_string(),
            public_key: PublicKey("SERVER_PUBKEY=".to_string()),
            listen_port: Some(51820),
            peers: vec![peer1, peer2],
        };

        let poller = Poller::new(db.clone(), 30, PathBuf::from("."));
        let written = poller
            .record_poll_batch(&[iface], Utc::now())
            .await
            .expect("record batch");
        assert_eq!(written, 2);

        let row1 = crate::db::peers::find_by_public_key(&db.pool, &pk1.0)
            .await
            .expect("find peer1")
            .expect("peer1 exists");
        assert_eq!(row1.rx_bytes, 1000);
        assert_eq!(row1.tx_bytes, 2000);

        let snaps1 = crate::db::peers::find_snapshots(&db.pool, &pk1.0, 10)
            .await
            .expect("find snapshots");
        assert_eq!(snaps1.len(), 1);
        assert_eq!(snaps1[0].rx_bytes, 1000);
        assert_eq!(snaps1[0].tx_bytes, 2000);
    }

    #[tokio::test]
    async fn cleanup_expired_snapshots_respects_retention_days() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_RETENTION=";

        // Insert older snapshot (40 days ago) and newer snapshot (10 days ago)
        let old_ts =
            (Utc::now() - chrono::Duration::days(40)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let new_ts =
            (Utc::now() - chrono::Duration::days(10)).to_rfc3339_opts(SecondsFormat::Secs, true);

        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
        )
        .bind(pk)
        .bind(&old_ts)
        .execute(&db.pool)
        .await
        .expect("insert old snapshot");

        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 30, 40)",
        )
        .bind(pk)
        .bind(&new_ts)
        .execute(&db.pool)
        .await
        .expect("insert new snapshot");

        // Poller with 30-day retention: the 40-day row is the sparse baseline
        // and must be kept so 30-day usage can still compute a delta.
        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(30);
        let deleted = poller.cleanup_expired_snapshots().await.expect("cleanup");
        assert_eq!(deleted, 0);

        let remaining = crate::db::peers::find_snapshots(&db.pool, pk, 10)
            .await
            .expect("find snapshots");
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().any(|row| row.captured_at == old_ts));
        assert!(remaining.iter().any(|row| row.captured_at == new_ts));
    }

    #[tokio::test]
    async fn cleanup_preserves_sparse_baseline_for_thirty_day_usage() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_SPARSE_USAGE=";
        let old_ts =
            (Utc::now() - chrono::Duration::days(40)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let new_ts =
            (Utc::now() - chrono::Duration::days(5)).to_rfc3339_opts(SecondsFormat::Secs, true);

        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 1000, 2000)",
        )
        .bind(pk)
        .bind(&old_ts)
        .execute(&db.pool)
        .await
        .expect("insert old snapshot");
        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 5000, 8000)",
        )
        .bind(pk)
        .bind(&new_ts)
        .execute(&db.pool)
        .await
        .expect("insert new snapshot");

        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(31);
        let deleted = poller.cleanup_expired_snapshots().await.expect("cleanup");
        assert_eq!(deleted, 0);

        let window_start =
            (Utc::now() - chrono::Duration::days(30)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let baseline = crate::db::peers::find_baseline_snapshot(&db.pool, pk, &window_start)
            .await
            .expect("baseline")
            .expect("40-day snapshot must remain as the 30-day baseline");
        let in_window = crate::db::peers::find_snapshots_since(&db.pool, pk, &window_start)
            .await
            .expect("in-window");
        let mut inputs = vec![crate::domain::history::SnapshotInput {
            captured_at: baseline.captured_at,
            rx_bytes: baseline.rx_bytes as u64,
            tx_bytes: baseline.tx_bytes as u64,
        }];
        inputs.extend(
            in_window
                .into_iter()
                .map(|row| crate::domain::history::SnapshotInput {
                    captured_at: row.captured_at,
                    rx_bytes: row.rx_bytes as u64,
                    tx_bytes: row.tx_bytes as u64,
                }),
        );
        let summary = crate::domain::history::compute_usage_summary(&inputs);
        assert_eq!(summary.rx_total_delta, 4_000);
        assert_eq!(summary.tx_total_delta, 6_000);
    }

    #[tokio::test]
    async fn cleanup_expired_snapshots_disabled_when_zero() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_RETENTION_ZERO=";

        let old_ts =
            (Utc::now() - chrono::Duration::days(100)).to_rfc3339_opts(SecondsFormat::Secs, true);
        sqlx::query(
            "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
        )
        .bind(pk)
        .bind(&old_ts)
        .execute(&db.pool)
        .await
        .expect("insert old snapshot");

        // Poller with retention_days = 0 (disabled)
        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(0);
        let deleted = poller.cleanup_expired_snapshots().await.expect("cleanup");
        assert_eq!(deleted, 0);

        let remaining = crate::db::peers::find_snapshots(&db.pool, pk, 10)
            .await
            .expect("find snapshots");
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn cleanup_expired_snapshots_handles_overflow_gracefully() {
        let db = Database::connect_for_test().await.expect("test database");

        // Poller with overflow retention_days (e.g. 200,000 days or u32::MAX)
        let poller_huge =
            Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(200_000);
        let deleted = poller_huge
            .cleanup_expired_snapshots()
            .await
            .expect("must not panic on huge retention days");
        assert_eq!(deleted, 0);

        let poller_max =
            Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(u32::MAX);
        let deleted_max = poller_max
            .cleanup_expired_snapshots()
            .await
            .expect("must not panic on u32::MAX");
        assert_eq!(deleted_max, 0);
    }

    #[tokio::test]
    async fn cleanup_expired_snapshots_step_retains_newest_pre_cutoff_snapshot() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_STEP_THROTTLE=";

        // Insert 12 old snapshots (50 days ago)
        for i in 1..=12 {
            let ts = (Utc::now() - chrono::Duration::days(50 + i))
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            sqlx::query(
                "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
            )
            .bind(pk)
            .bind(&ts)
            .execute(&db.pool)
            .await
            .expect("insert snapshot");
        }

        // Poller with 31 days retention
        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(31);
        poller.cleanup_expired_snapshots_step().await;

        // Cleanup was executed: 11 older rows go away, the newest pre-cutoff
        // snapshot is retained as the usage baseline.
        let remaining = crate::db::peers::find_snapshots(&db.pool, pk, 20)
            .await
            .expect("find snapshots");
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn run_retention_loop_runs_on_startup_and_interval() {
        let db = Database::connect_for_test().await.expect("test database");
        let pk = "KEY_RETENTION_LOOP=";

        // Insert 10 old snapshots (50 days ago)
        for i in 1..=10 {
            let ts = (Utc::now() - chrono::Duration::days(50 + i))
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            sqlx::query(
                "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
            )
            .bind(pk)
            .bind(&ts)
            .execute(&db.pool)
            .await
            .expect("insert snapshot");
        }

        // Create poller with 31 days retention and a 7200s poller interval (to verify it doesn't wait on poller)
        let poller = Poller::new(db.clone(), 7200, PathBuf::from(".")).with_retention_days(31);

        // Spawn retention loop with 50ms interval and 10ms backlog delay
        let poller_clone = poller.clone();
        let handle = tokio::spawn(async move {
            poller_clone
                .run_retention_loop_with_intervals(
                    Duration::from_millis(50),
                    Duration::from_millis(10),
                )
                .await;
        });

        // Give it a moment to run the startup cleanup
        tokio::time::sleep(Duration::from_millis(25)).await;

        let remaining = crate::db::peers::find_snapshots(&db.pool, pk, 20)
            .await
            .expect("find snapshots");
        assert_eq!(remaining.len(), 1);

        // Insert more expired snapshots and verify the loop picks them up on the next tick
        for i in 1..=5 {
            let ts = (Utc::now() - chrono::Duration::days(50 + i))
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            sqlx::query(
                "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, 10, 20)",
            )
            .bind(pk)
            .bind(&ts)
            .execute(&db.pool)
            .await
            .expect("insert snapshot");
        }

        // Wait for the next 50ms tick
        tokio::time::sleep(Duration::from_millis(60)).await;

        let remaining_after = crate::db::peers::find_snapshots(&db.pool, pk, 20)
            .await
            .expect("find snapshots");
        assert_eq!(remaining_after.len(), 1);

        handle.abort();
    }

    /// A host with the installer's `awg0` and a hand-made `awg1`.
    const TWO_INTERFACE_DUMP: &str = "\
awg0\tPRIVATE0\tSERVER0_PUB=\t51820\toff\n\
awg0\tMANAGED_PEER_A=\t(none)\t203.0.113.10:4000\t10.8.0.2/32\t1700000000\t10\t20\toff\n\
awg0\tMANAGED_PEER_B=\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\toff\n\
awg1\tPRIVATE1\tSERVER1_PUB=\t51821\toff\n\
awg1\tFOREIGN_PEER=\t(none)\t203.0.113.11:4001\t10.9.0.2/32\t1700000000\t30\t40\toff\n\
";

    async fn peer_exists(db: &Database, public_key: &str) -> bool {
        crate::db::peers::find_by_public_key(&db.pool, public_key)
            .await
            .expect("find peer")
            .is_some()
    }

    #[tokio::test]
    async fn scoped_poll_batch_records_only_managed_interface_peers() {
        let db = Database::connect_for_test().await.expect("test database");
        let dump = awg::parse_dump(TWO_INTERFACE_DUMP).expect("parse dump");
        let scoped = scope_to_interface(dump, "awg0");
        assert_eq!(scoped.ignored, vec!["awg1".to_string()]);

        let poller = Poller::new(db.clone(), 30, PathBuf::from("."));
        let written = poller
            .record_poll_batch(&scoped.matched, Utc::now())
            .await
            .expect("record scoped batch");
        assert_eq!(written, 2);

        assert!(peer_exists(&db, "MANAGED_PEER_A=").await);
        assert!(peer_exists(&db, "MANAGED_PEER_B=").await);
        assert!(!peer_exists(&db, "FOREIGN_PEER=").await);

        let foreign_snapshots: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM snapshots WHERE public_key = ?")
                .bind("FOREIGN_PEER=")
                .fetch_one(&db.pool)
                .await
                .expect("count snapshots");
        assert_eq!(foreign_snapshots, 0);
    }

    #[tokio::test]
    async fn scoped_stale_cleanup_removes_peers_recorded_from_other_interfaces() {
        let db = Database::connect_for_test().await.expect("test database");
        let dump = awg::parse_dump(TWO_INTERFACE_DUMP).expect("parse dump");
        let poller = Poller::new(db.clone(), 30, PathBuf::from("."));

        // An earlier, unscoped poll recorded the foreign interface's peer.
        poller
            .record_poll_batch(&dump, Utc::now())
            .await
            .expect("record unscoped batch");
        assert!(peer_exists(&db, "FOREIGN_PEER=").await);

        let scoped = scope_to_interface(dump, "awg0");
        poller
            .remove_stale_peers(&scoped.matched)
            .await
            .expect("scoped stale cleanup");

        assert!(!peer_exists(&db, "FOREIGN_PEER=").await);
        assert!(peer_exists(&db, "MANAGED_PEER_A=").await);
        assert!(peer_exists(&db, "MANAGED_PEER_B=").await);
    }

    #[tokio::test]
    async fn scoped_stale_cleanup_is_skipped_while_managed_interface_is_down() {
        let db = Database::connect_for_test().await.expect("test database");
        let dump = awg::parse_dump(TWO_INTERFACE_DUMP).expect("parse dump");
        let poller = Poller::new(db.clone(), 30, PathBuf::from("."));
        poller
            .record_poll_batch(&scope_to_interface(dump, "awg0").matched, Utc::now())
            .await
            .expect("record scoped batch");

        // Only the foreign interface is up: the dump carries no managed peers,
        // which must not be mistaken for "every managed peer was removed".
        let only_foreign = awg::parse_dump(
            "awg1\tPRIVATE1\tSERVER1_PUB=\t51821\toff\n\
             awg1\tFOREIGN_PEER=\t(none)\t(none)\t10.9.0.2/32\t0\t0\t0\toff\n",
        )
        .expect("parse dump");
        let scoped = scope_to_interface(only_foreign, "awg0");
        assert!(scoped.matched.is_empty());
        poller
            .remove_stale_peers(&scoped.matched)
            .await
            .expect("cleanup skipped");

        assert!(peer_exists(&db, "MANAGED_PEER_A=").await);
        assert!(peer_exists(&db, "MANAGED_PEER_B=").await);
    }

    #[tokio::test]
    async fn override_without_readable_params_still_names_the_followed_interface() {
        let selector = InterfaceSelector::from_override(Some("awg1"))
            .expect("valid override")
            .with_params_reader(|| {
                Err(awg::AwgError::NonZeroExit {
                    status: 1,
                    stderr: "sudo: a password is required".into(),
                })
            });
        let mode = selector
            .resolve_mode_off_thread()
            .await
            .expect("override needs no params");
        assert_eq!(mode.interface(), "awg1");
        assert!(!mode.is_managing());
    }

    async fn seed_expired_managed_peer(db: &Database) -> i64 {
        sqlx::query(
            "INSERT INTO peers (public_key, allowed_ips, managed_client_name, expires_at) \
             VALUES ('EXPIRED_SCOPE_KEY=', '10.66.66.9/32', 'expired-user', '2000-01-01T00:00:00Z')",
        )
        .execute(&db.pool)
        .await
        .expect("seed expired peer")
        .last_insert_rowid()
    }

    async fn removal_pending(db: &Database, id: i64) -> i64 {
        sqlx::query_scalar("SELECT removal_pending FROM peers WHERE id = ?")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .expect("removal_pending")
    }

    #[tokio::test]
    async fn expired_user_cleanup_only_runs_in_management_mode() {
        let db = Database::connect_for_test().await.expect("test database");
        let id = seed_expired_managed_peer(&db).await;
        let state_dir = tempfile::tempdir().expect("state tempdir");
        let poller = Poller::new_full(
            db.clone(),
            30,
            state_dir.path().join("missing-clients"),
            state_dir.path().to_path_buf(),
            0,
            InterfaceSelector::from_override(Some("awg1")).expect("valid override"),
        );

        // Monitoring-only: the installer's interface must not be reconciled,
        // so the expired peer is left untouched and no removal is started.
        poller
            .cleanup_expired_users_step(&PanelMode::MonitoringOnly {
                monitored: "awg1".into(),
                installer: Some("awg0".into()),
            })
            .await;
        assert_eq!(removal_pending(&db, id).await, 0);
        let attempts: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE action IN (?, ?)")
                .bind(crate::db::events::EVT_USER_REMOVE_REQUESTED)
                .bind(crate::db::events::EVT_USER_REMOVE_FAILED)
                .fetch_one(&db.pool)
                .await
                .expect("count removal events");
        assert_eq!(attempts, 0);

        // Management mode starts the native removal (which cannot complete in
        // the test environment) and therefore marks the retry state.
        poller
            .cleanup_expired_users_step(&PanelMode::Managing {
                interface: "awg0".into(),
            })
            .await;
        assert_eq!(removal_pending(&db, id).await, 1);
    }

    #[test]
    fn scope_log_reports_mode_changes_once() {
        let mut log = ScopeLog::default();
        let managing = PanelMode::Managing {
            interface: "awg0".into(),
        };
        let monitoring = PanelMode::MonitoringOnly {
            monitored: "awg1".into(),
            installer: Some("awg0".into()),
        };

        assert_eq!(log.observe_mode(&managing), Some(None));
        assert_eq!(log.observe_mode(&managing), None);
        assert_eq!(log.observe_mode(&monitoring), Some(Some(managing.clone())));
        assert_eq!(log.observe_mode(&monitoring), None);
        assert_eq!(log.observe_mode(&managing), Some(Some(monitoring)));
    }

    #[test]
    fn scope_log_reports_each_change_once() {
        let mut log = ScopeLog::default();
        let foreign = vec!["awg1".to_string()];

        let first = log.observe("awg0", true, &foreign);
        assert_eq!(
            first,
            ScopeChanges {
                interface: true,
                presence: false,
                ignored: true,
            }
        );

        let steady = log.observe("awg0", true, &foreign);
        assert_eq!(steady, ScopeChanges::default());

        let down = log.observe("awg0", false, &foreign);
        assert_eq!(
            down,
            ScopeChanges {
                interface: false,
                presence: true,
                ignored: false,
            }
        );

        let alone = log.observe("awg0", true, &[]);
        assert_eq!(
            alone,
            ScopeChanges {
                interface: false,
                presence: true,
                ignored: true,
            }
        );

        let switched = log.observe("awg1", true, &[]);
        assert_eq!(
            switched,
            ScopeChanges {
                interface: true,
                presence: false,
                ignored: false,
            }
        );
    }

    #[test]
    fn scope_log_first_observation_warns_only_when_managed_interface_is_missing() {
        let mut log = ScopeLog::default();
        let first = log.observe("awg0", false, &[]);
        assert_eq!(
            first,
            ScopeChanges {
                interface: true,
                presence: true,
                ignored: false,
            }
        );
    }

    #[tokio::test]
    async fn concurrency_stress_test_file_db() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("stress_concurrency.db");
        let db = Database::connect(db_path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();

        let peer_count = 30;
        let mut pks = Vec::new();
        for i in 0..peer_count {
            let pk = format!("CONCURRENT_PK_{:03}=", i);
            sqlx::query("INSERT INTO peers (public_key, allowed_ips) VALUES (?, ?)")
                .bind(&pk)
                .bind(format!("10.8.0.{}/32", i + 2))
                .execute(&db.pool)
                .await
                .expect("seed peer");
            pks.push(pk);
        }

        // Seed expired snapshots (40 days old) crossing the 5,000-row batch boundary (6,000 rows)
        // to thoroughly exercise concurrent chunk deletion, inter-batch sleep, and lock yielding.
        let expired_count = 6000;
        let expired_ts =
            (Utc::now() - chrono::Duration::days(40)).to_rfc3339_opts(SecondsFormat::Secs, true);
        {
            let mut tx = db.pool.begin().await.expect("seed tx");
            for i in 0..expired_count {
                let pk = &pks[i % pks.len()];
                sqlx::query(
                    "INSERT INTO snapshots (public_key, captured_at, rx_bytes, tx_bytes) VALUES (?, ?, ?, ?)",
                )
                .bind(pk)
                .bind(&expired_ts)
                .bind(100)
                .bind(200)
                .execute(&mut *tx)
                .await
                .expect("seed snapshot");
            }
            tx.commit().await.expect("commit seed tx");
        }

        let poller = Poller::new(db.clone(), 30, PathBuf::from(".")).with_retention_days(31);

        // Writer task 1: Poller writing batches of snapshots and upserting peers
        let poller1 = poller.clone();
        let pks1 = pks.clone();
        let writer_task = tokio::spawn(async move {
            for round in 0..15 {
                let mut peers = Vec::new();
                for pk in &pks1 {
                    peers.push(awg::AwgPeer {
                        public_key: PublicKey(pk.clone()),
                        endpoint: Some("198.51.100.1:51820".to_string()),
                        allowed_ips: vec!["10.8.0.2/32".to_string()],
                        last_handshake: Some(Utc::now()),
                        rx_bytes: (round + 1) * 1000,
                        tx_bytes: (round + 1) * 2000,
                    });
                }
                let iface = awg::AwgInterface {
                    name: "awg0".to_string(),
                    public_key: PublicKey("SERVER_KEY=".to_string()),
                    listen_port: Some(51820),
                    peers,
                };
                poller1
                    .record_poll_batch(&[iface], Utc::now())
                    .await
                    .expect("record_poll_batch in writer task");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        // Writer task 2: Snapshot retention cleaner running concurrently
        let poller2 = poller.clone();
        let cleaner_task = tokio::spawn(async move {
            let mut total_deleted = 0u64;
            for _ in 0..10 {
                let deleted = poller2
                    .cleanup_expired_snapshots()
                    .await
                    .expect("cleanup in cleaner task");
                total_deleted += deleted;
                tokio::time::sleep(Duration::from_millis(8)).await;
            }
            total_deleted
        });

        // Reader task 1: API listing visible peers
        let db_r1 = db.clone();
        let reader_visible = tokio::spawn(async move {
            for _ in 0..30 {
                let peers = crate::db::peers::list_visible(&db_r1.pool)
                    .await
                    .expect("list_visible in reader");
                assert_eq!(peers.len(), peer_count);
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
        });

        // Reader task 2: Traffic history queries
        let db_r2 = db.clone();
        let pks2 = pks.clone();
        let reader_history = tokio::spawn(async move {
            for _ in 0..30 {
                for pk in pks2.iter().take(5) {
                    let _ = crate::db::peers::find_snapshots(&db_r2.pool, pk, 10)
                        .await
                        .expect("find_snapshots in reader");
                }
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
        });

        // Writer task 3: Web handler updating metadata / disabling peers
        let db_w3 = db.clone();
        let pks3 = pks.clone();
        let web_updater = tokio::spawn(async move {
            for i in 0..15 {
                let target_pk = &pks3[i % pks3.len()];
                let row = crate::db::peers::find_by_public_key(&db_w3.pool, target_pk)
                    .await
                    .expect("find peer")
                    .expect("peer exists");
                let updated =
                    crate::db::peers::update_peer_disabled(&db_w3.pool, row.id, i % 2 == 1)
                        .await
                        .expect("update disabled");
                assert!(updated.is_some());
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let (r1, r2, r3, r4, r5) = tokio::join!(
            writer_task,
            cleaner_task,
            reader_visible,
            reader_history,
            web_updater
        );
        r1.expect("writer task");
        let cleaner_deleted = r2.expect("cleaner task");
        r3.expect("reader visible task");
        r4.expect("reader history task");
        r5.expect("web updater task");

        // Each of the 30 peers keeps one pre-cutoff baseline; the rest of the
        // 6,000 expired rows are deleted across batch boundaries.
        assert_eq!(cleaner_deleted, (expired_count - peer_count) as u64);

        let expired_remaining: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM snapshots WHERE captured_at = ?")
                .bind(&expired_ts)
                .fetch_one(&db.pool)
                .await
                .expect("count expired snapshots");
        assert_eq!(expired_remaining.0, peer_count as i64);

        let fresh_count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM snapshots WHERE captured_at > ?")
                .bind(&expired_ts)
                .fetch_one(&db.pool)
                .await
                .expect("count fresh snapshots");
        assert!(fresh_count.0 > 0);
    }
}
