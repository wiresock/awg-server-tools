// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

//! Panel-owned settings. Secret-bearing values deliberately lack Debug/Serialize.
use super::{config::Settings, DeliveryError, Result};
use serde::Deserialize;
use sqlx::{Sqlite, SqlitePool, Transaction};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasswordAction {
    Keep,
    Replace,
    Clear,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelSettingsInput {
    pub revision: i64,
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub tls: String,
    #[serde(default)]
    pub allow_plaintext: bool,
    pub authenticate: bool,
    pub username: String,
    pub password_action: PasswordAction,
    pub password: Option<String>,
    pub from: String,
    pub reply_to: Option<String>,
    pub public_base: Option<String>,
    pub ttl_seconds: i64,
}

pub struct StoredSettings {
    pub revision: i64,
    pub settings: Settings,
}

impl PanelSettingsInput {
    pub fn resolve(&self, previous: &Settings, auth_enabled: bool) -> Result<Settings> {
        if self.revision < 0 || self.revision == i64::MAX {
            return Err(DeliveryError("settings_changed"));
        }
        if self.enabled && !auth_enabled {
            return Err(DeliveryError("email_requires_auth"));
        }
        let supplied = self.password.as_deref().unwrap_or("");
        let password = match self.password_action {
            PasswordAction::Keep if supplied.is_empty() => previous.password.clone(),
            PasswordAction::Clear if supplied.is_empty() => String::new(),
            PasswordAction::Replace
                if !supplied.is_empty()
                    && supplied.len() <= 4096
                    && !supplied.chars().any(char::is_control) =>
            {
                supplied.into()
            }
            _ => return Err(DeliveryError("invalid_password_action")),
        };
        let host = self.host.trim();
        if (self.enabled || !host.is_empty())
            && (host.is_empty()
                || host.len() > 253
                || host.chars().any(|c| c.is_whitespace() || c.is_control())
                || host.contains(['/', '\\', '@', '?', '#'])
                || url::Host::parse(host).is_err())
        {
            return Err(DeliveryError("invalid_smtp_host"));
        }
        let tls = super::config::TransportSecurity::parse(&self.tls)?;
        if tls == super::config::TransportSecurity::None && !self.allow_plaintext {
            return Err(DeliveryError("plaintext_ack_required"));
        }
        tls.validate_credentials(self.authenticate, &self.username, &password)?;
        if self.port == 0 {
            return Err(DeliveryError("invalid_smtp_port"));
        }
        if !(300..=604800).contains(&self.ttl_seconds) {
            return Err(DeliveryError("invalid_ttl"));
        }
        let username = self.username.trim();
        if username.len() > 320 || username.chars().any(char::is_control) {
            return Err(DeliveryError("invalid_smtp_username"));
        }
        if self.enabled && self.authenticate && (username.is_empty() || password.is_empty()) {
            return Err(DeliveryError("smtp_credentials_required"));
        }
        let from = if !self.enabled && self.from.trim().is_empty() {
            String::new()
        } else {
            super::config::mailbox(&self.from)?
        };
        let reply_to = self
            .reply_to
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(super::config::mailbox)
            .transpose()?;
        let public_base = self
            .public_base
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(super::config::public_base)
            .transpose()?;
        Ok(Settings {
            enabled: self.enabled,
            host: host.into(),
            port: self.port,
            tls,
            from,
            reply_to,
            username: username.into(),
            authenticate: self.authenticate,
            password,
            public_base,
            ttl: self.ttl_seconds,
        })
    }
}

pub fn verify_private_database(pool: &SqlitePool) -> Result<()> {
    let filename = pool.connect_options().get_filename().to_path_buf();
    // SQLx gives unit-test shared-memory databases this non-filesystem name.
    // No such exception is compiled into the shipping executable.
    #[cfg(test)]
    if filename
        .to_string_lossy()
        .starts_with("file:sqlx-in-memory-")
    {
        return Ok(());
    }
    verify_private_path(&filename)
}

#[cfg(unix)]
fn verify_private_path(filename: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let unsafe_store = DeliveryError("settings_storage_not_private");
    let path = if filename.is_absolute() {
        filename.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| unsafe_store)?
            .join(filename)
    };
    if std::fs::canonicalize(&path).map_err(|_| unsafe_store)? != path {
        return Err(unsafe_store);
    }
    let parent = path.parent().ok_or(unsafe_store)?;
    let directory = std::fs::symlink_metadata(parent).map_err(|_| unsafe_store)?;
    let uid = unsafe { libc::geteuid() };
    if !directory.is_dir()
        || directory.file_type().is_symlink()
        || directory.uid() != uid
        || directory.mode() & 0o077 != 0
    {
        return Err(unsafe_store);
    }
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let metadata = match std::fs::symlink_metadata(&name) {
            Ok(value) => value,
            Err(error) if !suffix.is_empty() && error.kind() == std::io::ErrorKind::NotFound => {
                continue
            }
            Err(_) => return Err(unsafe_store),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != uid
            || metadata.mode() & 0o177 != 0
            || metadata.nlink() != 1
        {
            return Err(unsafe_store);
        }
    }
    Ok(())
}
#[cfg(not(unix))]
fn verify_private_path(_: &std::path::Path) -> Result<()> {
    // This Linux server must not mistake POSIX mode bits for a Windows ACL.
    Err(DeliveryError("settings_storage_not_private"))
}

#[derive(sqlx::FromRow)]
struct StoredRow {
    revision: i64,
    enabled: bool,
    host: String,
    port: i64,
    tls: String,
    authenticate: bool,
    username: String,
    password: String,
    from_address: String,
    reply_to: Option<String>,
    public_base: Option<String>,
    ttl_seconds: i64,
}

pub async fn load_saved(pool: &SqlitePool, auth_enabled: bool) -> Result<Option<StoredSettings>> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_panel_settings WHERE id=1)")
            .fetch_one(pool)
            .await?;
    if !exists {
        return Ok(None);
    }
    verify_private_database(pool)?;
    let row: StoredRow = sqlx::query_as("SELECT * FROM email_panel_settings WHERE id=1")
        .fetch_one(pool)
        .await?;
    let mut previous = Settings::parse(|_| None, auth_enabled)?;
    previous.password = row.password;
    let input = PanelSettingsInput {
        revision: row.revision,
        enabled: row.enabled,
        host: row.host,
        port: row
            .port
            .try_into()
            .map_err(|_| DeliveryError("invalid_smtp_port"))?,
        allow_plaintext: row.tls == "none",
        tls: row.tls,
        authenticate: row.authenticate,
        username: row.username,
        password_action: PasswordAction::Keep,
        password: None,
        from: row.from_address,
        reply_to: row.reply_to,
        public_base: row.public_base,
        ttl_seconds: row.ttl_seconds,
    };
    let settings = input.resolve(&previous, auth_enabled)?;
    Ok(Some(StoredSettings {
        revision: row.revision,
        settings,
    }))
}

/// Caller owns ordered admission guards and the transaction through commit and
/// runtime swap. No transport/network operation belongs inside this function.
pub async fn write_saved(
    pool: &SqlitePool,
    tx: &mut Transaction<'_, Sqlite>,
    expected: i64,
    settings: &Settings,
) -> Result<i64> {
    verify_private_database(pool)?;
    // Obtain the SQLite writer before comparing, including the empty-row case.
    sqlx::query("UPDATE email_panel_settings SET revision=revision WHERE id=1")
        .execute(&mut **tx)
        .await?;
    let current: Option<i64> =
        sqlx::query_scalar("SELECT revision FROM email_panel_settings WHERE id=1")
            .fetch_optional(&mut **tx)
            .await?;
    if current.unwrap_or(0) != expected || expected < 0 {
        return Err(DeliveryError("settings_changed"));
    }
    let revision = expected
        .checked_add(1)
        .ok_or(DeliveryError("settings_changed"))?;
    sqlx::query("INSERT INTO email_panel_settings(id,revision,enabled,host,port,tls,authenticate,username,password,from_address,reply_to,public_base,ttl_seconds) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,enabled=excluded.enabled,host=excluded.host,port=excluded.port,tls=excluded.tls,authenticate=excluded.authenticate,username=excluded.username,password=excluded.password,from_address=excluded.from_address,reply_to=excluded.reply_to,public_base=excluded.public_base,ttl_seconds=excluded.ttl_seconds")
        .bind(revision).bind(settings.enabled).bind(&settings.host).bind(settings.port as i64)
        .bind(settings.tls.as_str()).bind(settings.authenticate).bind(&settings.username).bind(&settings.password)
        .bind(&settings.from).bind(&settings.reply_to).bind(settings.public_base.as_ref().map(|u|u.as_str()))
        .bind(settings.ttl).execute(&mut **tx).await?;
    sqlx::query("UPDATE delivery_clients SET binding_version=binding_version+1")
        .execute(&mut **tx)
        .await?;
    sqlx::query("INSERT INTO delivery_settings VALUES(1,?) ON CONFLICT(id) DO UPDATE SET config_fingerprint=excluded.config_fingerprint")
        .bind(settings.fingerprint()).execute(&mut **tx).await?;
    verify_private_database(pool)?;
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn env() -> Settings {
        Settings::parse(
            |name| match name {
                "AWG_EMAIL_ENABLED" => Some("true".into()),
                "AWG_SMTP_HOST" => Some("old.example.test".into()),
                "AWG_SMTP_FROM" => Some("sender@example.test".into()),
                "AWG_SMTP_USERNAME" => Some("old-user".into()),
                "AWG_SMTP_PASSWORD" => Some("old-secret-canary".into()),
                _ => None,
            },
            true,
        )
        .unwrap()
    }
    fn input() -> PanelSettingsInput {
        serde_json::from_value(serde_json::json!({"revision":0,"enabled":true,"host":"new.example.test","port":587,"tls":"starttls","authenticate":true,"username":"new-user","password_action":"keep","from":"sender@example.test","reply_to":"support@example.test","public_base":null,"ttl_seconds":86400})).unwrap()
    }
    async fn save(db: &Database, revision: i64, settings: &Settings) -> Result<i64> {
        let mut tx = db.pool.begin().await?;
        let revision = write_saved(&db.pool, &mut tx, revision, settings).await?;
        tx.commit().await?;
        Ok(revision)
    }
    async fn disk() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("panel.sqlite3");
        let db = Database::connect(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let path = dir.path().join(format!("panel.sqlite3{suffix}"));
            if path.exists() {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        (dir, db)
    }

    #[test]
    fn panel_plaintext_requires_acknowledgment_and_no_retained_credentials() {
        let mut value = serde_json::json!({"revision":0,"enabled":true,"host":"relay.example.test","port":25,"tls":"none","authenticate":false,"username":"","password_action":"clear","from":"sender@example.test","ttl_seconds":86400});
        let body: PanelSettingsInput = serde_json::from_value(value.clone()).unwrap();
        assert!(body.resolve(&env(), true).is_err());
        value["allow_plaintext"] = true.into();
        let body: PanelSettingsInput = serde_json::from_value(value.clone())
            .expect("explicit plaintext acknowledgment must be supported");
        assert!(body.resolve(&env(), true).is_ok());
        value["password_action"] = "keep".into();
        let body: PanelSettingsInput = serde_json::from_value(value).unwrap();
        assert!(matches!(
            body.resolve(&env(), true),
            Err(DeliveryError("plaintext_auth_forbidden"))
        ));
    }
    #[test]
    fn panel_password_keep_replace_clear_are_explicit() {
        let previous = env();
        let mut body = input();
        let kept = body
            .resolve(&previous, true)
            .expect("keep succeeds without sending a password");
        assert_eq!(kept.password, "old-secret-canary");
        assert_eq!(kept.host, "new.example.test");
        body.password = Some(String::new());
        assert_eq!(
            body.resolve(&previous, true).unwrap().password,
            "old-secret-canary"
        );
        body.password_action = PasswordAction::Replace;
        assert!(
            body.resolve(&previous, true).is_err(),
            "empty replace cannot erase the secret"
        );
        body.password = Some("new-secret-canary".into());
        let replaced = body.resolve(&previous, true).unwrap();
        assert_eq!(replaced.password, "new-secret-canary");
        body.password_action = PasswordAction::Clear;
        body.password = None;
        assert!(
            body.resolve(&previous, true).is_err(),
            "enabled authenticated SMTP requires a password"
        );
        body.enabled = false;
        assert!(body.resolve(&previous, true).unwrap().password.is_empty());
        assert!(
            body.resolve(&previous, false).is_ok(),
            "disabled configuration is safe to retain"
        );
    }
    #[tokio::test]
    async fn panel_plaintext_profile_roundtrips_without_credentials() {
        let (_dir, db) = disk().await;
        let mut body = input();
        body.tls = "none".into();
        body.allow_plaintext = true;
        body.authenticate = false;
        body.username.clear();
        body.password_action = PasswordAction::Clear;
        let profile = body.resolve(&env(), true).unwrap();
        save(&db, 0, &profile).await.unwrap();
        let loaded = load_saved(&db.pool, true).await.unwrap().unwrap();
        assert_eq!(
            loaded.settings.tls,
            super::super::config::TransportSecurity::None
        );
        assert!(loaded.settings.password.is_empty());
        assert!(!loaded.settings.authenticate);
        for (auth, username, password) in [
            (true, "", ""),
            (false, "user", ""),
            (false, "", "retained-secret"),
        ] {
            let mut body = input();
            body.tls = "none".into();
            body.allow_plaintext = true;
            body.authenticate = auth;
            body.username = username.into();
            body.enabled = false;
            let mut previous = env();
            previous.password = password.into();
            assert!(matches!(
                body.resolve(&previous, true),
                Err(DeliveryError("plaintext_auth_forbidden"))
            ));
        }
    }
    #[tokio::test]
    async fn panel_smtp_migration_preserves_existing_profile_bytes_and_revision() {
        let db = Database::connect_for_test().await.unwrap();
        sqlx::query("DROP TABLE email_panel_settings; DROP TABLE smtp_connection_checks;")
            .execute(&db.pool)
            .await
            .unwrap();
        // Reproduce the previous schema before applying only the new migration.
        let previous = include_str!("../../migrations/0012_email_panel_settings.sql")
            .split("-- Existing jobs")
            .next()
            .unwrap();
        sqlx::raw_sql(previous).execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO email_panel_settings VALUES(1,42,1,'relay.example.test',465,'implicit',1,'dummy-user','dummy-secret','from@example.test',NULL,NULL,3600)").execute(&db.pool).await.unwrap();
        let before: (i64, String, String, String) =
            sqlx::query_as("SELECT revision,tls,username,password FROM email_panel_settings")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        sqlx::raw_sql(include_str!(
            "../../migrations/0013_smtp_connection_check.sql"
        ))
        .execute(&db.pool)
        .await
        .unwrap();
        let after: (i64, String, String, String) =
            sqlx::query_as("SELECT revision,tls,username,password FROM email_panel_settings")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(before, after);
        assert!(sqlx::query("UPDATE email_panel_settings SET tls='none'")
            .execute(&db.pool)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn panel_cas_and_restart_do_not_resurrect_cleared_env_secret() {
        let (dir, db) = disk().await;
        assert!(load_saved(&db.pool, true).await.unwrap().is_none());
        let mut body = input();
        body.enabled = false;
        body.password_action = PasswordAction::Clear;
        let settings = body.resolve(&env(), true).unwrap();
        assert_eq!(save(&db, 0, &settings).await.unwrap(), 1);
        assert!(matches!(
            save(&db, 0, &env()).await,
            Err(DeliveryError("settings_changed"))
        ));
        db.pool.close().await;
        let reopened = Database::connect(dir.path().join("panel.sqlite3").to_str().unwrap())
            .await
            .unwrap();
        let stored = load_saved(&reopened.pool, true)
            .await
            .unwrap()
            .expect("full saved configuration wins over env");
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.settings.host, "new.example.test");
        assert!(!stored.settings.enabled);
        assert!(stored.settings.password.is_empty());
    }
    #[tokio::test]
    async fn panel_settings_rollback_does_not_change_configuration_or_binding() {
        let db = Database::connect_for_test().await.unwrap();
        sqlx::query("INSERT INTO delivery_clients(id,interface,managed_name,last_public_key) VALUES('client','awg0','phone','key')").execute(&db.pool).await.unwrap();
        let mut tx = db.pool.begin().await.unwrap();
        assert_eq!(write_saved(&db.pool, &mut tx, 0, &env()).await.unwrap(), 1);
        tx.rollback().await.unwrap();
        assert!(load_saved(&db.pool, true).await.unwrap().is_none());
        let version: i64 =
            sqlx::query_scalar("SELECT binding_version FROM delivery_clients WHERE id='client'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(version, 1);
        save(&db, 0, &env()).await.unwrap();
        let version: i64 =
            sqlx::query_scalar("SELECT binding_version FROM delivery_clients WHERE id='client'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(
            version, 2,
            "settings and binding invalidation commit together"
        );
    }
    #[tokio::test]
    async fn panel_private_storage_accepts_private_db_and_rejects_public_sidecars() {
        let (dir, db) = disk().await;
        verify_private_database(&db.pool).expect("private fixture allowed");
        for suffix in ["", "-wal", "-shm"] {
            let path = dir.path().join(format!("panel.sqlite3{suffix}"));
            assert!(path.exists());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(
                matches!(
                    verify_private_database(&db.pool),
                    Err(DeliveryError("settings_storage_not_private"))
                ),
                "unsafe database/sidecar must fail closed"
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_private_database(&db.pool).is_err());
    }
    #[tokio::test]
    async fn panel_private_storage_rejects_symlink_and_hardlinked_database() {
        let (dir, db) = disk().await;
        let path = dir.path().join("panel.sqlite3");
        std::fs::hard_link(&path, dir.path().join("other.sqlite3")).unwrap();
        assert!(
            verify_private_database(&db.pool).is_err(),
            "hardlink can expose a credential-bearing DB outside the private directory"
        );
        std::fs::remove_file(dir.path().join("other.sqlite3")).unwrap();
        let alias = dir.path().join("alias.sqlite3");
        symlink(&path, &alias).unwrap();
        let aliased = Database::connect(alias.to_str().unwrap()).await.unwrap();
        assert!(verify_private_database(&aliased.pool).is_err());
    }
    #[tokio::test]
    async fn panel_saved_secret_is_not_read_after_permissions_weaken() {
        let (dir, db) = disk().await;
        save(&db, 0, &env()).await.unwrap();
        std::fs::set_permissions(
            dir.path().join("panel.sqlite3"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            load_saved(&db.pool, true).await,
            Err(DeliveryError("settings_storage_not_private"))
        ));
    }

    #[test]
    fn panel_input_rejects_unsafe_settings_without_secret_in_errors() {
        for case in 0..9 {
            let mut body = input();
            match case {
                0 => body.tls = "none".into(),
                1 => body.host = "smtp.example.test/path".into(),
                2 => body.port = 0,
                3 => body.ttl_seconds = 299,
                4 => body.ttl_seconds = 604801,
                5 => body.from = "sender@example.test,other@example.test".into(),
                6 => body.username = "user\r\ncanary".into(),
                7 => body.public_base = Some("http://download.example.test".into()),
                8 => body.password = Some("not-allowed-on-keep-canary".into()),
                _ => unreachable!(),
            }
            let error = match body.resolve(&env(), true) {
                Ok(_) => panic!("unsafe settings accepted"),
                Err(error) => error,
            };
            assert!(!error.to_string().contains("canary"));
        }
        assert!(matches!(
            input().resolve(&env(), false),
            Err(DeliveryError("email_requires_auth"))
        ));
        let mut anonymous = input();
        anonymous.authenticate = false;
        anonymous.password_action = PasswordAction::Clear;
        let settings = anonymous.resolve(&env(), true).unwrap();
        assert!(!settings.authenticate);
        assert!(settings.password.is_empty());
    }

    #[tokio::test]
    async fn panel_concurrent_saves_have_one_winner_and_no_lost_update() {
        let (_dir, db) = disk().await;
        let a = env();
        let mut b = env();
        b.host = "other.example.test".into();
        let (first, second) = tokio::join!(save(&db, 0, &a), save(&db, 0, &b));
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let loser = if first.is_err() { first } else { second };
        assert!(matches!(loser, Err(DeliveryError("settings_changed"))));
        assert_eq!(
            load_saved(&db.pool, true).await.unwrap().unwrap().revision,
            1
        );
    }
}
