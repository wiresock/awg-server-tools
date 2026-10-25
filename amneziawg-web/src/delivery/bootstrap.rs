// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

//! Initial configuration admission, before the worker or public routes start.
use super::{
    config::Settings, exports::ExportSource, runtime::TransportFactory, service::DeliveryContext,
    settings,
};
use std::sync::Arc;

pub async fn initialize(
    source: ExportSource,
    auth_enabled: bool,
    admin_base: &str,
    fallback: impl FnOnce() -> super::Result<Settings>,
    factory: Arc<dyn TransportFactory>,
) -> anyhow::Result<Arc<DeliveryContext>> {
    // Do not even inspect saved SMTP secrets when authentication is disabled.
    if !auth_enabled {
        return blocked(source, "email_requires_auth");
    }
    let (settings, revision) = match settings::load_saved(&source.db.pool, auth_enabled).await {
        Ok(Some(saved)) => (saved.settings, saved.revision),
        Ok(None) => (fallback()?, 0),
        Err(super::DeliveryError("settings_storage_not_private")) => {
            return blocked(source, "email_storage_restart_required");
        }
        Err(error) => return Err(error.into()),
    };
    crate::web::delivery_base_path(
        admin_base,
        settings.enabled && settings.public_base.is_some(),
    )
    .map_err(anyhow::Error::msg)?;
    let owner = super::service::worker_lock(&source.lock_directory)?;
    let transport = factory.build(&settings)?;
    let mut context = DeliveryContext::new(source, settings, transport, Some(owner), revision);
    context.transport_factory = factory;
    let context = Arc::new(context);
    context.recover().await?;
    Ok(context)
}

pub(crate) fn blocked(
    source: ExportSource,
    reason: &'static str,
) -> anyhow::Result<Arc<DeliveryContext>> {
    // Empty constants, never the environment or saved row. No worker lock,
    // transport factory or ordinary recovery (which would alter bindings).
    let mut context = DeliveryContext::new(
        source,
        Settings::parse(|_| None, false)?,
        Arc::new(super::smtp::Disabled),
        None,
        0,
    );
    context.startup_blocked = Some(reason);
    Ok(Arc::new(context))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn review_bootstrap_storage_failure_pauses_email_without_secret_read_or_fallback() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("fixture.sqlite");
        let db = Database::connect(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        // An unreadable secret representation detects accidental SELECT *;
        // no real secret or network address is involved.
        sqlx::query("INSERT INTO email_panel_settings(id,revision,enabled,host,port,tls,authenticate,username,password,from_address,ttl_seconds) VALUES(1,7,1,'fixture.example.test',587,'starttls',1,'fixture',X'FF','sender@example.test',86400)").execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO delivery_settings VALUES(1,X'CAFE')")
            .execute(&db.pool)
            .await
            .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let builds = Arc::new(AtomicUsize::new(0));
        let counter = builds.clone();
        let factory: Arc<dyn TransportFactory> = Arc::new(move |_: &Settings| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::new(super::super::smtp::Disabled) as Arc<dyn super::super::smtp::Transport>)
        });
        let context = initialize(
            ExportSource {
                db: db.clone(),
                directory: dir.path().into(),
                lock_directory: dir.path().into(),
                ownership: Arc::new(super::super::exports::ServerOwnership {
                    override_name: None,
                }),
            },
            true,
            "",
            || panic!("unsafe saved profile must never fall back to environment"),
            factory,
        )
        .await
        .expect("private-storage failure must not stop peer panel startup");
        assert!(context.enabled().is_err());
        assert!(context.runtime().settings.password.is_empty());
        assert!(!context.runtime().settings.enabled);
        assert_eq!(builds.load(Ordering::SeqCst), 0);
        assert!(
            context.recover().await.is_err(),
            "ordinary recovery cannot lift startup blocking"
        );
        let fingerprint: Vec<u8> =
            sqlx::query_scalar("SELECT config_fingerprint FROM delivery_settings")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(fingerprint, vec![0xca, 0xfe]);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT revision FROM email_panel_settings")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            7
        );
    }
    fn source(db: Database, dir: &std::path::Path) -> ExportSource {
        ExportSource {
            db,
            directory: dir.into(),
            lock_directory: dir.into(),
            ownership: Arc::new(super::super::exports::ServerOwnership {
                override_name: None,
            }),
        }
    }
    fn private_files(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let p = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
            if p.exists() {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }
    fn no_factory() -> Arc<dyn TransportFactory> {
        Arc::new(
            |_: &Settings| -> super::super::Result<Arc<dyn super::super::smtp::Transport>> {
                panic!("must not build a transport")
            },
        )
    }
    #[tokio::test]
    async fn review_bootstrap_private_repair_requires_restart_and_preserves_disabled_profile() {
        for enabled in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = dir.path().join("fixture.sqlite");
            let db = Database::connect(path.to_str().unwrap()).await.unwrap();
            db.migrate().await.unwrap();
            sqlx::query("INSERT INTO email_panel_settings(id,revision,enabled,host,port,tls,authenticate,username,password,from_address,ttl_seconds) VALUES(1,7,?,'fixture.example.test',587,'starttls',1,'fixture','dummy-canary','sender@example.test',86400)").bind(enabled).execute(&db.pool).await.unwrap();
            private_files(&path);
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
            let ctx = initialize(
                source(db.clone(), dir.path()),
                true,
                "",
                || panic!("no environment fallback"),
                no_factory(),
            )
            .await
            .unwrap();
            assert_eq!(ctx.startup_blocked, Some("email_storage_restart_required"));
            let view = serde_json::to_string(&ctx.settings_view()).unwrap();
            for secret in [
                "dummy-canary",
                "fixture.example.test",
                "sender@example.test",
            ] {
                assert!(!view.contains(secret));
            }
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(ctx.recover().await.is_err());
            assert!(ctx.guards().await.is_err());
            assert!(!ctx.settings_view().storage_ready);
            assert!(ctx.test_configuration(0, None).is_err());
            let draft=serde_json::from_value(serde_json::json!({"revision":0,"enabled":false,"host":"","port":587,"tls":"starttls","authenticate":false,"username":"","password_action":"clear","from":"","reply_to":null,"public_base":null,"ttl_seconds":86400})).unwrap();
            assert_eq!(
                ctx.update_settings(draft, true, String::new())
                    .await
                    .err()
                    .unwrap()
                    .0,
                "email_storage_restart_required"
            );
            tokio::time::timeout(std::time::Duration::from_millis(100), ctx.clone().run())
                .await
                .expect("blocked worker must return without polling");
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM delivery_settings")
                    .fetch_one(&db.pool)
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT revision FROM email_panel_settings")
                    .fetch_one(&db.pool)
                    .await
                    .unwrap(),
                7
            );
            let factory: Arc<dyn TransportFactory> = Arc::new(|s: &Settings| {
                assert_eq!(s.password, "dummy-canary");
                Ok(Arc::new(super::super::smtp::Disabled)
                    as Arc<dyn super::super::smtp::Transport>)
            });
            let restarted = initialize(
                source(db.clone(), dir.path()),
                true,
                "",
                || panic!("saved profile required"),
                factory,
            )
            .await
            .unwrap();
            assert!(restarted.startup_ready().is_ok());
            assert_eq!(restarted.runtime().revision, 7);
            assert_eq!(restarted.runtime().settings.enabled, enabled);
        }
    }
    #[tokio::test]
    async fn review_bootstrap_auth_disabled_never_reads_secret_or_environment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.sqlite");
        let db = Database::connect(path.to_str().unwrap()).await.unwrap();
        db.migrate().await.unwrap();
        sqlx::query("INSERT INTO email_panel_settings(id,revision,enabled,host,port,tls,authenticate,username,password,from_address,ttl_seconds) VALUES(1,2,1,'fixture.example.test',587,'starttls',1,'fixture',X'FF','sender@example.test',86400)").execute(&db.pool).await.unwrap();
        let ctx = initialize(
            source(db.clone(), dir.path()),
            false,
            "",
            || panic!("auth-disabled must not inspect SMTP environment"),
            no_factory(),
        )
        .await
        .unwrap();
        assert_eq!(ctx.startup_blocked, Some("email_requires_auth"));
        assert!(ctx.runtime().settings.password.is_empty());
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM delivery_settings")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            0
        );
    }
    #[tokio::test]
    async fn review_bootstrap_does_not_swallow_database_or_lifecycle_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture.sqlite");
        let db = Database::connect(path.to_str().unwrap()).await.unwrap();
        assert!(initialize(
            source(db.clone(), dir.path()),
            true,
            "",
            || panic!("DB error must propagate"),
            no_factory()
        )
        .await
        .is_err());
        db.migrate().await.unwrap();
        let mut input = source(db, dir.path());
        input.lock_directory = dir.path().join("missing-lifecycle");
        assert!(initialize(
            input,
            true,
            "",
            || Settings::parse(|_| None, true),
            no_factory()
        )
        .await
        .is_err());
    }
}
