//! Durable client identity and invalidation, independent of peer row lifetime.
use crate::delivery::{DeliveryError, Result};
use serde::Serialize;
use sqlx::SqlitePool;

#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct Client {
    pub id: String,
    pub peer_id: Option<i64>,
    pub interface: String,
    pub managed_name: String,
    pub last_public_key: String,
    pub email: Option<String>,
    pub binding_version: i64,
    #[serde(skip)]
    pub export_digest: Option<Vec<u8>>,
    pub retired_at: Option<i64>,
}
pub async fn client(pool: &SqlitePool, id: &str) -> Result<Client> {
    sqlx::query_as("SELECT * FROM delivery_clients WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(DeliveryError("not_found"))
}
pub async fn invalidate(pool: &SqlitePool, id: &str) -> Result<()> {
    sqlx::query("UPDATE delivery_clients SET binding_version=binding_version+1 WHERE id=?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct Job {
    pub id: String,
    pub client_id: String,
    pub request_id: String,
    pub actor: String,
    pub recipient: String,
    pub mode: String,
    pub link_ttl_seconds: i64,
    pub formats: String,
    pub binding_version: i64,
    #[serde(skip)]
    pub export_digest: Vec<u8>,
    pub state: String,
    pub attempts: i64,
    pub next_attempt_at: i64,
    pub created_at: i64,
    pub error_code: Option<String>,
    pub invalidated_at: Option<i64>,
    pub invalidation_code: Option<String>,
}
pub async fn job(pool: &SqlitePool, id: &str) -> Result<Job> {
    sqlx::query_as("SELECT * FROM email_jobs WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(DeliveryError("not_found"))
}
pub fn matches(job: &Job, snapshot: &crate::delivery::exports::ExportSnapshot) -> bool {
    job.invalidated_at.is_none()
        && snapshot.client.binding_version == job.binding_version
        && snapshot.digest == job.export_digest
        && snapshot.client.email.as_deref() == Some(&job.recipient)
}

#[cfg(test)]
mod tests {
    use crate::db::Database;
    use sqlx::Row;

    #[tokio::test]
    async fn panel_settings_upgrade_does_not_import_credentials() {
        let db = Database::connect_for_test().await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_panel_settings")
            .fetch_one(&db.pool)
            .await
            .expect("panel settings migration installed");
        assert_eq!(
            count, 0,
            "operator environment must not be silently persisted"
        );
    }

    #[tokio::test]
    async fn delivery_upgrade_from_0010_preserves_peers_without_email() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let all = sqlx::migrate!("./migrations");
        let old = sqlx::migrate::Migrator {
            migrations: std::borrow::Cow::Owned(
                all.iter().filter(|m| m.version <= 10).cloned().collect(),
            ),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        old.run(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO peers(public_key,allowed_ips,comment) VALUES('original','10.0.0.2/32','keep me')").execute(&db.pool).await.unwrap();
        db.migrate().await.unwrap();
        let comment: String =
            sqlx::query_scalar("SELECT comment FROM peers WHERE public_key='original'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(comment, "keep me");
        let contacts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM delivery_clients")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(contacts, 0);
        let jobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_jobs")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(jobs, 0);
    }

    async fn fixture() -> Database {
        let db = Database::connect_for_test().await.unwrap();
        sqlx::query("INSERT INTO peers(public_key,allowed_ips) VALUES('key-one','10.0.0.2/32')")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO delivery_clients(id,peer_id,interface,managed_name,last_public_key,email) VALUES('client',1,'awg0','phone','key-one','user@example.test')")
            .execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO email_jobs(id,client_id,request_id,actor,recipient,mode,formats,binding_version,export_digest,state,created_at,next_attempt_at) VALUES('job','client','request','admin','user@example.test','link','[]',1,X'01','sending',1,1)")
            .execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO delivery_grants(id,job_id,token_hash,binding_version,export_digest,expires_at) VALUES('grant','job',X'02',1,X'01',9999999999)")
            .execute(&db.pool).await.unwrap();
        db
    }

    #[tokio::test]
    async fn delivery_identity_survives_peer_replacement_and_name_reuse() {
        let db = fixture().await;
        sqlx::query("DELETE FROM peers WHERE id=1")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO peers(public_key,allowed_ips,managed_client_name) VALUES('key-two','10.0.0.2/32','phone')").execute(&db.pool).await.unwrap();
        let row = sqlx::query(
            "SELECT peer_id,email,last_public_key FROM delivery_clients WHERE id='client'",
        )
        .fetch_one(&db.pool)
        .await
        .unwrap();
        assert_eq!(row.get::<Option<i64>, _>("peer_id"), None);
        assert_eq!(row.get::<String, _>("email"), "user@example.test");
        assert_eq!(row.get::<String, _>("last_public_key"), "key-one");
    }

    #[tokio::test]
    async fn delivery_old_key_never_revives_and_sending_is_not_cancelled() {
        let db = fixture().await;
        for disabled in [1, 0] {
            sqlx::query("UPDATE peers SET disabled=? WHERE id=1")
                .bind(disabled)
                .execute(&db.pool)
                .await
                .unwrap();
        }
        let row = sqlx::query("SELECT state,invalidated_at FROM email_jobs WHERE id='job'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("state"), "sending");
        assert!(row.get::<Option<i64>, _>("invalidated_at").is_some());
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM delivery_grants WHERE id='grant'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert!(revoked.is_some());
    }
}
