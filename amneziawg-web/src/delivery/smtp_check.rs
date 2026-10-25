//! Explicit saved-profile or transient-draft checks, never message submission.
use super::{config::TransportSecurity, service::DeliveryContext, smtp::ConnectionCheck, *};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    pub revision: i64,
    pub draft: Option<super::settings::PanelSettingsInput>,
}
#[derive(Serialize)]
pub struct CheckOutcome {
    pub settings_revision: i64,
    pub settings_changed: bool,
    pub outcome: ConnectionCheck,
    pub security: TransportSecurity,
    pub authenticated: bool,
}
impl DeliveryContext {
    pub async fn check_smtp(self: &Arc<Self>, body: CheckRequest) -> Result<CheckOutcome> {
        // A disconnected HTTP caller must not free the slot while its bounded
        // connection check is still in flight. No automatic retries.
        let ctx = self.clone();
        tokio::spawn(async move { ctx.run_smtp_check(body).await })
            .await
            .map_err(|_| DeliveryError("smtp_check_unknown"))?
    }
    async fn run_smtp_check(&self, body: CheckRequest) -> Result<CheckOutcome> {
        let _slot = self
            .test_slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| DeliveryError("test_busy"))?;
        let runtime = self.test_configuration(body.revision, body.draft)?;
        tokio::time::timeout(self.admission_budget, async {
            let _guards = self.guards().await?;
            self.validate_test_revision(runtime.revision)?;
            let mut tx = self.source.db.pool.begin().await?;
            sqlx::query("DELETE FROM smtp_connection_checks WHERE created_at<=?")
                .bind(self.time() - 3600)
                .execute(&mut *tx)
                .await?;
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM smtp_connection_checks")
                .fetch_one(&mut *tx)
                .await?;
            if count >= 5 {
                return Err(DeliveryError("smtp_check_limit"));
            }
            sqlx::query("INSERT INTO smtp_connection_checks(created_at) VALUES(?)")
                .bind(self.time())
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok::<_, DeliveryError>(())
        })
        .await
        .map_err(|_| DeliveryError("admission_timeout"))??;
        // Only the immutable admitted transport remains; no global lock or DB
        // transaction spans DNS, TCP, TLS, AUTH or NOOP.
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            runtime.transport.check(),
        )
        .await
        .unwrap_or(ConnectionCheck::Timeout);
        Ok(CheckOutcome {
            settings_revision: runtime.revision,
            settings_changed: self.runtime().revision != runtime.revision
                || self.quarantined.load(std::sync::atomic::Ordering::Acquire),
            outcome,
            security: runtime.settings.tls,
            authenticated: outcome == ConnectionCheck::Connected && runtime.settings.authenticate,
        })
    }
}
