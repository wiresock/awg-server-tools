//! Explicit, deduplicated harmless test messages; never VPN export jobs.
use super::{
    service::DeliveryContext,
    smtp::{MailMessage, Submission},
    *,
};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestRequest {
    pub revision: i64,
    pub recipient: String,
    pub request_id: String,
    pub draft: Option<super::settings::PanelSettingsInput>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TestOutcome {
    pub id: String,
    pub settings_revision: i64,
    pub recipient: String,
    pub state: String,
    pub created_at: i64,
    pub error_code: Option<String>,
    #[sqlx(skip)]
    pub settings_changed: bool,
}
impl DeliveryContext {
    /// Read-only recovery for browser reloads. This never admits or resubmits
    /// mail and returns no credentials, SMTP payload or private config.
    pub async fn test_status(&self, id: &str) -> Result<Option<TestOutcome>> {
        if id.len() != 43
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DeliveryError("invalid_request_id"));
        }
        let mut row: Option<TestOutcome> =
            sqlx::query_as("SELECT * FROM email_test_attempts WHERE id=?")
                .bind(id)
                .fetch_optional(&self.source.db.pool)
                .await?;
        if let Some(row) = &mut row {
            row.settings_changed = row.settings_revision != self.runtime().revision;
            if row.state == "sending" && row.created_at < self.time() - 60 {
                row.state = "unknown".into();
                row.error_code = Some("completion_unknown".into());
            }
        }
        Ok(row)
    }
    async fn test_outcome(&self, body: &TestRequest) -> Result<Option<TestOutcome>> {
        // A lost completion write cannot leave the UI showing "sending"
        // forever. This never resubmits, including after a clock jump.
        sqlx::query("UPDATE email_test_attempts SET state='unknown',error_code='completion_unknown' WHERE id=? AND state='sending' AND created_at<?")
            .bind(&body.request_id).bind(self.time()-60).execute(&self.source.db.pool).await?;
        let row = self.test_status(&body.request_id).await?;
        match row {
            Some(row) => {
                if row.recipient != body.recipient || row.settings_revision != body.revision {
                    return Err(DeliveryError("invalid_request_id"));
                }
                Ok(Some(row))
            }
            None => Ok(None),
        }
    }
    pub async fn test_email(self: &Arc<Self>, mut body: TestRequest) -> Result<TestOutcome> {
        body.recipient = config::mailbox(&body.recipient)?;
        if body.request_id.len() != 43
            || !body
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DeliveryError("invalid_request_id"));
        }
        let ctx = self.clone();
        tokio::spawn(async move { ctx.submit_test(body).await })
            .await
            .map_err(|_| DeliveryError("test_result_unknown"))?
    }
    async fn submit_test(&self, mut body: TestRequest) -> Result<TestOutcome> {
        if let Some(row) = self.test_outcome(&body).await? {
            return Ok(row);
        }
        let _slot = self
            .test_slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| DeliveryError("test_busy"))?;
        // Existing attempt IDs above always recover the original attempt,
        // even if a caller accidentally includes a different draft on retry.
        let runtime = self.test_configuration(body.revision, body.draft.take())?;
        tokio::time::timeout(self.admission_budget, async {
            let _guards = self.guards().await?;
            self.validate_test_revision(runtime.revision)?;
            let mut tx = self.source.db.pool.begin().await?;
            sqlx::query("UPDATE email_test_attempts SET state=state WHERE id=?")
                .bind(&body.request_id).execute(&mut *tx).await?;
            let existing:bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM email_test_attempts WHERE id=?)")
                .bind(&body.request_id).fetch_one(&mut *tx).await?;
            if existing { return Err(DeliveryError("test_busy")); }
            sqlx::query("DELETE FROM email_test_attempts WHERE created_at<? AND state<>'sending'")
                .bind(self.time()-30*86400).execute(&mut *tx).await?;
            let count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM email_test_attempts WHERE created_at>?")
                .bind(self.time()-3600).fetch_one(&mut *tx).await?;
            if count>=5 { return Err(DeliveryError("test_limit")); }
            sqlx::query("INSERT INTO email_test_attempts(id,settings_revision,recipient,state,created_at) VALUES(?,?,?,'sending',?)")
                .bind(&body.request_id).bind(runtime.revision).bind(&body.recipient).bind(self.time())
                .execute(&mut *tx).await?;
            tx.commit().await?;
            Ok::<_,DeliveryError>(())
        }).await.map_err(|_|DeliveryError("test_result_unknown"))??;
        let mail=MailMessage {recipient:body.recipient.clone(),subject:"SMTP test from AmneziaWG panel".into(),
            body:"This is an explicitly requested SMTP test. It contains no VPN configuration or private key.".into(),attachments:Vec::new()};
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            runtime.transport.submit(&mail),
        )
        .await
        .unwrap_or(Submission::Unknown);
        let (state, code) = match outcome {
            Submission::Accepted => ("accepted", "accepted_by_smtp"),
            Submission::DefiniteTransient => ("failed", "transient_rejection"),
            Submission::DefinitePermanent => ("failed", "permanent_rejection"),
            Submission::Unknown => ("unknown", "acceptance_unknown"),
        };
        sqlx::query(
            "UPDATE email_test_attempts SET state=?,error_code=? WHERE id=? AND state='sending'",
        )
        .bind(state)
        .bind(code)
        .bind(&body.request_id)
        .execute(&self.source.db.pool)
        .await
        .map_err(|_| DeliveryError("test_result_unknown"))?;
        self.test_outcome(&body)
            .await?
            .ok_or(DeliveryError("test_result_unknown"))
    }
}
