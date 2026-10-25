// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

use super::{
    service::DeliveryContext,
    smtp::{MailMessage, Submission},
    *,
};
use crate::db::delivery;
use std::sync::Arc;

/// Holds bytes, not guards/transactions. Network work cannot block revocation.
pub struct AdmittedMail {
    pub job: delivery::Job,
    pub mail: MailMessage,
    pub runtime: Arc<super::runtime::RuntimeConfiguration>,
}
impl DeliveryContext {
    pub async fn admit(&self, id: &str) -> Result<AdmittedMail> {
        self.enabled()?;
        let guards = self.guards().await?;
        self.enabled()?;
        let runtime = self.runtime();
        let job = delivery::job(&self.source.db.pool, id).await?;
        if job.state != "queued" || job.next_attempt_at > self.time() {
            return Err(DeliveryError("not_queued"));
        }
        let snapshot = self
            .source
            .snapshot(&job.client_id, &guards, self.time() + 30)
            .await?;
        if !delivery::matches(&job, &snapshot) {
            delivery::invalidate(&self.source.db.pool, &job.client_id).await?;
            return Err(DeliveryError("changed"));
        }
        let formats: Vec<Format> =
            serde_json::from_str(&job.formats).map_err(|_| DeliveryError("invalid_formats"))?;
        let mut mail = MailMessage {
            recipient: job.recipient.clone(),
            subject: "Your VPN configuration".into(),
            body: "VPN configuration (contains your private key). This email cannot be recalled."
                .into(),
            attachments: Vec::new(),
        };
        let token = if job.mode == "link" {
            Some(random_id())
        } else {
            None
        };
        if let Some(token) = &token {
            mail.body=format!("Retrieve your VPN configuration: {}\nThis link expires. Open it and explicitly select Retrieve configuration.",runtime.settings.link(token)?);
        } else {
            for format in formats {
                mail.attachments
                    .push((format, format.render(&snapshot.content)?));
            }
        }
        let mut tx = self.source.db.pool.begin().await?;
        let changed=sqlx::query("UPDATE email_jobs SET state='sending',attempts=attempts+1,error_code=NULL WHERE id=? AND state='queued' AND invalidated_at IS NULL").bind(id).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(DeliveryError("changed"));
        }
        self.validate_transaction(&mut tx, &snapshot, self.time() + 30)
            .await?;
        // Count admissions, including retries, under the same SQLite writer.
        // Queue confirmation reserves first attempts separately; a retry that
        // exhausts the budget fails visibly rather than bypassing the limit.
        sqlx::query("DELETE FROM delivery_send_budget WHERE at<=?")
            .bind(self.time() - 3600)
            .execute(&mut *tx)
            .await?;
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM delivery_send_budget WHERE client_id=?")
                .bind(&job.client_id)
                .fetch_one(&mut *tx)
                .await?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM delivery_send_budget WHERE actor='admin'")
                .fetch_one(&mut *tx)
                .await?;
        if count >= 5 || total >= 100 {
            return Err(DeliveryError("send_limit"));
        }
        sqlx::query("INSERT INTO delivery_send_budget(client_id,actor,at) VALUES(?,'admin',?)")
            .bind(&job.client_id)
            .bind(self.time())
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE delivery_grants SET revoked_at=COALESCE(revoked_at,?) WHERE job_id=?")
            .bind(self.time())
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if let Some(token) = &token {
            sqlx::query("INSERT INTO delivery_grants(id,job_id,token_hash,binding_version,export_digest,expires_at) VALUES(?,?,?,?,?,?)")
                .bind(random_id()).bind(id).bind(hash(token.as_bytes())).bind(job.binding_version).bind(&job.export_digest).bind(self.time()+job.link_ttl_seconds).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(AdmittedMail { job, mail, runtime })
    }
    pub async fn complete(&self, admitted: &AdmittedMail, outcome: Submission) -> Result<()> {
        let validity = match self.guards().await {
            Ok(guards) => self
                .source
                .snapshot(&admitted.job.client_id, &guards, self.time())
                .await
                .map(|snapshot| delivery::matches(&admitted.job, &snapshot)),
            Err(_) => Err(DeliveryError("validity_unverified")),
        };
        let mut tx = self.source.db.pool.begin().await?;
        // Take the SQLite writer before checking durable versions/invalidation.
        sqlx::query("UPDATE email_jobs SET attempts=attempts WHERE id=?")
            .bind(&admitted.job.id)
            .execute(&mut *tx)
            .await?;
        let current: delivery::Job = sqlx::query_as("SELECT * FROM email_jobs WHERE id=?")
            .bind(&admitted.job.id)
            .fetch_one(&mut *tx)
            .await?;
        let version: Option<i64> = sqlx::query_scalar(
            "SELECT binding_version FROM delivery_clients WHERE id=? AND email=?",
        )
        .bind(&current.client_id)
        .bind(&current.recipient)
        .fetch_optional(&mut *tx)
        .await?;
        let valid = validity.as_ref().is_ok_and(|v| *v)
            && current.invalidated_at.is_none()
            && version == Some(current.binding_version)
            && self.runtime().settings.enabled
            && self.runtime().revision == admitted.runtime.revision;
        let annotation = if validity.is_err() {
            "validity_unverified"
        } else {
            "stale_or_revoked"
        };
        if !valid {
            sqlx::query("UPDATE email_jobs SET invalidated_at=COALESCE(invalidated_at,?),invalidation_code=COALESCE(invalidation_code,?) WHERE id=?").bind(self.time()).bind(annotation).bind(&current.id).execute(&mut *tx).await?;
        }
        let (state, code) = match outcome {
            Submission::Accepted => ("accepted", "accepted_by_smtp"),
            Submission::DefiniteTransient if valid && current.attempts < 3 => {
                ("queued", "transient_rejection")
            }
            Submission::DefiniteTransient => ("failed", "transient_rejection"),
            Submission::DefinitePermanent => ("failed", "permanent_rejection"),
            Submission::Unknown => ("unknown", "acceptance_unknown"),
        };
        if !valid || outcome != Submission::Accepted {
            sqlx::query(
                "UPDATE delivery_grants SET revoked_at=COALESCE(revoked_at,?) WHERE job_id=?",
            )
            .bind(self.time())
            .bind(&current.id)
            .execute(&mut *tx)
            .await?;
        }
        // Persist the observed acceptance time with the result. Repeated completion
        // and later reads cannot reset the UI's display expiry; other outcomes do
        // not acquire a success timestamp.
        let accepted_at = (outcome == Submission::Accepted).then(|| self.time());
        sqlx::query("UPDATE email_jobs SET state=?,error_code=?,next_attempt_at=?,accepted_at=COALESCE(accepted_at,?) WHERE id=? AND state='sending'")
            .bind(state).bind(code).bind(self.time()+if current.attempts==1 {60}else{300}).bind(accepted_at).bind(&current.id).execute(&mut *tx).await?;
        tx.commit().await?;
        tracing::info!(job_id=%current.id,status=state,"email submission finished");
        Ok(())
    }
    pub async fn process(&self, id: &str) -> Result<()> {
        let admitted = match self.admit(id).await {
            Ok(mail) => mail,
            Err(e) => {
                sqlx::query("UPDATE email_jobs SET state='failed',error_code=? WHERE id=? AND state='queued'").bind(e.0).bind(id).execute(&self.source.db.pool).await?;
                return Err(e);
            }
        };
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            admitted.runtime.transport.submit(&admitted.mail),
        )
        .await
        .unwrap_or(Submission::Unknown);
        if let Err(error) = self.complete(&admitted, outcome).await {
            // Fail closed in memory even if SQLite remains unavailable. Commit
            // errors can have uncertain outcomes, so include an accepted row in
            // this best-effort repair; never automatically submit it again.
            self.quarantined
                .store(true, std::sync::atomic::Ordering::Release);
            let _ = self.mark_persistence_unknown(id).await;
            return Err(error);
        }
        Ok(())
    }
    async fn mark_persistence_unknown(&self, id: &str) -> Result<()> {
        let mut tx = self.source.db.pool.begin().await?;
        sqlx::query("UPDATE email_jobs SET state='unknown',error_code='persistence_unknown',invalidated_at=COALESCE(invalidated_at,?),invalidation_code=COALESCE(invalidation_code,'persistence_unknown') WHERE id=?")
            .bind(self.time()).bind(id).execute(&mut *tx).await?;
        sqlx::query("UPDATE delivery_grants SET revoked_at=COALESCE(revoked_at,?) WHERE job_id=?")
            .bind(self.time())
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn run(self: Arc<Self>) {
        let mut purge_at = 0;
        loop {
            if self.enabled().is_err() {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
            if self.time() >= purge_at {
                let _ = self.purge().await;
                purge_at = self.time() + 86400;
            }
            let next:std::result::Result<Option<String>,_>=sqlx::query_scalar("SELECT id FROM email_jobs WHERE state='queued' AND next_attempt_at<=? ORDER BY created_at,id LIMIT 1").bind(self.time()).fetch_optional(&self.source.db.pool).await;
            if let Ok(Some(id)) = next {
                if let Err(e) = self.process(&id).await {
                    tracing::warn!(job_id=%id,code=e.0,"email attempt stopped");
                }
            } else {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    }
}
