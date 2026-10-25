use super::{service::DeliveryContext, *};
use crate::db::delivery;
use sqlx::Row;

pub struct NewSession {
    pub cookie: String,
    pub csrf: String,
    pub expires_at: i64,
}
pub fn csrf(session: &str) -> String {
    URL_SAFE_NO_PAD.encode(hash(format!("delivery-csrf:{session}").as_bytes()))
}
impl DeliveryContext {
    pub async fn redeem(&self, raw: &str) -> Result<NewSession> {
        self.enabled()?;
        if raw.len() != 43 {
            return Err(DeliveryError("unavailable"));
        }
        let guards = self.guards().await?;
        self.enabled()?;
        let grant=sqlx::query("SELECT g.id,g.job_id,g.expires_at FROM delivery_grants g JOIN email_jobs j ON j.id=g.job_id WHERE g.token_hash=? AND g.revoked_at IS NULL AND g.redeemed_at IS NULL AND g.expires_at>? AND j.state='accepted' AND j.invalidated_at IS NULL")
            .bind(hash(raw.as_bytes())).bind(self.time()).fetch_optional(&self.source.db.pool).await?.ok_or(DeliveryError("unavailable"))?;
        let job = delivery::job(&self.source.db.pool, grant.get("job_id")).await?;
        let snapshot = self
            .source
            .snapshot(&job.client_id, &guards, self.time())
            .await?;
        if !delivery::matches(&job, &snapshot) {
            delivery::invalidate(&self.source.db.pool, &job.client_id).await?;
            return Err(DeliveryError("unavailable"));
        }
        let cookie = random_id();
        let expires_at = (self.time() + 600).min(grant.get("expires_at"));
        let mut tx = self.source.db.pool.begin().await?;
        let changed=sqlx::query("UPDATE delivery_grants SET redeemed_at=? WHERE id=? AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM email_jobs WHERE id=delivery_grants.job_id AND state='accepted' AND invalidated_at IS NULL)")
            .bind(self.time()).bind(grant.get::<String,_>("id")).bind(self.time()).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(DeliveryError("unavailable"));
        }
        self.validate_transaction(&mut tx, &snapshot, self.time())
            .await?;
        sqlx::query(
            "INSERT INTO delivery_sessions(id_hash,grant_id,expires_at,remaining) VALUES(?,?,?,10)",
        )
        .bind(hash(cookie.as_bytes()))
        .bind(grant.get::<String, _>("id"))
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(NewSession {
            csrf: csrf(&cookie),
            cookie,
            expires_at,
        })
    }
    pub async fn export(&self, session: &str, format: Format) -> Result<Vec<u8>> {
        self.enabled()?;
        if session.len() != 43 {
            return Err(DeliveryError("unavailable"));
        }
        let guards = self.guards().await?;
        self.enabled()?;
        let session_hash = hash(session.as_bytes());
        let job_id:Option<String>=sqlx::query_scalar("SELECT g.job_id FROM delivery_sessions s JOIN delivery_grants g ON g.id=s.grant_id JOIN email_jobs j ON j.id=g.job_id WHERE s.id_hash=? AND s.expires_at>? AND s.remaining>0 AND g.expires_at>? AND g.revoked_at IS NULL AND j.state='accepted' AND j.invalidated_at IS NULL")
            .bind(&session_hash).bind(self.time()).bind(self.time()).fetch_optional(&self.source.db.pool).await?;
        let job = delivery::job(
            &self.source.db.pool,
            &job_id.ok_or(DeliveryError("unavailable"))?,
        )
        .await?;
        let snapshot = self
            .source
            .snapshot(&job.client_id, &guards, self.time())
            .await?;
        if !delivery::matches(&job, &snapshot) {
            delivery::invalidate(&self.source.db.pool, &job.client_id).await?;
            return Err(DeliveryError("unavailable"));
        }
        let bytes = format.render(&snapshot.content)?;
        let mut tx = self.source.db.pool.begin().await?;
        let changed=sqlx::query("UPDATE delivery_sessions SET remaining=remaining-1 WHERE id_hash=? AND expires_at>? AND remaining>0 AND grant_id IN (SELECT g.id FROM delivery_grants g JOIN email_jobs j ON j.id=g.job_id WHERE g.revoked_at IS NULL AND g.expires_at>? AND j.state='accepted' AND j.invalidated_at IS NULL)")
            .bind(&session_hash).bind(self.time()).bind(self.time()).execute(&mut *tx).await?.rows_affected();
        if changed != 1 {
            return Err(DeliveryError("unavailable"));
        }
        self.validate_transaction(&mut tx, &snapshot, self.time())
            .await?;
        tx.commit().await?;
        Ok(bytes)
    }
}
