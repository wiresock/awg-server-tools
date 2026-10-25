use super::{exports::*, service::*, smtp::*, *};
use crate::db::{delivery, Database};
use std::sync::Arc;

struct FixtureOwnership;
impl Ownership for FixtureOwnership {
    fn verify<'a>(
        &'a self,
        key: &'a str,
        _: &'a str,
        _: &'a str,
        content: &'a str,
        _: &'a crate::config_store::ClientConfig,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if (key == "fixture-key" && content.contains("PrivateKey = fixture-private"))
                || (key == "new-fixture-key"
                    && content.contains("PrivateKey = new-fixture-private"))
            {
                Ok(())
            } else {
                Err(DeliveryError("ownership_unverified"))
            }
        })
    }
}
struct Accept;
pub(crate) fn runtime_mut(
    ctx: &mut Arc<DeliveryContext>,
) -> &mut super::runtime::RuntimeConfiguration {
    Arc::make_mut(Arc::get_mut(ctx).unwrap().runtime.get_mut().unwrap())
}

struct NeverAccept {
    entered: tokio::sync::Notify,
}
impl Transport for NeverAccept {
    fn submit<'a>(&'a self, _: &'a MailMessage) -> BoxFuture<'a, Submission> {
        Box::pin(async move {
            self.entered.notify_one();
            std::future::pending().await
        })
    }
}
#[tokio::test]
async fn delivery_smtp_deadline_records_unknown_and_revokes_without_retry() {
    let mut f = Fixture::new().await;
    let transport = Arc::new(NeverAccept {
        entered: tokio::sync::Notify::new(),
    });
    runtime_mut(&mut f.ctx).transport = transport.clone();
    let id = f.queue(Mode::Link).await;
    let ctx = f.ctx.clone();
    let work_id = id.clone();
    let task = tokio::spawn(async move { ctx.process(&work_id).await });
    transport.entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    tokio::time::resume();
    task.await.unwrap().unwrap();
    let job = delivery::job(&f.ctx.source.db.pool, &id).await.unwrap();
    assert_eq!(job.state, "unknown");
    assert_eq!(job.attempts, 1);
    let revoked: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM delivery_grants WHERE job_id=?")
            .bind(&id)
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
    assert!(revoked.is_some());
    assert!(f.ctx.admit(&id).await.is_err());
}

#[tokio::test]
async fn delivery_admin_budget_counts_other_clients_and_expires_at_hour_boundary() {
    let f = Fixture::new().await;
    let second = f.second_client().await;
    let id = f.queue(Mode::Direct).await;
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100) INSERT INTO delivery_send_budget(client_id,actor,at) SELECT ?,'admin',? FROM n").bind(second).bind(f.ctx.time()).execute(&f.ctx.source.db.pool).await.unwrap();
    assert!(matches!(
        f.ctx.admit(&id).await,
        Err(DeliveryError("send_limit"))
    ));
    sqlx::query("UPDATE delivery_send_budget SET at=?")
        .bind(f.ctx.time() - 3600)
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    let admitted = f.ctx.admit(&id).await.unwrap();
    f.ctx
        .complete(&admitted, Submission::Accepted)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM delivery_send_budget")
        .fetch_one(&f.ctx.source.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn delivery_retry_admission_counts_against_hourly_budget() {
    let f = Fixture::new().await;
    let id = f.queue(Mode::Direct).await;
    let first = f.ctx.admit(&id).await.unwrap();
    f.ctx
        .complete(&first, Submission::DefiniteTransient)
        .await
        .unwrap();
    sqlx::query("UPDATE email_jobs SET next_attempt_at=0 WHERE id=?")
        .bind(&id)
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    let second = f.ctx.admit(&id).await.unwrap();
    f.ctx
        .complete(&second, Submission::DefiniteTransient)
        .await
        .unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM delivery_send_budget WHERE client_id=?")
            .bind(&f.client)
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
    assert_eq!(
        count, 2,
        "every SMTP admission, including retries, consumes budget"
    );
    for _ in 0..3 {
        sqlx::query("INSERT INTO delivery_send_budget(client_id,actor,at) VALUES(?,'admin',?)")
            .bind(&f.client)
            .bind(f.ctx.time())
            .execute(&f.ctx.source.db.pool)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE email_jobs SET next_attempt_at=0 WHERE id=?")
        .bind(&id)
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.ctx.admit(&id).await,
        Err(DeliveryError("send_limit"))
    ));
    assert_eq!(
        delivery::job(&f.ctx.source.db.pool, &id)
            .await
            .unwrap()
            .attempts,
        2
    );
}
impl Transport for Accept {
    fn submit<'a>(&'a self, _: &'a MailMessage) -> BoxFuture<'a, Submission> {
        Box::pin(async { Submission::Accepted })
    }
}
pub(crate) struct Fixture {
    pub ctx: Arc<DeliveryContext>,
    pub directory: tempfile::TempDir,
    pub client: String,
}

#[tokio::test]
async fn delivery_failed_outcome_persistence_revokes_token() {
    let f = Fixture::new().await;
    let id = f.queue(Mode::Link).await;
    sqlx::query("CREATE TRIGGER reject_accepted BEFORE UPDATE OF state ON email_jobs WHEN NEW.state='accepted' BEGIN SELECT RAISE(ABORT,'fixture persistence failure'); END")
        .execute(&f.ctx.source.db.pool).await.unwrap();
    assert!(f.ctx.process(&id).await.is_err());
    let job = delivery::job(&f.ctx.source.db.pool, &id).await.unwrap();
    assert_eq!(job.state, "unknown");
    let revoked: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM delivery_grants WHERE job_id=?")
            .bind(&id)
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
    assert!(
        revoked.is_some(),
        "uncertain persistence must revoke the grant, not only change job status"
    );
}

struct SlowTransport {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    recipient: std::sync::Mutex<Option<String>>,
}
impl Transport for SlowTransport {
    fn submit<'a>(&'a self, mail: &'a MailMessage) -> BoxFuture<'a, Submission> {
        Box::pin(async move {
            *self.recipient.lock().unwrap() = Some(mail.recipient.clone());
            self.entered.notify_one();
            self.release.notified().await;
            Submission::Accepted
        })
    }
}
#[tokio::test]
async fn delivery_slow_smtp_does_not_block_rotation_revoke_mapping_or_admin() {
    let mut f = Fixture::new().await;
    let transport = Arc::new(SlowTransport {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        recipient: std::sync::Mutex::new(None),
    });
    runtime_mut(&mut f.ctx).transport = transport.clone();
    let id = f.queue(Mode::Direct).await;
    let ctx = f.ctx.clone();
    let work_id = id.clone();
    let worker = tokio::spawn(async move { ctx.process(&work_id).await });
    transport.entered.notified().await;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let lock =
            crate::admin::client_manager::acquire_lifecycle_lock(f.directory.path()).unwrap();
        // Model a supported CLI key rotation under its existing directory lock.
        std::fs::write(
            f.directory.path().join("awg0-client-phone.conf"),
            "[Interface]\nPrivateKey = new-key\nAddress = 10.0.0.2/32",
        )
        .unwrap();
        drop(lock);
        f.ctx.revoke(&f.client).await.unwrap();
        let mapping = crate::poller::acquire_config_mapping_lock().await;
        drop(mapping);
        sqlx::query("UPDATE peers SET comment='unrelated edit'")
            .execute(&f.ctx.source.db.pool)
            .await
            .unwrap();
    })
    .await
    .expect("SMTP must not hold lifecycle, mapping, global-state or DB guards");
    assert!(!worker.is_finished());
    transport.release.notify_one();
    worker.await.unwrap().unwrap();
    let job = delivery::job(&f.ctx.source.db.pool, &id).await.unwrap();
    assert_eq!(job.state, "accepted");
    assert!(job.invalidated_at.is_some());
    assert_eq!(
        transport.recipient.lock().unwrap().as_deref(),
        Some("recipient@example.test")
    );
}

#[tokio::test]
async fn delivery_retry_uses_fresh_token_and_revalidates_version() {
    let f = Fixture::new().await;
    let id = f.queue(Mode::Link).await;
    let first = f.ctx.admit(&id).await.unwrap();
    let first_token = first
        .mail
        .body
        .split('#')
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    f.ctx
        .complete(&first, Submission::DefiniteTransient)
        .await
        .unwrap();
    let job = delivery::job(&f.ctx.source.db.pool, &id).await.unwrap();
    assert_eq!(job.state, "queued");
    assert_eq!(job.attempts, 1);
    assert!(job.next_attempt_at >= f.ctx.time() + 59);
    assert!(f.ctx.admit(&id).await.is_err());
    sqlx::query("UPDATE email_jobs SET next_attempt_at=0 WHERE id=?")
        .bind(&id)
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    let second = f.ctx.admit(&id).await.unwrap();
    let second_token = second
        .mail
        .body
        .split('#')
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    assert_ne!(first_token, second_token);
    f.ctx
        .complete(&second, Submission::DefiniteTransient)
        .await
        .unwrap();
    f.ctx.revoke(&f.client).await.unwrap();
    sqlx::query("UPDATE email_jobs SET next_attempt_at=0 WHERE id=?")
        .bind(&id)
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    assert!(f.ctx.admit(&id).await.is_err());
    assert!(f.ctx.redeem(&first_token).await.is_err());
    assert!(f.ctx.redeem(second_token).await.is_err());
    let hashes: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT token_hash FROM delivery_grants WHERE job_id=?")
            .bind(&id)
            .fetch_all(&f.ctx.source.db.pool)
            .await
            .unwrap();
    assert_eq!(hashes.len(), 2);
    assert!(hashes.contains(&hash(first_token.as_bytes())));
    assert!(hashes.contains(&hash(second_token.as_bytes())));
}

#[tokio::test]
async fn delivery_unknown_and_permanent_never_auto_retry() {
    for outcome in [Submission::Unknown, Submission::DefinitePermanent] {
        let f = Fixture::new().await;
        let id = f.queue(Mode::Link).await;
        let mail = f.ctx.admit(&id).await.unwrap();
        f.ctx.complete(&mail, outcome).await.unwrap();
        let job = delivery::job(&f.ctx.source.db.pool, &id).await.unwrap();
        assert_eq!(
            job.state,
            if outcome == Submission::Unknown {
                "unknown"
            } else {
                "failed"
            }
        );
        assert!(f.ctx.admit(&id).await.is_err());
        let revoked: Option<i64> =
            sqlx::query_scalar("SELECT revoked_at FROM delivery_grants WHERE job_id=?")
                .bind(&id)
                .fetch_one(&f.ctx.source.db.pool)
                .await
                .unwrap();
        assert!(revoked.is_some());
    }
}

#[tokio::test]
async fn delivery_parallel_redemption_and_expiry_boundary() {
    let mut f = Fixture::new().await;
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(now()));
    let time = clock.clone();
    Arc::get_mut(&mut f.ctx).unwrap().clock =
        Arc::new(move || time.load(std::sync::atomic::Ordering::SeqCst));
    let id = f.queue(Mode::Link).await;
    let mail = f.ctx.admit(&id).await.unwrap();
    f.ctx.complete(&mail, Submission::Accepted).await.unwrap();
    let token = mail
        .mail
        .body
        .split('#')
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let (a, b) = tokio::join!(f.ctx.redeem(token), f.ctx.redeem(token));
    assert_ne!(a.is_ok(), b.is_ok());
    let session = a.or(b).unwrap();
    clock.store(session.expires_at, std::sync::atomic::Ordering::SeqCst);
    assert!(f.ctx.export(&session.cookie, Format::Conf).await.is_err());
}

#[tokio::test]
async fn delivery_password_change_preserves_grant_but_settings_change_revokes() {
    let mut f = Fixture::new().await;
    let id = f.queue(Mode::Link).await;
    let mail = f.ctx.admit(&id).await.unwrap();
    f.ctx.complete(&mail, Submission::Accepted).await.unwrap();
    runtime_mut(&mut f.ctx).settings.password = "test-only-replacement".into();
    f.ctx.recover().await.unwrap();
    let revoked: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM delivery_grants WHERE job_id=?")
            .bind(&id)
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
    assert!(revoked.is_none());
    runtime_mut(&mut f.ctx).settings.host = "another.example.test".into();
    f.ctx.recover().await.unwrap();
    let revoked: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM delivery_grants WHERE job_id=?")
            .bind(&id)
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
    assert!(revoked.is_some());
}

#[test]
fn delivery_worker_lock_refuses_second_owner() {
    let directory = tempfile::tempdir().unwrap();
    let first = worker_lock(directory.path()).unwrap();
    assert!(worker_lock(directory.path()).is_err());
    drop(first);
    assert!(worker_lock(directory.path()).is_ok());
}
impl Fixture {
    pub async fn second_client(&self) -> String {
        let path = self.directory.path().join("awg0-client-second.conf");
        std::fs::write(&path,"[Interface]\nPrivateKey = new-fixture-private\nAddress = 10.0.0.3/32\n[Peer]\nPublicKey = fixture-server\n").unwrap();
        sqlx::query("INSERT INTO peers(public_key,allowed_ips,managed_client_name,config_path,has_config) VALUES('new-fixture-key','10.0.0.3/32','second',?,1)").bind(path.to_str().unwrap()).execute(&self.ctx.source.db.pool).await.unwrap();
        let c = self
            .ctx
            .contacts()
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.last_public_key == "new-fixture-key")
            .unwrap();
        self.ctx
            .set_email(&c.id, c.binding_version, Some("second@example.test"))
            .await
            .unwrap();
        c.id
    }
    pub async fn new() -> Self {
        let db = Database::connect_for_test().await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("awg0-client-phone.conf");
        std::fs::write(&path,"[Interface]\nPrivateKey = fixture-private\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = fixture-server\n").unwrap();
        sqlx::query("INSERT INTO peers(public_key,allowed_ips,managed_client_name,config_path,has_config) VALUES('fixture-key','10.0.0.2/32','phone',?,1)")
            .bind(path.to_str().unwrap()).execute(&db.pool).await.unwrap();
        let settings = config::Settings::parse(
            |name| match name {
                "AWG_EMAIL_ENABLED" => Some("true".into()),
                "AWG_SMTP_HOST" => Some("relay.example.test".into()),
                "AWG_SMTP_FROM" => Some("vpn@example.test".into()),
                "AWG_DELIVERY_PUBLIC_BASE_URL" => {
                    Some("https://download.example.test/share".into())
                }
                _ => None,
            },
            true,
        )
        .unwrap();
        let source = ExportSource {
            db,
            directory: directory.path().into(),
            lock_directory: directory.path().into(),
            ownership: Arc::new(FixtureOwnership),
        };
        let mut ctx = DeliveryContext::new(source, settings, Arc::new(Accept), None, 0);
        ctx.transport_factory =
            Arc::new(|_: &config::Settings| Ok(Arc::new(Accept) as Arc<dyn Transport>));
        let ctx = Arc::new(ctx);
        ctx.recover().await.unwrap();
        let contact = ctx.contacts().await.unwrap().remove(0);
        ctx.set_email(
            &contact.id,
            contact.binding_version,
            Some("recipient@example.test"),
        )
        .await
        .unwrap();
        Self {
            ctx,
            directory,
            client: contact.id,
        }
    }
    pub async fn queue(&self, mode: Mode) -> String {
        let p = self
            .ctx
            .preview(
                "session-one",
                std::slice::from_ref(&self.client),
                mode,
                &[Format::Conf],
            )
            .await
            .unwrap();
        self.ctx
            .enqueue("session-one", &p.id, &p.id)
            .await
            .unwrap()
            .remove(0)
    }
}

struct DelayedOwnership {
    entered: tokio::sync::Notify,
}

struct BatchBarrierOwnership {
    calls: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
impl Ownership for BatchBarrierOwnership {
    fn verify<'a>(
        &'a self,
        key: &'a str,
        name: &'a str,
        interface: &'a str,
        content: &'a str,
        config: &'a crate::config_store::ClientConfig,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                self.entered.notify_one();
                self.release.notified().await;
            }
            FixtureOwnership
                .verify(key, name, interface, content, config)
                .await
        })
    }
}

#[tokio::test]
async fn delivery_batch_revalidates_all_snapshots_at_atomic_queue_commit() {
    for recipient_change in [false, true] {
        let mut f = Fixture::new().await;
        let second = f.second_client().await;
        let clock = Arc::new(std::sync::atomic::AtomicI64::new(now()));
        let clock_read = clock.clone();
        Arc::get_mut(&mut f.ctx).unwrap().clock =
            Arc::new(move || clock_read.load(std::sync::atomic::Ordering::SeqCst));
        let expiry = chrono::DateTime::from_timestamp(f.ctx.time() + 60, 0)
            .unwrap()
            .to_rfc3339();
        sqlx::query("UPDATE peers SET expires_at=? WHERE public_key='fixture-key'")
            .bind(expiry)
            .execute(&f.ctx.source.db.pool)
            .await
            .unwrap();
        let preview = f
            .ctx
            .preview(
                "actor",
                &[f.client.clone(), second],
                Mode::Direct,
                &[Format::Conf],
            )
            .await
            .unwrap();
        let barrier = Arc::new(BatchBarrierOwnership {
            calls: std::sync::atomic::AtomicUsize::new(0),
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        Arc::get_mut(&mut f.ctx).unwrap().source.ownership = barrier.clone();
        let ctx = f.ctx.clone();
        let task =
            tokio::spawn(async move { ctx.enqueue("actor", &preview.id, &preview.id).await });
        barrier.entered.notified().await;
        // First snapshot is already verified. Change durable recipient/version
        // or move the clock across its expiry safety margin before commit.
        if recipient_change {
            sqlx::query("UPDATE delivery_clients SET email='changed@example.test',binding_version=binding_version+1 WHERE id=?").bind(&f.client).execute(&f.ctx.source.db.pool).await.unwrap();
        } else {
            clock.fetch_add(40, std::sync::atomic::Ordering::SeqCst);
        }
        barrier.release.notify_one();
        assert!(matches!(task.await.unwrap(), Err(DeliveryError("changed"))));
        assert!(
            f.ctx.jobs().await.unwrap().is_empty(),
            "the batch must reject atomically, including earlier items"
        );
    }
}

#[tokio::test]
async fn delivery_cancelled_batch_releases_guards_and_leaves_no_jobs() {
    let mut f = Fixture::new().await;
    let second = f.second_client().await;
    let barrier = Arc::new(BatchBarrierOwnership {
        calls: std::sync::atomic::AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    Arc::get_mut(&mut f.ctx).unwrap().source.ownership = barrier.clone();
    let ctx = f.ctx.clone();
    let first = f.client.clone();
    let task = tokio::spawn(async move {
        ctx.preview("actor", &[first, second], Mode::Direct, &[Format::Conf])
            .await
    });
    barrier.entered.notified().await;
    task.abort();
    assert!(matches!(task.await,Err(e) if e.is_cancelled()));
    tokio::time::timeout(std::time::Duration::from_millis(500), async {
        f.ctx.revoke(&f.client).await.unwrap();
        let mapping = crate::poller::acquire_config_mapping_lock().await;
        drop(mapping);
        let lifecycle =
            crate::admin::client_manager::acquire_lifecycle_lock(f.directory.path()).unwrap();
        drop(lifecycle);
    })
    .await
    .unwrap();
    assert!(f.ctx.jobs().await.unwrap().is_empty());
}
impl Ownership for DelayedOwnership {
    fn verify<'a>(
        &'a self,
        key: &'a str,
        name: &'a str,
        interface: &'a str,
        content: &'a str,
        config: &'a crate::config_store::ClientConfig,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.entered.notify_one();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            FixtureOwnership
                .verify(key, name, interface, content, config)
                .await
        })
    }
}

#[tokio::test]
async fn delivery_batch_budget_bounds_total_work_and_releases_revoke_poller_locks() {
    for enqueue in [false, true] {
        let mut f = Fixture::new().await;
        let second = f.second_client().await;
        let ids = vec![f.client.clone(), second];
        let preview = f
            .ctx
            .preview("actor", &ids, Mode::Direct, &[Format::Conf])
            .await
            .unwrap();
        let slow = Arc::new(DelayedOwnership {
            entered: tokio::sync::Notify::new(),
        });
        let ctx = Arc::get_mut(&mut f.ctx).unwrap();
        ctx.admission_budget = std::time::Duration::from_millis(150);
        ctx.source.ownership = slow.clone();
        let ctx = f.ctx.clone();
        let task = tokio::spawn(async move {
            if enqueue {
                ctx.enqueue("actor", &preview.id, &preview.id)
                    .await
                    .map(|_| ())
            } else {
                ctx.preview("actor", &ids, Mode::Direct, &[Format::Conf])
                    .await
                    .map(|_| ())
            }
        });
        slow.entered.notified().await;
        let began = std::time::Instant::now();
        let revoke = f.ctx.revoke(&f.client);
        let poller = async {
            let guard = crate::poller::acquire_config_mapping_lock().await;
            drop(guard);
        };
        let (result, revoked, ()) =
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::join!(task, revoke, poller)
            })
            .await
            .unwrap();
        revoked.unwrap();
        assert!(began.elapsed() < std::time::Duration::from_millis(600));
        assert!(
            matches!(result.unwrap(), Err(DeliveryError("admission_timeout"))),
            "budget applies to the whole batch, not each helper"
        );
        assert!(
            f.ctx.jobs().await.unwrap().is_empty(),
            "cancelled batch must not leave a partial queue"
        );
        let lock =
            crate::admin::client_manager::acquire_lifecycle_lock(f.directory.path()).unwrap();
        drop(lock);
    }
}

#[tokio::test]
async fn delivery_batch_budget_includes_waiting_for_global_guard() {
    let mut f = Fixture::new().await;
    Arc::get_mut(&mut f.ctx).unwrap().admission_budget = std::time::Duration::from_millis(50);
    let held = crate::admin::EXPIRATION_STATE_LOCK.lock().await;
    let began = std::time::Instant::now();
    let result = f
        .ctx
        .preview(
            "actor",
            std::slice::from_ref(&f.client),
            Mode::Direct,
            &[Format::Conf],
        )
        .await;
    drop(held);
    assert!(matches!(result, Err(DeliveryError("admission_timeout"))));
    assert!(began.elapsed() < std::time::Duration::from_millis(500));
}

#[tokio::test]
async fn delivery_duplicate_confirmation_and_changed_email() {
    let f = Fixture::new().await;
    let p = f
        .ctx
        .preview(
            "session-one",
            std::slice::from_ref(&f.client),
            Mode::Direct,
            &[Format::Conf],
        )
        .await
        .unwrap();
    let first = f.ctx.enqueue("session-one", &p.id, &p.id).await.unwrap();
    assert_eq!(
        first,
        f.ctx.enqueue("session-one", &p.id, &p.id).await.unwrap()
    );
    let p2 = f
        .ctx
        .preview(
            "session-one",
            std::slice::from_ref(&f.client),
            Mode::Direct,
            &[Format::Conf],
        )
        .await
        .unwrap();
    let c = delivery::client(&f.ctx.source.db.pool, &f.client)
        .await
        .unwrap();
    f.ctx
        .set_email(&f.client, c.binding_version, Some("new@example.test"))
        .await
        .unwrap();
    assert!(f.ctx.enqueue("session-one", &p2.id, &p2.id).await.is_err());
    assert_eq!(
        delivery::job(&f.ctx.source.db.pool, &first[0])
            .await
            .unwrap()
            .state,
        "cancelled"
    );
}
#[tokio::test]
async fn delivery_inflight_recipient_is_frozen_late_accept_never_reactivates() {
    let f = Fixture::new().await;
    let id = f.queue(Mode::Link).await;
    let admitted = f.ctx.admit(&id).await.unwrap();
    let c = delivery::client(&f.ctx.source.db.pool, &f.client)
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_millis(500),
        f.ctx
            .set_email(&f.client, c.binding_version, Some("new@example.test")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(admitted.mail.recipient, "recipient@example.test");
    f.ctx
        .complete(&admitted, Submission::Accepted)
        .await
        .unwrap();
    let job = delivery::job(&f.ctx.source.db.pool, &id).await.unwrap();
    assert_eq!(job.state, "accepted");
    assert!(job.invalidated_at.is_some());
    let token = admitted
        .mail
        .body
        .split('#')
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    assert!(f.ctx.redeem(token).await.is_err());
}
#[tokio::test]
async fn delivery_unknown_never_retries_and_restart_revokes() {
    let f = Fixture::new().await;
    let id = f.queue(Mode::Link).await;
    let admitted = f.ctx.admit(&id).await.unwrap();
    f.ctx.recover().await.unwrap();
    assert_eq!(
        delivery::job(&f.ctx.source.db.pool, &id)
            .await
            .unwrap()
            .state,
        "unknown"
    );
    f.ctx
        .complete(&admitted, Submission::Accepted)
        .await
        .unwrap();
    assert_eq!(
        delivery::job(&f.ctx.source.db.pool, &id)
            .await
            .unwrap()
            .state,
        "unknown"
    );
    assert!(f.ctx.admit(&id).await.is_err());
}
#[tokio::test]
async fn delivery_session_allows_conf_then_qr_and_is_bounded() {
    let f = Fixture::new().await;
    let id = f.queue(Mode::Link).await;
    let admitted = f.ctx.admit(&id).await.unwrap();
    f.ctx
        .complete(&admitted, Submission::Accepted)
        .await
        .unwrap();
    let token = admitted
        .mail
        .body
        .split('#')
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let session = f.ctx.redeem(token).await.unwrap();
    assert!(f.ctx.redeem(token).await.is_err());
    for i in 0..10 {
        let format = if i == 1 { Format::Qr } else { Format::Conf };
        assert!(!f
            .ctx
            .export(&session.cookie, format)
            .await
            .unwrap()
            .is_empty());
    }
    assert!(f.ctx.export(&session.cookie, Format::Conf).await.is_err());
}
#[tokio::test]
async fn delivery_file_change_revokes_even_if_original_is_restored() {
    let f = Fixture::new().await;
    let id = f.queue(Mode::Direct).await;
    let path = f.directory.path().join("awg0-client-phone.conf");
    let original = std::fs::read(&path).unwrap();
    std::fs::write(
        &path,
        b"[Interface]\nPrivateKey = replacement\nAddress = 10.0.0.2/32",
    )
    .unwrap();
    assert!(f.ctx.admit(&id).await.is_err());
    std::fs::write(&path, original).unwrap();
    assert!(f.ctx.admit(&id).await.is_err());
}
#[tokio::test]
async fn delivery_disabled_and_expired_are_rejected() {
    let f = Fixture::new().await;
    for update in [
        "UPDATE peers SET disabled=1",
        "UPDATE peers SET disabled=0,expires_at='2000-01-01T00:00:00Z'",
        "UPDATE peers SET expires_at=NULL,archived=1",
        "UPDATE peers SET archived=0,removal_pending=1",
    ] {
        sqlx::query(update)
            .execute(&f.ctx.source.db.pool)
            .await
            .unwrap();
        let preview = f
            .ctx
            .preview(
                "session-one",
                std::slice::from_ref(&f.client),
                Mode::Direct,
                &[Format::Conf],
            )
            .await
            .unwrap();
        assert!(preview.items.is_empty());
        assert_eq!(preview.skipped.len(), 1);
        assert!(f
            .ctx
            .enqueue("session-one", &preview.id, &preview.id)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn delivery_rebind_requires_explicit_current_versions_and_preserves_email() {
    let f = Fixture::new().await;
    let job = f.queue(Mode::Link).await;
    let mail = f.ctx.admit(&job).await.unwrap();
    f.ctx.complete(&mail, Submission::Accepted).await.unwrap();
    let path = f.directory.path().join("awg0-client-phone.conf");
    sqlx::query("DELETE FROM peers")
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    std::fs::write(&path,"[Interface]\nPrivateKey = new-fixture-private\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = fixture-server\n").unwrap();
    sqlx::query("INSERT INTO peers(public_key,allowed_ips,managed_client_name,config_path,has_config) VALUES('new-fixture-key','10.0.0.2/32','phone',?,1)").bind(path.to_str().unwrap()).execute(&f.ctx.source.db.pool).await.unwrap();
    let contacts = f.ctx.contacts().await.unwrap();
    let target = contacts.iter().find(|c| c.peer_id.is_some()).unwrap();
    assert!(target.email.is_none());
    let old = delivery::client(&f.ctx.source.db.pool, &f.client)
        .await
        .unwrap();
    assert!(old.peer_id.is_none());
    assert_eq!(old.last_public_key, "fixture-key");
    let snapshot = {
        let guards = f.ctx.guards().await.unwrap();
        f.ctx
            .source
            .snapshot(&target.id, &guards, f.ctx.time() + 30)
            .await
            .unwrap()
    };
    assert!(f
        .ctx
        .rebind(
            &old.id,
            old.binding_version - 1,
            &target.id,
            snapshot.client.binding_version
        )
        .await
        .is_err());
    f.ctx
        .rebind(
            &old.id,
            old.binding_version,
            &target.id,
            snapshot.client.binding_version,
        )
        .await
        .unwrap();
    let bound = delivery::client(&f.ctx.source.db.pool, &old.id)
        .await
        .unwrap();
    assert_eq!(bound.email.as_deref(), Some("recipient@example.test"));
    assert_eq!(bound.last_public_key, "new-fixture-key");
    assert!(bound.peer_id.is_some());
    let token = mail
        .mail
        .body
        .split('#')
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    assert!(f.ctx.redeem(token).await.is_err());
}

#[tokio::test]
async fn delivery_batch_queue_and_persistent_budgets_enforce_limits() {
    let f = Fixture::new().await;
    assert!(f
        .ctx
        .preview(
            "one",
            &vec![f.client.clone(); 51],
            Mode::Direct,
            &[Format::Conf]
        )
        .await
        .is_err());
    for _ in 0..5 {
        f.queue(Mode::Direct).await;
    }
    let preview = f
        .ctx
        .preview(
            "new-session",
            std::slice::from_ref(&f.client),
            Mode::Direct,
            &[Format::Conf],
        )
        .await
        .unwrap();
    assert_eq!(
        f.ctx
            .enqueue("new-session", &preview.id, &preview.id)
            .await
            .unwrap_err()
            .0,
        "send_limit"
    );
    sqlx::query("UPDATE delivery_send_budget SET at=0")
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    // Bulk-create synthetic terminal-free intent rows, no configs or emails sent.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<500) INSERT INTO email_jobs(id,client_id,request_id,actor,recipient,mode,formats,binding_version,export_digest,state,next_attempt_at,created_at) SELECT 'bulk-'||x,?,'bulk-'||x,'admin','fixture@example.test','direct','[]',1,X'00','queued',0,0 FROM n")
        .bind(&f.client).execute(&f.ctx.source.db.pool).await.unwrap();
    assert_eq!(
        f.ctx
            .enqueue("new-session", &preview.id, &preview.id)
            .await
            .unwrap_err()
            .0,
        "send_limit"
    );
}

#[tokio::test]
async fn bulk_remove_checked_identity_refuses_stale_key_without_file_mutation() {
    let f = Fixture::new().await;
    let pool = &f.ctx.source.db.pool;
    let id: i64 = sqlx::query_scalar("SELECT id FROM peers WHERE public_key='fixture-key'")
        .fetch_one(pool)
        .await
        .unwrap();
    let original = std::fs::read(f.directory.path().join("awg0-client-phone.conf")).unwrap();
    let result = crate::admin::execute_remove_user_checked(
        &f.ctx.source.db,
        f.directory.path(),
        f.directory.path(),
        id,
        "phone",
        "admin",
        "old-key",
    )
    .await;
    assert!(matches!(
        result,
        Err(crate::admin::client_manager::RemoveClientError::IdentityMismatch(_))
    ));
    assert_eq!(
        std::fs::read(f.directory.path().join("awg0-client-phone.conf")).unwrap(),
        original
    );
    let pending: i64 = sqlx::query_scalar("SELECT removal_pending FROM peers WHERE id=?")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
}

#[tokio::test]
async fn bulk_remove_claim_is_key_conditional_and_revokes_existing_delivery() {
    let f = Fixture::new().await;
    let pool = &f.ctx.source.db.pool;
    let link = f.queue(Mode::Link).await;
    f.ctx.process(&link).await.unwrap();
    let pending = f.queue(Mode::Direct).await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM peers WHERE public_key='fixture-key'")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(
        !crate::db::peers::mark_removal_pending_matching(pool, id, "old-key")
            .await
            .unwrap()
    );
    assert_eq!(delivery::job(pool, &pending).await.unwrap().state, "queued");
    assert!(
        crate::db::peers::mark_removal_pending_matching(pool, id, "fixture-key")
            .await
            .unwrap()
    );
    assert_eq!(
        delivery::job(pool, &pending).await.unwrap().state,
        "cancelled"
    );
    let revoked: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM delivery_grants WHERE job_id=?")
            .bind(&link)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(revoked.is_some());
    assert!(f.ctx.admit(&pending).await.is_err());
}
