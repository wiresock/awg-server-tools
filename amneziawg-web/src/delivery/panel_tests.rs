use super::{settings::PanelSettingsInput, smtp::*, test_mail::TestRequest, tests::*, *};
use crate::db::delivery;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

fn input(revision: i64) -> PanelSettingsInput {
    serde_json::from_value(serde_json::json!({"revision":revision,"enabled":true,
      "host":"new.example.test","port":587,"tls":"starttls","authenticate":false,
      "username":"","password_action":"keep","from":"new@example.test",
      "reply_to":"support@example.test","public_base":"https://new.example.test/download",
      "ttl_seconds":3600}))
    .unwrap()
}
fn test_request(revision: i64, id: &str) -> TestRequest {
    TestRequest {
        revision,
        recipient: "admin@example.test".into(),
        request_id: id.into(),
    }
}
#[derive(Default)]
struct Capture {
    calls: AtomicUsize,
    recipients: Mutex<Vec<String>>,
    bodies: Mutex<Vec<String>>,
    attachments: AtomicUsize,
}
impl Transport for Capture {
    fn submit<'a>(&'a self, mail: &'a MailMessage) -> BoxFuture<'a, Submission> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.recipients.lock().unwrap().push(mail.recipient.clone());
            self.bodies.lock().unwrap().push(mail.body.clone());
            self.attachments
                .fetch_add(mail.attachments.len(), Ordering::SeqCst);
            Submission::Accepted
        })
    }
}
#[derive(Default)]
struct Barrier {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    recipient: Mutex<String>,
}
impl Transport for Barrier {
    fn submit<'a>(&'a self, mail: &'a MailMessage) -> BoxFuture<'a, Submission> {
        Box::pin(async move {
            *self.recipient.lock().unwrap() = mail.recipient.clone();
            self.entered.notify_one();
            self.release.notified().await;
            Submission::Accepted
        })
    }
}
#[tokio::test]
async fn panel_save_does_not_wait_for_smtp_and_late_accept_cannot_restore_grants() {
    let mut f = Fixture::new().await;
    let slow = Arc::new(Barrier::default());
    runtime_mut(&mut f.ctx).transport = slow.clone();
    let new_transport = Arc::new(Capture::default());
    let factory_transport = new_transport.clone();
    Arc::get_mut(&mut f.ctx).unwrap().transport_factory =
        Arc::new(move |_: &config::Settings| Ok(factory_transport.clone() as Arc<dyn Transport>));
    let accepted = f.queue(Mode::Link).await;
    let admitted = f.ctx.admit(&accepted).await.unwrap();
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
    let active = f.queue(Mode::Link).await;
    let queued = f.queue(Mode::Direct).await;
    let ctx = f.ctx.clone();
    let id = active.clone();
    let worker = tokio::spawn(async move { ctx.process(&id).await });
    slow.entered.notified().await;
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        f.ctx.update_settings(input(0), true, "".into()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!worker.is_finished());
    assert_eq!(
        delivery::job(&f.ctx.source.db.pool, &queued)
            .await
            .unwrap()
            .state,
        "cancelled"
    );
    assert!(f.ctx.export(&session.cookie, Format::Conf).await.is_err());
    assert_eq!(*slow.recipient.lock().unwrap(), "recipient@example.test");
    slow.release.notify_one();
    worker.await.unwrap().unwrap();
    let job = delivery::job(&f.ctx.source.db.pool, &active).await.unwrap();
    assert_eq!(job.state, "accepted");
    assert!(job.invalidated_at.is_some());
    let active_grants: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM delivery_grants WHERE revoked_at IS NULL")
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
    assert_eq!(active_grants, 0);
    assert_eq!(
        new_transport.calls.load(Ordering::SeqCst),
        0,
        "Save must not submit mail"
    );
    let fresh = f.queue(Mode::Direct).await;
    f.ctx.process(&fresh).await.unwrap();
    assert_eq!(new_transport.calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn panel_test_mail_is_harmless_deduplicated_and_hourly_bounded() {
    let mut f = Fixture::new().await;
    let capture = Arc::new(Capture::default());
    runtime_mut(&mut f.ctx).transport = capture.clone();
    let id = random_id();
    for _ in 0..2 {
        assert_eq!(
            f.ctx.test_email(test_request(0, &id)).await.unwrap().state,
            "accepted"
        );
    }
    assert_eq!(capture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(capture.attachments.load(Ordering::SeqCst), 0);
    assert!(!capture.bodies.lock().unwrap()[0].contains("fixture-private"));
    let mut mismatch = test_request(0, &id);
    mismatch.recipient = "other@example.test".into();
    assert!(matches!(
        f.ctx.test_email(mismatch).await,
        Err(DeliveryError("invalid_request_id"))
    ));
    for _ in 0..4 {
        f.ctx
            .test_email(test_request(0, &random_id()))
            .await
            .unwrap();
    }
    assert!(matches!(
        f.ctx.test_email(test_request(0, &random_id())).await,
        Err(DeliveryError("test_limit"))
    ));
    assert_eq!(capture.calls.load(Ordering::SeqCst), 5);
    assert!(f.ctx.jobs().await.unwrap().is_empty());
}
#[tokio::test]
async fn panel_test_inflight_is_snapshot_bound_and_duplicate_reports_sending() {
    let mut f = Fixture::new().await;
    let slow = Arc::new(Barrier::default());
    runtime_mut(&mut f.ctx).transport = slow.clone();
    let id = random_id();
    let ctx = f.ctx.clone();
    let task_id = id.clone();
    let work = tokio::spawn(async move { ctx.test_email(test_request(0, &task_id)).await });
    slow.entered.notified().await;
    assert_eq!(
        f.ctx.test_email(test_request(0, &id)).await.unwrap().state,
        "sending"
    );
    assert!(matches!(
        f.ctx.test_email(test_request(0, &random_id())).await,
        Err(DeliveryError("test_busy"))
    ));
    f.ctx
        .update_settings(input(0), true, "".into())
        .await
        .unwrap();
    assert_eq!(*slow.recipient.lock().unwrap(), "admin@example.test");
    slow.release.notify_one();
    let result = work.await.unwrap().unwrap();
    assert_eq!(result.state, "accepted");
    assert!(result.settings_changed);
    assert!(matches!(
        f.ctx.test_email(test_request(0, &random_id())).await,
        Err(DeliveryError("settings_changed"))
    ));
}
#[tokio::test]
async fn panel_stranded_test_attempt_is_unknown_without_resubmission() {
    let mut f = Fixture::new().await;
    let capture = Arc::new(Capture::default());
    runtime_mut(&mut f.ctx).transport = capture.clone();
    let id = random_id();
    sqlx::query(
        "INSERT INTO email_test_attempts VALUES(?,0,'admin@example.test','sending',?,NULL)",
    )
    .bind(&id)
    .bind(f.ctx.time() - 61)
    .execute(&f.ctx.source.db.pool)
    .await
    .unwrap();
    assert_eq!(
        f.ctx.test_email(test_request(0, &id)).await.unwrap().state,
        "unknown"
    );
    assert_eq!(capture.calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn panel_recovery_never_clears_quarantine_with_live_old_grants() {
    let f = Fixture::new().await;
    f.ctx
        .update_settings(input(0), true, "".into())
        .await
        .unwrap();
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
    f.ctx.quarantined.store(true, Ordering::Release);
    assert!(f
        .ctx
        .update_settings(input(1), true, "".into())
        .await
        .is_err());
    assert!(
        f.ctx.enabled().is_ok(),
        "successful durable recovery reopens admission only after invalidation"
    );
    assert!(
        f.ctx.redeem(token).await.is_err(),
        "recovery from uncertain persistence must not restore old access"
    );
}
#[tokio::test]
async fn panel_failed_save_keeps_runtime_and_queue_intact() {
    let f = Fixture::new().await;
    let job = f.queue(Mode::Direct).await;
    sqlx::query("CREATE TRIGGER fixture_save_failure BEFORE INSERT ON email_panel_settings BEGIN SELECT RAISE(ABORT,'fixture failure'); END").execute(&f.ctx.source.db.pool).await.unwrap();
    assert!(f
        .ctx
        .update_settings(input(0), true, "".into())
        .await
        .is_err());
    assert_eq!(f.ctx.runtime().revision, 0);
    assert!(f.ctx.enabled().is_ok());
    assert_eq!(
        delivery::job(&f.ctx.source.db.pool, &job)
            .await
            .unwrap()
            .state,
        "queued"
    );
    assert!(settings::load_saved(&f.ctx.source.db.pool, true)
        .await
        .unwrap()
        .is_none());
}
#[tokio::test]
async fn panel_commit_error_reloads_durable_settings_and_never_applies_candidate() {
    let f = Fixture::new().await;
    sqlx::query("CREATE TABLE fixture_commit_failure(value INTEGER REFERENCES peers(id) DEFERRABLE INITIALLY DEFERRED)").execute(&f.ctx.source.db.pool).await.unwrap();
    sqlx::query("CREATE TRIGGER fixture_deferred_failure AFTER INSERT ON email_panel_settings BEGIN INSERT INTO fixture_commit_failure VALUES(-999); END").execute(&f.ctx.source.db.pool).await.unwrap();
    assert!(matches!(
        f.ctx.update_settings(input(0), true, "".into()).await,
        Err(DeliveryError("settings_result_unknown"))
    ));
    assert_eq!(f.ctx.runtime().revision, 0);
    assert!(settings::load_saved(&f.ctx.source.db.pool, true)
        .await
        .unwrap()
        .is_none());
    assert_ne!(f.ctx.runtime().settings.host, "new.example.test");
}
#[tokio::test]
async fn panel_password_only_save_also_invalidates_old_preview_and_grants() {
    let f = Fixture::new().await;
    f.ctx
        .update_settings(input(0), true, "".into())
        .await
        .unwrap();
    let id = f.queue(Mode::Link).await;
    let admitted = f.ctx.admit(&id).await.unwrap();
    f.ctx
        .complete(&admitted, Submission::Accepted)
        .await
        .unwrap();
    let mut body = input(1);
    body.password_action = settings::PasswordAction::Replace;
    body.password = Some("dummy-password-canary".into());
    f.ctx.update_settings(body, true, "".into()).await.unwrap();
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
    assert_eq!(f.ctx.runtime().revision, 2);
}
#[tokio::test]
async fn panel_cancelled_request_does_not_interrupt_durable_save() {
    let mut f = Fixture::new().await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = entered.clone();
    Arc::get_mut(&mut f.ctx).unwrap().transport_factory = Arc::new(move |_: &config::Settings| {
        signal.notify_one();
        Ok(Arc::new(Capture::default()) as Arc<dyn Transport>)
    });
    let guard = f.ctx.guards().await.unwrap();
    let ctx = f.ctx.clone();
    let request = tokio::spawn(async move { ctx.update_settings(input(0), true, "".into()).await });
    entered.notified().await;
    request.abort();
    drop(guard);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while f.ctx.runtime().revision != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        settings::load_saved(&f.ctx.source.db.pool, true)
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
}
#[tokio::test]
async fn panel_disabled_worker_can_be_enabled_without_restart() {
    let mut f = Fixture::new().await;
    runtime_mut(&mut f.ctx).settings.enabled = false;
    let worker = tokio::spawn(f.ctx.clone().run());
    tokio::task::yield_now().await;
    assert!(!worker.is_finished());
    f.ctx
        .update_settings(input(0), true, "".into())
        .await
        .unwrap();
    let id = f.queue(Mode::Direct).await;
    tokio::time::timeout(std::time::Duration::from_secs(4), async {
        while delivery::job(&f.ctx.source.db.pool, &id)
            .await
            .unwrap()
            .state
            != "accepted"
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    worker.abort();
    let _ = worker.await;
}
#[tokio::test]
async fn panel_preview_ttl_is_bound_and_settings_change_rejects_old_confirmation() {
    let f = Fixture::new().await;
    let p = f
        .ctx
        .preview_with_ttl(
            "admin",
            std::slice::from_ref(&f.client),
            Mode::Link,
            &[Format::Conf],
            Some(600),
        )
        .await
        .unwrap();
    let jobs = f.ctx.enqueue("admin", &p.id, &p.id).await.unwrap();
    let admitted = f.ctx.admit(&jobs[0]).await.unwrap();
    assert_eq!(admitted.job.link_ttl_seconds, 600);
    let expires: i64 = sqlx::query_scalar("SELECT expires_at FROM delivery_grants WHERE job_id=?")
        .bind(&jobs[0])
        .fetch_one(&f.ctx.source.db.pool)
        .await
        .unwrap();
    assert_eq!(expires, f.ctx.time() + 600);
    let old = f
        .ctx
        .preview(
            "admin",
            std::slice::from_ref(&f.client),
            Mode::Direct,
            &[Format::Conf],
        )
        .await
        .unwrap();
    f.ctx
        .update_settings(input(0), true, "".into())
        .await
        .unwrap();
    assert!(matches!(
        f.ctx.enqueue("admin", &old.id, &old.id).await,
        Err(DeliveryError("settings_changed"))
    ));
}

struct ConnectionProbe {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
impl Transport for ConnectionProbe {
    fn submit<'a>(&'a self, _: &'a MailMessage) -> BoxFuture<'a, Submission> {
        panic!("connection check submitted mail")
    }
    fn check<'a>(&'a self) -> BoxFuture<'a, ConnectionCheck> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            ConnectionCheck::Connected
        })
    }
}
#[tokio::test]
async fn panel_connection_check_releases_guards_and_binds_revision_without_mail() {
    let mut f = Fixture::new().await;
    let probe = Arc::new(ConnectionProbe {
        entered: Default::default(),
        release: Default::default(),
    });
    runtime_mut(&mut f.ctx).transport = probe.clone();
    let ctx = f.ctx.clone();
    let task = tokio::spawn(async move {
        ctx.check_smtp(super::smtp_check::CheckRequest { revision: 0 })
            .await
    });
    probe.entered.notified().await;
    assert!(matches!(
        f.ctx
            .check_smtp(super::smtp_check::CheckRequest { revision: 0 })
            .await,
        Err(DeliveryError("test_busy"))
    ));
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        f.ctx.update_settings(input(0), true, "".into()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!task.is_finished());
    probe.release.notify_one();
    let result = task.await.unwrap().unwrap();
    assert_eq!(result.settings_revision, 0);
    assert!(result.settings_changed);
    assert_eq!(result.outcome, ConnectionCheck::Connected);
    assert!(matches!(
        f.ctx
            .check_smtp(super::smtp_check::CheckRequest { revision: 0 })
            .await,
        Err(DeliveryError("settings_changed"))
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_test_attempts")
        .fetch_one(&f.ctx.source.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
#[tokio::test]
async fn panel_connection_check_deadline_releases_slot_and_uses_durable_budget() {
    let mut f = Fixture::new().await;
    let probe = Arc::new(ConnectionProbe {
        entered: Default::default(),
        release: Default::default(),
    });
    runtime_mut(&mut f.ctx).transport = probe.clone();
    let ctx = f.ctx.clone();
    let task = tokio::spawn(async move {
        ctx.check_smtp(super::smtp_check::CheckRequest { revision: 0 })
            .await
    });
    probe.entered.notified().await;
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    tokio::time::resume();
    assert_eq!(
        task.await.unwrap().unwrap().outcome,
        ConnectionCheck::Timeout
    );
    assert_eq!(f.ctx.test_slot.available_permits(), 1);
    sqlx::query("INSERT INTO smtp_connection_checks(created_at) VALUES (?),(?),(?),(?)")
        .bind(f.ctx.time())
        .bind(f.ctx.time())
        .bind(f.ctx.time())
        .bind(f.ctx.time())
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.ctx
            .check_smtp(super::smtp_check::CheckRequest { revision: 0 })
            .await,
        Err(DeliveryError("smtp_check_limit"))
    ));
    sqlx::query("UPDATE smtp_connection_checks SET created_at=?")
        .bind(f.ctx.time() - 3600)
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
    probe.release.notify_one();
    assert_eq!(
        f.ctx
            .check_smtp(super::smtp_check::CheckRequest { revision: 0 })
            .await
            .unwrap()
            .outcome,
        ConnectionCheck::Connected
    );
}
