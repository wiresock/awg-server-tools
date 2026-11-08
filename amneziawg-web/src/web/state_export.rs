// SPDX-FileCopyrightText: 2026 Vadim Smirnov (doing business as WireSock)
// SPDX-License-Identifier: MIT

//! Panel download of an encrypted server-state archive.
//!
//! The panel does not implement the archive format. It checks the admin
//! session and the current password, then streams the privileged helper's
//! stdout. The archive passphrase is written to the helper's stdin and wiped.

use std::ffi::OsStr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdout};

use crate::auth::{self, extract_session_token, is_session_valid};
use crate::awg::{PRIVILEGED_HELPER_BIN, SUDO_BIN};
use crate::db::events::{
    list_events, log_event, EVT_STATE_EXPORTED, EVT_STATE_EXPORT_FAILED,
};

use super::AppState;

const PASS_MIN_CHARS: usize = 16;
const PASS_MAX_BYTES: usize = 1024;
const EXPORT_FIRST_BYTE: Duration = Duration::from_secs(360);
const EXPORT_KILL_GRACE: Duration = Duration::from_secs(5);
const EXPORT_STDERR_BYTES: usize = 2048;
const EXPORT_STDERR_LINES: usize = 20;
const ENDPOINT_CACHE_TTL: Duration = Duration::from_secs(60);
const SUMMARY_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_STALE_DAYS: i64 = 7;
const EXPORT_FAILURE: &str =
    "The encrypted archive was not created. See the panel log. The VPN was not changed.";
const EXPORT_BUSY: &str = "Another state export is already running.";

#[cfg(test)]
static SUMMARY_SPAWNS: AtomicUsize = AtomicUsize::new(0);

#[derive(Deserialize)]
pub(super) struct ExportForm {
    csrf_token: Option<String>,
    #[serde(default)]
    current_password: String,
    #[serde(default)]
    passphrase: String,
    #[serde(default)]
    passphrase_confirm: String,
}

#[derive(Serialize)]
struct ExportStatus {
    last_export: Option<String>,
    stale: bool,
    stale_days: i64,
    export_block: Option<String>,
}

#[derive(Serialize)]
struct EndpointStatus {
    hostname: Option<u64>,
    ip_literal: Option<u64>,
    warning: Option<String>,
}

pub(super) fn render_controls(base: &str, csrf_token: &str) -> String {
    super::with_js_base(
        &include_str!("state_export.html")
            .replace("{{csrf}}", &super::esc(csrf_token))
            .replace("{{base}}", base),
        base,
    )
}

/// `GET /api/admin/state-export` – last export and the stale reminder.
///
/// This does not count endpoints and does not take the lifecycle lock.
pub(super) async fn api_status(State(state): State<AppState>) -> Response {
    let last = last_export_at(&state).await;
    let days = stale_after_days();
    json_status(last, Utc::now(), days, export_tool_block().as_deref())
}

/// `GET /api/admin/state-export/endpoints` – cached literal-IP count.
///
/// The home page fetches this only after the migration section is opened.
pub(super) async fn api_endpoints(State(state): State<AppState>) -> Response {
    let summary = state
        .endpoint_summary
        .get_or_load(endpoint_counts_uncached)
        .await;
    json_endpoints(summary)
}

/// `POST /admin/state/export` – stream an encrypted archive.
///
/// This route is not behind the session middleware: a missing session is
/// audited here. A bearer token is not a session and is not accepted.
pub(super) async fn post_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ExportForm>,
) -> Response {
    export_with(&state, &headers, form, None).await
}

pub(super) fn parse_stale_days(raw: Option<&str>) -> i64 {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return DEFAULT_STALE_DAYS;
    };
    match raw.parse::<i64>() {
        Ok(days) if (1..=3650).contains(&days) => days,
        _ => DEFAULT_STALE_DAYS,
    }
}

fn stale_after_days() -> i64 {
    parse_stale_days(std::env::var("AWG_STATE_EXPORT_STALE_DAYS").ok().as_deref())
}

pub(super) fn validate_archive_passphrase(value: &str) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("passphrase_empty");
    }
    if value.len() > PASS_MAX_BYTES {
        return Err("passphrase_too_long");
    }
    // C0 and DEL. A canonical tty would act on these before age saw the line.
    // C1 (U+0080–U+009F) is not a line-discipline control and stays allowed.
    if value
        .chars()
        .any(|ch| (ch as u32) <= 0x1f || ch == '\u{007f}')
    {
        return Err("passphrase_forbidden");
    }
    if value.chars().count() < PASS_MIN_CHARS {
        return Err("passphrase_too_short");
    }
    Ok(())
}

pub(super) fn literal_ip_warning(count: u64) -> Option<String> {
    match count {
        0 => None,
        1 => Some(
            "1 profile uses an IP in Endpoint; it will need a new profile after a ban".to_string(),
        ),
        n => Some(format!(
            "{n} profiles use an IP in Endpoint; they will need a new profile after a ban"
        )),
    }
}

fn parse_endpoint_summary(text: &str) -> Option<(u64, u64)> {
    let mut lines = text.lines();
    let hostname: u64 = lines.next()?.parse().ok()?;
    let ip_literal: u64 = lines.next()?.parse().ok()?;
    if lines.next().is_some() {
        return None;
    }
    Some((hostname, ip_literal))
}

fn json_status(
    last: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    stale_days: i64,
    export_block: Option<&str>,
) -> Response {
    let stale = match last {
        None => true,
        Some(at) => now.signed_duration_since(at) >= chrono::Duration::days(stale_days),
    };
    let body = ExportStatus {
        last_export: last.map(|at| at.format("%Y-%m-%d %H:%M UTC").to_string()),
        stale,
        stale_days,
        export_block: export_block.map(str::to_string),
    };
    no_store(axum::Json(body).into_response())
}

fn json_endpoints(summary: Option<(u64, u64)>) -> Response {
    let (hostname, ip_literal, warning) = match summary {
        Some((hostname, ip)) => (Some(hostname), Some(ip), literal_ip_warning(ip)),
        None => (None, None, None),
    };
    let body = EndpointStatus {
        hostname,
        ip_literal,
        warning,
    };
    no_store(axum::Json(body).into_response())
}

/// Lock-free presence check. The panel sandbox cannot install a missing tool.
fn export_tool_block() -> Option<String> {
    for tool in ["age", "python3", "sqlite3"] {
        let present = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
            .iter()
            .any(|dir| Path::new(dir).join(tool).is_file());
        if !present {
            return Some(format!(
                "export-state requires {tool}; rerun the panel upgrade"
            ));
        }
    }
    None
}

fn export_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new(SUDO_BIN);
    command.args(["-n", PRIVILEGED_HELPER_BIN, "export-state"]);
    command
}

fn summary_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new(SUDO_BIN);
    command.args(["-n", PRIVILEGED_HELPER_BIN, "endpoint-summary"]);
    command
}

#[cfg_attr(test, allow(unreachable_code))]
async fn endpoint_counts_uncached() -> Option<(u64, u64)> {
    #[cfg(test)]
    {
        // Unit tests must not call sudo. Reaching this function is the
        // regression the status route is not allowed to have.
        SUMMARY_SPAWNS.fetch_add(1, Ordering::SeqCst);
        return None;
    }
    endpoint_counts_spawn().await
}

async fn endpoint_counts_spawn() -> Option<(u64, u64)> {
    let mut command = summary_command();
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    tokio::spawn(async move {
        let mut sink = [0u8; 1024];
        loop {
            match stderr.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    let read = tokio::time::timeout(SUMMARY_TIMEOUT, async {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).await.ok()?;
        let status = child.wait().await.ok()?;
        if !status.success() {
            return None;
        }
        Some(buf)
    })
    .await
    .ok()??;
    parse_endpoint_summary(&String::from_utf8_lossy(&read))
}

async fn export_with(
    state: &AppState,
    headers: &HeaderMap,
    mut form: ExportForm,
    program: Option<(&OsStr, Vec<String>, Option<std::path::PathBuf>)>,
) -> Response {
    if !state.auth.enabled {
        audit(state, EVT_STATE_EXPORT_FAILED, Some("reauth_unavailable")).await;
        return deny(StatusCode::FORBIDDEN, "State export requires an admin password.");
    }
    let cookie = headers
        .get("cookie")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let session_ok = extract_session_token(cookie)
        .is_some_and(|token| is_session_valid(&state.sessions, &token, state.auth.session_ttl));
    if !session_ok {
        audit(state, EVT_STATE_EXPORT_FAILED, Some("unauthenticated")).await;
        return deny(StatusCode::UNAUTHORIZED, "Sign in again before exporting.");
    }
    if !super::validate_form_csrf(state, cookie, form.csrf_token.as_deref().unwrap_or("")) {
        audit(state, EVT_STATE_EXPORT_FAILED, Some("csrf_rejected")).await;
        return deny(
            StatusCode::FORBIDDEN,
            "Request validation failed. Reload the page and try again.",
        );
    }
    let password = Secret::new(std::mem::take(&mut form.current_password));
    let password_text = std::str::from_utf8(password.expose()).unwrap_or("");
    if let Err(reason) = auth::reauthenticate(&state.auth, password_text) {
        drop(password);
        audit(state, EVT_STATE_EXPORT_FAILED, Some(reason)).await;
        tracing::warn!(reason, "state export reauthentication failed");
        return deny(StatusCode::FORBIDDEN, "The current password was not accepted.");
    }
    drop(password);

    let passphrase = Secret::new(std::mem::take(&mut form.passphrase));
    let confirm = Secret::new(std::mem::take(&mut form.passphrase_confirm));
    let pass_text = std::str::from_utf8(passphrase.expose()).unwrap_or("");
    let confirm_text = std::str::from_utf8(confirm.expose()).unwrap_or("");
    if let Err(reason) = validate_archive_passphrase(pass_text) {
        drop(passphrase);
        drop(confirm);
        audit(state, EVT_STATE_EXPORT_FAILED, Some(reason)).await;
        return deny(StatusCode::BAD_REQUEST, passphrase_message(reason));
    }
    if !auth::csrf_eq(pass_text, confirm_text) {
        drop(passphrase);
        drop(confirm);
        audit(state, EVT_STATE_EXPORT_FAILED, Some("passphrase_mismatch")).await;
        return deny(
            StatusCode::BAD_REQUEST,
            "The passphrase and confirmation do not match.",
        );
    }
    drop(confirm);

    // After validation, so a rejected passphrase does not hold the gate.
    let permit = match state.export_gate.try_acquire() {
        Some(permit) => permit,
        None => {
            drop(passphrase);
            audit(state, EVT_STATE_EXPORT_FAILED, Some("export_busy")).await;
            return deny(StatusCode::CONFLICT, EXPORT_BUSY);
        }
    };
    let spawned = match program {
        Some((program, args, cwd)) => {
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            spawn_export(
                state,
                program,
                &arg_refs,
                passphrase.expose(),
                cwd.as_deref(),
                permit,
            )
            .await
        }
        None => {
            spawn_export(
                state,
                OsStr::new(SUDO_BIN),
                &["-n", PRIVILEGED_HELPER_BIN, "export-state"],
                passphrase.expose(),
                None,
                permit,
            )
            .await
        }
    };
    drop(passphrase);
    let mut session = match spawned {
        Ok(session) => session,
        Err(error) => {
            tracing::warn!(error = %error, "state export failed to start");
            audit(state, EVT_STATE_EXPORT_FAILED, Some("export_failed")).await;
            return deny(StatusCode::BAD_GATEWAY, EXPORT_FAILURE);
        }
    };

    let mut first = vec![0u8; 8192];
    let read = tokio::time::timeout(EXPORT_FIRST_BYTE, session.stdout.read(&mut first)).await;
    let timed_out = read.is_err();
    let first_len = match read {
        Ok(Ok(n)) if n > 0 => n,
        _ => {
            let reason = if timed_out {
                "export_timed_out"
            } else {
                "export_failed"
            };
            session.abort(reason).await;
            return deny(StatusCode::BAD_GATEWAY, EXPORT_FAILURE);
        }
    };
    first.truncate(first_len);
    session.into_response(axum::body::Bytes::from(first), &archive_filename(Utc::now()))
}

fn passphrase_message(reason: &str) -> &'static str {
    match reason {
        "passphrase_empty" => "The archive passphrase was empty.",
        "passphrase_too_short" => "The archive passphrase must be at least 16 characters.",
        "passphrase_too_long" => "The archive passphrase is too long.",
        "passphrase_forbidden" => "The archive passphrase cannot contain a control character.",
        _ => "The archive passphrase was not accepted.",
    }
}

fn archive_filename(now: DateTime<Utc>) -> String {
    format!("amneziawg-state-{}.awgx", now.format("%Y%m%dT%H%M%SZ"))
}

fn actor<'a>(state: &'a AppState) -> &'a str {
    if state.auth.username.is_empty() {
        "anonymous"
    } else {
        state.auth.username.as_str()
    }
}

async fn audit(state: &AppState, action: &str, reason: Option<&str>) {
    let detail = reason.map(|reason| serde_json::json!({ "reason": reason }).to_string());
    log_event(
        &state.db.pool,
        action,
        None,
        None,
        detail.as_deref(),
        actor(state),
    )
    .await;
}

async fn last_export_at(state: &AppState) -> Option<DateTime<Utc>> {
    let rows = list_events(&state.db.pool, None, Some(EVT_STATE_EXPORTED), 1)
        .await
        .ok()?;
    let text = rows.first()?.created_at.as_str();
    parse_event_time(text)
}

fn parse_event_time(value: &str) -> Option<DateTime<Utc>> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&Utc));
    }
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|naive| Utc.from_utc_datetime(&naive))
}

struct Secret(Vec<u8>);

impl Secret {
    fn new(value: String) -> Self {
        Self(value.into_bytes())
    }

    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

struct ExportSession {
    child: Child,
    stdout: ChildStdout,
    completed: AtomicBool,
    state: AppState,
    stderr_tail: Arc<Mutex<Vec<u8>>>,
    stderr_done: Option<tokio::sync::oneshot::Receiver<()>>,
    /// Held until the session drops so a second export is refused with 409.
    #[allow(dead_code)]
    permit: ExportPermit,
}

impl Drop for ExportSession {
    fn drop(&mut self) {
        if self.completed.swap(true, Ordering::SeqCst) {
            return;
        }
        kill_export(&mut self.child);
        warn_export_stderr(&self.stderr_tail, "client_disconnected");
        let state = self.state.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                audit(&state, EVT_STATE_EXPORT_FAILED, Some("client_disconnected")).await;
            });
        }
    }
}

impl ExportSession {
    fn into_response(self, first: axum::body::Bytes, filename: &str) -> Response {
        let stream = futures_util::stream::unfold((Some(self), Some(first)), |(session, first)| async move {
            let mut session = session?;
            if let Some(chunk) = first {
                return Some((Ok::<_, std::io::Error>(chunk), (Some(session), None)));
            }
            let mut buf = vec![0u8; 8192];
            match session.stdout.read(&mut buf).await {
                Ok(0) => {
                    session.finish().await;
                    None
                }
                Ok(n) => {
                    buf.truncate(n);
                    Some((
                        Ok(axum::body::Bytes::from(buf)),
                        (Some(session), None),
                    ))
                }
                Err(error) => {
                    session.abort("export_failed").await;
                    Some((Err(error), (None, None)))
                }
            }
        });
        let mut response = Body::from_stream(stream).into_response();
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
        if let Ok(disposition) =
            HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        {
            headers.insert(CONTENT_DISPOSITION, disposition);
        }
        response
    }

    async fn finish(&mut self) {
        if self.completed.swap(true, Ordering::SeqCst) {
            return;
        }
        let ok = matches!(self.child.wait().await, Ok(status) if status.success());
        self.wait_for_stderr().await;
        if ok {
            audit(&self.state, EVT_STATE_EXPORTED, None).await;
        } else {
            warn_export_stderr(&self.stderr_tail, "export_failed");
            audit(&self.state, EVT_STATE_EXPORT_FAILED, Some("export_failed")).await;
        }
    }

    async fn abort(&mut self, reason: &'static str) {
        if self.completed.swap(true, Ordering::SeqCst) {
            return;
        }
        kill_export(&mut self.child);
        let _ = self.child.wait().await;
        self.wait_for_stderr().await;
        warn_export_stderr(&self.stderr_tail, reason);
        audit(&self.state, EVT_STATE_EXPORT_FAILED, Some(reason)).await;
    }

    async fn wait_for_stderr(&mut self) {
        if let Some(done) = self.stderr_done.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), done).await;
        }
    }
}

async fn spawn_export(
    state: &AppState,
    program: &OsStr,
    args: &[&str],
    passphrase: &[u8],
    current_dir: Option<&Path>,
    permit: ExportPermit,
) -> std::io::Result<ExportSession> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // SIGKILL on drop is not relayed by sudo, so the grace task reaps.
        .kill_on_drop(false);
    if let Some(dir) = current_dir {
        command.current_dir(dir);
    }
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn()?;
    let stderr_tail = Arc::new(Mutex::new(Vec::new()));
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    if let Some(mut stderr) = child.stderr.take() {
        let tail = Arc::clone(&stderr_tail);
        let mut secret = passphrase.to_vec();
        tokio::spawn(async move {
            let mut chunk = [0u8; 512];
            loop {
                match stderr.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut buf = tail.lock().unwrap_or_else(|poison| poison.into_inner());
                        // Hold back the last secret-length bytes so a passphrase
                        // split across reads is still removed before the trim.
                        append_stderr_tail(&mut buf, &chunk[..n], &secret);
                        wipe_bytes(&mut chunk[..n]);
                    }
                }
            }
            {
                let mut buf = tail.lock().unwrap_or_else(|poison| poison.into_inner());
                seal_stderr_tail(&mut buf, &secret);
            }
            wipe_bytes(&mut secret);
            let _ = done_tx.send(());
        });
    } else {
        let _ = done_tx.send(());
    }
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("export helper has no stdin"))?;
    stdin.write_all(passphrase).await?;
    drop(stdin);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("export helper has no stdout"))?;
    Ok(ExportSession {
        child,
        stdout,
        completed: AtomicBool::new(false),
        state: state.clone(),
        stderr_tail,
        stderr_done: Some(done_rx),
        permit,
    })
}

fn kill_export(child: &mut Child) {
    #[cfg(unix)]
    if let Some(raw) = child.id() {
        let pid = raw as i32;
        // sudo relays TERM to the helper and cannot relay KILL. The helper
        // then stops the installer, which stops age and pack.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        let reap = async move {
            let deadline = tokio::time::Instant::now() + EXPORT_KILL_GRACE;
            loop {
                if reap_export(pid) {
                    return;
                }
                if tokio::time::Instant::now() >= deadline {
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                        libc::kill(pid, libc::SIGKILL);
                    }
                    for _ in 0..50 {
                        if reap_export(pid) {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(reap);
            return;
        }
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let _ = child.start_kill();
}

#[cfg(unix)]
fn reap_export(pid: i32) -> bool {
    let mut status = 0;
    let reaped = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    reaped == pid || reaped == -1
}

fn append_stderr_tail(buf: &mut Vec<u8>, chunk: &[u8], secret: &[u8]) {
    buf.extend_from_slice(chunk);
    redact_secret(buf, secret);
    let hold = secret.len().saturating_sub(1);
    if hold == 0 || buf.len() <= hold {
        trim_stderr_tail(buf);
        return;
    }
    let mut head = buf[..buf.len() - hold].to_vec();
    let pending = buf[buf.len() - hold..].to_vec();
    trim_stderr_tail(&mut head);
    head.extend_from_slice(&pending);
    *buf = head;
}

fn seal_stderr_tail(buf: &mut Vec<u8>, secret: &[u8]) {
    redact_secret(buf, secret);
    trim_stderr_tail(buf);
}

fn push_stderr_tail(buf: &mut Vec<u8>, chunk: &[u8]) {
    buf.extend_from_slice(chunk);
    trim_stderr_tail(buf);
}

fn trim_stderr_tail(buf: &mut Vec<u8>) {
    if buf.len() > EXPORT_STDERR_BYTES {
        let drop_bytes = buf.len() - EXPORT_STDERR_BYTES;
        buf.drain(..drop_bytes);
    }
    loop {
        let newlines = buf.iter().filter(|byte| **byte == b'\n').count();
        let lines = newlines + usize::from(!buf.is_empty() && !buf.ends_with(b"\n"));
        if lines <= EXPORT_STDERR_LINES {
            break;
        }
        let Some(pos) = buf.iter().position(|byte| *byte == b'\n') else {
            break;
        };
        buf.drain(..=pos);
    }
}

fn redact_secret(buf: &mut Vec<u8>, secret: &[u8]) {
    if secret.is_empty() || secret.len() > buf.len() {
        return;
    }
    let mut index = 0;
    while index + secret.len() <= buf.len() {
        if &buf[index..index + secret.len()] == secret {
            buf.splice(index..index + secret.len(), b"[redacted]".iter().copied());
            index += b"[redacted]".len();
        } else {
            index += 1;
        }
    }
}

fn wipe_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(Ordering::SeqCst);
}

fn warn_export_stderr(tail: &Mutex<Vec<u8>>, reason: &str) {
    let buf = tail
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone();
    let text = String::from_utf8_lossy(&buf);
    tracing::warn!(reason, stderr = %text, "state export helper failed");
    // The tracing callsite interest cache is process-global. A parallel test
    // that emits this event with no subscriber can hide it from a subscriber
    // installed on another thread, so tests also keep the line here.
    #[cfg(test)]
    TEST_EXPORT_LOG.with(|log| {
        log.borrow_mut()
            .extend_from_slice(format!("{reason} {text}\n").as_bytes());
    });
}

#[cfg(test)]
thread_local! {
    static TEST_EXPORT_LOG: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn take_test_export_log() -> String {
    TEST_EXPORT_LOG.with(|log| String::from_utf8_lossy(&std::mem::take(&mut *log.borrow_mut())).into_owned())
}

pub(super) struct EndpointSummaryCache {
    gate: tokio::sync::Mutex<()>,
    slot: tokio::sync::RwLock<Option<(Instant, Option<(u64, u64)>)>>,
}

impl EndpointSummaryCache {
    pub(super) fn new() -> Self {
        Self {
            gate: tokio::sync::Mutex::new(()),
            slot: tokio::sync::RwLock::new(None),
        }
    }

    /// One helper call at a time. A hit, including a cached failure, is returned
    /// without starting another. Callers that arrive during the load wait for it.
    pub(super) async fn get_or_load<F, Fut>(&self, load: F) -> Option<(u64, u64)>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<(u64, u64)>>,
    {
        if let Some(value) = self.fresh().await {
            return value;
        }
        let _guard = self.gate.lock().await;
        if let Some(value) = self.fresh().await {
            return value;
        }
        let value = load().await;
        *self.slot.write().await = Some((Instant::now(), value));
        value
    }

    async fn fresh(&self) -> Option<Option<(u64, u64)>> {
        let slot = self.slot.read().await;
        match &*slot {
            Some((at, value)) if at.elapsed() < ENDPOINT_CACHE_TTL => Some(*value),
            _ => None,
        }
    }

    #[cfg(test)]
    async fn expire(&self) {
        let mut slot = self.slot.write().await;
        if let Some((at, _)) = slot.as_mut() {
            *at = Instant::now()
                .checked_sub(ENDPOINT_CACHE_TTL + Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }
}

pub(super) struct ExportGate {
    busy: AtomicBool,
}

pub(super) struct ExportPermit {
    gate: Arc<ExportGate>,
}

impl ExportGate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            busy: AtomicBool::new(false),
        })
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ExportPermit> {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| ExportPermit {
                gate: Arc::clone(self),
            })
    }
}

impl Drop for ExportPermit {
    fn drop(&mut self) {
        self.gate.busy.store(false, Ordering::SeqCst);
    }
}

fn deny(status: StatusCode, message: &'static str) -> Response {
    no_store((status, message).into_response())
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{add_session, generate_session_id, AuthConfig, DEFAULT_SESSION_TTL_SECS};
    use futures_util::StreamExt;
    use crate::db::Database;
    use axum::body::Body as AxumBody;
    use axum::http::Request;
    use tower::util::ServiceExt;

    fn passphrase() -> &'static str {
        "state-export-panel-secret"
    }

    async fn test_state(enabled: bool) -> AppState {
        let db = Database::connect_for_test().await.expect("db");
        let dir = std::env::temp_dir().join(format!(
            "awg-state-export-test-{}",
            generate_session_id()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let auth = if enabled {
            AuthConfig {
                enabled: true,
                username: "admin".to_string(),
                password_hash: AuthConfig::hash_password_fast("testpassword"),
                api_token: Some("super-secret-token".to_string()),
                secure_cookie: false,
                session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
            }
        } else {
            AuthConfig::disabled()
        };
        AppState::new(
            db,
            auth,
            dir.clone(),
            dir.clone(),
            dir.join("proxy.json"),
        )
    }

    fn session_headers(state: &AppState) -> (HeaderMap, String) {
        let id = generate_session_id();
        let csrf = add_session(&state.sessions, id.clone());
        let mut headers = HeaderMap::new();
        headers.insert(
            "cookie",
            HeaderValue::from_str(&format!("awg_session={id}")).unwrap(),
        );
        (headers, csrf)
    }

    fn form(csrf: &str, password: &str, pass: &str, confirm: &str) -> ExportForm {
        ExportForm {
            csrf_token: Some(csrf.to_string()),
            current_password: password.to_string(),
            passphrase: pass.to_string(),
            passphrase_confirm: confirm.to_string(),
        }
    }

    async fn reasons(state: &AppState) -> Vec<String> {
        let rows = list_events(&state.db.pool, None, Some(EVT_STATE_EXPORT_FAILED), 10)
            .await
            .expect("events");
        rows.into_iter()
            .map(|row| row.detail.unwrap_or_default())
            .collect()
    }

    #[test]
    fn passphrase_rules_match_the_installer() {
        assert_eq!(validate_archive_passphrase(""), Err("passphrase_empty"));
        assert_eq!(
            validate_archive_passphrase("too-short"),
            Err("passphrase_too_short")
        );
        assert_eq!(
            validate_archive_passphrase("sixteen-chars!!\n"),
            Err("passphrase_forbidden")
        );
        for control in [
            '\u{0}', '\t', '\n', '\r', '\u{15}', '\u{17}', '\u{8}', '\u{7f}', '\u{3}', '\u{4}',
            '\u{16}',
        ] {
            let mut value = "0123456789abcdef".to_string();
            value.push(control);
            assert_eq!(
                validate_archive_passphrase(&value),
                Err("passphrase_forbidden"),
                "control U+{code:04X} was accepted",
                code = control as u32
            );
        }
        assert_eq!(validate_archive_passphrase("0123456789abcdef"), Ok(()));
        assert_eq!(
            validate_archive_passphrase("0123456789abcde\u{80}"),
            Ok(())
        );
        assert_eq!(
            passphrase_message("passphrase_forbidden"),
            "The archive passphrase cannot contain a control character."
        );
        assert_eq!(
            validate_archive_passphrase(&"x".repeat(1025)),
            Err("passphrase_too_long")
        );
        assert_eq!(validate_archive_passphrase(passphrase()), Ok(()));
        assert_eq!(literal_ip_warning(0), None);
        assert_eq!(
            literal_ip_warning(1).as_deref(),
            Some("1 profile uses an IP in Endpoint; it will need a new profile after a ban")
        );
        assert_eq!(
            literal_ip_warning(2).as_deref(),
            Some("2 profiles use an IP in Endpoint; they will need a new profile after a ban")
        );
        assert_eq!(parse_stale_days(None), 7);
        assert_eq!(parse_stale_days(Some("14")), 14);
        assert_eq!(parse_stale_days(Some("0")), 7);
        assert_eq!(parse_stale_days(Some("nope")), 7);
        assert_eq!(parse_endpoint_summary("3\n2\n"), Some((3, 2)));
        assert_eq!(parse_endpoint_summary("PrivateKey = secret\n"), None);
    }

    #[test]
    fn export_argv_is_only_the_helper_subcommand() {
        let mut command = export_command();
        let program = command.as_std().get_program().to_owned();
        let args: Vec<_> = command
            .as_std_mut()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(program, std::ffi::OsStr::new(SUDO_BIN));
        assert_eq!(
            args,
            vec![
                "-n".to_string(),
                PRIVILEGED_HELPER_BIN.to_string(),
                "export-state".to_string()
            ]
        );
        let rendered = args.join(" ");
        assert!(!rendered.contains(passphrase()));
        assert!(!rendered.contains("testpassword"));
    }

    #[test]
    fn summary_argv_is_read_only() {
        let mut command = summary_command();
        let args: Vec<_> = command
            .as_std_mut()
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(args.last().map(String::as_str), Some("endpoint-summary"));
        assert!(!args.join(" ").contains(passphrase()));
    }

    #[tokio::test]
    async fn unauthenticated_and_reauth_failures_are_audited_without_the_secret() {
        let state = test_state(true).await;
        let (headers, csrf) = session_headers(&state);
        let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(LogSink(logs.clone()))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let response = export_with(
            &state,
            &HeaderMap::new(),
            form(&csrf, "testpassword", passphrase(), passphrase()),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(reasons(&state).await.iter().any(|detail| detail.contains("unauthenticated")));

        let response = export_with(
            &state,
            &headers,
            form(&csrf, "wrong-password-value", passphrase(), passphrase()),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let failed = reasons(&state).await;
        assert!(failed.iter().any(|detail| detail.contains("reauth_failed")));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let logged_bytes = logs.lock().expect("log").clone();
        let logged = String::from_utf8_lossy(&logged_bytes);
        for secret in [passphrase(), "wrong-password-value", "testpassword"] {
            assert!(!logged.contains(secret), "{secret} leaked into logs");
            assert!(!body.windows(secret.len()).any(|w| w == secret.as_bytes()));
            assert!(failed.iter().all(|detail| !detail.contains(secret)));
        }

        let disabled = test_state(false).await;
        let response = export_with(
            &disabled,
            &HeaderMap::new(),
            form("", "", passphrase(), passphrase()),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(reasons(&disabled)
            .await
            .iter()
            .any(|detail| detail.contains("reauth_unavailable")));
    }

    #[tokio::test]
    async fn rejected_passphrases_do_not_start_the_helper() {
        let state = test_state(true).await;
        let (headers, csrf) = session_headers(&state);
        for (pass, confirm, reason) in [
            ("", "", "passphrase_empty"),
            ("too-short", "too-short", "passphrase_too_short"),
            ("has-a-newline\nxxxx", "has-a-newline\nxxxx", "passphrase_forbidden"),
            ("0123456789abcdef\t", "0123456789abcdef\t", "passphrase_forbidden"),
            ("0123456789abc\u{15}ef", "0123456789abc\u{15}ef", "passphrase_forbidden"),
            (passphrase(), "different-passphrase", "passphrase_mismatch"),
        ] {
            let response = export_with(
                &state,
                &headers,
                form(&csrf, "testpassword", pass, confirm),
                Some((
                    OsStr::new("helper-must-not-run"),
                    Vec::new(),
                    None,
                )),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{reason}");
        }
        let failed = reasons(&state).await.join("\n");
        assert!(failed.contains("passphrase_empty"));
        assert!(failed.contains("passphrase_too_short"));
        assert!(failed.contains("passphrase_forbidden"));
        assert!(failed.contains("passphrase_mismatch"));
        assert!(!failed.contains(passphrase()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stream_has_no_temp_file_and_disconnect_kills_the_child() {
        let state = test_state(true).await;
        let (headers, csrf) = session_headers(&state);
        let root = std::env::temp_dir().join(format!("awg-export-{}", generate_session_id()));
        let cwd = root.join("cwd");
        std::fs::create_dir_all(&cwd).unwrap();
        let script = root.join("helper.sh");
        let pidfile = root.join("pid");
        let shafile = root.join("sha");
        std::fs::write(
            &script,
            "#!/bin/bash\nset -eu\nmode=\"$1\"\npidfile=\"$2\"\nshafile=\"$3\"\nslow=\"${4:-}\"\nprintf '%s\\n' \"$$\" > \"$pidfile\"\nif [[ \"$mode\" == fail ]]; then sha256sum >/dev/null; exit 1; fi\ndigest=$(sha256sum)\nprintf '%s\\n' \"${digest%% *}\" > \"$shafile\"\nprintf 'age-encryption.org/v1\\n'\ndd if=/dev/zero bs=64 count=1 status=none\nif [[ \"$slow\" == slow ]]; then sleep 60; fi\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let response = export_with(
            &state,
            &headers,
            form(&csrf, "testpassword", passphrase(), passphrase()),
            Some((
                script.as_os_str(),
                vec![
                    "ok".into(),
                    pidfile.display().to_string(),
                    shafile.display().to_string(),
                    String::new(),
                ],
                Some(cwd.clone()),
            )),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL).and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        let disposition = response
            .headers()
            .get(CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(disposition.contains("attachment;"));
        assert!(disposition.contains(".awgx"));
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.starts_with(b"age-encryption.org/v1\n"));
        assert!(!body.windows(passphrase().len()).any(|w| w == passphrase().as_bytes()));
        assert!(std::fs::read_dir(&cwd).unwrap().next().is_none());
        let digest = std::fs::read_to_string(&shafile).unwrap();
        assert_eq!(digest.trim(), sha256_hex(passphrase().as_bytes()));
        assert!(!digest.contains(passphrase()));
        let saved = list_events(&state.db.pool, None, Some(EVT_STATE_EXPORTED), 5)
            .await
            .unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].actor, "admin");
        assert!(saved[0].detail.as_deref().unwrap_or("").is_empty() || saved[0].detail.is_none() || !saved[0].detail.as_deref().unwrap_or("").contains(passphrase()));

        let pidfile = root.join("slow.pid");
        let shafile = root.join("slow.sha");
        let response = export_with(
            &state,
            &headers,
            form(&csrf, "testpassword", passphrase(), passphrase()),
            Some((
                script.as_os_str(),
                vec![
                    "ok".into(),
                    pidfile.display().to_string(),
                    shafile.display().to_string(),
                    "slow".into(),
                ],
                Some(cwd.clone()),
            )),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let first = stream.next().await.expect("chunk").expect("bytes");
        assert!(first.starts_with(b"age-encryption.org/"));
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
        assert!(!cmdline.windows(passphrase().len()).any(|w| w == passphrase().as_bytes()));
        assert!(!environ.windows(passphrase().len()).any(|w| w == passphrase().as_bytes()));
        drop(stream);
        let mut dead = false;
        for _ in 0..50 {
            if unsafe { libc::kill(pid, 0) } != 0 {
                dead = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(dead, "child {pid} still running after the response was dropped");
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let failed = reasons(&state).await;
        assert!(
            failed.iter().any(|detail| detail.contains("client_disconnected")),
            "{failed:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn helper_failure_writes_no_body() {
        let state = test_state(true).await;
        let (headers, csrf) = session_headers(&state);
        let root = std::env::temp_dir().join(format!("awg-export-fail-{}", generate_session_id()));
        std::fs::create_dir_all(&root).unwrap();
        let script = root.join("helper.sh");
        std::fs::write(
            &script,
            "#!/bin/bash\nset -eu\nsha256sum >/dev/null\nexit 1\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&script, perms).unwrap();
        let response = export_with(
            &state,
            &headers,
            form(&csrf, "testpassword", passphrase(), passphrase()),
            Some((script.as_os_str(), Vec::new(), Some(root.clone()))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.windows(passphrase().len()).any(|w| w == passphrase().as_bytes()));
        assert!(!body.starts_with(b"age-encryption.org/"));
        assert!(body.windows(b"panel log".len()).any(|w| w == b"panel log"));
        assert!(reasons(&state).await.iter().any(|d| d.contains("export_failed")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn route_requires_a_session_even_with_a_bearer_token() {
        let db = Database::connect_for_test().await.unwrap();
        let hash = AuthConfig::hash_password_fast("testpassword");
        let app = super::super::router_with_proxy_sessions_file(
            db,
            AuthConfig {
                enabled: true,
                username: "admin".into(),
                password_hash: hash,
                api_token: Some("super-secret-token".into()),
                secure_cookie: false,
                session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
            },
            std::path::PathBuf::from("/tmp/test-configs"),
            std::env::temp_dir().join("missing-proxy-sessions.json"),
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/state/export")
                    .header("authorization", "Bearer super-secret-token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(AxumBody::from(
                        "current_password=testpassword&passphrase=state-export-panel-secret&passphrase_confirm=state-export-panel-secret",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.windows(passphrase().len()).any(|w| w == passphrase().as_bytes()));
    }

    #[tokio::test]
    async fn status_json_reports_stale_exports_and_the_endpoint_warning() {
        let now = Utc.with_ymd_and_hms(2026, 11, 8, 12, 0, 0).unwrap();
        let old = now - chrono::Duration::days(8);
        let parsed = parse_event_time("2026-11-08 12:00:00").unwrap();
        assert_eq!(parsed, now);
        let response = json_status(Some(old), now, 7, None);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("\"stale\":true"));
        assert!(!text.contains("ip_literal"), "{text}");
        assert!(!text.contains("warning"), "{text}");
        assert!(text.contains("2026-10-31 12:00 UTC"), "{text}");
        assert!(text.contains("\"export_block\":null"));
        let blocked = json_status(
            Some(now),
            now,
            7,
            Some("export-state requires age; rerun the panel upgrade"),
        );
        let body = axum::body::to_bytes(blocked.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("export-state requires age; rerun the panel upgrade"));
        let endpoints = json_endpoints(Some((1, 2)));
        let body = axum::body::to_bytes(endpoints.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("2 profiles use an IP in Endpoint"));
        assert!(text.contains("\"ip_literal\":2"));
        let fresh = json_endpoints(Some((4, 0)));
        let body = axum::body::to_bytes(fresh.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("\"ip_literal\":0"));
        assert!(text.contains("\"warning\":null"));
        let never = json_status(None, now, 7, None);
        let body = axum::body::to_bytes(never.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("\"last_export\":null"));
        assert!(text.contains("\"stale\":true"));
        let missing = json_endpoints(None);
        let body = axum::body::to_bytes(missing.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("\"ip_literal\":null"));
    }

    #[tokio::test]
    async fn status_request_does_not_spawn_the_summary_helper() {
        let state = test_state(true).await;
        let before = SUMMARY_SPAWNS.load(Ordering::SeqCst);
        let response = api_status(State(state)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(SUMMARY_SPAWNS.load(Ordering::SeqCst), before);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains("ip_literal"), "{text}");
    }

    #[tokio::test]
    async fn signed_in_home_shows_the_export_section() {
        let db = Database::connect_for_test().await.unwrap();
        let dir = std::env::temp_dir().join(format!(
            "awg-state-export-home-{}",
            generate_session_id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let app = super::super::router_with_proxy_sessions_file(
            db,
            AuthConfig {
                enabled: true,
                username: "admin".into(),
                password_hash: AuthConfig::hash_password_fast("testpassword"),
                api_token: Some("super-secret-token".into()),
                secure_cookie: false,
                session_ttl: Duration::from_secs(DEFAULT_SESSION_TTL_SECS),
            },
            dir.clone(),
            dir.join("proxy.json"),
        );
        let login_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let html = axum::body::to_bytes(login_page.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = std::str::from_utf8(&html).unwrap();
        let marker = "name=\"csrf_token\" value=\"";
        let csrf_at = html.find(marker).expect("login csrf");
        let rest = &html[csrf_at + marker.len()..];
        let csrf = &rest[..rest.find('"').unwrap()];
        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(AxumBody::from(format!(
                        "username=admin&password=testpassword&csrf_token={csrf}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let cookie = login
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .trim()
            .to_string();
        let page = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("cookie", cookie)
                    .body(AxumBody::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::OK);
        let body = axum::body::to_bytes(page.into_body(), usize::MAX)
            .await
            .unwrap();
        let page_html = std::str::from_utf8(&body).unwrap();
        assert!(page_html.contains("id=\"state-export-panel\""));
        assert!(page_html.contains("action=\"/admin/state/export\""));
        assert!(page_html.contains("name=\"passphrase_confirm\""));
        assert!(!page_html.contains(passphrase()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn helper_stderr_is_logged_without_the_passphrase() {
        let state = test_state(true).await;
        let (headers, csrf) = session_headers(&state);
        let root = std::env::temp_dir().join(format!("awg-export-log-{}", generate_session_id()));
        std::fs::create_dir_all(&root).unwrap();
        let script = root.join("helper.sh");
        std::fs::write(&script, "#!/bin/bash\nset -eu\ncat >&2\nexit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&script, perms).unwrap();
        let _ = take_test_export_log();
        let response = export_with(
            &state,
            &headers,
            form(&csrf, "testpassword", passphrase(), passphrase()),
            Some((script.as_os_str(), Vec::new(), Some(root.clone()))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let logged = take_test_export_log();
        assert!(logged.contains("[redacted]"), "{logged}");
        assert!(!logged.contains(passphrase()), "{logged}");
        assert!(std::str::from_utf8(&body).unwrap().contains("panel log"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_export_is_refused_until_the_first_finishes() {
        let state = test_state(true).await;
        let (headers, csrf) = session_headers(&state);
        let root = std::env::temp_dir().join(format!("awg-export-gate-{}", generate_session_id()));
        let cwd = root.join("cwd");
        std::fs::create_dir_all(&cwd).unwrap();
        let script = root.join("helper.sh");
        std::fs::write(
            &script,
            "#!/bin/bash\nset -eu\nmode=\"${1:-ok}\"\nif [[ \"$mode\" == slow ]]; then sha256sum >/dev/null; printf 'age-encryption.org/v1\\n'; sleep 60; else sha256sum >/dev/null; printf 'age-encryption.org/v1\\n'; fi\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&script, perms).unwrap();
        let first = export_with(
            &state,
            &headers,
            form(&csrf, "testpassword", passphrase(), passphrase()),
            Some((
                script.as_os_str(),
                vec!["slow".into()],
                Some(cwd.clone()),
            )),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = export_with(
            &state,
            &headers,
            form(&csrf, "testpassword", passphrase(), passphrase()),
            Some((
                script.as_os_str(),
                vec!["ok".into()],
                Some(cwd.clone()),
            )),
        )
        .await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("Another state export is already running."));
        drop(first);
        let third = export_with(
            &state,
            &headers,
            form(&csrf, "testpassword", passphrase(), passphrase()),
            Some((
                script.as_os_str(),
                vec!["ok".into()],
                Some(cwd),
            )),
        )
        .await;
        assert_eq!(third.status(), StatusCode::OK);
        let _ = axum::body::to_bytes(third.into_body(), usize::MAX).await;
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stderr_tail_keeps_the_last_lines_and_bytes() {
        let mut buf = Vec::new();
        for index in 0..30 {
            push_stderr_tail(&mut buf, format!("line {index:02}\n").as_bytes());
        }
        let text = String::from_utf8(buf.clone()).unwrap();
        assert_eq!(text.lines().count(), 20);
        assert!(text.contains("line 10"));
        assert!(!text.contains("line 09"));
        let mut wide = Vec::new();
        push_stderr_tail(&mut wide, &vec![b'a'; 3000]);
        assert!(wide.len() <= 2048);
        let mut secret = b"state-export-panel-secret leaked".to_vec();
        redact_secret(&mut secret, b"state-export-panel-secret");
        assert_eq!(secret, b"[redacted] leaked");
        let mut split = Vec::new();
        let pass = b"state-export-panel-secret";
        append_stderr_tail(&mut split, b"note state-export-panel-", pass);
        append_stderr_tail(&mut split, b"secret end", pass);
        seal_stderr_tail(&mut split, pass);
        let text = String::from_utf8(split).unwrap();
        assert!(text.contains("[redacted]"), "{text}");
        assert!(!text.contains("state-export-panel-secret"), "{text}");
    }

    #[tokio::test]
    async fn endpoint_cache_runs_one_load_and_reuses_it() {
        let cache = EndpointSummaryCache::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let first = calls.clone();
        let second = calls.clone();
        let left = cache.get_or_load(|| async move {
            first.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(80)).await;
            Some((1, 2))
        });
        let right = cache.get_or_load(|| async move {
            second.fetch_add(1, Ordering::SeqCst);
            Some((9, 9))
        });
        let (left, right) = tokio::join!(left, right);
        assert_eq!(left, Some((1, 2)));
        assert_eq!(right, Some((1, 2)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let third = calls.clone();
        let cached = cache
            .get_or_load(|| async move {
                third.fetch_add(1, Ordering::SeqCst);
                Some((0, 0))
            })
            .await;
        assert_eq!(cached, Some((1, 2)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        cache.expire().await;
        let fourth = calls.clone();
        let again = cache
            .get_or_load(|| async move {
                fourth.fetch_add(1, Ordering::SeqCst);
                None
            })
            .await;
        assert_eq!(again, None);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let fifth = calls.clone();
        let held = cache
            .get_or_load(|| async move {
                fifth.fetch_add(1, Ordering::SeqCst);
                Some((3, 3))
            })
            .await;
        assert_eq!(held, None);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn export_gate_allows_one_holder() {
        let gate = ExportGate::new();
        let held = gate.try_acquire().expect("first");
        assert!(gate.try_acquire().is_none());
        drop(held);
        assert!(gate.try_acquire().is_some());
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[derive(Clone)]
    struct LogSink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
        type Writer = LogSink;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
}
