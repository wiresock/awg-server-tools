use super::*;
use crate::delivery::{self, service::DeliveryContext, DeliveryError, Format, Mode};
use std::sync::Arc;

impl IntoResponse for DeliveryError {
    fn into_response(self) -> Response {
        (StatusCode::CONFLICT, Json(json!({"error":self.0}))).into_response()
    }
}
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin/delivery", get(page))
        .route("/admin/delivery/advanced", get(advanced_page))
        .route("/static/delivery-admin.js", get(script))
        .route("/static/email-common.js", get(common_script))
        .route("/static/email-settings.js", get(settings_script))
        .route("/static/peer-email.js", get(peer_script))
        .route(
            "/api/admin/delivery/settings",
            get(settings).post(save_settings),
        )
        .route("/api/admin/delivery/settings/check", post(check_smtp))
        .route("/api/admin/delivery/settings/test", post(test_settings))
        .route("/api/admin/delivery/settings/test/:id", get(test_status))
        .route("/api/admin/delivery/contacts", get(contacts))
        .route("/api/admin/delivery/jobs", get(jobs))
        .route("/api/admin/delivery/contact", post(contact))
        .route("/admin/delivery/contact-form", post(contact_form))
        .route("/api/admin/delivery/contact-delete", post(contact_delete))
        .route("/api/admin/delivery/preview", post(preview))
        .route("/api/admin/delivery/send", post(send))
        .route("/api/admin/delivery/revoke", post(revoke))
        .route("/api/admin/delivery/rebind-preview", post(rebind_preview))
        .route("/api/admin/delivery/rebind", post(rebind))
        .layer(axum::extract::DefaultBodyLimit::max(16384))
        .layer(middleware::map_response(|response: Response| async {
            delivery_public::secure(response)
        }))
}
fn ctx(state: &AppState) -> Result<&Arc<DeliveryContext>, DeliveryError> {
    state
        .delivery
        .as_ref()
        .ok_or(DeliveryError("delivery_unavailable"))
}
fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<String, DeliveryError> {
    if !state.auth.enabled {
        return Err(DeliveryError("authentication_required"));
    }
    // An explicit Authorization header must stand on its own. Never fall back
    // to an ambient cookie after a wrong bearer credential.
    if let Some(header) = headers.get("authorization") {
        let supplied = header.to_str().ok().and_then(|s| s.strip_prefix("Bearer "));
        if !supplied
            .zip(state.auth.api_token.as_deref())
            .is_some_and(|(a, b)| crate::auth::csrf_eq(a, b))
        {
            return Err(DeliveryError("authentication_required"));
        }
        return Ok("api-admin".into());
    }
    let cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = extract_session_token(cookie).ok_or(DeliveryError("authentication_required"))?;
    if !is_session_valid(&state.sessions, &token, state.auth.session_ttl) {
        return Err(DeliveryError("authentication_required"));
    }
    if mutation
        && !validate_form_csrf(
            state,
            cookie,
            headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
        )
    {
        return Err(DeliveryError("csrf_required"));
    }
    // Preview ownership is session-specific; persisted budget actor is normalized
    // separately so logging in again cannot reset the administrator's budget.
    Ok(format!(
        "session:{}",
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            delivery::hash(token.as_bytes())
        )
    ))
}
pub(super) fn creation_email(
    state: &AppState,
    headers: &HeaderMap,
    email: Option<&str>,
    form_csrf: Option<&str>,
) -> Result<Option<String>, DeliveryError> {
    let Some(email) = email.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let email = delivery::config::mailbox(email)?;
    let mut headers = headers.clone();
    if let Some(csrf) = form_csrf {
        headers.insert(
            "x-csrf-token",
            csrf.parse().map_err(|_| DeliveryError("csrf_required"))?,
        );
    }
    authorize(state, &headers, true)?;
    ctx(state)?;
    Ok(Some(email))
}
pub(super) async fn save_created_email(
    state: &AppState,
    result: &crate::admin::CreateUserResult,
    email: Option<&str>,
) -> bool {
    let Some(email) = email else {
        return true;
    };
    let Some(ctx) = &state.delivery else {
        return false;
    };
    let Ok(contacts) = ctx.contacts().await else {
        return false;
    };
    let Some(contact) = contacts.iter().find(|c| {
        c.last_public_key == result.public_key
            && c.managed_name == result.client_name
            && c.peer_id.is_some()
            && c.retired_at.is_none()
            && c.email.is_none()
    }) else {
        return false;
    };
    ctx.set_email(&contact.id, contact.binding_version, Some(email))
        .await
        .is_ok()
}
pub(super) fn peer_panel(
    state: &AppState,
    contact: &crate::db::delivery::Client,
    csrf: &str,
) -> String {
    format!(
        r#"<div id="peer-email" class="peer-email-editor">
<form method="POST" action="{base}/admin/delivery/contact-form" aria-label="Peer email">
<input type="hidden" name="client_id" value="{id}"><input type="hidden" name="version" value="{version}"><input type="hidden" name="csrf_token" value="{csrf}">
<label for="peer-delivery-email">Email (optional)</label><input id="peer-delivery-email" type="email" name="email" maxlength="254" value="{email}">
<p class="meta">Email is saved separately. Save any peer details above first; saving email reloads this page.</p>
<button type="submit">Save email</button> <button type="reset" aria-label="Cancel email changes">Cancel</button></form>
<p class="meta">Clearing or changing email revokes existing links and queued sends. Saving never sends automatically.</p>
</div>"#,
        base = esc(&state.base_path),
        id = esc(&contact.id),
        version = contact.binding_version,
        csrf = esc(csrf),
        email = esc(contact.email.as_deref().unwrap_or("")),
    )
}

#[derive(Deserialize)]
struct ContactForm {
    client_id: String,
    version: i64,
    email: Option<String>,
    csrf_token: String,
}
async fn contact_form(
    State(state): State<AppState>,
    mut headers: HeaderMap,
    Form(body): Form<ContactForm>,
) -> Result<Redirect, DeliveryError> {
    headers.insert(
        "x-csrf-token",
        body.csrf_token
            .parse()
            .map_err(|_| DeliveryError("csrf_required"))?,
    );
    authorize(&state, &headers, true)?;
    let ctx = ctx(&state)?;
    ctx.set_email(&body.client_id, body.version, body.email.as_deref())
        .await?;
    let contact = crate::db::delivery::client(&ctx.source.db.pool, &body.client_id).await?;
    Ok(Redirect::to(
        &state.url(
            &contact
                .peer_id
                .map(|id| format!("/peers/{id}"))
                .unwrap_or_else(|| "/admin/delivery".into()),
        ),
    ))
}

async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, DeliveryError> {
    authorize(&state, &headers, false)?;
    let csrf = session_csrf_from_headers(&state, &headers);
    let mut html = html_head("AmneziaWG - Settings", &state.base_path);
    // This secret-bearing page retains the strict no-inline-script CSP. The
    // shared email script updates versions through the same read-only endpoint.
    let nav = nav_bar_section(&state.base_path, &csrf, true);
    html.push_str(nav.split("<script>").next().unwrap_or(&nav));
    html.push_str(&format!(
        include_str!("email_settings.html"),
        base = esc(&state.base_path),
        csrf = esc(&csrf)
    ));
    html.push_str("</body></html>");
    Ok(Html(html))
}
async fn advanced_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Html<String>, DeliveryError> {
    authorize(&state, &headers, false)?;
    let html = format!(
        include_str!("delivery_admin.html"),
        stylesheet = esc(&panel_stylesheet_href(&state.base_path, PANEL_CSS)),
        base = esc(&state.base_path),
        csrf = esc(&session_csrf_from_headers(&state, &headers)),
    );
    Ok(Html(html))
}
async fn common_script() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("email_common.js"),
    )
}
async fn settings_script() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("email_settings.js"),
    )
}
async fn peer_script() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("peer_email.js"),
    )
}
async fn script() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("delivery_admin.js"),
    )
}
async fn settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<delivery::runtime::SettingsView>, DeliveryError> {
    authorize(&state, &headers, false)?;
    Ok(Json(ctx(&state)?.settings_view()))
}
async fn save_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<
        Json<delivery::settings::PanelSettingsInput>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<delivery::runtime::SettingsView>, DeliveryError> {
    authorize(&state, &headers, true)?;
    // Extractor diagnostics can include submitted values: never return them for
    // this secret-bearing form, including wrong types and unknown fields.
    let Json(body) = payload.map_err(|_| DeliveryError("invalid_settings"))?;
    Ok(Json(
        ctx(&state)?
            .update_settings(body, state.auth.enabled, state.base_path.clone())
            .await?,
    ))
}
async fn test_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<
        Json<delivery::test_mail::TestRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<delivery::test_mail::TestOutcome>, DeliveryError> {
    authorize(&state, &headers, true)?;
    let Json(body) = payload.map_err(|_| DeliveryError("invalid_test_request"))?;
    Ok(Json(ctx(&state)?.test_email(body).await?))
}
async fn check_smtp(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<
        Json<delivery::smtp_check::CheckRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Result<Json<delivery::smtp_check::CheckOutcome>, DeliveryError> {
    authorize(&state, &headers, true)?;
    let Json(body) = payload.map_err(|_| DeliveryError("invalid_test_request"))?;
    Ok(Json(ctx(&state)?.check_smtp(body).await?))
}
async fn test_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<Option<delivery::test_mail::TestOutcome>>, DeliveryError> {
    authorize(&state, &headers, false)?;
    Ok(Json(ctx(&state)?.test_status(&id).await?))
}
async fn contacts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::db::delivery::Client>>, DeliveryError> {
    authorize(&state, &headers, false)?;
    Ok(Json(ctx(&state)?.contacts().await?))
}
async fn jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::db::delivery::Job>>, DeliveryError> {
    authorize(&state, &headers, false)?;
    Ok(Json(ctx(&state)?.jobs().await?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Contact {
    client_id: String,
    version: i64,
    email: Option<String>,
}
async fn contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Contact>,
) -> Result<Json<serde_json::Value>, DeliveryError> {
    authorize(&state, &headers, true)?;
    ctx(&state)?
        .set_email(&body.client_id, body.version, body.email.as_deref())
        .await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    client_id: String,
    version: i64,
}
async fn contact_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Identity>,
) -> Result<Json<serde_json::Value>, DeliveryError> {
    authorize(&state, &headers, true)?;
    ctx(&state)?
        .delete_contact(&body.client_id, body.version)
        .await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selection {
    clients: Vec<String>,
    mode: Mode,
    formats: Vec<Format>,
    #[serde(default)]
    ttl_seconds: Option<i64>,
}
async fn preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Selection>,
) -> Result<Json<delivery::service::Preview>, DeliveryError> {
    let actor = authorize(&state, &headers, true)?;
    let ctx = ctx(&state)?;
    let result = match body.ttl_seconds {
        Some(ttl) => {
            ctx.preview_with_ttl(&actor, &body.clients, body.mode, &body.formats, Some(ttl))
                .await?
        }
        None => {
            ctx.preview(&actor, &body.clients, body.mode, &body.formats)
                .await?
        }
    };
    Ok(Json(result))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    preview_id: String,
    request_id: String,
}
async fn send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Confirmation>,
) -> Result<Json<Vec<String>>, DeliveryError> {
    let actor = authorize(&state, &headers, true)?;
    Ok(Json(
        ctx(&state)?
            .enqueue(&actor, &body.preview_id, &body.request_id)
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    client_id: String,
}
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Revoke>,
) -> Result<Json<serde_json::Value>, DeliveryError> {
    authorize(&state, &headers, true)?;
    ctx(&state)?.revoke(&body.client_id).await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rebind {
    client_id: String,
    version: i64,
    target_id: String,
    target_version: i64,
}
async fn rebind_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Rebind>,
) -> Result<Json<serde_json::Value>, DeliveryError> {
    authorize(&state, &headers, true)?;
    let ctx = ctx(&state)?;
    let guards = ctx.guards().await?;
    let old = crate::db::delivery::client(&ctx.source.db.pool, &body.client_id).await?;
    let selected_target = crate::db::delivery::client(&ctx.source.db.pool, &body.target_id).await?;
    if old.binding_version != body.version || selected_target.binding_version != body.target_version
    {
        return Err(DeliveryError("changed"));
    }
    let target = ctx
        .source
        .snapshot(&body.target_id, &guards, ctx.time() + 30)
        .await?;
    if old.peer_id.is_some()
        || old.retired_at.is_some()
        || target.client.email.is_some()
        || old.interface != target.client.interface
        || old.id == target.client.id
    {
        return Err(DeliveryError("rebind_ineligible"));
    }
    let addresses =
        crate::config_store::ClientConfig::from_content(std::path::PathBuf::new(), &target.content)
            .addresses;
    Ok(Json(
        json!({"old":old,"target":target.client,"target_addresses":addresses,"old_addresses":null}),
    ))
}
async fn rebind(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Rebind>,
) -> Result<Json<serde_json::Value>, DeliveryError> {
    authorize(&state, &headers, true)?;
    ctx(&state)?
        .rebind(
            &body.client_id,
            body.version,
            &body.target_id,
            body.target_version,
        )
        .await?;
    Ok(Json(json!({"ok":true})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::tests::Fixture;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    fn panel_body() -> serde_json::Value {
        json!({"revision":0,"enabled":true,"host":"new.example.test","port":587,
          "tls":"starttls","authenticate":true,"username":"fixture-user",
          "password_action":"replace","password":"panel-api-secret-canary",
          "from":"sender@example.test","reply_to":"support@example.test",
          "public_base":"https://download.example.test/share","ttl_seconds":3600})
    }
    fn panel_state(f: &Fixture) -> AppState {
        let mut auth = crate::auth::AuthConfig::disabled();
        auth.enabled = true;
        auth.api_token = Some("fixture".into());
        let mut state = AppState::new(
            f.ctx.source.db.clone(),
            auth,
            f.directory.path().into(),
            f.directory.path().into(),
            f.directory.path().join("unused"),
        );
        state.delivery = Some(f.ctx.clone());
        state
    }
    fn panel_request(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("authorization", "Bearer fixture")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }
    #[tokio::test]
    async fn panel_connection_check_has_explicit_authenticated_route() {
        let f = Fixture::new().await;
        let app = super::super::build_router_state(panel_state(&f));
        let response = app
            .oneshot(panel_request(
                "/api/admin/delivery/settings/check",
                json!({"revision":0}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 16384).await.unwrap()).unwrap();
        assert_eq!(value["settings_revision"], 0);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_test_attempts")
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "connection check must not enqueue a test message");
    }
    #[tokio::test]
    async fn panel_test_status_recovery_is_authenticated_read_only_and_does_not_resend() {
        let f = Fixture::new().await;
        let app = super::super::build_router_state(panel_state(&f));
        let id = crate::delivery::random_id();
        let body = json!({"revision":0,"recipient":"admin@example.test","request_id":id});
        assert_eq!(
            app.clone()
                .oneshot(panel_request("/api/admin/delivery/settings/test", body))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/admin/delivery/settings/test/{id}"))
                        .header("authorization", "Bearer fixture")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["cache-control"],
                "no-store, no-cache, max-age=0"
            );
            let value: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            assert_eq!(value["state"], "accepted");
            assert_eq!(value["recipient"], "admin@example.test");
        }
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/admin/delivery/settings/test/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::OK);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_test_attempts")
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert!(f.ctx.jobs().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn panel_native_email_settings_and_main_peer_actions_are_rendered() {
        let f = Fixture::new().await;
        let state = panel_state(&f);
        let session = generate_session_id();
        add_session(&state.sessions, session.clone());
        let app = super::super::build_router_state(state);
        for (path, needles) in [
            (
                "/peers/1",
                vec![
                    "Send config by email",
                    "class=\"btn peer-send-email\"",
                    "href=\"/?send_peer=1\"",
                    "id=\"peer-email\"",
                ],
            ),
            (
                "/admin/delivery",
                vec![
                    "SMTP server",
                    "<h1>Settings</h1>",
                    "id=\"email-settings-form\"",
                    "Password action",
                    "Send test email",
                    "Save settings",
                ],
            ),
            (
                "/",
                vec![
                    "Bulk actions",
                    "data-email-select=\"1\"",
                    "href=\"/peers/1\"",
                    "Send config",
                    "id=\"email-send-dialog\"",
                ],
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("cookie", format!("awg_session={session}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = String::from_utf8(
                to_bytes(response.into_body(), 262144)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap();
            for needle in needles {
                assert!(body.contains(needle), "{path} is missing {needle}");
            }
            if path == "/peers/1" {
                let editor = body
                    .split("id=\"peer-editor\"")
                    .nth(1)
                    .expect("one Edit peer card");
                let editor = editor.split("<!-- peer-editor-end -->").next().unwrap();
                let forms: Vec<_> = editor.split("<form ").skip(1).collect();
                assert_eq!(
                    forms.len(),
                    2,
                    "details and email have separate forms in the same card"
                );
                assert!(forms[0].contains("action=\"/peers/1\""));
                assert!(!forms[0].contains("name=\"email\""));
                assert!(
                    forms[0].contains("</form>"),
                    "email must not nest inside details form"
                );
                assert!(forms[1].contains("action=\"/admin/delivery/contact-form\""));
                assert_eq!(forms[1].matches("name=\"email\"").count(), 1);
                assert!(forms[1].contains("name=\"version\""));
                assert!(
                    forms[1].contains("type=\"reset\""),
                    "Cancel must not submit email"
                );
                assert_eq!(body.matches("class=\"btn peer-send-email\"").count(), 1);
            } else if path == "/" {
                let table = body
                    .split("class=\"peer-table\"")
                    .nth(1)
                    .unwrap()
                    .split("</table>")
                    .next()
                    .unwrap();
                assert!(!table.contains("data-label=\"Actions\""));
                assert!(!table.contains("<th>Actions</th>"));
                assert!(table.contains("href=\"/peers/1\""));
                assert!(table.contains("data-email-select=\"1\""));
            }
            assert!(!body.contains("<pre id=\"settings\""));
            assert!(!body.contains("value=\"fixture-secret"));
        }
    }
    #[tokio::test]
    async fn panel_save_and_test_require_csrf_and_never_echo_invalid_secrets() {
        let f = Fixture::new().await;
        let state = panel_state(&f);
        let session = generate_session_id();
        let csrf = add_session(&state.sessions, session.clone());
        let app = super::super::build_router_state(state);
        for path in [
            "/api/admin/delivery/settings",
            "/api/admin/delivery/settings/test",
            "/api/admin/delivery/settings/check",
        ] {
            for authorized in [false, true] {
                let mut request = Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("cookie", format!("awg_session={session}"))
                    .header("content-type", "application/json");
                if authorized {
                    request = request.header("x-csrf-token", &csrf);
                }
                let response=app.clone().oneshot(request.body(Body::from(r#"{"password":"invalid-secret-canary","revision":"invalid-secret-canary"}"#)).unwrap()).await.unwrap();
                assert_eq!(response.status(), StatusCode::CONFLICT);
                let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
                let text = std::str::from_utf8(&bytes).unwrap();
                assert!(!text.contains("invalid-secret-canary"));
                if !authorized {
                    assert!(text.contains("csrf_required"));
                }
            }
        }
        assert_eq!(f.ctx.runtime().revision, 0);
    }
    #[tokio::test]
    async fn draft_test_routes_redact_nested_secrets_and_enforce_csrf() {
        let mut f = Fixture::new().await;
        crate::delivery::tests::runtime_mut(&mut f.ctx)
            .settings
            .password = "stored-secret-canary".into();
        let state = panel_state(&f);
        let session = generate_session_id();
        let csrf = add_session(&state.sessions, session.clone());
        let app = super::super::build_router_state(state);
        for path in [
            "/api/admin/delivery/settings/check",
            "/api/admin/delivery/settings/test",
        ] {
            for malformed in [false, true] {
                for authorized in [false, true] {
                    let mut draft = panel_body();
                    draft["password_action"] = "keep".into();
                    draft["password"] = if malformed {
                        json!({"nested-secret-canary": true})
                    } else {
                        serde_json::Value::Null
                    };
                    let mut body = json!({"revision":0,"draft":draft});
                    if path.ends_with("/test") {
                        body["recipient"] = "recipient@example.test".into();
                        body["request_id"] = "a".repeat(43).into();
                    }
                    let mut request = Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("cookie", format!("awg_session={session}"))
                        .header("content-type", "application/json");
                    if authorized {
                        request = request.header("x-csrf-token", &csrf);
                    }
                    let response = app
                        .clone()
                        .oneshot(request.body(Body::from(body.to_string())).unwrap())
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::CONFLICT);
                    let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
                    let text = std::str::from_utf8(&bytes).unwrap();
                    assert!(!text.contains("secret-canary"));
                    if !authorized {
                        assert!(text.contains("csrf_required"));
                    } else if !malformed {
                        assert!(text.contains("draft_password_scope_changed"));
                    }
                }
            }
        }
        assert_eq!(f.ctx.runtime().revision, 0);
        assert!(f.ctx.jobs().await.unwrap().is_empty());
    }
    #[tokio::test]
    async fn panel_disabled_start_exposes_public_routes_only_after_safe_enable() {
        let mut f = Fixture::new().await;
        crate::delivery::tests::runtime_mut(&mut f.ctx)
            .settings
            .enabled = false;
        crate::delivery::tests::runtime_mut(&mut f.ctx)
            .settings
            .public_base = None;
        let app = super::super::build_router_state(panel_state(&f));
        let request = || {
            Request::builder()
                .uri("/delivery/")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            app.clone().oneshot(request()).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        let response = app
            .clone()
            .oneshot(panel_request("/api/admin/delivery/settings", panel_body()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            app.oneshot(request()).await.unwrap().status(),
            StatusCode::OK
        );
        for base in ["/delivery", "/delivery/", "/%64elivery", "/delivery/redeem"] {
            let body = serde_json::from_value(panel_body()).unwrap();
            assert!(f
                .ctx
                .update_settings(body, true, base.into())
                .await
                .is_err());
        }
    }
    #[tokio::test]
    async fn panel_settings_api_saves_redacted_version_and_cancels_old_queue() {
        let f = Fixture::new().await;
        let job = f.queue(crate::delivery::Mode::Link).await;
        let app = super::super::build_router_state(panel_state(&f));
        let response = app
            .clone()
            .oneshot(panel_request("/api/admin/delivery/settings", panel_body()))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "versioned settings Save must be supported"
        );
        let body = String::from_utf8(
            to_bytes(response.into_body(), 16384)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!body.contains("panel-api-secret-canary"));
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["revision"], 1);
        assert_eq!(value["source"], "panel");
        assert_eq!(value["host"], "new.example.test");
        assert_eq!(value["credentials_present"], true);
        assert_eq!(
            crate::db::delivery::job(&f.ctx.source.db.pool, &job)
                .await
                .unwrap()
                .state,
            "cancelled"
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_test_attempts")
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "Save must not send a test message");
        let stale = app
            .oneshot(panel_request("/api/admin/delivery/settings", panel_body()))
            .await
            .unwrap();
        assert_eq!(stale.status(), StatusCode::CONFLICT);
    }
    #[tokio::test]
    async fn panel_test_email_is_explicit_and_duplicate_id_is_not_repeated() {
        let f = Fixture::new().await;
        let app = super::super::build_router_state(panel_state(&f));
        let request = json!({"revision":0,"recipient":"admin@example.test","request_id":crate::delivery::random_id()});
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(panel_request(
                    "/api/admin/delivery/settings/test",
                    request.clone(),
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "explicit test endpoint must exist"
            );
            let value: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            assert_eq!(value["state"], "accepted");
            assert_eq!(value["settings_revision"], 0);
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM email_test_attempts")
            .fetch_one(&f.ctx.source.db.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert!(
            f.ctx.jobs().await.unwrap().is_empty(),
            "test message must not enqueue VPN configurations"
        );
    }

    #[tokio::test]
    async fn delivery_rebind_preview_shows_verified_addresses_and_rejects_changed_recipient() {
        let f = Fixture::new().await;
        let target_id = f.second_client().await;
        sqlx::query(
            "UPDATE delivery_clients SET peer_id=NULL,binding_version=binding_version+1 WHERE id=?",
        )
        .bind(&f.client)
        .execute(&f.ctx.source.db.pool)
        .await
        .unwrap();
        let old = crate::db::delivery::client(&f.ctx.source.db.pool, &f.client)
            .await
            .unwrap();
        let target = crate::db::delivery::client(&f.ctx.source.db.pool, &target_id)
            .await
            .unwrap();
        f.ctx
            .set_email(&target_id, target.binding_version, None)
            .await
            .unwrap();
        let target = crate::db::delivery::client(&f.ctx.source.db.pool, &target_id)
            .await
            .unwrap();
        let mut auth = crate::auth::AuthConfig::disabled();
        auth.enabled = true;
        auth.api_token = Some("fixture".into());
        let mut state = AppState::new(
            f.ctx.source.db.clone(),
            auth,
            f.directory.path().into(),
            f.directory.path().into(),
            f.directory.path().join("unused"),
        );
        state.delivery = Some(f.ctx.clone());
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer fixture".parse().unwrap());
        let body = || Rebind {
            client_id: old.id.clone(),
            version: old.binding_version,
            target_id: target.id.clone(),
            target_version: target.binding_version,
        };
        let Json(p) = rebind_preview(State(state.clone()), headers.clone(), Json(body()))
            .await
            .unwrap();
        assert_eq!(p["target_addresses"], json!(["10.0.0.3/32"]));
        assert!(p["old_addresses"].is_null());
        assert_eq!(p["old"]["email"], "recipient@example.test");
        f.ctx
            .set_email(&old.id, old.binding_version, Some("changed@example.test"))
            .await
            .unwrap();
        assert!(
            rebind_preview(State(state), headers, Json(body()))
                .await
                .is_err(),
            "stale contact selection must not silently retarget the recipient"
        );
    }

    #[tokio::test]
    async fn delivery_creation_saves_email_for_exact_key_without_enqueuing() {
        let f = Fixture::new().await;
        let mut auth = crate::auth::AuthConfig::disabled();
        auth.enabled = true;
        auth.api_token = Some("fixture".into());
        let mut state = AppState::new(
            f.ctx.source.db.clone(),
            auth,
            f.directory.path().into(),
            f.directory.path().into(),
            f.directory.path().join("unused"),
        );
        state.delivery = Some(f.ctx.clone());
        let contact = crate::db::delivery::client(&f.ctx.source.db.pool, &f.client)
            .await
            .unwrap();
        f.ctx
            .set_email(&f.client, contact.binding_version, None)
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer fixture".parse().unwrap());
        assert!(creation_email(
            &state,
            &headers,
            Some("bad@example.test\r\nBcc: x@example.test"),
            None
        )
        .is_err());
        let email = creation_email(&state, &headers, Some("new@example.test"), None).unwrap();
        let mut result = crate::admin::CreateUserResult {
            public_key: "wrong-key".into(),
            config_path: "unused".into(),
            client_name: "phone".into(),
            sync_required: false,
            metadata_persisted: true,
        };
        assert!(!save_created_email(&state, &result, email.as_deref()).await);
        result.public_key = "fixture-key".into();
        assert!(save_created_email(&state, &result, email.as_deref()).await);
        assert_eq!(
            crate::db::delivery::client(&f.ctx.source.db.pool, &f.client)
                .await
                .unwrap()
                .email,
            email
        );
        assert!(f.ctx.jobs().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delivery_page_uses_versioned_shared_stylesheet() {
        let f = Fixture::new().await;
        let mut auth = crate::auth::AuthConfig::disabled();
        auth.enabled = true;
        auth.api_token = Some("fixture".into());
        let state = AppState::new(
            f.ctx.source.db.clone(),
            auth,
            f.directory.path().into(),
            f.directory.path().into(),
            f.directory.path().join("unused"),
        )
        .with_base_path("/private".into());
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer fixture".parse().unwrap());
        for base in ["/private", "/ADMIN_BASE/ADMIN_STYLESHEET/ADMIN_CSRF"] {
            let html = page(
                State(state.clone().with_base_path(base.into())),
                headers.clone(),
            )
            .await
            .unwrap()
            .0;
            let stylesheet = panel_stylesheet_href(base, PANEL_CSS);
            assert!(html.contains(&format!("href=\"{}\"", esc(&stylesheet))));
            assert!(html.contains(&format!("href=\"{base}/\"")));
            assert!(html.contains(&format!("src=\"{base}/static/email-settings.js\"")));
            assert!(html.contains(&format!("src=\"{base}/static/email-common.js\"")));
            assert!(
                !html.contains("<script>"),
                "settings page CSP does not allow inline scripts"
            );
            assert!(!html.contains(&format!("href=\"{base}/static/panel.css\"")));
            let advanced = advanced_page(
                State(state.clone().with_base_path(base.into())),
                headers.clone(),
            )
            .await
            .unwrap()
            .0;
            assert!(advanced.contains(&format!("href=\"{}\"", esc(&stylesheet))));
            assert!(advanced.contains(&format!("src=\"{base}/static/delivery-admin.js\"")));
        }
    }

    #[tokio::test]
    async fn delivery_peer_form_clears_email_and_revokes_without_sending() {
        let f = Fixture::new().await;
        let job = f.queue(crate::delivery::Mode::Direct).await;
        let mut auth = crate::auth::AuthConfig::disabled();
        auth.enabled = true;
        let mut state = AppState::new(
            f.ctx.source.db.clone(),
            auth,
            f.directory.path().into(),
            f.directory.path().into(),
            f.directory.path().join("unused"),
        );
        state.delivery = Some(f.ctx.clone());
        let session = generate_session_id();
        let csrf = add_session(&state.sessions, session.clone());
        let contact = crate::db::delivery::client(&f.ctx.source.db.pool, &f.client)
            .await
            .unwrap();
        let panel = peer_panel(&state, &contact, &csrf);
        assert!(panel.contains("type=\"email\""));
        assert!(panel.contains("aria-label=\"Peer email\""));
        let app = super::super::build_router_state(state);
        for (version, email) in [
            (contact.binding_version, "not-an-email"),
            (contact.binding_version - 1, "stale@example.test"),
        ] {
            let rejected = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/admin/delivery/contact-form")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header("cookie", format!("awg_session={session}"))
                        .body(Body::from(format!(
                            "client_id={}&version={version}&email={email}&csrf_token={csrf}",
                            f.client
                        )))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::CONFLICT);
            let unchanged = crate::db::delivery::client(&f.ctx.source.db.pool, &f.client)
                .await
                .unwrap();
            assert_eq!(unchanged.email, contact.email);
            assert_eq!(unchanged.binding_version, contact.binding_version);
            assert_eq!(
                crate::db::delivery::job(&f.ctx.source.db.pool, &job)
                    .await
                    .unwrap()
                    .state,
                "queued"
            );
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/delivery/contact-form")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", format!("awg_session={session}"))
                    .body(Body::from(format!(
                        "client_id={}&version={}&email=&csrf_token={}",
                        f.client, contact.binding_version, csrf
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(
            crate::db::delivery::client(&f.ctx.source.db.pool, &f.client)
                .await
                .unwrap()
                .email
                .is_none()
        );
        assert_eq!(
            crate::db::delivery::job(&f.ctx.source.db.pool, &job)
                .await
                .unwrap()
                .state,
            "cancelled"
        );
    }
    #[tokio::test]
    async fn delivery_mutation_requires_csrf_or_independent_bearer() {
        let f = Fixture::new().await;
        let mut auth = crate::auth::AuthConfig::disabled();
        auth.enabled = true;
        auth.api_token = Some("fixture-bearer".into());
        let mut state = AppState::new(
            f.ctx.source.db.clone(),
            auth,
            f.directory.path().into(),
            f.directory.path().into(),
            f.directory.path().join("unused"),
        );
        state.delivery = Some(f.ctx.clone());
        let session = generate_session_id();
        let csrf = add_session(&state.sessions, session.clone());
        let cookie = format!("awg_session={session}");
        let app = super::super::build_router_state(state);
        for (bearer, csrf_header, expected) in [
            (None, None, "csrf_required"),
            (
                Some("wrong"),
                Some(csrf.as_str()),
                "authentication_required",
            ),
            (Some("fixture-bearer"), None, "ok"),
            (None, Some(csrf.as_str()), "ok"),
        ] {
            let c = crate::db::delivery::client(&f.ctx.source.db.pool, &f.client)
                .await
                .unwrap();
            let mut request = Request::builder()
                .method("POST")
                .uri("/api/admin/delivery/contact")
                .header("content-type", "application/json")
                .header("cookie", &cookie);
            if let Some(bearer) = bearer {
                request = request.header("authorization", format!("Bearer {bearer}"));
            }
            if let Some(csrf) = csrf_header {
                request = request.header("x-csrf-token", csrf);
            }
            let response=app.clone().oneshot(request.body(Body::from(json!({"client_id":f.client,"version":c.binding_version,"email":"edited@example.test"}).to_string())).unwrap()).await.unwrap();
            let value: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            if expected == "ok" {
                assert_eq!(value["ok"], true);
            } else {
                assert_eq!(value["error"], expected);
            }
        }
    }
    #[tokio::test]
    async fn delivery_settings_never_expose_password_or_allow_auth_disabled() {
        let mut f = Fixture::new().await;
        crate::delivery::tests::runtime_mut(&mut f.ctx)
            .settings
            .password = "fixture-secret-canary".into();
        for enabled in [true, false] {
            let mut auth = crate::auth::AuthConfig::disabled();
            auth.enabled = enabled;
            auth.api_token = Some("fixture".into());
            let mut state = AppState::new(
                f.ctx.source.db.clone(),
                auth,
                f.directory.path().into(),
                f.directory.path().into(),
                f.directory.path().join("unused"),
            );
            state.delivery = Some(f.ctx.clone());
            let app = super::super::build_router_state(state);
            let response = app
                .oneshot(
                    Request::builder()
                        .uri("/api/admin/delivery/settings")
                        .header("authorization", "Bearer fixture")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body =
                String::from_utf8(to_bytes(response.into_body(), 8192).await.unwrap().to_vec())
                    .unwrap();
            assert!(!body.contains("fixture-secret-canary"));
            assert!(!body.contains("password"));
            if !enabled {
                assert!(body.contains("authentication_required"));
            }
        }
    }
}
