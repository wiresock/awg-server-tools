use crate::delivery::{self, service::DeliveryContext, Format};
use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct PublicState {
    ctx: Arc<DeliveryContext>,
    limits: Arc<Mutex<Limits>>,
}
#[derive(Default)]
struct Limits {
    start: i64,
    total: u32,
    ips: HashMap<IpAddr, u32>,
}
const SESSION: &str = "__Secure-awg_delivery";
const BOOT: &str = "__Secure-awg_delivery_boot";
pub fn router(ctx: Arc<DeliveryContext>) -> Router {
    Router::new()
        .route("/delivery/", get(landing))
        .route("/delivery/app.js", get(script))
        .route("/delivery/redeem", post(redeem))
        .route("/delivery/export", post(export))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::map_response(|response: Response| async {
            secure(response)
        }))
        .with_state(PublicState {
            ctx,
            limits: Arc::new(Mutex::new(Limits::default())),
        })
}
pub(super) fn secure(mut response: Response) -> Response {
    for (key,value) in [("cache-control","no-store, no-cache, max-age=0"),("pragma","no-cache"),("referrer-policy","no-referrer"),("x-content-type-options","nosniff"),("content-security-policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src blob:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")] {
        response.headers_mut().insert(axum::http::HeaderName::from_static(key),axum::http::HeaderValue::from_static(value));
    }
    response
}
fn unavailable() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error":"Configuration unavailable"})),
    )
        .into_response()
}
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}
fn set_cookie(ctx: &DeliveryContext, name: &str, value: &str, age: i64) -> String {
    format!(
        "{name}={value}; Path={}; Max-Age={age}; HttpOnly; Secure; SameSite=Strict",
        ctx.runtime().settings.external_path()
    )
}
async fn landing(State(state): State<PublicState>) -> Response {
    if state.ctx.enabled().is_err() || state.ctx.runtime().settings.public_base.is_none() {
        return unavailable();
    }
    let boot = delivery::random_id();
    let mut response =
        Html(include_str!("delivery.html").replace("BOOTSTRAP_NONCE", &boot)).into_response();
    response.headers_mut().insert(
        "set-cookie",
        set_cookie(&state.ctx, BOOT, &boot, 600).parse().unwrap(),
    );
    response
}
async fn script() -> Response {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        include_str!("delivery.js"),
    )
        .into_response()
}
fn check(state: &PublicState, headers: &HeaderMap, address: Option<SocketAddr>) -> bool {
    if state.ctx.enabled().is_err() || state.ctx.runtime().settings.public_base.is_none() {
        return false;
    }
    // Forwarded headers are deliberately ignored. Proxy deployments share a
    // socket-IP bucket; an explicit trusted-proxy feature is not enabled in v1.
    let ip = address
        .map(|s| s.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    let mut limits = state.limits.lock().unwrap();
    let now = state.ctx.time();
    if now - limits.start >= 60 {
        limits.start = now;
        limits.total = 0;
        limits.ips.clear();
    }
    if limits.total >= 100 || limits.ips.get(&ip).copied().unwrap_or(0) >= 10 {
        return false;
    }
    limits.total += 1;
    *limits.ips.entry(ip).or_default() += 1;
    headers.get("origin").and_then(|v| v.to_str().ok())
        == Some(state.ctx.runtime().settings.origin().as_str())
        && headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.split(';').next() == Some("application/json"))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Redeem {
    token: String,
}
async fn redeem(
    State(state): State<PublicState>,
    address: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    payload: std::result::Result<Json<Redeem>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !check(&state, &headers, address.map(|a| a.0)) {
        return unavailable();
    }
    let nonce = headers
        .get("x-delivery-csrf")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if nonce.len() != 43 || !cookie(&headers, BOOT).is_some_and(|v| crate::auth::csrf_eq(nonce, v))
    {
        return unavailable();
    }
    let Ok(Json(payload)) = payload else {
        return unavailable();
    };
    match state.ctx.redeem(&payload.token).await {
        Ok(session) => {
            let mut response =
                Json(serde_json::json!({"csrf":session.csrf,"expires_at":session.expires_at}))
                    .into_response();
            response.headers_mut().insert(
                "set-cookie",
                set_cookie(
                    &state.ctx,
                    SESSION,
                    &session.cookie,
                    session.expires_at - state.ctx.time(),
                )
                .parse()
                .unwrap(),
            );
            response
        }
        Err(_) => unavailable(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    format: Format,
}
async fn export(
    State(state): State<PublicState>,
    address: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    payload: std::result::Result<Json<Export>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !check(&state, &headers, address.map(|a| a.0)) {
        return unavailable();
    }
    let Some(session) = cookie(&headers, SESSION) else {
        return unavailable();
    };
    let nonce = headers
        .get("x-delivery-csrf")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::auth::csrf_eq(nonce, &delivery::tokens::csrf(session)) {
        return unavailable();
    }
    let Ok(Json(payload)) = payload else {
        return unavailable();
    };
    match state.ctx.export(session, payload.format).await {
        Ok(bytes) => {
            let mut response = bytes.into_response();
            response.headers_mut().insert(
                "content-type",
                if payload.format == Format::Qr {
                    "image/svg+xml"
                } else {
                    "text/plain; charset=utf-8"
                }
                .parse()
                .unwrap(),
            );
            response.headers_mut().insert(
                "content-disposition",
                format!("attachment; filename=\"{}\"", payload.format.filename())
                    .parse()
                    .unwrap(),
            );
            response
        }
        Err(_) => unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{smtp::Submission, tests::Fixture, Mode};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    #[derive(Clone)]
    struct CapturedLogs(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for CapturedLogs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn delivery_public_exchange_never_logs_token_cookie_config_or_recipient() {
        use tracing::instrument::WithSubscriber;
        let f = Fixture::new().await;
        let logs = CapturedLogs(Arc::new(Mutex::new(Vec::new())));
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        async {
            tracing::info!("fixture logging enabled");
            let token = accepted(&f).await;
            // Match the supported startup invariant: enabled delivery requires
            // admin authentication, while these public requests have no login.
            let mut auth = crate::auth::AuthConfig::disabled();
            auth.enabled = true;
            let app = super::super::router_with_delivery(
                f.ctx.source.db.clone(),
                auth,
                f.directory.path().into(),
                f.directory.path().into(),
                f.directory.path().join("unused"),
                crate::managed_interface::InterfaceSelector::from_params(),
                "/private",
                f.ctx.clone(),
            )
            .unwrap();
            let (boot, nonce) = bootstrap(&app).await;
            let response = app
                .clone()
                .oneshot(post_request(
                    "/delivery/redeem",
                    serde_json::json!({"token":token}),
                    "https://download.example.test",
                    &boot,
                    &nonce,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let cookie = response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let body: serde_json::Value = serde_json::from_str(&text(response).await).unwrap();
            let csrf = body["csrf"].as_str().unwrap();
            let response = app
                .oneshot(post_request(
                    "/delivery/export",
                    serde_json::json!({"format":"conf"}),
                    "https://download.example.test",
                    &cookie,
                    csrf,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(text(response).await.contains("fixture-private"));
            let captured = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
            assert!(captured.contains("fixture logging enabled"));
            for secret in [
                &token,
                cookie.split_once('=').unwrap().1,
                &nonce,
                csrf,
                "fixture-private",
                "recipient@example.test",
            ] {
                assert!(
                    !captured.contains(secret),
                    "sensitive value must not enter logs"
                );
            }
        }
        .with_subscriber(subscriber)
        .await;
    }
    async fn text(response: Response) -> String {
        String::from_utf8(
            to_bytes(response.into_body(), 131072)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }
    async fn accepted(f: &Fixture) -> String {
        let id = f.queue(Mode::Link).await;
        let admitted = f.ctx.admit(&id).await.unwrap();
        f.ctx
            .complete(&admitted, Submission::Accepted)
            .await
            .unwrap();
        admitted
            .mail
            .body
            .split('#')
            .nth(1)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .into()
    }
    fn post_request(
        path: &str,
        body: serde_json::Value,
        origin: &str,
        cookie: &str,
        csrf: &str,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .header("origin", origin)
            .header("cookie", cookie)
            .header("x-delivery-csrf", csrf)
            .body(Body::from(body.to_string()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        ));
        request
    }
    async fn bootstrap(app: &Router) -> (String, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/delivery/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let nonce = cookie.split_once('=').unwrap().1.to_owned();
        (cookie, nonce)
    }
    #[tokio::test]
    async fn delivery_scanner_get_head_does_not_disclose_or_consume() {
        let f = Fixture::new().await;
        let token = accepted(&f).await;
        let app = router(f.ctx.clone());
        for method in ["GET", "HEAD"] {
            for path in ["/delivery/", "/delivery/redeem", "/delivery/export"] {
                let response = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    response.headers()["cache-control"],
                    "no-store, no-cache, max-age=0"
                );
                assert_eq!(response.headers()["referrer-policy"], "no-referrer");
                let body = text(response).await;
                assert!(!body.contains("fixture-private"));
                assert!(!body.contains(&token));
            }
        }
        assert!(f.ctx.redeem(&token).await.is_ok());
    }
    #[tokio::test]
    async fn delivery_route_redeem_exports_and_revocation_have_uniform_errors() {
        let f = Fixture::new().await;
        let token = accepted(&f).await;
        let app = router(f.ctx.clone());
        let (boot, nonce) = bootstrap(&app).await;
        let response = app
            .clone()
            .oneshot(post_request(
                "/delivery/redeem",
                serde_json::json!({"token":token}),
                "https://download.example.test",
                &boot,
                &nonce,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie_header = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(cookie_header.contains("Path=/share/delivery/"));
        assert!(cookie_header.contains("HttpOnly; Secure; SameSite=Strict"));
        assert!(!cookie_header.contains("Domain="));
        let session_cookie = cookie_header.split(';').next().unwrap();
        let value: serde_json::Value = serde_json::from_str(&text(response).await).unwrap();
        let csrf = value["csrf"].as_str().unwrap();
        for format in ["conf", "qr", "vpn-uri"] {
            let response = app
                .clone()
                .oneshot(post_request(
                    "/delivery/export",
                    serde_json::json!({"format":format}),
                    "https://download.example.test",
                    session_cookie,
                    csrf,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = text(response).await;
            assert!(match format {
                "conf" => body.contains("fixture-private"),
                "qr" => body.contains("<svg"),
                _ => body.starts_with("vpn://"),
            });
        }
        f.ctx.revoke(&f.client).await.unwrap();
        let revoked = app
            .clone()
            .oneshot(post_request(
                "/delivery/export",
                serde_json::json!({"format":"conf"}),
                "https://download.example.test",
                session_cookie,
                csrf,
            ))
            .await
            .unwrap();
        assert_eq!(revoked.status(), StatusCode::NOT_FOUND);
        let invalid = app
            .clone()
            .oneshot(post_request(
                "/delivery/redeem",
                serde_json::json!({"token":"invalid"}),
                "https://download.example.test",
                &boot,
                &nonce,
            ))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
        assert_eq!(text(revoked).await, text(invalid).await);
    }
    #[tokio::test]
    async fn delivery_origin_csrf_and_forwarded_headers_cannot_bypass_checks() {
        let f = Fixture::new().await;
        let token = accepted(&f).await;
        let app = router(f.ctx.clone());
        let (boot, nonce) = bootstrap(&app).await;
        for (origin, csrf) in [
            ("https://attacker.example", nonce.as_str()),
            ("https://download.example.test", "wrong"),
        ] {
            let mut request = post_request(
                "/delivery/redeem",
                serde_json::json!({"token":token}),
                origin,
                &boot,
                csrf,
            );
            request
                .headers_mut()
                .insert("host", "download.example.test".parse().unwrap());
            request.headers_mut().insert(
                "forwarded",
                "host=download.example.test;proto=https".parse().unwrap(),
            );
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                StatusCode::NOT_FOUND
            );
        }
        assert!(f.ctx.redeem(&token).await.is_ok());
    }
    #[tokio::test]
    async fn delivery_rate_limit_ignores_spoofed_forwarded_ip() {
        let f = Fixture::new().await;
        let app = router(f.ctx.clone());
        let (boot, nonce) = bootstrap(&app).await;
        for index in 0..10 {
            let mut request = post_request(
                "/delivery/redeem",
                serde_json::json!({"token":"invalid"}),
                "https://download.example.test",
                &boot,
                &nonce,
            );
            request.headers_mut().insert(
                "x-forwarded-for",
                format!("192.0.2.{index}").parse().unwrap(),
            );
            app.clone().oneshot(request).await.unwrap();
        }
        let token = accepted(&f).await;
        assert_eq!(
            app.clone()
                .oneshot(post_request(
                    "/delivery/redeem",
                    serde_json::json!({"token":token}),
                    "https://download.example.test",
                    &boot,
                    &nonce
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert!(
            f.ctx.redeem(&token).await.is_ok(),
            "rate limiting must occur before consumption"
        );
    }
    #[tokio::test]
    async fn delivery_public_subtree_does_not_expose_private_admin_prefix() {
        let f = Fixture::new().await;
        let mut auth = crate::auth::AuthConfig::disabled();
        auth.enabled = true;
        let mut state = super::super::AppState::new(
            f.ctx.source.db.clone(),
            auth,
            f.directory.path().into(),
            f.directory.path().into(),
            f.directory.path().join("unused.json"),
        )
        .with_base_path("/private".into());
        state.delivery = Some(f.ctx.clone());
        let app = super::super::build_router_state(state);
        for (path, status) in [
            ("/delivery/", StatusCode::OK),
            ("/delivery/api/peers", StatusCode::NOT_FOUND),
            ("/api/peers", StatusCode::NOT_FOUND),
            ("/private/api/peers", StatusCode::UNAUTHORIZED),
            ("/private/api/admin/delivery/jobs", StatusCode::UNAUTHORIZED),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                status,
                "{path}"
            );
        }
    }
}
#[tokio::test]
async fn delivery_admin_base_conflicts_return_configuration_error_without_panicking() {
    let f = crate::delivery::tests::Fixture::new().await;
    let build = |base| {
        crate::web::router_with_delivery(
            f.ctx.source.db.clone(),
            crate::auth::AuthConfig::disabled(),
            f.directory.path().into(),
            f.directory.path().into(),
            f.directory.path().join("unused"),
            crate::managed_interface::InterfaceSelector::from_params(),
            base,
            f.ctx.clone(),
        )
    };
    for base in [
        "/delivery",
        " /delivery ",
        "/delivery/",
        "/delivery/redeem",
        "/delivery/export",
        "/delivery/app.js",
        "/delivery/other",
        "/delivery//",
        "/delivery/../admin",
        "/%64elivery",
        "/delivery%2fexport",
        "/delivery\\export",
    ] {
        assert!(
            build(base).is_err(),
            "ambiguous/reserved base must fail: {base}"
        );
    }
    for base in ["", "/", "/private", "/private/delivery", "/delivery-admin"] {
        assert!(build(base).is_ok(), "supported base: {base}");
    }
}
