//! Signing in from a browser (`pandod server --login-listen`, ADR-031): OpenID Connect
//! providers such as Google, and links sent by email. A successful sign-in creates an ordinary
//! platform token, handed to the web console in the URL fragment as `#pando_session=…`.
//!
//! * OIDC: authorization code with PKCE (S256), `state` and `nonce`. The state is random, sent
//!   back to the browser in an HttpOnly cookie, and kept server-side only as a hash, with the
//!   nonce and verifier, for 10 minutes and one use. ID tokens are checked by
//!   [`OidcAuthenticator`] (signature from the issuer's keys, issuer, audience, lifetime), then
//!   for algorithm (RS256/ES256), nonce, `iat` and a verified email.
//! * Email: a single-use link, valid 15 minutes, stored as a BLAKE3 hash. Opening it shows a
//!   button, so mail scanners that fetch links don't use it up. Requests answer the same
//!   whether or not the address may sign in.
//! * A first sign-in creates a person's account if the signup policy allows; an identity is
//!   never linked to an existing account by matching email.

mod store;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail};
use axum::Router;
use axum::extract::{ConnectInfo, Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine as _;
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use serde::Deserialize;
use sha2::Digest as _;
use tokio::sync::OnceCell;

use crate::directory::TokenRec;
use crate::hosting::{Registry, now_ms};
use crate::oidc::{OidcAuthenticator, OidcConfig};

pub(crate) use store::SCHEMA;

const SESSION_DAYS: i64 = 30;
const STATE_TTL_MS: i64 = 10 * 60_000;
const EMAIL_TTL_MS: i64 = 15 * 60_000;
const COOKIE: &str = "pando_login";
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'";
const TURNSTILE: &str = "https://challenges.cloudflare.com";

/// Who may create an account by signing in. People who already have one can always sign in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Signup {
    /// Only addresses and `@domains` on the list (`pando admin signup allow`).
    Waitlist,
    Open,
    /// No new accounts.
    Closed,
}

/// Sign-in settings as given on the command line; secrets come from `secret(NAME)`.
pub struct Settings {
    /// Where people reach this server, e.g. `https://pando.example.com`.
    pub public_url: String,
    /// `ID=ISSUER_URL` per OpenID Connect provider.
    pub oidc: Vec<String>,
    /// `smtps://host:465` or `smtp://host:587?tls=required`; without it, no email links.
    pub smtp_url: Option<String>,
    pub mail_from: Option<String>,
    pub turnstile_site_key: Option<String>,
    pub signup: Signup,
    /// Logins sign-in never hands out (the site administrators).
    pub reserved: Vec<String>,
}

/// A secret from the environment: `NAME`, or the contents of the file `NAME_FILE`.
pub fn env_secret(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty()).or_else(|| {
        let path = std::env::var(format!("{name}_FILE")).ok()?;
        std::fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
    })
}

struct Provider {
    id: String,
    name: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    /// Discovered on first use and kept (keys refresh themselves).
    discovered: OnceCell<Discovered>,
}

struct Discovered {
    tokens: OidcAuthenticator,
    authorization_endpoint: String,
    token_endpoint: String,
}

struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

/// Simple token buckets: `burst` requests, refilled evenly over `per`.
// ponytail: per-process and not atomic between get and insert; a shared store if pandod scales out.
struct Buckets(quick_cache::sync::Cache<String, (Instant, f64)>);

impl Buckets {
    fn take(&self, key: String, burst: f64, per: Duration) -> bool {
        let now = Instant::now();
        let (at, left) = self.0.get(&key).unwrap_or((now, burst));
        let left = (left + now.duration_since(at).as_secs_f64() * burst / per.as_secs_f64()).min(burst);
        let ok = left >= 1.0;
        self.0.insert(key, (now, if ok { left - 1.0 } else { left }));
        ok
    }
}

pub struct Login {
    registry: Arc<Registry>,
    public_url: String,
    secure_cookie: bool,
    providers: Vec<Provider>,
    mailer: Option<Mailer>,
    turnstile: Option<(String, String)>,
    signup: Signup,
    reserved: Vec<String>,
    http: reqwest::Client,
    buckets: Buckets,
}

impl Login {
    pub fn new(s: Settings, registry: Arc<Registry>, secret: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let url =
            reqwest::Url::parse(&s.public_url).context("--public-url must be a URL like https://pando.example.com")?;
        let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if url.scheme() != "https" && !(url.scheme() == "http" && local) {
            bail!("--public-url must use https (http only for localhost)");
        }
        if url.path() != "/" || url.query().is_some() {
            bail!("--public-url is an origin, like https://pando.example.com, without a path");
        }
        let mut providers = Vec::new();
        for spec in &s.oidc {
            let (id, issuer) =
                spec.split_once('=').context("--oidc takes ID=ISSUER_URL, e.g. google=https://accounts.google.com")?;
            if id.is_empty() || !id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                bail!("--oidc provider id `{id}`: use lowercase letters, digits and `-`");
            }
            let env = format!("PANDO_OIDC_{}", id.to_ascii_uppercase().replace('-', "_"));
            let need = |what: &str| {
                secret(&format!("{env}_{what}"))
                    .with_context(|| format!("--oidc {id} needs {env}_{what} (or {env}_{what}_FILE)"))
            };
            providers.push(Provider {
                id: id.to_owned(),
                name: if id == "google" { "Google".to_owned() } else { id.to_owned() },
                issuer: issuer.trim_end_matches('/').to_owned(),
                client_id: need("CLIENT_ID")?,
                client_secret: need("CLIENT_SECRET")?,
                discovered: OnceCell::new(),
            });
        }
        let mailer = match (&s.smtp_url, &s.mail_from) {
            (Some(smtp), Some(from)) => {
                let mut b = AsyncSmtpTransport::<Tokio1Executor>::from_url(smtp).context("--smtp-url")?;
                if let Some(user) = secret("PANDO_SMTP_USERNAME") {
                    let pass =
                        secret("PANDO_SMTP_PASSWORD").context("PANDO_SMTP_USERNAME needs PANDO_SMTP_PASSWORD")?;
                    b = b.credentials(lettre::transport::smtp::authentication::Credentials::new(user, pass));
                }
                Some(Mailer {
                    transport: b.timeout(Some(Duration::from_secs(20))).build(),
                    from: from.parse().context("--mail-from must be an address like Pando <login@example.com>")?,
                })
            }
            (None, None) => None,
            _ => bail!("email sign-in needs both --smtp-url and --mail-from"),
        };
        let turnstile = match (s.turnstile_site_key, secret("PANDO_TURNSTILE_SECRET")) {
            (Some(k), Some(sec)) => Some((k, sec)),
            (None, None) => None,
            _ => bail!("Turnstile needs both --turnstile-site-key and PANDO_TURNSTILE_SECRET"),
        };
        if providers.is_empty() && mailer.is_none() {
            bail!("--login-listen needs a way to sign in: --oidc, or --smtp-url and --mail-from");
        }
        Ok(Self {
            registry,
            public_url: s.public_url.trim_end_matches('/').to_owned(),
            secure_cookie: url.scheme() == "https",
            providers,
            mailer,
            turnstile,
            signup: s.signup,
            reserved: s.reserved,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            buckets: Buckets(quick_cache::sync::Cache::new(100_000)),
        })
    }

    fn provider(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.id == id)
    }

    async fn discovered<'a>(&self, p: &'a Provider) -> anyhow::Result<&'a Discovered> {
        p.discovered
            .get_or_try_init(|| async {
                let url = format!("{}/.well-known/openid-configuration", p.issuer);
                let meta: serde_json::Value = self.http.get(&url).send().await?.error_for_status()?.json().await?;
                let endpoint =
                    |k: &str| meta[k].as_str().map(str::to_owned).with_context(|| format!("{url} has no {k}"));
                let (authorization_endpoint, token_endpoint) =
                    (endpoint("authorization_endpoint")?, endpoint("token_endpoint")?);
                // ponytail: this fetches the discovery document a second time, once per provider.
                let tokens = OidcAuthenticator::discover(OidcConfig {
                    issuer: p.issuer.clone(),
                    audience: p.client_id.clone(),
                    principal_claim: "sub".into(),
                    ..Default::default()
                })
                .await?;
                Ok::<_, anyhow::Error>(Discovered { tokens, authorization_endpoint, token_endpoint })
            })
            .await
    }

    /// Whether a new account may be created for `email`.
    fn may_sign_up(&self, email: &str) -> anyhow::Result<bool> {
        Ok(match self.signup {
            Signup::Open => true,
            Signup::Closed => false,
            Signup::Waitlist => self.registry.signup_allowed(email)?,
        })
    }

    /// Signs `subject` in (creating the account if allowed) and sends the browser on with a
    /// fresh session token.
    fn finish(&self, provider: &str, subject: &str, email: Option<&str>, next: &str) -> Response {
        let login = match self.registry.identity_login(provider, subject) {
            Ok(Some(login)) => login,
            Ok(None) => {
                let Some(email) = email else {
                    return fail(StatusCode::FORBIDDEN, "Your account needs a verified email address to sign up here.");
                };
                match self.may_sign_up(email) {
                    Ok(true) => match self.registry.create_person(provider, subject, email, &self.reserved) {
                        Ok(login) => {
                            tracing::info!(target: crate::telemetry::AUDIT, kind = "sign_up", principal = %login, target = provider);
                            login
                        }
                        Err(e) => return broken(e),
                    },
                    Ok(false) => {
                        return fail(
                            StatusCode::FORBIDDEN,
                            &format!(
                                "{email} can't create an account on this server yet. Ask its administrators for an invitation."
                            ),
                        );
                    }
                    Err(e) => return broken(e),
                }
            }
            Err(e) => return broken(e),
        };
        let now = now_ms();
        let made = self.registry.create_token(TokenRec {
            id: String::new(),
            account: login.clone(),
            name: "browser session".into(),
            acts_as: login.clone(),
            repositories: vec![],
            max_role: pando_proto::Role::Admin,
            created_at_ms: now,
            expires_at_ms: now + SESSION_DAYS * 86_400_000,
            last_used_at_ms: 0,
        });
        match made {
            Ok((t, secret)) => {
                tracing::info!(target: crate::telemetry::AUDIT, kind = "sign_in", principal = %login, target = %format!("{provider} token {}", t.id));
                redirect(&format!("{}{next}#pando_session={secret}", self.public_url))
            }
            Err(e) => broken(e),
        }
    }
}

/// A same-origin path to return to after signing in: `/` and below, never `//host`, a scheme
/// or a backslash (which browsers treat as `/`).
fn safe_next(next: Option<&str>) -> Option<String> {
    let n = next.unwrap_or("/");
    let ok = n.starts_with('/')
        && !n.starts_with("//")
        && n.len() <= 1024
        && !n.contains('#')
        && n.bytes().all(|b| b.is_ascii_graphic() && b != b'\\');
    ok.then(|| n.to_owned())
}

/// A lowercased email address, if `s` looks like one.
fn normal_email(s: &str) -> Option<String> {
    let e = s.trim().to_ascii_lowercase();
    let (local, domain) = e.split_once('@')?;
    let ok = !local.is_empty()
        && e.len() <= 254
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && local.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b'@' | b'<' | b'>' | b'"' | b'\\' | b',' | b';'));
    ok.then_some(e)
}

/// A waitlist entry: an email address or `@domain`, lowercased.
pub fn signup_entry(s: &str) -> Option<String> {
    match s.trim().strip_prefix('@') {
        Some(domain) => normal_email(&format!("x@{domain}")).map(|e| e[1..].to_owned()),
        None => normal_email(s),
    }
}

fn random_hex() -> anyhow::Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).context("reading random bytes")?;
    Ok(hex::encode(b))
}

fn hash(s: &str) -> blake3::Hash {
    blake3::hash(s.as_bytes())
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// A small page; `body` is HTML whose dynamic parts are already escaped.
fn page(status: StatusCode, title: &str, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <title>{t}</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem}}\
         input,button{{font:inherit;padding:.5rem;margin:.25rem 0;width:100%;box-sizing:border-box}}</style>\
         <main><h1>{t}</h1>{body}</main>",
        t = esc(title)
    );
    (status, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

fn fail(status: StatusCode, message: &str) -> Response {
    page(status, "Sign-in failed", &format!("<p>{}</p><p><a href=\"/\">Back</a></p>", esc(message)))
}

/// An internal error: logged, and shown to the person only as "something went wrong".
fn broken(e: impl std::fmt::Display) -> Response {
    tracing::error!(error = %e, "sign-in");
    fail(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong on our side. Please try again.")
}

fn redirect(to: &str) -> Response {
    match HeaderValue::from_str(to) {
        Ok(v) => (StatusCode::SEE_OTHER, [(header::LOCATION, v)]).into_response(),
        Err(e) => broken(e),
    }
}

/// Headers every answer carries; pages that need more set their own CSP.
async fn harden(mut r: Response) -> Response {
    let h = r.headers_mut();
    h.entry(header::CONTENT_SECURITY_POLICY).or_insert(HeaderValue::from_static(CSP));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    r
}

pub fn router(login: Arc<Login>) -> Router {
    Router::new()
        .route("/login/providers", get(providers))
        .route("/login/oidc/{id}", get(oidc_start))
        .route("/login/oidc/{id}/callback", get(oidc_callback))
        .route("/login/email", get(email_form).post(email_request))
        .route("/login/email/verify", get(email_confirm).post(email_verify))
        .layer(axum::middleware::map_response(harden))
        .with_state(login)
}

/// Serves the sign-in pages until the process ends.
pub async fn serve(listener: tokio::net::TcpListener, login: Arc<Login>) -> anyhow::Result<()> {
    axum::serve(listener, router(login).into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

async fn providers(State(l): State<Arc<Login>>) -> Response {
    let list: Vec<_> = l
        .providers
        .iter()
        .map(|p| serde_json::json!({ "id": p.id, "name": p.name, "url": format!("/login/oidc/{}", p.id) }))
        .collect();
    let mut body = serde_json::json!({ "providers": list, "email": l.mailer.is_some() });
    if let Some((key, _)) = &l.turnstile {
        body["turnstile_site_key"] = key.clone().into();
    }
    axum::Json(body).into_response()
}

#[derive(Deserialize)]
struct NextQuery {
    next: Option<String>,
}

async fn oidc_start(State(l): State<Arc<Login>>, Path(id): Path<String>, Query(q): Query<NextQuery>) -> Response {
    let Some(p) = l.provider(&id) else { return fail(StatusCode::NOT_FOUND, "There is no such way to sign in here.") };
    let Some(next) = safe_next(q.next.as_deref()) else {
        return fail(StatusCode::BAD_REQUEST, "That sign-in link is not valid.");
    };
    let d = match l.discovered(p).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(provider = %p.id, error = %e, "OIDC discovery failed");
            return fail(StatusCode::BAD_GATEWAY, &format!("{} is not answering. Please try again later.", p.name));
        }
    };
    let (state, nonce, verifier) = match (random_hex(), random_hex(), random_hex()) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return broken("no randomness"),
    };
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
    if let Err(e) =
        l.registry.put_login_state(hash(&state).as_bytes(), &p.id, &nonce, &verifier, &next, now_ms() + STATE_TTL_MS)
    {
        return broken(e);
    }
    let mut url = match reqwest::Url::parse(&d.authorization_endpoint) {
        Ok(u) => u,
        Err(e) => return broken(e),
    };
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &p.client_id)
        .append_pair("redirect_uri", &format!("{}/login/oidc/{}/callback", l.public_url, p.id))
        .append_pair("scope", "openid email profile")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let mut r = redirect(url.as_str());
    let secure = if l.secure_cookie { "; Secure" } else { "" };
    let cookie = format!("{COOKIE}={state}; Path=/login; Max-Age=600; HttpOnly; SameSite=Lax{secure}");
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    r
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(name)?.strip_prefix('='))
}

async fn oidc_callback(
    State(l): State<Arc<Login>>,
    Path(id): Path<String>,
    Query(q): Query<Callback>,
    headers: HeaderMap,
) -> Response {
    let mut r = oidc_finish(&l, &id, q, &headers).await;
    // The sign-in is over either way: drop the cookie.
    let secure = if l.secure_cookie { "; Secure" } else { "" };
    if let Ok(v) = HeaderValue::from_str(&format!("{COOKIE}=; Path=/login; Max-Age=0; HttpOnly; SameSite=Lax{secure}"))
    {
        r.headers_mut().insert(header::SET_COOKIE, v);
    }
    r
}

async fn oidc_finish(l: &Login, id: &str, q: Callback, headers: &HeaderMap) -> Response {
    let refused = |why: &str| {
        tracing::info!(provider = %id, why, "sign-in refused");
        fail(StatusCode::BAD_REQUEST, "Sign-in could not be completed. Please start again.")
    };
    let Some(p) = l.provider(id) else { return fail(StatusCode::NOT_FOUND, "There is no such way to sign in here.") };
    if q.error.is_some() {
        return refused("the provider returned an error");
    }
    let (Some(code), Some(state)) = (q.code, q.state) else { return refused("no code or state") };
    // The state must come back to the browser that started the sign-in (hashes compare in
    // constant time).
    if cookie(headers, COOKIE).map(hash) != Some(hash(&state)) {
        return refused("state does not match the cookie");
    }
    let (nonce, verifier, next) = match l.registry.take_login_state(hash(&state).as_bytes(), &p.id) {
        Ok(Some(s)) => s,
        Ok(None) => return refused("unknown, used or expired state"),
        Err(e) => return broken(e),
    };
    let d = match l.discovered(p).await {
        Ok(d) => d,
        Err(e) => return broken(e),
    };
    let redirect_uri = format!("{}/login/oidc/{}/callback", l.public_url, p.id);
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", p.client_id.as_str()),
        ("client_secret", p.client_secret.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    let answer = async {
        l.http.post(&d.token_endpoint).form(&form).send().await?.error_for_status()?.json::<serde_json::Value>().await
    };
    let id_token = match answer.await {
        Ok(v) => match v["id_token"].as_str() {
            Some(t) => t.to_owned(),
            None => return refused("no id_token from the token endpoint"),
        },
        Err(e) => {
            tracing::warn!(provider = %p.id, error = %e, "OIDC token exchange failed");
            return refused("token exchange failed");
        }
    };
    match jsonwebtoken::decode_header(&id_token) {
        Ok(h) if matches!(h.alg, jsonwebtoken::Algorithm::RS256 | jsonwebtoken::Algorithm::ES256) => {}
        _ => return refused("ID token algorithm"),
    }
    let claims = match d.tokens.claims(&id_token) {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(provider = %p.id, error = %e.message(), "ID token rejected");
            return refused("ID token rejected");
        }
    };
    if claims["nonce"].as_str().map(hash) != Some(hash(&nonce)) {
        return refused("nonce mismatch");
    }
    if !claims["iat"].as_i64().is_some_and(|iat| iat <= now_ms() / 1000 + 60) {
        return refused("missing or future iat");
    }
    let Some(subject) = claims["sub"].as_str().filter(|s| !s.is_empty() && s.len() <= 255) else {
        return refused("no sub");
    };
    let email = (claims["email_verified"] == serde_json::Value::Bool(true))
        .then(|| claims["email"].as_str().and_then(normal_email))
        .flatten();
    l.finish(&p.id, subject, email.as_deref(), &next)
}

async fn email_form(State(l): State<Arc<Login>>, Query(q): Query<NextQuery>) -> Response {
    if l.mailer.is_none() {
        return fail(StatusCode::NOT_FOUND, "Email sign-in is not set up on this server.");
    }
    let next = esc(&safe_next(q.next.as_deref()).unwrap_or_else(|| "/".into()));
    let widget = match &l.turnstile {
        Some((key, _)) => format!(
            "<script src=\"{TURNSTILE}/turnstile/v0/api.js\" async defer></script><div class=\"cf-turnstile\" data-sitekey=\"{}\"></div>",
            esc(key)
        ),
        None => String::new(),
    };
    let mut r = page(
        StatusCode::OK,
        "Sign in with email",
        &format!(
            "<form method=post action=\"/login/email\"><label>Email address<input type=email name=email required autocomplete=email></label>\
             <input type=hidden name=next value=\"{next}\">{widget}<button>Send me a sign-in link</button></form>"
        ),
    );
    if l.turnstile.is_some() {
        let csp = format!("{CSP}; script-src {TURNSTILE}; frame-src {TURNSTILE}; connect-src {TURNSTILE}");
        if let Ok(v) = HeaderValue::from_str(&csp) {
            r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, v);
        }
    }
    r
}

#[derive(Deserialize)]
struct EmailRequest {
    email: String,
    next: Option<String>,
    #[serde(rename = "cf-turnstile-response")]
    turnstile: Option<String>,
}

/// The client's address: the connection's, or, behind a proxy on the same machine (Caddy), the
/// last `X-Forwarded-For` entry, which the proxy wrote.
fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> String {
    let forwarded = || headers.get("x-forwarded-for")?.to_str().ok()?.rsplit(',').next().map(|s| s.trim().to_owned());
    if peer.ip().is_loopback() { forwarded().unwrap_or_else(|| peer.ip().to_string()) } else { peer.ip().to_string() }
}

async fn email_request(
    State(l): State<Arc<Login>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<EmailRequest>,
) -> Response {
    if l.mailer.is_none() {
        return fail(StatusCode::NOT_FOUND, "Email sign-in is not set up on this server.");
    }
    let ip = client_ip(peer, &headers);
    if !l.buckets.take(format!("ip:{ip}"), 10.0, Duration::from_secs(600)) {
        return fail(StatusCode::TOO_MANY_REQUESTS, "Too many requests. Please wait a few minutes and try again.");
    }
    if let Some((_, secret)) = &l.turnstile {
        let form = [
            ("secret", secret.as_str()),
            ("response", f.turnstile.as_deref().unwrap_or("")),
            ("remoteip", ip.as_str()),
        ];
        let check = async {
            l.http
                .post(format!("{TURNSTILE}/turnstile/v0/siteverify"))
                .form(&form)
                .send()
                .await?
                .json::<serde_json::Value>()
                .await
        };
        if !check.await.is_ok_and(|v| v["success"] == serde_json::Value::Bool(true)) {
            return fail(
                StatusCode::BAD_REQUEST,
                "We couldn't check that you're a person. Please go back and try again.",
            );
        }
    }
    let Some(email) = normal_email(&f.email) else {
        return fail(StatusCode::BAD_REQUEST, "That doesn't look like an email address.");
    };
    let Some(next) = safe_next(f.next.as_deref()) else {
        return fail(StatusCode::BAD_REQUEST, "That sign-in link is not valid.");
    };
    // Whether a link is sent is decided off the request path, so the answer (and its timing)
    // is the same for every address.
    tokio::spawn(async move {
        if let Err(e) = send_link(&l, &email, &next).await {
            tracing::warn!(error = %e, "sending a sign-in link");
        }
    });
    page(
        StatusCode::OK,
        "Check your email",
        "<p>If that address can sign in here, a link is on its way. It works once, within 15 minutes.</p>",
    )
}

async fn send_link(l: &Login, email: &str, next: &str) -> anyhow::Result<()> {
    if !l.buckets.take(format!("to:{email}"), 3.0, Duration::from_secs(900)) {
        return Ok(());
    }
    let known = l.registry.identity_login("email", email)?.is_some();
    if !known && !l.may_sign_up(email)? {
        return Ok(());
    }
    let Some(m) = &l.mailer else { return Ok(()) };
    let token = random_hex()?;
    l.registry.put_email_login(hash(&token).as_bytes(), email, next, now_ms() + EMAIL_TTL_MS)?;
    let link = format!("{}/login/email/verify?token={token}", l.public_url);
    let msg = lettre::Message::builder()
        .from(m.from.clone())
        .to(email.parse()?)
        .subject("Your sign-in link")
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body(format!(
            "Open this link to sign in to {}:\n\n{link}\n\nIt works once, within 15 minutes. If you didn't ask for it, ignore this email.\n",
            l.public_url
        ))?;
    m.transport.send(msg).await?;
    Ok(())
}

#[derive(Deserialize)]
struct TokenForm {
    token: Option<String>,
}

async fn email_confirm(Query(q): Query<TokenForm>) -> Response {
    let token = q.token.unwrap_or_default();
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return fail(StatusCode::BAD_REQUEST, "That sign-in link is not valid.");
    }
    page(
        StatusCode::OK,
        "Sign in",
        &format!(
            "<form method=post action=\"/login/email/verify\"><input type=hidden name=token value=\"{}\"><button>Sign in</button></form>",
            esc(&token)
        ),
    )
}

async fn email_verify(State(l): State<Arc<Login>>, Form(f): Form<TokenForm>) -> Response {
    let token = f.token.unwrap_or_default();
    match l.registry.take_email_login(hash(&token).as_bytes()) {
        Ok(Some((email, next))) => l.finish("email", &email, Some(&email), &next),
        Ok(None) => fail(StatusCode::BAD_REQUEST, "This link has expired or was already used. Ask for a new one."),
        Err(e) => broken(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_paths_stay_on_this_site() {
        for ok in [None, Some("/"), Some("/acme/app?tab=1")] {
            assert!(safe_next(ok).is_some(), "{ok:?}");
        }
        for bad in ["//evil.com", "https://evil.com", "/\\evil.com", "evil", "/a#b", "/a b", "/\u{e9}"] {
            assert!(safe_next(Some(bad)).is_none(), "{bad}");
        }
    }

    #[test]
    fn emails_and_waitlist_entries() {
        assert_eq!(normal_email(" Mira@Example.COM ").as_deref(), Some("mira@example.com"));
        for bad in ["mira", "@example.com", "mira@example", "a@b@c.com", "a b@c.com", "a@-.com."] {
            assert!(normal_email(bad).is_none(), "{bad}");
        }
        assert_eq!(signup_entry("@Example.com").as_deref(), Some("@example.com"));
        assert_eq!(signup_entry("mira@example.com").as_deref(), Some("mira@example.com"));
        assert!(signup_entry("@example").is_none());
        assert_eq!(esc("<a href=\"x\">'&"), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;");
    }
}
