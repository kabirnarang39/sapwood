//! Browser sign-in against a mock OpenID Connect issuer and a mail sink: the whole flow ends in a
//! working platform token, and every forged or replayed step is refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Form, State};
use axum::routing::{get, post};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use pando_adapters::flags::SpecFlags;
use pando_core::acl::{AccessPolicy, AllowAllPolicy};
use pando_core::ports::NoChecks;
use pando_proto::platform_client::PlatformClient;
use pando_proto::{Empty, SetSignupAllowRequest};
use pando_server::hosting::{BuildRoutes, Hosting, Registry, RepoServices, Templates, now_ms};
use pando_server::login::{Login, Settings, Signup};
use pando_server::permissions::Access;
use pando_server::{ServeOptions, authority_routes, config, serve};
use serde_json::{Value, json};
use sha2::Digest;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const KEY: &[u8] = include_bytes!("fixtures/test-oidc-key.pem");
const JWKS: &str = include_str!("fixtures/test-oidc-jwks.json");
const CLIENT: &str = "pando-test-client";

#[derive(Default)]
struct Idp {
    issuer: String,
    id_token: Mutex<String>,
    form: Mutex<HashMap<String, String>>,
}

async fn idp() -> Arc<Idp> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp = Arc::new(Idp { issuer: format!("http://{}", listener.local_addr().unwrap()), ..Default::default() });
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|State(i): State<Arc<Idp>>| async move {
                axum::Json(json!({
                    "issuer": i.issuer,
                    "authorization_endpoint": format!("{}/authorize", i.issuer),
                    "token_endpoint": format!("{}/token", i.issuer),
                    "jwks_uri": format!("{}/jwks", i.issuer),
                }))
            }),
        )
        .route("/jwks", get(|| async { ([("content-type", "application/json")], JWKS) }))
        .route(
            "/token",
            post(|State(i): State<Arc<Idp>>, Form(f): Form<HashMap<String, String>>| async move {
                *i.form.lock().unwrap() = f;
                axum::Json(json!({ "id_token": *i.id_token.lock().unwrap(), "token_type": "Bearer" }))
            }),
        )
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });
    idp
}

/// A tiny SMTP server that keeps every message it is given.
async fn smtp_sink() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("smtp://{}", listener.local_addr().unwrap());
    let mail = Arc::new(Mutex::new(Vec::new()));
    let keep = mail.clone();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let keep = keep.clone();
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut lines = BufReader::new(r).lines();
                w.write_all(b"220 sink\r\n").await.unwrap();
                while let Ok(Some(line)) = lines.next_line().await {
                    let verb = line.get(..4).unwrap_or("").to_ascii_uppercase();
                    let answer: &[u8] = match verb.as_str() {
                        "DATA" => {
                            w.write_all(b"354 go on\r\n").await.unwrap();
                            let mut body = String::new();
                            while let Ok(Some(l)) = lines.next_line().await {
                                if l == "." {
                                    break;
                                }
                                body.push_str(&l);
                                body.push('\n');
                            }
                            keep.lock().unwrap().push(body);
                            b"250 kept\r\n"
                        }
                        "QUIT" => b"221 bye\r\n",
                        _ => b"250 ok\r\n",
                    };
                    w.write_all(answer).await.unwrap();
                    if verb == "QUIT" {
                        break;
                    }
                }
            });
        }
    });
    (url, mail)
}

struct World {
    idp: Arc<Idp>,
    login: String,
    grpc: String,
    registry: Arc<Registry>,
    mail: Arc<Mutex<Vec<String>>>,
    http: reqwest::Client,
    _dir: tempfile::TempDir,
}

async fn world() -> World {
    let idp = idp().await;
    let (smtp, mail) = smtp_sink().await;
    let registry = Arc::new(Registry::open("memory").unwrap());
    registry.set_signup_entry("mira@a.example", true).unwrap();
    registry.set_signup_entry("@corp.example", true).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let login_url = format!("http://{}", listener.local_addr().unwrap());
    let settings = Settings {
        public_url: login_url.clone(),
        oidc: vec![format!("mock={}", idp.issuer)],
        smtp_url: Some(smtp),
        mail_from: Some("Pando <login@pando.example>".into()),
        turnstile_site_key: None,
        signup: Signup::Waitlist,
        reserved: vec!["root".into()],
    };
    let env: HashMap<&str, &str> =
        [("PANDO_OIDC_MOCK_CLIENT_ID", CLIENT), ("PANDO_OIDC_MOCK_CLIENT_SECRET", "test-secret")].into();
    let login = Login::new(settings, registry.clone(), &|k| env.get(k).map(|v| v.to_string())).unwrap();
    tokio::spawn(pando_server::login::serve(listener, Arc::new(login)));

    // The platform server that accepts the tokens sign-in hands out.
    let dir = tempfile::tempdir().unwrap();
    let access = Arc::new(Access { open: false, admins: vec!["root".into()] });
    let build: BuildRoutes = Arc::new(move |_, repo| {
        let policy: Arc<dyn AccessPolicy> = Arc::new(AllowAllPolicy);
        RepoServices {
            routes: authority_routes(repo, Arc::new(SpecFlags::all_on()), policy, Arc::new(NoChecks)),
            review_land: None,
        }
    });
    let templates = Templates {
        metadata: format!("sqlite://{}/repos/{{repo}}.db", dir.path().display()),
        objects: "metadata".into(),
    };
    let hosting = Hosting::new(templates, registry.clone(), build, access).unwrap();
    let default = config::open_repo("memory", "metadata").await.unwrap();
    let routes = authority_routes(default, Arc::new(SpecFlags::all_on()), Arc::new(AllowAllPolicy), Arc::new(NoChecks));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let grpc = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(serve(
        listener,
        routes,
        Arc::new(pando_server::permissions::NoOtherAuth),
        ServeOptions { hosting: Some(Arc::new(hosting)), ..Default::default() },
        std::future::pending(),
    ));
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
    World { idp, login: login_url, grpc, registry, mail, http, _dir: dir }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn sign(claims: &Value, kid: &str) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(kid.into());
    encode(&h, claims, &EncodingKey::from_rsa_pem(KEY).unwrap()).unwrap()
}

fn location(r: &reqwest::Response) -> String {
    r.headers()["location"].to_str().unwrap().to_owned()
}

/// A started sign-in: the state, nonce and PKCE challenge sent to the issuer, and the cookie.
struct Started {
    state: String,
    nonce: String,
    challenge: String,
    cookie: String,
}

impl World {
    async fn start(&self, next: &str) -> Started {
        let r = self.http.get(format!("{}/login/oidc/mock?next={next}", self.login)).send().await.unwrap();
        assert_eq!(r.status(), 303);
        let cookie = r.headers()["set-cookie"].to_str().unwrap().to_owned();
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax") && cookie.contains("Path=/login"));
        let to = reqwest::Url::parse(&location(&r)).unwrap();
        assert!(to.as_str().starts_with(&format!("{}/authorize?", self.idp.issuer)));
        let q: HashMap<String, String> = to.query_pairs().into_owned().collect();
        assert_eq!(q["client_id"], CLIENT);
        assert_eq!(q["redirect_uri"], format!("{}/login/oidc/mock/callback", self.login));
        assert_eq!(q["code_challenge_method"], "S256");
        Started {
            state: q["state"].clone(),
            nonce: q["nonce"].clone(),
            challenge: q["code_challenge"].clone(),
            cookie: cookie.split(';').next().unwrap().to_owned(),
        }
    }

    fn claims(&self, s: &Started, sub: &str, email: &str) -> Value {
        json!({
            "iss": self.idp.issuer, "aud": CLIENT, "sub": sub, "email": email, "email_verified": true,
            "nonce": s.nonce, "iat": now(), "exp": now() + 300,
        })
    }

    async fn callback(&self, s: &Started, id_token: &str) -> reqwest::Response {
        *self.idp.id_token.lock().unwrap() = id_token.to_owned();
        self.http
            .get(format!("{}/login/oidc/mock/callback?code=c0de&state={}", self.login, s.state))
            .header("cookie", &s.cookie)
            .send()
            .await
            .unwrap()
    }

    /// Signs in through the issuer with `claims` adjusted by `change`; the session token, or
    /// the refusal's status.
    async fn oidc(&self, sub: &str, email: &str, change: impl FnOnce(&mut Value)) -> Result<String, u16> {
        let s = self.start("/").await;
        let mut c = self.claims(&s, sub, email);
        change(&mut c);
        let r = self.callback(&s, &sign(&c, "test-key-1")).await;
        session(r).await
    }

    async fn viewer(&self, token: &str) -> Result<String, tonic::Status> {
        let mut p = PlatformClient::connect(self.grpc.clone()).await.unwrap();
        let mut req = tonic::Request::new(Empty {});
        req.metadata_mut().insert("authorization", format!("Bearer {token}").parse().unwrap());
        Ok(p.viewer(req).await?.into_inner().account.unwrap().login)
    }

    async fn wait_for_mail(&self, n: usize) -> Vec<String> {
        for _ in 0..100 {
            if self.mail.lock().unwrap().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        self.mail.lock().unwrap().clone()
    }

    async fn ask_for_link(&self, email: &str) -> (u16, String) {
        let r = self.http.post(format!("{}/login/email", self.login)).form(&[("email", email)]).send().await.unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }
}

async fn session(r: reqwest::Response) -> Result<String, u16> {
    if r.status() != 303 {
        return Err(r.status().as_u16());
    }
    let to = location(&r);
    Ok(to.split_once("#pando_session=").expect("token in the fragment").1.to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn oidc_sign_in_creates_an_account_and_a_working_session() {
    let w = world().await;
    let s = w.start("/acme/app").await;
    let r = w.callback(&s, &sign(&w.claims(&s, "g-1", "Mira@A.example"), "test-key-1")).await;
    assert_eq!(r.status(), 303);
    assert_eq!(r.headers()["referrer-policy"], "no-referrer");
    let to = location(&r);
    assert!(to.starts_with(&format!("{}/acme/app#pando_session=pando_", w.login)), "{to}");
    let token = session(r).await.unwrap();

    // PKCE: the verifier sent to the token endpoint hashes to the challenge.
    let form = w.idp.form.lock().unwrap().clone();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    assert_eq!(b64.encode(sha2::Sha256::digest(form["code_verifier"].as_bytes())), s.challenge);
    assert_eq!((form["code"].as_str(), form["client_id"].as_str()), ("c0de", CLIENT));

    assert_eq!(w.viewer(&token).await.unwrap(), "mira");
    let t = &w.registry.tokens("mira").unwrap()[0];
    assert_eq!(t.name, "browser session");
    assert_eq!(t.max_role, pando_proto::Role::Admin);
    assert!(t.repositories.is_empty());
    assert!((t.expires_at_ms - now_ms() - 30 * 86_400_000).abs() < 60_000);

    // The state is used up: replaying the callback fails.
    assert_eq!(
        session(w.callback(&s, &sign(&w.claims(&s, "g-1", "mira@a.example"), "test-key-1")).await).await,
        Err(400)
    );

    // Signing in again reaches the same account, whatever the email says now.
    let again = w.oidc("g-1", "renamed@else.example", |_| {}).await.unwrap();
    assert_eq!(w.viewer(&again).await.unwrap(), "mira");
}

#[tokio::test(flavor = "multi_thread")]
async fn forged_or_mismatched_id_tokens_are_refused() {
    let w = world().await;
    let refused = |r: Result<String, u16>| assert_eq!(r, Err(400));
    refused(w.oidc("g-2", "mira@a.example", |c| c["nonce"] = json!("another")).await);
    refused(w.oidc("g-2", "mira@a.example", |c| c["aud"] = json!("someone-else")).await);
    refused(w.oidc("g-2", "mira@a.example", |c| c["iss"] = json!("https://evil.example")).await);
    refused(w.oidc("g-2", "mira@a.example", |c| c["exp"] = json!(now() - 3600)).await);
    refused(w.oidc("g-2", "mira@a.example", |c| c["iat"] = json!(now() + 3600)).await);
    refused(
        w.oidc("g-2", "mira@a.example", |c| {
            c.as_object_mut().unwrap().remove("nonce");
        })
        .await,
    );

    // An unverified email can't open an account.
    assert_eq!(w.oidc("g-2", "mira@a.example", |c| c["email_verified"] = json!(false)).await, Err(403));

    // Unknown signing key, and an unsigned token.
    let s = w.start("/").await;
    refused(session(w.callback(&s, &sign(&w.claims(&s, "g-2", "mira@a.example"), "other-key")).await).await);
    let s = w.start("/").await;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let none = format!(
        "{}.{}.",
        b64.encode(r#"{"alg":"none","kid":"test-key-1"}"#),
        b64.encode(w.claims(&s, "g-2", "mira@a.example").to_string())
    );
    refused(session(w.callback(&s, &none).await).await);

    // A callback without the browser's cookie, or with another sign-in's, is refused.
    let s = w.start("/").await;
    let other = w.start("/").await;
    let good = sign(&w.claims(&s, "g-2", "mira@a.example"), "test-key-1");
    let forged = Started { cookie: other.cookie.clone(), ..s };
    refused(session(w.callback(&forged, &good).await).await);
    let none = Started { cookie: "x=y".into(), ..other };
    refused(session(w.callback(&none, &good).await).await);
    assert!(w.registry.identity_login("mock", "g-2").unwrap().is_none(), "nothing was created");

    // Only same-site paths are followed after signing in.
    for next in ["//evil.com", "https://evil.com", "/%5Cevil.com", "evil"] {
        let r = w.http.get(format!("{}/login/oidc/mock?next={next}", w.login)).send().await.unwrap();
        assert_eq!(r.status(), 400, "{next}");
    }
    let r = w.http.get(format!("{}/login/oidc/nope", w.login)).send().await.unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn waitlist_and_login_names() {
    let w = world().await;
    // Not on the list: refused, and no account appears.
    assert_eq!(w.oidc("g-3", "eve@else.example", |_| {}).await, Err(403));
    assert!(w.registry.account("eve").unwrap().is_none());
    // Listed by domain; the login comes from the address, suffixed when taken.
    let first = w.oidc("g-4", "dev@corp.example", |_| {}).await.unwrap();
    let second = w.oidc("g-5", "Dev@corp.example", |_| {}).await.unwrap();
    assert_eq!(w.viewer(&first).await.unwrap(), "dev");
    assert_eq!(w.viewer(&second).await.unwrap(), "dev-2");
    // Site administrators' logins are never handed out.
    let root = w.oidc("g-6", "root@corp.example", |_| {}).await.unwrap();
    assert_eq!(w.viewer(&root).await.unwrap(), "root-2");

    // Only site administrators manage the list.
    let mut p = PlatformClient::connect(w.grpc.clone()).await.unwrap();
    let call = |token: &str, entry: &str| {
        let mut req = tonic::Request::new(SetSignupAllowRequest { entry: entry.into(), allowed: true });
        req.metadata_mut().insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    };
    let e = p.set_signup_allow(call(&first, "eve@else.example")).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::PermissionDenied);
    w.registry.ensure_account("root", "").unwrap();
    let (_, admin) = w
        .registry
        .create_token(pando_server::directory::TokenRec {
            id: String::new(),
            account: "root".into(),
            name: "t".into(),
            acts_as: "root".into(),
            repositories: vec![],
            max_role: pando_proto::Role::Admin,
            created_at_ms: now_ms(),
            expires_at_ms: now_ms() + 60_000,
            last_used_at_ms: 0,
        })
        .unwrap();
    let e = p.set_signup_allow(call(&admin, "not an address")).await.unwrap_err();
    assert_eq!(e.code(), tonic::Code::InvalidArgument);
    p.set_signup_allow(call(&admin, " Eve@Else.example ")).await.unwrap();
    let mut req = tonic::Request::new(Empty {});
    req.metadata_mut().insert("authorization", format!("Bearer {admin}").parse().unwrap());
    let entries = p.list_signup_allow(req).await.unwrap().into_inner().entries;
    assert_eq!(entries, ["@corp.example", "eve@else.example", "mira@a.example"]);
    let eve = w.oidc("g-3", "eve@else.example", |_| {}).await.unwrap();
    assert_eq!(w.viewer(&eve).await.unwrap(), "eve");

    // The first administrator gets in by linking an identity to their account.
    let link = |token: &str, login: &str| {
        let mut req = tonic::Request::new(pando_proto::LinkIdentityRequest {
            login: login.into(),
            provider: "mock".into(),
            subject: "g-7".into(),
        });
        req.metadata_mut().insert("authorization", format!("Bearer {token}").parse().unwrap());
        req
    };
    assert_eq!(p.link_identity(link(&first, "dev")).await.unwrap_err().code(), tonic::Code::PermissionDenied);
    assert_eq!(p.link_identity(link(&admin, "nobody")).await.unwrap_err().code(), tonic::Code::NotFound);
    p.link_identity(link(&admin, "root")).await.unwrap();
    let root = w.oidc("g-7", "unlisted@else.example", |_| {}).await.unwrap();
    assert_eq!(w.viewer(&root).await.unwrap(), "root");
    assert_eq!(p.link_identity(link(&admin, "dev")).await.unwrap_err().code(), tonic::Code::AlreadyExists);
}

#[tokio::test(flavor = "multi_thread")]
async fn email_links_are_single_use_and_do_not_reveal_who_can_sign_in() {
    let w = world().await;
    let unknown = w.ask_for_link("stranger@else.example").await;
    let known = w.ask_for_link("Mira@A.example").await;
    assert_eq!(unknown, known, "the same answer either way");
    assert_eq!(known.0, 200);
    assert_eq!(w.ask_for_link("not-an-address").await.0, 400);

    let mail = w.wait_for_mail(1).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(w.mail.lock().unwrap().len(), 1, "only the listed address gets a link");
    // Quoted-printable, as mail clients would decode it.
    let body = mail[0].replace("=\n", "").replace("=3D", "=");
    assert!(body.contains("To: mira@a.example"), "{body}");
    let token = body.split("token=").nth(1).unwrap()[..64].to_owned();
    let link = format!("{}/login/email/verify?token={token}", w.login);

    // Opening the link (as a mail scanner would) shows a button and uses nothing up.
    for _ in 0..2 {
        let r = w.http.get(&link).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["x-frame-options"], "DENY");
        assert_eq!(r.headers()["cache-control"], "no-store");
        assert!(r.headers()["content-security-policy"].to_str().unwrap().starts_with("default-src 'none'"));
        assert!(r.text().await.unwrap().contains("method=post"));
    }
    let verify = || w.http.post(format!("{}/login/email/verify", w.login)).form(&[("token", token.as_str())]).send();
    let session_token = session(verify().await.unwrap()).await.unwrap();
    assert_eq!(w.viewer(&session_token).await.unwrap(), "mira");
    assert_eq!(session(verify().await.unwrap()).await, Err(400), "a link works once");
    assert_eq!(w.registry.identity_login("email", "mira@a.example").unwrap().as_deref(), Some("mira"));

    // Too many requests from one address are turned away.
    let mut statuses = Vec::new();
    for _ in 0..12 {
        statuses.push(w.ask_for_link("someone@else.example").await.0);
    }
    assert_eq!(statuses.last(), Some(&429));
}

#[tokio::test(flavor = "multi_thread")]
async fn providers_are_listed_for_the_console() {
    let w = world().await;
    let r = w.http.get(format!("{}/login/providers", w.login)).send().await.unwrap();
    assert_eq!(r.headers()["cache-control"], "no-store");
    let v: Value = r.json().await.unwrap();
    assert_eq!(v, json!({ "providers": [{ "id": "mock", "name": "mock", "url": "/login/oidc/mock" }], "email": true }));
}
