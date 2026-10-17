//! A platform server for tests: hosting, accounts and reviews, with static tokens
//! `admin`, `dev`, `mira`, `eve` and `agent/fix-01` (each `NAME-token`, `/` as `-`).

use std::sync::Arc;

use pando_adapters::flags::SpecFlags;
use pando_core::acl::{AccessPolicy, AllowAllPolicy};
use pando_core::ports::NoChecks;
use pando_server::auth::StaticTokens;
use pando_server::features::land::Land;
use pando_server::hosting::{BuildRoutes, Hosting, Registry, RepoServices, Templates};
use pando_server::permissions::{Access, ProtectedRefs};
use pando_server::{ServeOptions, WebAccess, authority_routes, config, serve};
use tokio::net::TcpListener;

pub struct Server {
    pub url: String,
    _dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

pub async fn start() -> Server {
    // Webhook tests call a receiver on loopback, as self-hosted CI on a private network would.
    start_with(Access { open: false, admins: vec!["admin".into()], webhook_allow_private: true, ..Default::default() })
        .await
}

/// A server with these access rules.
#[allow(dead_code)]
pub async fn start_with(access: Access) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let flags = Arc::new(SpecFlags::all_on());
    let policy: Arc<dyn AccessPolicy> = Arc::new(AllowAllPolicy);
    let checks = Arc::new(NoChecks);
    let registry = Arc::new(Registry::open("memory").unwrap());
    let access = Arc::new(access);
    let (reg, acc) = (registry.clone(), access.clone());
    let build: BuildRoutes = Arc::new(move |key, repo| {
        let protected: Arc<dyn AccessPolicy> = Arc::new(ProtectedRefs {
            inner: policy.clone(),
            registry: reg.clone(),
            key: key.clone(),
            access: acc.clone(),
        });
        RepoServices {
            routes: authority_routes(repo.clone(), flags.clone(), protected, checks.clone()),
            review_land: Some(Land::new(repo, flags.clone(), policy.clone(), checks.clone())),
        }
    });
    let templates = Templates {
        metadata: format!("sqlite://{}/repos/{{repo}}.db", dir.path().display()),
        objects: "metadata".into(),
    };
    let hosting = Hosting::new(templates, registry, build, access).unwrap();
    let default = config::open_repo("memory", "metadata").await.unwrap();
    let routes = authority_routes(default, Arc::new(SpecFlags::all_on()), Arc::new(AllowAllPolicy), Arc::new(NoChecks));
    let tokens = ["admin", "dev", "mira", "eve", "agent/fix-01"].map(|w| format!("{w}:{}-token", w.replace('/', "-")));
    let auth = Arc::new(StaticTokens::new(tokens));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel();
    let web = WebAccess { enabled: false, origins: vec![] };
    tokio::spawn(serve(
        listener,
        routes,
        auth,
        ServeOptions { web, hosting: Some(Arc::new(hosting)), ..Default::default() },
        async {
            let _ = rx.await;
        },
    ));
    Server { url, _dir: dir, _stop: tx }
}
