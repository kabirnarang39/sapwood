//! One server, many repositories: created by admins, isolated from each other, each with its own
//! storage, addressed as SERVER/OWNER/NAME; repository calls that name none are refused.

use std::sync::Arc;

use pando::remote::{GrpcRemote, Remote};
use pando_adapters::flags::SpecFlags;
use pando_core::acl::AllowAllPolicy;
use pando_core::object::{Changeset, FileChange, Kind, Mode, encode_object};
use pando_core::ports::NoChecks;
use pando_proto::{CreateRepositoryRequest, CreateTokenRequest, ListRepositoriesRequest, Role, SetMemberRequest};
use pando_server::auth::StaticTokens;
use pando_server::features::land::Land;
use pando_server::hosting::{BuildRoutes, Hosting, Registry, RepoServices, Templates};
use pando_server::permissions::Access;
use pando_server::{ServeOptions, WebAccess, authority_routes, config, serve};
use tokio::net::TcpListener;
use tonic::Code;

struct Server {
    url: String,
    dir: tempfile::TempDir,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn start() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let flags = Arc::new(SpecFlags::all_on());
    let policy = Arc::new(AllowAllPolicy);
    let checks = Arc::new(NoChecks);
    let (f, p, c) = (flags.clone(), policy.clone(), checks.clone());
    let build: BuildRoutes = Arc::new(move |_, repo| RepoServices {
        routes: authority_routes(repo.clone(), f.clone(), p.clone(), c.clone()),
        review_land: Some(Land::new(repo, f.clone(), p.clone(), c.clone())),
    });
    let templates = Templates {
        metadata: format!("sqlite://{}/repos/{{repo}}.db", dir.path().display()),
        objects: "metadata".into(),
    };
    let access = Arc::new(Access { open: false, admins: vec!["admin".into()], ..Default::default() });
    let hosting = Hosting::new(templates, Arc::new(Registry::open("memory").unwrap()), build, access).unwrap();
    let default = config::open_repo("memory", "metadata").await.unwrap();
    let routes = authority_routes(default, flags, policy, checks);
    let auth = Arc::new(StaticTokens::new([
        "admin:admin-token".to_string(),
        "dev:dev-token".to_string(),
        "eve:eve-token".to_string(),
    ]));
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
    Server { url, dir, _stop: tx }
}

fn create(owner: &str, name: &str) -> CreateRepositoryRequest {
    CreateRepositoryRequest {
        owner: owner.into(),
        name: name.into(),
        description: format!("{name} repository"),
        ..Default::default()
    }
}

/// Lands one file on `main` of the repository at `url`, starting it if empty.
async fn land(url: &str, path: &str, body: &str) {
    let r = GrpcRemote::connect(url, None, Some("dev-token")).unwrap();
    let (blob, payload) = encode_object(Kind::Blob, body.as_bytes());
    r.objects().put_many(vec![(blob, payload)]).await.unwrap();
    let base = r.get_ref("main").await.unwrap();
    let cs = r
        .create_changeset(Changeset {
            parents: base.iter().map(|b| b.0.to_vec()).collect(),
            changes: vec![FileChange::upsert(path, Mode::File, blob)],
            author: "agent/test-01".into(),
            message: format!("Add {path}"),
            timestamp_ms: pando_server::hosting::now_ms(),
        })
        .await
        .unwrap();
    match base {
        None => assert!(r.compare_and_swap("main", None, cs.id).await.unwrap()),
        Some(_) => {
            r.land("main", cs.id).await.unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn one_server_hosts_isolated_repositories() {
    let s = start().await;
    let admin = GrpcRemote::connect(&s.url, None, Some("admin-token")).unwrap();
    let dev = GrpcRemote::connect(&s.url, None, Some("dev-token")).unwrap();

    // Only admins create repositories; names are validated; a repository exists once.
    let denied = dev.platform().create_repository(create("lumen", "fleet")).await.unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied, "{denied:?}");
    for bad in [("lumen", "../etc"), ("lu men", "x"), ("lumen", "")] {
        let e = admin.platform().create_repository(create(bad.0, bad.1)).await.unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "{bad:?}: {e:?}");
    }
    admin.platform().create_repository(create("lumen", "fleet")).await.unwrap();
    admin.platform().create_repository(create("lumen", "web")).await.unwrap();
    let again = admin.platform().create_repository(create("lumen", "fleet")).await.unwrap_err();
    assert_eq!(again.code(), Code::AlreadyExists);
    assert!(s.dir.path().join("repos/lumen/fleet.db").exists(), "each repository gets its own database");

    // Repositories are private: only members of lumen may use them.
    let member =
        |login: &str, role: Role| SetMemberRequest { org: "lumen".into(), login: login.into(), role: role as i32 };
    let e = dev.platform().set_member(member("dev", Role::Write)).await.unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "a non-member does not even see the organisation: {e:?}");
    admin.platform().set_member(member("dev", Role::Write)).await.unwrap();

    // Each repository has its own history.
    land(&format!("{}/lumen/fleet", s.url), "billing/tax.rs", "rate = 19\n").await;
    land(&format!("{}/lumen/fleet", s.url), "billing/refund.rs", "window = 30\n").await;
    land(&format!("{}/lumen/web", s.url), "src/cart.ts", "export const MAX = 20;\n").await;
    let fleet = GrpcRemote::connect(&format!("{}/lumen/fleet", s.url), None, Some("dev-token")).unwrap();
    let web = GrpcRemote::connect(&format!("{}/lumen/web", s.url), None, Some("dev-token")).unwrap();
    let (fleet_tip, web_tip) =
        (fleet.get_ref("main").await.unwrap().unwrap(), web.get_ref("main").await.unwrap().unwrap());
    assert_ne!(fleet_tip, web_tip);
    assert_eq!(fleet.log("main", "", 100).await.unwrap().len(), 2);
    assert_eq!(web.log("main", "", 100).await.unwrap().len(), 1);
    assert!(
        web.log(&fleet_tip.to_string(), "", 1).await.is_err(),
        "one repository's history is invisible from another"
    );

    // Repository calls that name no repository are refused, whoever makes them (the server's
    // own `--metadata` repository is never reached unchecked).
    let e = dev.get_ref("main").await.unwrap_err();
    assert!(format!("{e:#}").contains("name one"), "{e:#}");

    // An unknown repository is a clear NotFound, not an empty repository.
    let missing = GrpcRemote::connect(&format!("{}/lumen/nope", s.url), None, Some("dev-token")).unwrap();
    let e = missing.get_ref("main").await.unwrap_err();
    assert!(format!("{e:#}").contains("no repository `lumen/nope`"), "{e:#}");

    // A stranger can't see private repositories, not even that they exist.
    let eve = GrpcRemote::connect(&format!("{}/lumen/fleet", s.url), None, Some("eve-token")).unwrap();
    let e = eve.get_ref("main").await.unwrap_err();
    assert!(format!("{e:#}").contains("no repository `lumen/fleet`"), "{e:#}");
    let eve_list = GrpcRemote::connect(&s.url, None, Some("eve-token")).unwrap();
    let seen = eve_list.platform().list_repositories(ListRepositoriesRequest::default()).await.unwrap().into_inner();
    assert!(seen.repositories.is_empty(), "{seen:?}");

    // A token for an agent, limited to lumen/web and to reading.
    let t = dev
        .platform()
        .create_token(CreateTokenRequest {
            name: "web reader".into(),
            acts_as: "agent/reader-01".into(),
            repositories: vec!["lumen/web".into()],
            max_role: Role::Read as i32,
            expires_at_ms: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(t.secret.starts_with("pando_"));
    let agent_web = GrpcRemote::connect(&format!("{}/lumen/web", s.url), None, Some(&t.secret)).unwrap();
    assert_eq!(agent_web.get_ref("main").await.unwrap(), Some(web_tip), "the agent reads lumen/web as its owner may");
    let e = agent_web.compare_and_swap("main", Some(web_tip), fleet_tip).await.unwrap_err();
    assert!(format!("{e:#}").contains("this needs write"), "a read-only token can't write: {e:#}");
    let agent_fleet = GrpcRemote::connect(&format!("{}/lumen/fleet", s.url), None, Some(&t.secret)).unwrap();
    assert!(agent_fleet.get_ref("main").await.is_err(), "the token does not reach lumen/fleet");

    // Even an administrator's token, once limited to some repositories, can't administer.
    let limited = admin
        .platform()
        .create_token(CreateTokenRequest {
            name: "web admin".into(),
            repositories: vec!["lumen/web".into()],
            max_role: Role::Admin as i32,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let as_limited = GrpcRemote::connect(&s.url, None, Some(&limited.secret)).unwrap();
    let e = as_limited.platform().set_member(member("eve", Role::Admin)).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied, "{e:?}");

    // Listings report each repository's activity.
    let list = dev
        .platform()
        .list_repositories(ListRepositoriesRequest { owner: "lumen".into(), ..Default::default() })
        .await
        .unwrap()
        .into_inner();
    let by_name: std::collections::HashMap<_, _> = list.repositories.iter().map(|r| (r.name.as_str(), r)).collect();
    assert_eq!(by_name["fleet"].lands_24h, 2);
    assert_eq!(by_name["web"].lands_24h, 1);
    assert_eq!(by_name["fleet"].tip, fleet_tip.0.to_vec());
}
