//! Keeping tenants apart: repository calls must name their repository, and a multi-tenant server
//! (ADR-032) keeps internal repositories, organisations and webhooks to their own tenant.

use pando::remote::{GrpcRemote, Remote};
use pando_core::object::{Changeset, FileChange, Kind, Mode, encode_object};
use pando_proto::{
    CreateOrganizationRequest, CreateRepositoryRequest, CreateTokenRequest, CreateWebhookRequest, Empty, RepositoryRef,
    Role, SetMemberRequest, Visibility,
};
use pando_server::permissions::Access;
use tonic::Code;

mod common;
use common::{Server, start, start_with};

async fn multi_tenant() -> Server {
    start_with(Access {
        open: false,
        admins: vec!["admin".into()],
        multi_tenant: true,
        max_orgs_per_account: 3,
        webhook_allow_private: false,
    })
    .await
}

fn as_(s: &Server, who: &str, repo: &str) -> GrpcRemote {
    let url = if repo.is_empty() { s.url.clone() } else { format!("{}/{repo}", s.url) };
    GrpcRemote::connect(&url, None, Some(&format!("{}-token", who.replace('/', "-")))).unwrap()
}

async fn changeset(r: &GrpcRemote, parent: Option<pando_core::Id>, body: &str) -> pando_core::Id {
    let (blob, payload) = encode_object(Kind::Blob, body.as_bytes());
    r.objects().put_many(vec![(blob, payload)]).await.unwrap();
    r.create_changeset(Changeset {
        parents: parent.iter().map(|p| p.0.to_vec()).collect(),
        changes: vec![FileChange::upsert("a.txt", Mode::File, blob)],
        author: "x".into(),
        message: "m".into(),
        timestamp_ms: 1,
    })
    .await
    .unwrap()
    .id
}

async fn create(s: &Server, name: &str, visibility: Visibility) {
    let (owner, name) = name.split_once('/').unwrap();
    as_(s, "admin", "")
        .platform()
        .create_repository(CreateRepositoryRequest {
            owner: owner.into(),
            name: name.into(),
            visibility: visibility as i32,
            ..Default::default()
        })
        .await
        .unwrap();
}

async fn member(s: &Server, org: &str, login: &str) -> Result<(), tonic::Status> {
    let m = SetMemberRequest { org: org.into(), login: login.into(), role: Role::Write as i32 };
    as_(s, "admin", "").platform().set_member(m).await.map(|_| ())
}

/// Signs in once, which records the account.
async fn sign_in(s: &Server, who: &str) {
    as_(s, who, "").platform().viewer(Empty {}).await.unwrap();
}

/// A repository call that names no repository is refused: it used to reach the server's own
/// repository with no access check at all.
#[tokio::test(flavor = "multi_thread")]
async fn repository_calls_must_name_a_repository() {
    let s = start().await;
    let eve = as_(&s, "eve", "");
    let (blob, payload) = encode_object(Kind::Blob, b"eve was here");
    assert!(eve.objects().put_many(vec![(blob, payload)]).await.is_err());
    assert!(eve.get_ref("main").await.is_err());

    // Nor does a token limited to reading one repository write anywhere else.
    create(&s, "lumen/web", Visibility::Private).await;
    let t = as_(&s, "admin", "")
        .platform()
        .create_token(CreateTokenRequest {
            name: "ro".into(),
            repositories: vec!["lumen/web".into()],
            max_role: Role::Read as i32,
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let ro = GrpcRemote::connect(&s.url, None, Some(&t.secret)).unwrap();
    let e = ro.compare_and_swap("main", None, pando_core::Id([7; 32])).await.unwrap_err();
    assert!(format!("{e:#}").contains("name one"), "{e:#}");
    let web = GrpcRemote::connect(&format!("{}/lumen/web", s.url), None, Some(&t.secret)).unwrap();
    assert_eq!(web.get_ref("main").await.unwrap(), None, "named, it reads what it may");
}

#[tokio::test(flavor = "multi_thread")]
async fn internal_repositories_are_for_the_owning_organisation() {
    for mt in [true, false] {
        let s = if mt { multi_tenant().await } else { start().await };
        create(&s, "lumen/docs", Visibility::Internal).await;
        sign_in(&s, "dev").await;
        member(&s, "lumen", "dev").await.unwrap();
        let dev = as_(&s, "dev", "lumen/docs");
        let tip = changeset(&dev, None, "hello").await;
        assert!(dev.compare_and_swap("main", None, tip).await.unwrap());
        let eve = as_(&s, "eve", "lumen/docs").get_ref("main").await;
        if mt {
            assert!(format!("{:#}", eve.unwrap_err()).contains("no repository `lumen/docs`"));
        } else {
            assert_eq!(eve.unwrap(), Some(tip), "without --multi-tenant every account reads internal repositories");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn members_must_have_signed_in() {
    let s = multi_tenant().await;
    create(&s, "lumen/docs", Visibility::Private).await;
    let e = member(&s, "lumen", "stranger@example.com").await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert!(e.message().contains("has no Pando account yet"), "{e:?}");
    sign_in(&s, "mira").await;
    member(&s, "lumen", "mira").await.unwrap();
    member(&s, "lumen", "agent/new-01").await.unwrap();

    let s = start().await;
    create(&s, "lumen/docs", Visibility::Private).await;
    member(&s, "lumen", "stranger@example.com").await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn people_create_a_few_organisations_of_their_own() {
    let s = multi_tenant().await;
    let org = |login: &str| CreateOrganizationRequest { login: login.into(), ..Default::default() };
    let dev = as_(&s, "dev", "");
    for name in ["acme", "acme-labs", "acme-ops"] {
        let o = dev.platform().create_organization(org(name)).await.unwrap().into_inner();
        assert_eq!(o.viewer_role, Role::Admin as i32, "the creator administers {name}");
    }
    let e = dev.platform().create_organization(org("acme-four")).await.unwrap_err();
    assert_eq!(e.code(), Code::ResourceExhausted, "{e:?}");

    // Organisations and accounts share one namespace; some names belong to the service.
    sign_in(&s, "mira").await;
    let mira = as_(&s, "mira", "");
    assert_eq!(mira.platform().create_organization(org("dev")).await.unwrap_err().code(), Code::AlreadyExists);
    assert_eq!(mira.platform().create_organization(org("acme")).await.unwrap_err().code(), Code::AlreadyExists);
    for reserved in ["admin", "API", "pando", "-x"] {
        let e = mira.platform().create_organization(org(reserved)).await.unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "{reserved}: {e:?}");
    }
    let e = as_(&s, "agent/fix-01", "").platform().create_organization(org("bots")).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied, "{e:?}");

    // Without --multi-tenant only site administrators create organisations.
    let s = start().await;
    let e = as_(&s, "dev", "").platform().create_organization(org("acme")).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread")]
async fn webhooks_may_not_call_the_servers_own_network() {
    let hook = |url: &str| CreateWebhookRequest {
        repository: Some(RepositoryRef { owner: "lumen".into(), name: "fleet".into() }),
        url: url.into(),
        ..Default::default()
    };
    let refused = [
        "http://127.0.0.1:7420",
        "http://10.0.0.5",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://169.254.169.254",
        "http://100.64.0.1",
        "http://localhost:7420/hook",
        "http://user:pw@example.com/",
        "file:///etc/passwd",
    ];
    // Multi-tenant, and a server left at its defaults: the same refusals.
    let default = start_with(Access { open: false, admins: vec!["admin".into()], ..Default::default() }).await;
    for s in [multi_tenant().await, default] {
        create(&s, "lumen/fleet", Visibility::Private).await;
        let admin = as_(&s, "admin", "");
        for url in refused {
            let e = admin.platform().create_webhook(hook(url)).await.unwrap_err();
            assert_eq!(e.code(), Code::InvalidArgument, "{url}: {e:?}");
        }
    }
    // --webhook-allow-private lets a self-hosted server call its own network, not metadata.
    let s = start().await;
    create(&s, "lumen/fleet", Visibility::Private).await;
    let admin = as_(&s, "admin", "");
    admin.platform().create_webhook(hook("http://127.0.0.1:7420")).await.unwrap();
    let e = admin.platform().create_webhook(hook("http://169.254.169.254")).await.unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
}
