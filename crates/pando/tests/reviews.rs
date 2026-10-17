//! Change requests end to end (ADR-024): protected branches refuse direct lands, a change
//! request collects comments, reviews and checks, lands as one changeset once nothing blocks it,
//! loses stale approvals when its branch moves, and is rebased onto its target unless they
//! changed the same files.

use pando::remote::{GrpcRemote, Remote};
use pando_core::Id;
use pando_core::object::{Changeset, FileChange, Kind, Mode, encode_object};
use pando_proto::{
    AddCommentRequest, ChangeRequestRef, ChangeRequestState, Check, CheckState, CreateChangeRequestRequest,
    CreateRepositoryRequest, InboxRequest, ListChangeRequestsRequest, ListEventsRequest, Protection,
    ReportCheckRequest, RepositoryRef, Role, SetMemberRequest, SubmitReviewRequest, Verdict,
};
use tokio::net::TcpListener;
use tonic::Code;

mod common;
use common::{Server, start};

fn as_(s: &Server, who: &str) -> GrpcRemote {
    GrpcRemote::connect(&format!("{}/lumen/fleet", s.url), None, Some(&format!("{}-token", who.replace('/', "-"))))
        .unwrap()
}

/// A changeset on top of `parent` writing `files`.
async fn changeset(r: &GrpcRemote, parent: Option<Id>, files: &[(&str, &str)], message: &str) -> Id {
    let mut changes = Vec::new();
    for (path, body) in files {
        let (blob, payload) = encode_object(Kind::Blob, body.as_bytes());
        r.objects().put_many(vec![(blob, payload)]).await.unwrap();
        changes.push(FileChange::upsert(*path, Mode::File, blob));
    }
    r.create_changeset(Changeset {
        parents: parent.iter().map(|p| p.0.to_vec()).collect(),
        changes,
        author: "dev".into(),
        message: message.into(),
        timestamp_ms: pando_server::hosting::now_ms(),
    })
    .await
    .unwrap()
    .id
}

/// Moves (or creates) `branch` to a new changeset on its current tip, or on `from` when new.
async fn push(r: &GrpcRemote, branch: &str, from: &str, files: &[(&str, &str)]) -> Id {
    let tip = r.get_ref(branch).await.unwrap();
    let parent = match tip {
        Some(t) => Some(t),
        None => r.get_ref(from).await.unwrap(),
    };
    let cs = changeset(r, parent, files, &format!("Update {branch}")).await;
    assert!(r.compare_and_swap(branch, tip, cs).await.unwrap(), "{branch} moved");
    cs
}

fn repo() -> Option<RepositoryRef> {
    Some(RepositoryRef { owner: "lumen".into(), name: "fleet".into() })
}

fn cr_ref(number: u64) -> ChangeRequestRef {
    ChangeRequestRef { repository: repo(), number }
}

fn open(source: &str, title: &str, reviewers: &[&str]) -> CreateChangeRequestRequest {
    CreateChangeRequestRequest {
        repository: repo(),
        source: source.into(),
        target: "main".into(),
        title: title.into(),
        reviewers: reviewers.iter().map(|r| r.to_string()).collect(),
        ..Default::default()
    }
}

fn verdict(number: u64, v: Verdict) -> SubmitReviewRequest {
    SubmitReviewRequest { r#ref: Some(cr_ref(number)), verdict: v as i32, body: String::new() }
}

#[tokio::test(flavor = "multi_thread")]
async fn change_requests_gate_protected_branches() {
    let s = start().await;
    let admin = as_(&s, "admin");
    admin
        .platform()
        .create_repository(CreateRepositoryRequest {
            owner: "lumen".into(),
            name: "fleet".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    for (who, role) in [("dev", Role::Write), ("mira", Role::Write)] {
        let m = SetMemberRequest { org: "lumen".into(), login: who.into(), role: role as i32 };
        admin.platform().set_member(m).await.unwrap();
    }
    let (dev, mira, eve) = (as_(&s, "dev"), as_(&s, "mira"), as_(&s, "eve"));
    let first =
        changeset(&dev, None, &[("billing/tax.rs", "rate = 19\n"), ("billing/refund.rs", "window = 30\n")], "Start")
            .await;
    assert!(dev.compare_and_swap("main", None, first).await.unwrap());

    // Protect main: one approval and a passing build, and agents go through review too.
    admin
        .reviews()
        .set_protection(Protection {
            repository: repo(),
            pattern: "main".into(),
            required_approvals: 1,
            required_checks: vec!["build".into()],
            dismiss_stale: true,
            agents_land_directly: false,
            bypass: vec!["admins".into()],
        })
        .await
        .unwrap();
    let direct = changeset(&dev, Some(first), &[("billing/tax.rs", "rate = 20\n")], "Direct").await;
    let e = dev.land("main", direct).await.unwrap_err();
    assert!(format!("{e:#}").contains("`main` is protected"), "a protected branch refuses a direct land: {e:#}");

    // Open a change request from a branch.
    push(&dev, "tax-20", "main", &[("billing/tax.rs", "rate = 20\n")]).await;
    let cr = dev
        .reviews()
        .create_change_request(open("tax-20", "Raise the tax rate to 20", &["mira"]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(cr.number, 1);
    assert_eq!((cr.files, cr.additions, cr.deletions), (1, 1, 1));
    assert_eq!(cr.blockers, vec!["Needs 1 more approval", "Waiting for check build"]);
    let dup = dev.reviews().create_change_request(open("tax-20", "Again", &[])).await.unwrap_err();
    assert_eq!(dup.code(), Code::AlreadyExists);

    // Mira is asked; she comments on a line and approves. Dev can't approve their own.
    let inbox = mira.reviews().inbox(InboxRequest::default()).await.unwrap().into_inner();
    assert_eq!(inbox.items.len(), 1);
    assert_eq!(inbox.items[0].reason, "Review requested");
    let own = dev.reviews().submit_review(verdict(1, Verdict::Approved)).await.unwrap_err();
    assert_eq!(own.code(), Code::FailedPrecondition);
    mira.reviews()
        .add_comment(AddCommentRequest {
            r#ref: Some(cr_ref(1)),
            body: "Is 20 the new statutory rate?".into(),
            path: "billing/tax.rs".into(),
            line: 1,
            ..Default::default()
        })
        .await
        .unwrap();
    let cr = mira.reviews().submit_review(verdict(1, Verdict::Approved)).await.unwrap().into_inner();
    assert_eq!(cr.comments, 1);
    assert_eq!(cr.blockers, vec!["Waiting for check build"]);
    assert!(
        mira.reviews().inbox(InboxRequest::default()).await.unwrap().into_inner().items.is_empty(),
        "reviewed: out of the inbox"
    );

    // CI reports the build; nothing blocks it any more, and it lands as one changeset.
    let check = |state: CheckState| ReportCheckRequest {
        r#ref: Some(cr_ref(1)),
        check: Some(Check { name: "build".into(), state: state as i32, ..Default::default() }),
    };
    let cr = dev.reviews().report_check(check(CheckState::Failed)).await.unwrap().into_inner();
    assert_eq!(cr.blockers, vec!["Check build failed"]);
    let e = dev.reviews().land(cr_ref(1)).await.unwrap_err();
    assert!(e.message().contains("Check build failed"), "{e:?}");
    let cr = dev.reviews().report_check(check(CheckState::Passed)).await.unwrap().into_inner();
    assert!(cr.blockers.is_empty(), "{:?}", cr.blockers);
    let landed = dev.reviews().land(cr_ref(1)).await.unwrap().into_inner();
    assert_eq!(landed.change_request.unwrap().state, ChangeRequestState::Landed as i32);
    assert_eq!(pando::features::browse::cat(&dev, "main", "billing/tax.rs").await.unwrap(), b"rate = 20\n");
    let log = dev.log("main", "", 1).await.unwrap();
    assert!(
        log[0].changeset.message.starts_with("Raise the tax rate to 20 (#1)")
            && log[0].changeset.message.contains("Approved by mira")
    );

    // A new push makes the approval stale.
    push(&dev, "refund-45", "main", &[("billing/refund.rs", "window = 45\n")]).await;
    dev.reviews().create_change_request(open("refund-45", "Longer refund window", &["mira"])).await.unwrap();
    mira.reviews().submit_review(verdict(2, Verdict::Approved)).await.unwrap();
    push(&dev, "refund-45", "main", &[("billing/refund.rs", "window = 60\n")]).await;
    let cr = dev.reviews().get_change_request(cr_ref(2)).await.unwrap().into_inner();
    assert!(cr.blockers.contains(&"Needs 1 more approval".to_string()), "{:?}", cr.blockers);

    // The target moved: a change to other files rebases; one to the same file is a conflict.
    push(&dev, "docs", "main", &[("README.md", "Billing\n")]).await;
    dev.reviews().create_change_request(open("docs", "Add a README", &[])).await.unwrap();
    let other =
        changeset(&admin, admin.get_ref("main").await.unwrap(), &[("billing/refund.rs", "window = 50\n")], "Admin fix")
            .await;
    admin.land("main", other).await.expect("administrators bypass the protection");
    let cr = dev.reviews().get_change_request(cr_ref(2)).await.unwrap().into_inner();
    assert_eq!(cr.conflicts, vec!["billing/refund.rs"]);
    let e = dev.reviews().rebase(cr_ref(2)).await.unwrap_err();
    assert!(e.message().contains("billing/refund.rs"), "{e:?}");
    let cr = dev.reviews().rebase(cr_ref(3)).await.unwrap().into_inner();
    assert_eq!(cr.base, admin.get_ref("main").await.unwrap().unwrap().0.to_vec(), "rebased onto main");
    assert_eq!(pando::features::browse::cat(&dev, "docs", "billing/refund.rs").await.unwrap(), b"window = 50\n");

    // `pando land` on a protected branch proposes the work from a `review/` branch.
    push(&dev, "review/abc", "main", &[("ops/oncall.md", "dev\n")]).await;
    let auto = dev.reviews().create_change_request(open("review/abc", "On call", &[])).await.unwrap().into_inner();
    assert!(auto.from_protected_land);
    // Nobody was asked to review it, so it shows in the inbox of those who may approve.
    let inbox = mira.reviews().inbox(InboxRequest::default()).await.unwrap().into_inner();
    assert!(
        inbox
            .items
            .iter()
            .any(|i| i.reason == "Needs a reviewer" && i.change_request.as_ref().unwrap().number == auto.number),
        "{inbox:?}"
    );

    // Activity, and strangers.
    let events = dev
        .reviews()
        .list_events(ListEventsRequest { repository: repo(), ..Default::default() })
        .await
        .unwrap()
        .into_inner();
    assert!(events.events.len() >= 5, "{:?}", events.events);
    let e = eve
        .reviews()
        .list_change_requests(ListChangeRequestsRequest { repository: repo(), ..Default::default() })
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    let all = eve.reviews().list_events(ListEventsRequest::default()).await.unwrap().into_inner();
    assert!(all.events.is_empty(), "a stranger sees no activity");
}

/// A tiny HTTP receiver: every request's headers and body, answered 200.
async fn receiver() -> (String, tokio::sync::mpsc::UnboundedReceiver<(String, String)>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            let _ =
                                tx.send((text[..end].to_ascii_lowercase(), text[end + 4..end + 4 + len].to_owned()));
                            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
                            break;
                        }
                    }
                }
            });
        }
    });
    (url, rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn webhooks_deliver_signed_events() {
    let s = start().await;
    let admin = as_(&s, "admin");
    admin
        .platform()
        .create_repository(CreateRepositoryRequest {
            owner: "lumen".into(),
            name: "fleet".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let (url, mut got) = receiver().await;
    let created = admin
        .platform()
        .create_webhook(pando_proto::CreateWebhookRequest {
            repository: repo(),
            url: url.clone(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let secret = created.secret.clone();
    assert_eq!(secret.len(), 64, "the server makes a secret and shows it once");
    let hook = created.webhook.unwrap();
    // Only administrators manage webhooks; others don't even see them.
    let dev = as_(&s, "dev");
    admin
        .platform()
        .set_member(SetMemberRequest { org: "lumen".into(), login: "dev".into(), role: Role::Write as i32 })
        .await
        .unwrap();
    let e = dev.platform().list_webhook_deliveries(pando_proto::WebhookRef { id: hook.id.clone() }).await.unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    let bad = admin
        .platform()
        .create_webhook(pando_proto::CreateWebhookRequest {
            repository: repo(),
            url: "http://169.254.169.254/latest".into(),
            ..Default::default()
        })
        .await;
    assert_eq!(bad.unwrap_err().code(), Code::InvalidArgument, "cloud metadata is never a webhook target");

    // A ping arrives at once, signed.
    let ping =
        admin.platform().ping_webhook(pando_proto::WebhookRef { id: hook.id.clone() }).await.unwrap().into_inner();
    assert!(ping.delivered && ping.status == 200, "{ping:?}");
    let (headers, body) = got.recv().await.unwrap();
    assert!(headers.contains("x-pando-event: ping"));
    let sig = pando_server::webhooks::signature(&secret, body.as_bytes());
    assert!(headers.contains(&format!("x-pando-signature-256: {sig}")), "{headers}");

    // Landing on a branch is a push; opening a change request is a change_request event.
    let first = changeset(&dev, None, &[("a.txt", "a\n")], "Start").await;
    assert!(dev.compare_and_swap("main", None, first).await.unwrap());
    let next = tokio::time::timeout(std::time::Duration::from_secs(10), got.recv()).await.unwrap().unwrap();
    assert!(next.0.contains("x-pando-event: push"), "{}", next.0);
    let push: serde_json::Value = serde_json::from_str(&next.1).unwrap();
    assert_eq!(push["ref"], "main");
    assert_eq!(push["action"], "created");
    assert_eq!(push["repository"]["full_name"], "lumen/fleet");
    push_branch(&dev).await;
    dev.reviews().create_change_request(open("feature", "A feature", &[])).await.unwrap();
    let mut kinds = Vec::new();
    while let Ok(Some((h, _))) = tokio::time::timeout(std::time::Duration::from_secs(10), got.recv()).await {
        kinds.push(h.lines().find_map(|l| l.strip_prefix("x-pando-event: ").map(str::to_owned)).unwrap());
        if kinds.iter().any(|k| k == "change_request") && kinds.iter().any(|k| k == "push") {
            break;
        }
    }
    assert!(kinds.contains(&"push".to_owned()) && kinds.contains(&"change_request".to_owned()), "{kinds:?}");
    let log =
        admin.platform().list_webhook_deliveries(pando_proto::WebhookRef { id: hook.id }).await.unwrap().into_inner();
    assert!(log.deliveries.iter().filter(|d| d.delivered).count() >= 3, "{:?}", log.deliveries);
}

async fn push_branch(r: &GrpcRemote) {
    push(r, "feature", "main", &[("b.txt", "b\n")]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn changes_are_attributed_to_who_made_them() {
    let s = start().await;
    let admin = as_(&s, "admin");
    admin
        .platform()
        .create_repository(CreateRepositoryRequest {
            owner: "lumen".into(),
            name: "fleet".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    admin
        .platform()
        .set_member(SetMemberRequest { org: "lumen".into(), login: "dev".into(), role: Role::Write as i32 })
        .await
        .unwrap();
    let dev = as_(&s, "dev");
    let claim = |author: &str| Changeset {
        parents: vec![],
        changes: vec![],
        author: author.into(),
        message: "x".into(),
        timestamp_ms: 1,
    };
    // A member can't put someone else's name on a change.
    let spoofed = dev.create_changeset(claim("linus <linus@kernel.org>")).await.unwrap();
    assert_eq!(spoofed.changeset.author, "dev");
    // An administrator importing history keeps the original authors.
    let imported = admin.create_changeset(claim("Ada <ada@example.com>")).await.unwrap();
    assert_eq!(imported.changeset.author, "Ada <ada@example.com>");
}
