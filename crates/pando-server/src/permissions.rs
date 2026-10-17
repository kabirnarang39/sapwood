//! Who may do what on a platform server (ADR-023).
//!
//! [`PlatformAuth`] recognises platform tokens and records an account for everyone who signs in
//! another way. [`Access`] works out a caller's role on a repository: from site administration,
//! the repository's visibility, organisation membership, grants to them or their teams, and an
//! agent's owner, capped by the token they used. Every call that names a repository is checked:
//! reads need Read, anything else needs Write.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use pando_core::acl::{AccessPolicy, Principal};
use pando_proto::{AccountKind, Protection, Role, Visibility};
use tonic::Status;

use crate::auth::{Authenticator, TokenScope};
use crate::directory::{TOKEN_PREFIX, kind_of};
use crate::hosting::{Registry, RepoKey, RepoRecord};

/// Methods that only read a repository. Everything else needs Write, so a method added later
/// is protected until it is listed here.
const READS: &[&str] = &[
    "/pando.v1.Objects/Get",
    "/pando.v1.Objects/Missing",
    "/pando.v1.Changesets/Get",
    "/pando.v1.Refs/Get",
    "/pando.v1.Refs/List",
    "/pando.v1.History/Log",
    "/pando.v1.History/Blame",
    "/pando.v1.Diff/Diff",
    "/pando.v1.MergeBase/MergeBase",
    "/pando.v1.Browse/ListDir",
    "/pando.v1.Browse/ReadFile",
    "/pando.v1.Browse/Find",
    "/pando.v1.Browse/Checkout",
    "/pando.v1.Access/WhoAmI",
    "/pando.v1.Locks/List",
];

/// The role a call needs, from its gRPC path.
pub fn required_role(path: &str) -> Role {
    if READS.contains(&path) { Role::Read } else { Role::Write }
}

/// Access rules for a platform server.
#[derive(Default)]
pub struct Access {
    /// No authentication is configured (local development): every caller may do everything.
    pub open: bool,
    /// Logins that administer the whole server.
    pub admins: Vec<String>,
    /// Strangers share this server (`--multi-tenant`, ADR-032): internal repositories are for
    /// the owning organisation's members, organisations take existing accounts only, and any
    /// person may create a few organisations.
    pub multi_tenant: bool,
    /// Organisations a person may administer when they create their own (multi-tenant only).
    pub max_orgs_per_account: u32,
    /// Webhooks may call loopback and private networks (`--webhook-allow-private`; never with
    /// `multi_tenant`).
    pub webhook_allow_private: bool,
}

impl Access {
    pub fn is_admin(&self, who: &Principal) -> bool {
        self.open || self.admins.iter().any(|a| a == &who.0)
    }

    /// `who`'s role on `repo`, before any token limit.
    pub fn role(&self, reg: &Registry, who: &Principal, repo: &RepoRecord) -> Result<Role, Status> {
        if self.is_admin(who) {
            return Ok(Role::Admin);
        }
        let internal = |e: anyhow::Error| Status::internal(e.to_string());
        let mut role = reg.held_role(&who.0, &repo.key).map_err(internal)?;
        // Internal and public repositories are readable by everyone with an account here; on a
        // multi-tenant server, internal ones only by members of the owning organisation.
        if repo.visibility != Visibility::Private as i32
            && who.0 != Principal::anonymous().0
            && (!self.multi_tenant
                || repo.visibility != Visibility::Internal as i32
                || reg.in_org(&who.0, &repo.key.owner).map_err(internal)?)
        {
            role = role.max(Role::Read);
        }
        // An agent acts with its own roles or its owner's, whichever is higher.
        if let Some(agent) = reg.account(&who.0).map_err(internal)?
            && !agent.owner.is_empty()
            && agent.owner != who.0
        {
            let owner = Principal(agent.owner);
            let via = if self.is_admin(&owner) {
                Role::Admin
            } else {
                reg.held_role(&owner.0, &repo.key).map_err(internal)?
            };
            role = role.max(via);
        }
        Ok(role)
    }

    /// The role after the caller's token limits: none outside the token's repositories.
    pub fn effective(
        &self,
        reg: &Registry,
        who: &Principal,
        scope: Option<&TokenScope>,
        repo: &RepoRecord,
    ) -> Result<Role, Status> {
        let role = self.role(reg, who, repo)?;
        Ok(match scope {
            Some(s) if !s.repositories.is_empty() && !s.repositories.contains(&repo.key.to_string()) => {
                Role::Unspecified
            }
            Some(s) => role.min(s.max_role),
            None => role,
        })
    }

    /// Allows a call needing `need` on `repo`, or refuses it. A caller who may not read the
    /// repository is told it does not exist, so private names don't leak.
    pub fn check(
        &self,
        reg: &Registry,
        who: &Principal,
        scope: Option<&TokenScope>,
        repo: &RepoRecord,
        need: Role,
    ) -> Result<(), Status> {
        let role = self.effective(reg, who, scope, repo)?;
        if role < Role::Read {
            return Err(Status::not_found(format!("no repository `{}` on this server", repo.key)));
        }
        if role < need {
            return Err(Status::permission_denied(format!(
                "`{}` has {} access to {}; this needs {}",
                who.0,
                role_name(role),
                repo.key,
                role_name(need)
            )));
        }
        Ok(())
    }
}

pub fn role_name(r: Role) -> &'static str {
    match r {
        Role::Unspecified => "no",
        Role::Read => "read",
        Role::Triage => "triage",
        Role::Write => "write",
        Role::Maintain => "maintain",
        Role::Admin => "admin",
    }
}

/// Authentication on a platform server: platform tokens first, then the server's other
/// authentication (static tokens or single sign-on). Anyone who signs in gets an account.
pub struct PlatformAuth {
    registry: Arc<Registry>,
    inner: Arc<dyn Authenticator>,
    known: Mutex<HashSet<String>>,
}

impl PlatformAuth {
    pub fn new(registry: Arc<Registry>, inner: Arc<dyn Authenticator>) -> Self {
        Self { registry, inner, known: Mutex::new(HashSet::new()) }
    }

    fn record(&self, who: &Principal) {
        if who.0 == Principal::anonymous().0 || self.known.lock().unwrap().contains(&who.0) {
            return;
        }
        if crate::directory::valid_login(&who.0) {
            match self.registry.ensure_account(&who.0, "") {
                Ok(true) => {
                    tracing::info!(target: crate::telemetry::AUDIT, kind = "account_created", principal = %who.0)
                }
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "recording account");
                    return;
                }
            }
        }
        self.known.lock().unwrap().insert(who.0.clone());
    }
}

impl Authenticator for PlatformAuth {
    fn authenticate(&self, bearer: Option<&str>) -> Result<Principal, Status> {
        self.identify(bearer).map(|(p, _)| p)
    }

    fn identify(&self, bearer: Option<&str>) -> Result<(Principal, Option<TokenScope>), Status> {
        if let Some(secret) = bearer.filter(|b| b.starts_with(TOKEN_PREFIX)) {
            let token = self.registry.use_token(secret).map_err(|e| Status::internal(e.to_string()))?;
            if let Some(t) = token {
                let who = Principal(if t.acts_as.is_empty() { t.account } else { t.acts_as });
                return Ok((who, Some(TokenScope { repositories: t.repositories, max_role: t.max_role })));
            }
        }
        let (who, scope) = self.inner.identify(bearer)?;
        self.record(&who);
        Ok((who, scope))
    }
}

/// Protected branches (ADR-024): a branch with a protection is updated only by those it lets
/// bypass review (people, teams `org/team`, or `admins` for the repository's administrators),
/// or by agents when it lets agents land directly. Everyone else lands through a change request,
/// whose review is the gate.
pub struct ProtectedRefs {
    pub inner: Arc<dyn AccessPolicy>,
    pub registry: Arc<Registry>,
    pub key: RepoKey,
    pub access: Arc<Access>,
}

impl ProtectedRefs {
    fn may_bypass(&self, who: &Principal, p: &Protection) -> bool {
        if self.access.is_admin(who) || (p.agents_land_directly && kind_of(&who.0) == AccountKind::Agent) {
            return true;
        }
        p.bypass.iter().any(|b| {
            b == &who.0
                || (b == "admins" && self.registry.held_role(&who.0, &self.key).is_ok_and(|r| r >= Role::Admin))
                || (b.contains('/') && self.registry.in_team(&who.0, b).unwrap_or(false))
        })
    }
}

impl AccessPolicy for ProtectedRefs {
    fn can_write(&self, who: &Principal, path: &str) -> bool {
        self.inner.can_write(who, path)
    }

    fn can_update_ref(&self, who: &Principal, ref_name: &str) -> bool {
        if !self.inner.can_update_ref(who, ref_name) {
            return false;
        }
        match self.registry.protection_for(&self.key, ref_name) {
            Ok(Some(p)) => self.may_bypass(who, &p),
            Ok(None) => true,
            Err(e) => {
                tracing::warn!(error = %e, "reading branch protection; refusing the update");
                false
            }
        }
    }

    fn read_scope(&self, who: &Principal) -> pando_core::acl::ReadScope {
        self.inner.read_scope(who)
    }

    /// On a platform server a change is attributed to whoever made it. Repository
    /// administrators may record another author, so imports keep their original history.
    fn author_for(&self, who: &Principal, claimed: &str) -> String {
        let admin =
            self.access.is_admin(who) || self.registry.held_role(&who.0, &self.key).is_ok_and(|r| r >= Role::Admin);
        if admin || claimed == who.0 { claimed.to_owned() } else { who.0.clone() }
    }

    fn why_not_ref(&self, who: &Principal, ref_name: &str) -> Option<String> {
        if !self.inner.can_update_ref(who, ref_name) {
            return self.inner.why_not_ref(who, ref_name);
        }
        Some(format!(
            "`{ref_name}` is protected: land on a branch and open a change request \
             (pando checkout -b NAME && pando land && pando cr create --title \"…\")"
        ))
    }
}

/// Refuses every call: the inner authenticator of a server that accepts platform tokens only.
pub struct NoOtherAuth;

impl Authenticator for NoOtherAuth {
    fn authenticate(&self, bearer: Option<&str>) -> Result<Principal, Status> {
        Err(Status::unauthenticated(if bearer.is_some() { "invalid token" } else { "missing bearer token" }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::TokenRec;
    use crate::hosting::{RepoKey, now_ms};

    fn repo(name: &str, visibility: Visibility) -> RepoRecord {
        RepoRecord {
            key: RepoKey::parse(name).unwrap(),
            description: String::new(),
            visibility: visibility as i32,
            default_branch: "main".into(),
            created_at_ms: 0,
            archived: false,
            topics: vec![],
        }
    }

    fn p(s: &str) -> Principal {
        Principal(s.into())
    }

    #[test]
    fn reads_are_listed_and_everything_else_needs_write() {
        assert_eq!(required_role("/pando.v1.Browse/ReadFile"), Role::Read);
        assert_eq!(required_role("/pando.v1.Land/Land"), Role::Write);
        assert_eq!(required_role("/pando.v1.Objects/Put"), Role::Write);
        assert_eq!(required_role("/pando.v1.Refs/CompareAndSwap"), Role::Write);
        assert_eq!(required_role("/pando.v1.SomethingNew/Do"), Role::Write);
    }

    #[test]
    fn roles_visibility_agents_and_token_limits() {
        let reg = Registry::open("memory").unwrap();
        let access = Access { open: false, admins: vec!["root".into()], ..Default::default() };
        let private = repo("lumen/fleet", Visibility::Private);
        let internal = repo("lumen/docs", Visibility::Internal);

        // Strangers can't see private repositories at all; internal ones they can read.
        let e = access.check(&reg, &p("eve"), None, &private, Role::Read).unwrap_err();
        assert_eq!(e.code(), tonic::Code::NotFound);
        access.check(&reg, &p("eve"), None, &internal, Role::Read).unwrap();
        assert_eq!(
            access.check(&reg, &p("eve"), None, &internal, Role::Write).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );

        // Site administrators may do anything.
        access.check(&reg, &p("root"), None, &private, Role::Admin).unwrap();

        // A member writes; an agent they own acts with their role.
        reg.set_member("lumen", "kabir", Role::Write).unwrap();
        access.check(&reg, &p("kabir"), None, &private, Role::Write).unwrap();
        reg.ensure_account("agent/perf-05", "kabir").unwrap();
        access.check(&reg, &p("agent/perf-05"), None, &private, Role::Write).unwrap();

        // A token caps the role and can be limited to some repositories.
        let read_only = TokenScope { repositories: vec![], max_role: Role::Read };
        let e = access.check(&reg, &p("kabir"), Some(&read_only), &private, Role::Write).unwrap_err();
        assert_eq!(e.code(), tonic::Code::PermissionDenied);
        let elsewhere = TokenScope { repositories: vec!["lumen/docs".into()], max_role: Role::Admin };
        let e = access.check(&reg, &p("kabir"), Some(&elsewhere), &private, Role::Read).unwrap_err();
        assert_eq!(e.code(), tonic::Code::NotFound);

        // Without authentication configured, everything is allowed.
        let open = Access { open: true, ..Default::default() };
        open.check(&reg, &Principal::anonymous(), None, &private, Role::Admin).unwrap();
    }

    #[test]
    fn multi_tenant_internal_is_for_the_owning_organisation() {
        let reg = Registry::open("memory").unwrap();
        let access = Access { multi_tenant: true, ..Default::default() };
        let internal = repo("lumen/docs", Visibility::Internal);
        let public = repo("lumen/site", Visibility::Public);
        reg.set_member("lumen", "kabir", Role::Read).unwrap();
        // mira is in a team only (the registry doesn't insist on membership; the RPC does).
        reg.set_team(&crate::directory::TeamRec {
            org: "lumen".into(),
            slug: "docs".into(),
            name: "Docs".into(),
            description: String::new(),
            members: vec!["mira".into()],
        })
        .unwrap();
        access.check(&reg, &p("kabir"), None, &internal, Role::Read).unwrap();
        access.check(&reg, &p("mira"), None, &internal, Role::Read).unwrap();
        let e = access.check(&reg, &p("eve"), None, &internal, Role::Read).unwrap_err();
        assert_eq!(e.code(), tonic::Code::NotFound, "a stranger doesn't see another organisation's internal repo");
        access.check(&reg, &p("eve"), None, &public, Role::Read).unwrap();
        // A repository owned by someone with no organisation members is private to its grants.
        let personal = repo("eve/notes", Visibility::Internal);
        assert!(access.check(&reg, &p("kabir"), None, &personal, Role::Read).is_err());
        reg.set_grant(&personal.key, "kabir", Role::Read).unwrap();
        access.check(&reg, &p("kabir"), None, &personal, Role::Read).unwrap();
        // Without the flag, internal stays readable by every account.
        Access::default().check(&reg, &p("eve"), None, &internal, Role::Read).unwrap();
    }

    #[test]
    fn platform_tokens_authenticate_and_others_get_accounts() {
        let reg = Arc::new(Registry::open("memory").unwrap());
        let inner = Arc::new(crate::auth::StaticTokens::new(["alice:al1ce".to_owned()]));
        let auth = PlatformAuth::new(reg.clone(), inner);
        let (who, scope) = auth.identify(Some("al1ce")).unwrap();
        assert_eq!(who, p("alice"));
        assert!(scope.is_none());
        assert!(reg.account("alice").unwrap().is_some(), "signing in records an account");

        let (_, secret) = reg
            .create_token(TokenRec {
                id: String::new(),
                account: "alice".into(),
                name: "fleet".into(),
                acts_as: "agent/perf-05".into(),
                repositories: vec!["lumen/fleet".into()],
                max_role: Role::Write,
                created_at_ms: now_ms(),
                expires_at_ms: 0,
                last_used_at_ms: 0,
            })
            .unwrap();
        let (who, scope) = auth.identify(Some(&secret)).unwrap();
        assert_eq!(who, p("agent/perf-05"), "a token acts as its agent");
        assert_eq!(scope.unwrap().max_role, Role::Write);
        assert!(auth.identify(Some("pando_not-a-token")).is_err());
        assert!(PlatformAuth::new(reg, Arc::new(NoOtherAuth)).identify(None).is_err());
    }
}
