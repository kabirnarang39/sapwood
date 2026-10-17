//! Platform slice: the repositories a server hosts, the organisations that own them, their
//! members and teams, who may use each repository, and access tokens (ADR-022, ADR-023).
//! Change requests and reviews come with phase 3.

use std::collections::BTreeSet;
use std::sync::Arc;

use pando_core::acl::Principal;
use pando_proto::platform_server::{self, PlatformServer};
use pando_proto::{
    Account, AccountKind, CreateOrganizationRequest, CreateRepositoryRequest, CreateTokenRequest, CreateTokenResponse,
    CreateWebhookRequest, CreateWebhookResponse, Empty, Grant, ListGrantsResponse, ListMembersResponse,
    ListOrganizationsResponse, ListRepositoriesRequest, ListRepositoriesResponse, ListTeamsResponse,
    ListTokensResponse, ListWebhookDeliveriesResponse, ListWebhooksResponse, Member, OrgName, Organization, Repository,
    RepositoryRef, RevokeTokenRequest, Role, SetGrantRequest, SetMemberRequest, Team, TeamRef, Token,
    UpdateRepositoryRequest, ViewerResponse, Visibility, WebhookDelivery, WebhookRef,
};
use tonic::{Request, Response, Status};

use crate::auth::{TokenScope, principal};
use crate::directory::{self, AccountRec, DEFAULT_TOKEN_DAYS, OrgRec, TeamRec, TokenRec, kind_of};
use crate::hosting::{Hosting, Registry, RepoKey, RepoRecord, now_ms, valid_part};
use crate::permissions::role_name;
use crate::status::RpcResult;

const DAY_MS: i64 = 86_400_000;

/// Names nobody may give an organisation on a multi-tenant server: they would read as part of the
/// service (in URLs, mail and the console).
const RESERVED: &[&str] = &[
    "admin", "api", "login", "settings", "new", "explore", "www", "mail", "support", "help", "security", "status",
    "docs", "pando",
];

#[derive(Clone)]
pub struct Platform {
    hosting: Arc<Hosting>,
}

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

fn caller<T>(req: &Request<T>) -> (Principal, Option<TokenScope>) {
    (principal(req), req.extensions().get::<TokenScope>().cloned())
}

fn audit(kind: &str, who: &Principal, target: &str) {
    tracing::info!(target: crate::telemetry::AUDIT, kind, principal = %who.0, target);
}

fn account_of(rec: Option<AccountRec>, login: &str, site_admin: bool) -> Account {
    let rec = rec.unwrap_or_else(|| AccountRec {
        login: login.to_owned(),
        display_name: login.rsplit('/').next().unwrap_or(login).to_owned(),
        kind: kind_of(login),
        owner: String::new(),
        created_at_ms: 0,
    });
    Account {
        login: rec.login,
        display_name: rec.display_name,
        kind: rec.kind as i32,
        owner: rec.owner,
        avatar_url: String::new(),
        created_at_ms: rec.created_at_ms,
        site_admin,
    }
}

fn token_of(t: TokenRec) -> Token {
    Token {
        id: t.id,
        name: t.name,
        acts_as: t.acts_as,
        repositories: t.repositories,
        max_role: t.max_role as i32,
        created_at_ms: t.created_at_ms,
        expires_at_ms: t.expires_at_ms,
        last_used_at_ms: t.last_used_at_ms,
    }
}

/// Whether a token (if any) may administer an organisation: only one that isn't limited to some
/// repositories or below Admin.
fn token_administers(scope: Option<&TokenScope>) -> bool {
    scope.is_none_or(|s| s.repositories.is_empty() && s.max_role >= Role::Admin)
}

fn role_in(r: i32) -> Result<Role, Status> {
    Role::try_from(r).map_err(|_| Status::invalid_argument(format!("unknown role {r}")))
}

impl Platform {
    pub fn new(hosting: Arc<Hosting>) -> Self {
        Self { hosting }
    }

    fn reg(&self) -> &Registry {
        &self.hosting.registry
    }

    fn is_admin(&self, who: &Principal) -> bool {
        self.hosting.access.is_admin(who)
    }

    async fn repository(&self, rec: &RepoRecord, role: Role) -> Repository {
        let s = self.hosting.stats(rec).await;
        Repository {
            owner: rec.key.owner.clone(),
            name: rec.key.name.clone(),
            description: rec.description.clone(),
            visibility: rec.visibility,
            default_branch: rec.default_branch.clone(),
            created_at_ms: rec.created_at_ms,
            viewer_role: role as i32,
            archived: rec.archived,
            lands_24h: s.lands_24h,
            open_change_requests: self.reg().open_change_requests(&rec.key).unwrap_or(0),
            tip: s.tip.map(|t| t.0.to_vec()).unwrap_or_default(),
            tip_at_ms: s.tip_at_ms,
            topics: rec.topics.clone(),
        }
    }

    /// Repositories `who` can read, with their role on each.
    fn readable(
        &self,
        who: &Principal,
        scope: Option<&TokenScope>,
        owner: Option<&str>,
    ) -> Result<Vec<(RepoRecord, Role)>, Status> {
        let mut out = Vec::new();
        for rec in self.reg().list(owner).map_err(internal)? {
            let role = self.hosting.access.effective(self.reg(), who, scope, &rec)?;
            if role >= Role::Read {
                out.push((rec, role));
            }
        }
        Ok(out)
    }

    /// `who`'s role in an organisation: site administrators administer every organisation.
    fn org_role(&self, who: &Principal, org: &str) -> Result<Role, Status> {
        if self.is_admin(who) {
            return Ok(Role::Admin);
        }
        Ok(self
            .reg()
            .members(org)
            .map_err(internal)?
            .into_iter()
            .find(|(l, _)| l == &who.0)
            .map(|(_, r)| r)
            .unwrap_or(Role::Unspecified))
    }

    /// The organisation, if `who` may see it: a member, a site administrator, or someone who can
    /// read one of its repositories. Otherwise NotFound, so names don't leak.
    fn visible_org(&self, who: &Principal, scope: Option<&TokenScope>, login: &str) -> Result<OrgRec, Status> {
        let missing = || Status::not_found(format!("no organisation `{login}` on this server"));
        let org = self.reg().organization(login).map_err(internal)?.ok_or_else(missing)?;
        if self.org_role(who, login)? >= Role::Read || !self.readable(who, scope, Some(login))?.is_empty() {
            return Ok(org);
        }
        Err(missing())
    }

    fn require_org_admin(&self, who: &Principal, scope: Option<&TokenScope>, org: &str) -> Result<OrgRec, Status> {
        let rec = self.visible_org(who, scope, org)?;
        if !token_administers(scope) || self.org_role(who, org)? < Role::Admin {
            return Err(Status::permission_denied(format!("only administrators of {org} may change it")));
        }
        Ok(rec)
    }

    fn organization(&self, who: &Principal, scope: Option<&TokenScope>, o: OrgRec) -> Result<Organization, Status> {
        let members = self.reg().members(&o.login).map_err(internal)?;
        let agents = members.iter().filter(|(l, _)| kind_of(l) == AccountKind::Agent).count() as u32;
        Ok(Organization {
            viewer_role: self.org_role(who, &o.login)? as i32,
            repositories: self.readable(who, scope, Some(&o.login))?.len() as u32,
            members: members.len() as u32 - agents,
            agents,
            display_name: if o.display_name.is_empty() { o.login.clone() } else { o.display_name },
            login: o.login,
            description: o.description,
            created_at_ms: o.created_at_ms,
        })
    }

    fn organizations(&self, who: &Principal, scope: Option<&TokenScope>) -> Result<Vec<Organization>, Status> {
        let all = self.reg().organizations().map_err(internal)?;
        let mine: BTreeSet<String> = if self.is_admin(who) {
            all.iter().map(|o| o.login.clone()).collect()
        } else {
            let mut s: BTreeSet<String> =
                self.reg().memberships(&who.0).map_err(internal)?.into_iter().map(|(o, _)| o).collect();
            s.extend(self.readable(who, scope, None)?.into_iter().map(|(r, _)| r.key.owner));
            s
        };
        all.into_iter().filter(|o| mine.contains(&o.login)).map(|o| self.organization(who, scope, o)).collect()
    }

    /// A webhook, if `who` administers its repository; NotFound otherwise.
    fn webhook_for(
        &self,
        who: &Principal,
        scope: Option<&TokenScope>,
        id: &str,
    ) -> Result<(pando_proto::Webhook, RepoKey), Status> {
        let missing = || Status::not_found(format!("no webhook `{id}`"));
        let (hook, _) = self.reg().webhook(id).map_err(internal)?.ok_or_else(missing)?;
        let r = hook.repository.clone().ok_or_else(missing)?;
        let rec = self.require_repo(who, scope, &r, Role::Admin).map_err(|_| missing())?;
        Ok((hook, rec.key))
    }

    /// Records an account for a login being given access. On a multi-tenant server a person
    /// must have signed in already: a login is not theirs until they have proved it.
    fn existing_account(&self, login: &str) -> Result<(), Status> {
        if self.hosting.access.multi_tenant
            && kind_of(login) == AccountKind::Person
            && self.reg().account(login).map_err(internal)?.is_none()
        {
            return Err(Status::failed_precondition(format!(
                "{login} has no Pando account yet; ask them to sign in first, or send an invitation"
            )));
        }
        self.reg().ensure_account(login, "").map_err(internal)?;
        Ok(())
    }

    /// May `who` create the organisation `login`? Site administrators may create any; on a
    /// multi-tenant server, so may any person, up to a few, in a namespace shared with accounts.
    fn may_create_org(&self, who: &Principal, scope: Option<&TokenScope>, login: &str) -> Result<(), Status> {
        let access = &self.hosting.access;
        if !token_administers(scope) || !(self.is_admin(who) || access.multi_tenant) {
            return Err(Status::permission_denied(format!(
                "`{}` may not create organisations; add it to --platform-admins",
                who.0
            )));
        }
        if !access.multi_tenant {
            return Ok(());
        }
        if RESERVED.contains(&login.to_ascii_lowercase().as_str()) || !directory::valid_login(login) {
            return Err(Status::invalid_argument(format!("`{login}` is reserved; choose another name")));
        }
        if self.reg().account(login).map_err(internal)?.is_some() {
            return Err(Status::already_exists(format!("`{login}` is taken")));
        }
        if self.is_admin(who) {
            return Ok(());
        }
        if kind_of(&who.0) != AccountKind::Person || *who == Principal::anonymous() {
            return Err(Status::permission_denied("only people create organisations; agents can't"));
        }
        // ponytail: counted before inserting, so two creates at once can pass the cap by one.
        let max = access.max_orgs_per_account as usize;
        let admin_of =
            self.reg().memberships(&who.0).map_err(internal)?.iter().filter(|(_, r)| *r == Role::Admin).count();
        if admin_of >= max {
            return Err(Status::resource_exhausted(format!(
                "you administer {admin_of} organisations, the most this server allows ({max})"
            )));
        }
        Ok(())
    }

    fn require_repo(
        &self,
        who: &Principal,
        scope: Option<&TokenScope>,
        r: &RepositoryRef,
        need: Role,
    ) -> Result<RepoRecord, Status> {
        self.hosting.authorize(&RepoKey::new(&r.owner, &r.name)?, who, scope, need)
    }
}

pub fn service(s: Platform) -> PlatformServer<Platform> {
    PlatformServer::new(s)
}

#[tonic::async_trait]
impl platform_server::Platform for Platform {
    async fn viewer(&self, req: Request<Empty>) -> RpcResult<ViewerResponse> {
        let (who, scope) = caller(&req);
        let rec = self.reg().account(&who.0).map_err(internal)?;
        Ok(Response::new(ViewerResponse {
            account: Some(account_of(rec, &who.0, self.is_admin(&who))),
            organizations: self.organizations(&who, scope.as_ref())?,
        }))
    }

    async fn get_account(&self, req: Request<OrgName>) -> RpcResult<Account> {
        let login = req.into_inner().login;
        let rec = self.reg().account(&login).map_err(internal)?;
        let Some(rec) = rec else { return Err(Status::not_found(format!("no account `{login}` on this server"))) };
        let admin = self.hosting.access.admins.contains(&login);
        Ok(Response::new(account_of(Some(rec), &login, admin)))
    }

    async fn list_organizations(&self, req: Request<Empty>) -> RpcResult<ListOrganizationsResponse> {
        let (who, scope) = caller(&req);
        Ok(Response::new(ListOrganizationsResponse { organizations: self.organizations(&who, scope.as_ref())? }))
    }

    async fn get_organization(&self, req: Request<OrgName>) -> RpcResult<Organization> {
        let (who, scope) = caller(&req);
        let org = self.visible_org(&who, scope.as_ref(), &req.into_inner().login)?;
        Ok(Response::new(self.organization(&who, scope.as_ref(), org)?))
    }

    async fn create_organization(&self, req: Request<CreateOrganizationRequest>) -> RpcResult<Organization> {
        let (who, scope) = caller(&req);
        let r = req.into_inner();
        if !valid_part(&r.login) {
            return Err(Status::invalid_argument(format!(
                "`{}` is not a valid organisation name: use letters, digits, `.`, `_` and `-`",
                r.login
            )));
        }
        self.may_create_org(&who, scope.as_ref(), &r.login)?;
        let org = OrgRec {
            login: r.login,
            display_name: r.display_name,
            description: r.description,
            created_at_ms: now_ms(),
        };
        if !self.reg().create_organization(&org).map_err(internal)? {
            return Err(Status::already_exists(format!("`{}` already exists", org.login)));
        }
        if who != Principal::anonymous() {
            self.reg().set_member(&org.login, &who.0, Role::Admin).map_err(internal)?;
        }
        audit("create_organization", &who, &org.login);
        Ok(Response::new(self.organization(&who, scope.as_ref(), org)?))
    }

    async fn list_members(&self, req: Request<OrgName>) -> RpcResult<ListMembersResponse> {
        let (who, scope) = caller(&req);
        let org = self.visible_org(&who, scope.as_ref(), &req.into_inner().login)?;
        let teams = self.reg().teams(&org.login).map_err(internal)?;
        let members = self
            .reg()
            .members(&org.login)
            .map_err(internal)?
            .into_iter()
            .map(|(login, role)| {
                let rec = self.reg().account(&login).map_err(internal)?;
                Ok(Member {
                    teams: teams.iter().filter(|t| t.members.contains(&login)).map(|t| t.slug.clone()).collect(),
                    account: Some(account_of(rec, &login, self.hosting.access.admins.contains(&login))),
                    role: role as i32,
                })
            })
            .collect::<Result<_, Status>>()?;
        Ok(Response::new(ListMembersResponse { members }))
    }

    async fn set_member(&self, req: Request<SetMemberRequest>) -> RpcResult<Member> {
        let (who, scope) = caller(&req);
        let r = req.into_inner();
        self.require_org_admin(&who, scope.as_ref(), &r.org)?;
        directory::check_login(&r.login)?;
        let role = role_in(r.role)?;
        let admins = self
            .reg()
            .members(&r.org)
            .map_err(internal)?
            .into_iter()
            .filter(|(_, ro)| *ro == Role::Admin)
            .collect::<Vec<_>>();
        if role != Role::Admin && admins.len() == 1 && admins[0].0 == r.login {
            return Err(Status::failed_precondition(format!(
                "`{}` is the last administrator of {}; make someone else one first",
                r.login, r.org
            )));
        }
        self.existing_account(&r.login)?;
        self.reg().set_member(&r.org, &r.login, role).map_err(internal)?;
        audit("set_member", &who, &format!("{}:{}={}", r.org, r.login, role_name(role)));
        let rec = self.reg().account(&r.login).map_err(internal)?;
        Ok(Response::new(Member { account: Some(account_of(rec, &r.login, false)), role: role as i32, teams: vec![] }))
    }

    async fn list_teams(&self, req: Request<OrgName>) -> RpcResult<ListTeamsResponse> {
        let (who, scope) = caller(&req);
        let org = self.visible_org(&who, scope.as_ref(), &req.into_inner().login)?;
        let teams = self
            .reg()
            .teams(&org.login)
            .map_err(internal)?
            .into_iter()
            .map(|t| Team { org: t.org, slug: t.slug, name: t.name, description: t.description, members: t.members })
            .collect();
        Ok(Response::new(ListTeamsResponse { teams }))
    }

    async fn set_team(&self, req: Request<Team>) -> RpcResult<Team> {
        let (who, scope) = caller(&req);
        let t = req.into_inner();
        self.require_org_admin(&who, scope.as_ref(), &t.org)?;
        if !valid_part(&t.slug) {
            return Err(Status::invalid_argument(format!(
                "`{}` is not a valid team name: use letters, digits, `.`, `_` and `-`",
                t.slug
            )));
        }
        let mut members = t.members.clone();
        members.sort();
        members.dedup();
        directory::require_members(self.reg(), &t.org, &members)?;
        let name = if t.name.trim().is_empty() { t.slug.clone() } else { t.name.trim().to_owned() };
        let rec = TeamRec {
            org: t.org.clone(),
            slug: t.slug.clone(),
            name: name.clone(),
            description: t.description.clone(),
            members: members.clone(),
        };
        self.reg().set_team(&rec).map_err(internal)?;
        audit("set_team", &who, &format!("{}/{}", t.org, t.slug));
        Ok(Response::new(Team { org: t.org, slug: t.slug, name, description: t.description, members }))
    }

    async fn delete_team(&self, req: Request<TeamRef>) -> RpcResult<Empty> {
        let (who, scope) = caller(&req);
        let t = req.into_inner();
        self.require_org_admin(&who, scope.as_ref(), &t.org)?;
        if !self.reg().delete_team(&t.org, &t.slug).map_err(internal)? {
            return Err(Status::not_found(format!("no team `{}/{}`", t.org, t.slug)));
        }
        audit("delete_team", &who, &format!("{}/{}", t.org, t.slug));
        Ok(Response::new(Empty {}))
    }

    async fn list_repositories(&self, req: Request<ListRepositoriesRequest>) -> RpcResult<ListRepositoriesResponse> {
        let (who, scope) = caller(&req);
        let r = req.into_inner();
        let q = r.query.to_lowercase();
        let limit = if r.limit == 0 { 200 } else { r.limit.min(1000) } as usize;
        let mut out = Vec::new();
        for (rec, role) in self.readable(&who, scope.as_ref(), (!r.owner.is_empty()).then_some(r.owner.as_str()))? {
            if !q.is_empty()
                && !rec.key.name.to_lowercase().contains(&q)
                && !rec.description.to_lowercase().contains(&q)
            {
                continue;
            }
            out.push(self.repository(&rec, role).await);
            if out.len() == limit {
                break;
            }
        }
        Ok(Response::new(ListRepositoriesResponse { repositories: out, next_page_token: String::new() }))
    }

    async fn get_repository(&self, req: Request<RepositoryRef>) -> RpcResult<Repository> {
        let (who, scope) = caller(&req);
        let rec = self.require_repo(&who, scope.as_ref(), req.get_ref(), Role::Read)?;
        let role = self.hosting.access.effective(self.reg(), &who, scope.as_ref(), &rec)?;
        Ok(Response::new(self.repository(&rec, role).await))
    }

    async fn create_repository(&self, req: Request<CreateRepositoryRequest>) -> RpcResult<Repository> {
        let (who, scope) = caller(&req);
        let r = req.into_inner();
        let key = RepoKey::new(&r.owner, &r.name)?;
        let org = self.reg().organization(&key.owner).map_err(internal)?;
        let allowed = match &org {
            Some(_) => self.org_role(&who, &key.owner)? >= Role::Admin && token_administers(scope.as_ref()),
            None => self.is_admin(&who) && token_administers(scope.as_ref()),
        };
        if !allowed {
            return Err(Status::permission_denied(format!(
                "`{}` may not create repositories in {}: that takes an administrator of the organisation",
                who.0, key.owner
            )));
        }
        let branch = if r.default_branch.is_empty() { "main".to_owned() } else { r.default_branch };
        if branch.starts_with('_') || branch.contains("..") || branch.contains(char::is_whitespace) {
            return Err(Status::invalid_argument(format!("`{branch}` is not a valid branch name")));
        }
        let visibility =
            if r.visibility == Visibility::Unspecified as i32 { Visibility::Private as i32 } else { r.visibility };
        if org.is_none() {
            let rec = OrgRec {
                login: key.owner.clone(),
                display_name: String::new(),
                description: String::new(),
                created_at_ms: now_ms(),
            };
            self.reg().create_organization(&rec).map_err(internal)?;
            audit("create_organization", &who, &key.owner);
        }
        let rec = RepoRecord {
            key: key.clone(),
            description: r.description,
            visibility,
            default_branch: branch,
            created_at_ms: now_ms(),
            archived: false,
            topics: Vec::new(),
        };
        if !self.hosting.create(rec.clone()).await? {
            return Err(Status::already_exists(format!("`{key}` already exists")));
        }
        audit("create_repository", &who, &key.to_string());
        Ok(Response::new(self.repository(&rec, Role::Admin).await))
    }

    async fn update_repository(&self, req: Request<UpdateRepositoryRequest>) -> RpcResult<Repository> {
        let (who, scope) = caller(&req);
        let r = req.into_inner();
        let mut rec = self.require_repo(
            &who,
            scope.as_ref(),
            &RepositoryRef { owner: r.owner.clone(), name: r.name.clone() },
            Role::Admin,
        )?;
        for f in &r.fields {
            match f.as_str() {
                "description" => rec.description = r.description.clone(),
                "visibility" => {
                    if Visibility::try_from(r.visibility).unwrap_or(Visibility::Unspecified) == Visibility::Unspecified
                    {
                        return Err(Status::invalid_argument("choose private, internal or public"));
                    }
                    rec.visibility = r.visibility
                }
                "default_branch" => {
                    let b = &r.default_branch;
                    if b.is_empty() || b.starts_with('_') || b.contains("..") || b.contains(char::is_whitespace) {
                        return Err(Status::invalid_argument(format!("`{b}` is not a valid branch name")));
                    }
                    rec.default_branch = b.clone()
                }
                "archived" => rec.archived = r.archived,
                "topics" => {
                    rec.topics = r
                        .topics
                        .iter()
                        .map(|t| t.trim().to_lowercase())
                        .filter(|t| !t.is_empty() && !t.contains(','))
                        .collect()
                }
                other => return Err(Status::invalid_argument(format!("`{other}` can't be changed"))),
            }
        }
        self.reg().update(&rec).map_err(internal)?;
        audit("update_repository", &who, &format!("{}: {}", rec.key, r.fields.join(",")));
        Ok(Response::new(self.repository(&rec, Role::Admin).await))
    }

    async fn list_grants(&self, req: Request<RepositoryRef>) -> RpcResult<ListGrantsResponse> {
        let (who, scope) = caller(&req);
        let rec = self.require_repo(&who, scope.as_ref(), req.get_ref(), Role::Read)?;
        let grants = self
            .reg()
            .grants(&rec.key)
            .map_err(internal)?
            .into_iter()
            .map(|(principal, role)| Grant { principal, role: role as i32 })
            .collect();
        Ok(Response::new(ListGrantsResponse { grants }))
    }

    async fn set_grant(&self, req: Request<SetGrantRequest>) -> RpcResult<Grant> {
        let (who, scope) = caller(&req);
        let r = req.into_inner();
        let repo = r.repository.ok_or_else(|| Status::invalid_argument("name the repository"))?;
        let rec = self.require_repo(&who, scope.as_ref(), &repo, Role::Admin)?;
        let role = role_in(r.role)?;
        if !self.reg().is_team(&r.principal).map_err(internal)? {
            directory::check_login(&r.principal)?;
            self.existing_account(&r.principal)?;
        }
        self.reg().set_grant(&rec.key, &r.principal, role).map_err(internal)?;
        audit("set_grant", &who, &format!("{}:{}={}", rec.key, r.principal, role_name(role)));
        Ok(Response::new(Grant { principal: r.principal, role: role as i32 }))
    }

    async fn list_tokens(&self, req: Request<Empty>) -> RpcResult<ListTokensResponse> {
        let (who, _) = caller(&req);
        let tokens = self.reg().tokens(&who.0).map_err(internal)?.into_iter().map(token_of).collect();
        Ok(Response::new(ListTokensResponse { tokens }))
    }

    async fn create_token(&self, req: Request<CreateTokenRequest>) -> RpcResult<CreateTokenResponse> {
        let (who, scope) = caller(&req);
        let r = req.into_inner();
        let name = r.name.trim().to_owned();
        if name.is_empty() || name.len() > 100 {
            return Err(Status::invalid_argument("give the token a name of up to 100 characters"));
        }
        // Acting as yourself, or as an agent you answer for (created on first use).
        let acts_as = if r.acts_as.is_empty() { who.0.clone() } else { r.acts_as.clone() };
        if acts_as != who.0 {
            directory::check_login(&acts_as)?;
            if kind_of(&acts_as) != AccountKind::Agent {
                return Err(Status::permission_denied(
                    "a token can act only as you or as an agent (`agent/NAME`) you answer for",
                ));
            }
            match self.reg().account(&acts_as).map_err(internal)? {
                Some(a) if a.owner != who.0 && !self.is_admin(&who) => {
                    return Err(Status::permission_denied(format!("`{acts_as}` answers to `{}`, not you", a.owner)));
                }
                Some(_) => {}
                None => {
                    self.reg().ensure_account(&acts_as, &who.0).map_err(internal)?;
                    audit("create_agent", &who, &acts_as);
                }
            }
        }
        let mut max_role = role_in(r.max_role)?;
        if max_role == Role::Unspecified {
            max_role = Role::Admin;
        }
        let mut repositories: Vec<String> = directory::require_repositories(self.reg(), &r.repositories)?
            .into_iter()
            .map(|rec| rec.key.to_string())
            .collect();
        // A token made with a token can't reach further than the one used to make it.
        if let Some(s) = &scope {
            max_role = max_role.min(s.max_role);
            if !s.repositories.is_empty() {
                if repositories.is_empty() {
                    repositories = s.repositories.clone();
                } else if let Some(out) = repositories.iter().find(|n| !s.repositories.contains(n)) {
                    return Err(Status::permission_denied(format!("the token you are using does not reach {out}")));
                }
            }
        }
        let now = now_ms();
        let expires_at_ms = if r.expires_at_ms == 0 { now + DEFAULT_TOKEN_DAYS * DAY_MS } else { r.expires_at_ms };
        if expires_at_ms <= now || expires_at_ms > now + 366 * DAY_MS {
            return Err(Status::invalid_argument("a token expires between now and a year from now"));
        }
        let (t, secret) = self
            .reg()
            .create_token(TokenRec {
                id: String::new(),
                account: who.0.clone(),
                name,
                acts_as,
                repositories,
                max_role,
                created_at_ms: now,
                expires_at_ms,
                last_used_at_ms: 0,
            })
            .map_err(internal)?;
        audit("create_token", &who, &format!("{} as {}", t.id, t.acts_as));
        Ok(Response::new(CreateTokenResponse { token: Some(token_of(t)), secret }))
    }

    async fn revoke_token(&self, req: Request<RevokeTokenRequest>) -> RpcResult<Empty> {
        let (who, _) = caller(&req);
        let id = req.into_inner().id;
        let missing = || Status::not_found(format!("no token `{id}`"));
        let t = self.reg().token(&id).map_err(internal)?.ok_or_else(missing)?;
        if t.account != who.0 && !self.is_admin(&who) {
            return Err(missing());
        }
        self.reg().revoke_token(&id).map_err(internal)?;
        audit("revoke_token", &who, &id);
        Ok(Response::new(Empty {}))
    }

    async fn list_webhooks(&self, req: Request<RepositoryRef>) -> RpcResult<ListWebhooksResponse> {
        let (who, scope) = caller(&req);
        let rec = self.require_repo(&who, scope.as_ref(), req.get_ref(), Role::Admin)?;
        Ok(Response::new(ListWebhooksResponse { webhooks: self.reg().webhooks(&rec.key).map_err(internal)? }))
    }

    async fn create_webhook(&self, req: Request<CreateWebhookRequest>) -> RpcResult<CreateWebhookResponse> {
        let (who, scope) = caller(&req);
        let r = req.into_inner();
        let repo = r.repository.ok_or_else(|| Status::invalid_argument("name the repository"))?;
        let rec = self.require_repo(&who, scope.as_ref(), &repo, Role::Admin)?;
        let url = crate::webhooks::check_url(&r.url).map_err(Status::invalid_argument)?;
        crate::webhooks::resolve(&url, self.hosting.access.webhook_allow_private)
            .await
            .map_err(Status::invalid_argument)?;
        if let Some(bad) = r.events.iter().find(|e| !crate::webhooks::EVENTS.contains(&e.as_str())) {
            return Err(Status::invalid_argument(format!(
                "`{bad}` is not an event; choose from {}",
                crate::webhooks::EVENTS.join(", ")
            )));
        }
        if self.reg().webhooks(&rec.key).map_err(internal)?.len() >= 20 {
            return Err(Status::resource_exhausted("a repository has at most 20 webhooks"));
        }
        let (webhook, secret) =
            self.reg().create_webhook(&rec.key, &r.url, &r.events, &r.secret, &who.0).map_err(internal)?;
        audit("create_webhook", &who, &format!("{}: {}", rec.key, webhook.id));
        // The secret is returned once, only when the server made it.
        let secret = if r.secret.is_empty() { secret } else { String::new() };
        Ok(Response::new(CreateWebhookResponse { webhook: Some(webhook), secret }))
    }

    async fn delete_webhook(&self, req: Request<WebhookRef>) -> RpcResult<Empty> {
        let (who, scope) = caller(&req);
        let (hook, key) = self.webhook_for(&who, scope.as_ref(), &req.get_ref().id)?;
        self.reg().delete_webhook(&hook.id).map_err(internal)?;
        audit("delete_webhook", &who, &format!("{key}: {}", hook.id));
        Ok(Response::new(Empty {}))
    }

    async fn list_webhook_deliveries(&self, req: Request<WebhookRef>) -> RpcResult<ListWebhookDeliveriesResponse> {
        let (who, scope) = caller(&req);
        let (hook, _) = self.webhook_for(&who, scope.as_ref(), &req.get_ref().id)?;
        Ok(Response::new(ListWebhookDeliveriesResponse {
            deliveries: self.reg().deliveries(&hook.id, 50).map_err(internal)?,
        }))
    }

    async fn ping_webhook(&self, req: Request<WebhookRef>) -> RpcResult<WebhookDelivery> {
        let (who, scope) = caller(&req);
        let (hook, key) = self.webhook_for(&who, scope.as_ref(), &req.get_ref().id)?;
        let mut payload = crate::webhooks::envelope("ping", "ping", &key, &who.0);
        payload["hook"] = serde_json::json!({ "id": hook.id, "events": hook.events });
        let ids = self.reg().enqueue(&key, "ping", &payload, Some(&hook.id)).map_err(internal)?;
        let id = ids.first().ok_or_else(|| Status::internal("ping was not queued"))?;
        let delivery = crate::webhooks::deliver_now(self.reg(), id, self.hosting.access.webhook_allow_private)
            .await
            .map_err(internal)?;
        Ok(Response::new(delivery.ok_or_else(|| Status::internal("ping vanished"))?))
    }
}
