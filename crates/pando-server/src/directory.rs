//! Who is who on a platform server: accounts, organisations and their members, teams, access
//! grants on repositories, and access tokens. Kept in the registry database next to the list of
//! repositories, and the source of every per-repository role (ADR-023).

use std::collections::BTreeSet;

use anyhow::Context as _;
use pando_proto::{AccountKind, Role};
use tonic::Status;

use crate::hosting::{Registry, RepoKey, RepoRecord, now_ms};

/// What the directory adds to the registry schema. Organisations that already own repositories
/// (created before accounts existed) are recorded as organisations.
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS accounts (
  login TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  kind INTEGER NOT NULL,
  owner TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS organizations (
  login TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS members (
  org TEXT NOT NULL,
  login TEXT NOT NULL,
  role INTEGER NOT NULL,
  PRIMARY KEY (org, login)
);
CREATE INDEX IF NOT EXISTS members_by_login ON members (login);
CREATE TABLE IF NOT EXISTS teams (
  org TEXT NOT NULL,
  slug TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (org, slug)
);
CREATE TABLE IF NOT EXISTS team_members (
  org TEXT NOT NULL,
  slug TEXT NOT NULL,
  login TEXT NOT NULL,
  PRIMARY KEY (org, slug, login)
);
CREATE INDEX IF NOT EXISTS team_members_by_login ON team_members (login);
CREATE TABLE IF NOT EXISTS grants (
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  principal TEXT NOT NULL,
  role INTEGER NOT NULL,
  PRIMARY KEY (owner, name, principal)
);
CREATE TABLE IF NOT EXISTS tokens (
  id TEXT PRIMARY KEY,
  hash BLOB NOT NULL UNIQUE,
  account TEXT NOT NULL,
  name TEXT NOT NULL,
  acts_as TEXT NOT NULL,
  repositories TEXT NOT NULL DEFAULT '',
  max_role INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  last_used_at_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_by_account ON tokens (account);
INSERT OR IGNORE INTO organizations (login, created_at_ms)
  SELECT owner, MIN(created_at_ms) FROM repositories GROUP BY owner;
";

/// Every platform token starts with this, so it is recognisable in logs and secret scanners.
pub const TOKEN_PREFIX: &str = "pando_";

/// Tokens expire after 90 days unless asked otherwise.
pub const DEFAULT_TOKEN_DAYS: i64 = 90;

/// A login: a person (often an email address from single sign-on), or an agent written
/// `agent/NAME` or `bot/NAME`. 1–100 characters, no spaces or control characters.
pub fn valid_login(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && !s.starts_with(['.', '/', '-'])
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@' | b'/' | b'+'))
}

pub(crate) fn check_login(s: &str) -> Result<(), Status> {
    if valid_login(s) { Ok(()) } else { Err(Status::invalid_argument(format!("`{s}` is not a valid login"))) }
}

pub fn kind_of(login: &str) -> AccountKind {
    if login.starts_with("agent/") || login.starts_with("bot/") { AccountKind::Agent } else { AccountKind::Person }
}

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRec {
    pub login: String,
    pub display_name: String,
    pub kind: AccountKind,
    /// Agents: the account that answers for the agent.
    pub owner: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgRec {
    pub login: String,
    pub display_name: String,
    pub description: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamRec {
    pub org: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRec {
    pub id: String,
    pub account: String,
    pub name: String,
    pub acts_as: String,
    pub repositories: Vec<String>,
    pub max_role: Role,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub last_used_at_ms: i64,
}

/// What a token limits its holder to: some repositories (empty: all the holder can reach) and
/// a highest role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenScope {
    pub repositories: Vec<String>,
    pub max_role: Role,
}

fn role_from(i: i32) -> Role {
    Role::try_from(i).unwrap_or(Role::Unspecified)
}

fn split_list(s: String) -> Vec<String> {
    s.split(',').filter(|t| !t.is_empty()).map(str::to_owned).collect()
}

fn hash_secret(secret: &str) -> Vec<u8> {
    // Secrets are 32 random bytes: a fast hash is enough; nothing here is guessable.
    blake3::hash(secret.as_bytes()).as_bytes().to_vec()
}

impl Registry {
    // ---- accounts ----

    pub fn account(&self, login: &str) -> anyhow::Result<Option<AccountRec>> {
        self.cached(format!("account:{login}"), || self.account_uncached(login))
    }

    fn account_uncached(&self, login: &str) -> anyhow::Result<Option<AccountRec>> {
        let db = self.db.lock().unwrap();
        let mut st =
            db.prepare_cached("SELECT login, display_name, kind, owner, created_at_ms FROM accounts WHERE login = ?1")?;
        let mut rows = st.query_map([login], |r| {
            Ok(AccountRec {
                login: r.get(0)?,
                display_name: r.get(1)?,
                kind: AccountKind::try_from(r.get::<_, i32>(2)?).unwrap_or(AccountKind::Person),
                owner: r.get(3)?,
                created_at_ms: r.get(4)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Records an account the first time a login is seen; true if it was new.
    pub fn ensure_account(&self, login: &str, owner: &str) -> anyhow::Result<bool> {
        let db = self.db.lock().unwrap();
        let display = login.rsplit('/').next().unwrap_or(login).split('@').next().unwrap_or(login);
        let n = db.execute(
            "INSERT OR IGNORE INTO accounts (login, display_name, kind, owner, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            (login, display, kind_of(login) as i32, owner, now_ms()),
        )?;
        drop(db);
        if n == 1 {
            self.invalidate();
        }
        Ok(n == 1)
    }

    // ---- organisations, members, teams ----

    pub fn organization(&self, login: &str) -> anyhow::Result<Option<OrgRec>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached(
            "SELECT login, display_name, description, created_at_ms FROM organizations WHERE login = ?1",
        )?;
        let mut rows = st.query_map([login], |r| {
            Ok(OrgRec { login: r.get(0)?, display_name: r.get(1)?, description: r.get(2)?, created_at_ms: r.get(3)? })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn organizations(&self) -> anyhow::Result<Vec<OrgRec>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached(
            "SELECT login, display_name, description, created_at_ms FROM organizations ORDER BY login",
        )?;
        let rows = st.query_map([], |r| {
            Ok(OrgRec { login: r.get(0)?, display_name: r.get(1)?, description: r.get(2)?, created_at_ms: r.get(3)? })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Adds an organisation; false if it already exists.
    pub fn create_organization(&self, org: &OrgRec) -> anyhow::Result<bool> {
        self.invalidate();
        let db = self.db.lock().unwrap();
        let n = db.execute(
            "INSERT OR IGNORE INTO organizations (login, display_name, description, created_at_ms) VALUES (?1, ?2, ?3, ?4)",
            (&org.login, &org.display_name, &org.description, org.created_at_ms),
        )?;
        Ok(n == 1)
    }

    /// Members of `org` with their roles, ordered by login.
    pub fn members(&self, org: &str) -> anyhow::Result<Vec<(String, Role)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached("SELECT login, role FROM members WHERE org = ?1 ORDER BY login")?;
        let rows = st.query_map([org], |r| Ok((r.get::<_, String>(0)?, role_from(r.get(1)?))))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Sets a member's role; `Role::Unspecified` removes the member and their team places.
    pub fn set_member(&self, org: &str, login: &str, role: Role) -> anyhow::Result<()> {
        self.invalidate();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        if role == Role::Unspecified {
            tx.execute("DELETE FROM members WHERE org = ?1 AND login = ?2", (org, login))?;
            tx.execute("DELETE FROM team_members WHERE org = ?1 AND login = ?2", (org, login))?;
        } else {
            tx.execute(
                "INSERT INTO members (org, login, role) VALUES (?1, ?2, ?3)
                 ON CONFLICT (org, login) DO UPDATE SET role = excluded.role",
                (org, login, role as i32),
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether `login` belongs to `org`, directly or through one of its teams.
    pub fn in_org(&self, login: &str, org: &str) -> anyhow::Result<bool> {
        self.cached(format!("org:{login}:{org}"), || {
            let db = self.db.lock().unwrap();
            Ok(db.query_row(
                "SELECT EXISTS (SELECT 1 FROM members WHERE org = ?1 AND login = ?2)
                     OR EXISTS (SELECT 1 FROM team_members WHERE org = ?1 AND login = ?2)",
                (org, login),
                |r| r.get(0),
            )?)
        })
    }

    /// Organisations `login` belongs to, with its role in each.
    pub fn memberships(&self, login: &str) -> anyhow::Result<Vec<(String, Role)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached("SELECT org, role FROM members WHERE login = ?1 ORDER BY org")?;
        let rows = st.query_map([login], |r| Ok((r.get::<_, String>(0)?, role_from(r.get(1)?))))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn teams(&self, org: &str) -> anyhow::Result<Vec<TeamRec>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached("SELECT slug, name, description FROM teams WHERE org = ?1 ORDER BY slug")?;
        let mut teams = st
            .query_map([org], |r| {
                Ok(TeamRec {
                    org: org.to_owned(),
                    slug: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    members: Vec::new(),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut st = db.prepare_cached("SELECT login FROM team_members WHERE org = ?1 AND slug = ?2 ORDER BY login")?;
        for t in &mut teams {
            t.members = st.query_map((org, &t.slug), |r| r.get(0))?.collect::<Result<_, _>>()?;
        }
        Ok(teams)
    }

    /// Creates or replaces a team. Every member must already belong to the organisation.
    pub fn set_team(&self, team: &TeamRec) -> anyhow::Result<()> {
        self.invalidate();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "INSERT INTO teams (org, slug, name, description) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (org, slug) DO UPDATE SET name = excluded.name, description = excluded.description",
            (&team.org, &team.slug, &team.name, &team.description),
        )?;
        tx.execute("DELETE FROM team_members WHERE org = ?1 AND slug = ?2", (&team.org, &team.slug))?;
        for m in &team.members {
            tx.execute("INSERT INTO team_members (org, slug, login) VALUES (?1, ?2, ?3)", (&team.org, &team.slug, m))?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Removes a team, its members and its grants; false if there was no such team.
    pub fn delete_team(&self, org: &str, slug: &str) -> anyhow::Result<bool> {
        self.invalidate();
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let n = tx.execute("DELETE FROM teams WHERE org = ?1 AND slug = ?2", (org, slug))?;
        tx.execute("DELETE FROM team_members WHERE org = ?1 AND slug = ?2", (org, slug))?;
        tx.execute("DELETE FROM grants WHERE principal = ?1", [format!("{org}/{slug}")])?;
        tx.commit()?;
        Ok(n == 1)
    }

    /// Whether `org/slug` names a team (rather than an agent such as `agent/x`).
    pub fn is_team(&self, principal: &str) -> anyhow::Result<bool> {
        let Some((org, slug)) = principal.split_once('/') else { return Ok(false) };
        let db = self.db.lock().unwrap();
        let n: i64 =
            db.query_row("SELECT COUNT(*) FROM teams WHERE org = ?1 AND slug = ?2", (org, slug), |r| r.get(0))?;
        Ok(n > 0)
    }

    /// Whether `login` belongs to the team `org/slug`.
    pub fn in_team(&self, login: &str, team: &str) -> anyhow::Result<bool> {
        self.cached(format!("team:{login}:{team}"), || self.in_team_uncached(login, team))
    }

    fn in_team_uncached(&self, login: &str, team: &str) -> anyhow::Result<bool> {
        let Some((org, slug)) = team.split_once('/') else { return Ok(false) };
        let db = self.db.lock().unwrap();
        Ok(db.query_row(
            "SELECT EXISTS (SELECT 1 FROM team_members WHERE org = ?1 AND slug = ?2 AND login = ?3)",
            (org, slug, login),
            |r| r.get(0),
        )?)
    }

    // ---- grants ----

    pub fn grants(&self, key: &RepoKey) -> anyhow::Result<Vec<(String, Role)>> {
        let db = self.db.lock().unwrap();
        let mut st =
            db.prepare_cached("SELECT principal, role FROM grants WHERE owner = ?1 AND name = ?2 ORDER BY principal")?;
        let rows = st.query_map((&key.owner, &key.name), |r| Ok((r.get::<_, String>(0)?, role_from(r.get(1)?))))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Grants `role` on a repository; `Role::Unspecified` removes the grant.
    pub fn set_grant(&self, key: &RepoKey, principal: &str, role: Role) -> anyhow::Result<()> {
        self.invalidate();
        let db = self.db.lock().unwrap();
        if role == Role::Unspecified {
            db.execute(
                "DELETE FROM grants WHERE owner = ?1 AND name = ?2 AND principal = ?3",
                (&key.owner, &key.name, principal),
            )?;
        } else {
            db.execute(
                "INSERT INTO grants (owner, name, principal, role) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (owner, name, principal) DO UPDATE SET role = excluded.role",
                (&key.owner, &key.name, principal, role as i32),
            )?;
        }
        Ok(())
    }

    /// The highest role `login` holds on `repo` through organisation membership, direct
    /// grants and teams. Visibility, site administrators, agents' owners and token limits are
    /// applied by [`crate::permissions::Access`].
    pub fn held_role(&self, login: &str, repo: &RepoKey) -> anyhow::Result<Role> {
        self.cached(format!("role:{login}:{repo}"), || self.held_role_uncached(login, repo))
    }

    fn held_role_uncached(&self, login: &str, repo: &RepoKey) -> anyhow::Result<Role> {
        let db = self.db.lock().unwrap();
        let best: Option<i32> = db
            .prepare_cached(
                "SELECT MAX(role) FROM (
                   SELECT role FROM members WHERE org = ?1 AND login = ?3
                   UNION ALL
                   SELECT role FROM grants WHERE owner = ?1 AND name = ?2 AND principal = ?3
                   UNION ALL
                   SELECT g.role FROM grants g JOIN team_members t ON g.principal = t.org || '/' || t.slug
                   WHERE g.owner = ?1 AND g.name = ?2 AND t.login = ?3
                 )",
            )?
            .query_row((&repo.owner, &repo.name, login), |r| r.get(0))?;
        Ok(best.map(role_from).unwrap_or(Role::Unspecified))
    }

    // ---- tokens ----

    /// Creates a token and returns it with its secret, which is never stored.
    pub fn create_token(&self, mut rec: TokenRec) -> anyhow::Result<(TokenRec, String)> {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).context("reading random bytes for a token")?;
        let secret = format!("{TOKEN_PREFIX}{}", hex::encode(raw));
        let mut id = [0u8; 8];
        getrandom::fill(&mut id).context("reading random bytes for a token id")?;
        rec.id = hex::encode(id);
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO tokens (id, hash, account, name, acts_as, repositories, max_role, created_at_ms, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            (
                &rec.id,
                hash_secret(&secret),
                &rec.account,
                &rec.name,
                &rec.acts_as,
                rec.repositories.join(","),
                rec.max_role as i32,
                rec.created_at_ms,
                rec.expires_at_ms,
            ),
        )?;
        Ok((rec, secret))
    }

    fn token_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<TokenRec> {
        Ok(TokenRec {
            id: r.get(0)?,
            account: r.get(1)?,
            name: r.get(2)?,
            acts_as: r.get(3)?,
            repositories: split_list(r.get(4)?),
            max_role: role_from(r.get(5)?),
            created_at_ms: r.get(6)?,
            expires_at_ms: r.get(7)?,
            last_used_at_ms: r.get(8)?,
        })
    }

    pub fn tokens(&self, account: &str) -> anyhow::Result<Vec<TokenRec>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached(
            "SELECT id, account, name, acts_as, repositories, max_role, created_at_ms, expires_at_ms, last_used_at_ms
             FROM tokens WHERE account = ?1 ORDER BY created_at_ms DESC",
        )?;
        let rows = st.query_map([account], Self::token_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn token(&self, id: &str) -> anyhow::Result<Option<TokenRec>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached(
            "SELECT id, account, name, acts_as, repositories, max_role, created_at_ms, expires_at_ms, last_used_at_ms
             FROM tokens WHERE id = ?1",
        )?;
        let mut rows = st.query_map([id], Self::token_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn revoke_token(&self, id: &str) -> anyhow::Result<bool> {
        let db = self.db.lock().unwrap();
        Ok(db.execute("DELETE FROM tokens WHERE id = ?1", [id])? == 1)
    }

    pub fn has_tokens(&self) -> anyhow::Result<bool> {
        let db = self.db.lock().unwrap();
        Ok(db.query_row("SELECT EXISTS (SELECT 1 FROM tokens)", [], |r| r.get(0))?)
    }

    /// The token a secret belongs to, if it exists and has not expired. Records when it was
    /// last used, at most once a minute so authentication stays a read.
    pub fn use_token(&self, secret: &str) -> anyhow::Result<Option<TokenRec>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached(
            "SELECT id, account, name, acts_as, repositories, max_role, created_at_ms, expires_at_ms, last_used_at_ms
             FROM tokens WHERE hash = ?1",
        )?;
        let Some(t) = st.query_map([hash_secret(secret)], Self::token_row)?.next().transpose()? else {
            return Ok(None);
        };
        let now = now_ms();
        if t.expires_at_ms != 0 && t.expires_at_ms <= now {
            return Ok(None);
        }
        if now - t.last_used_at_ms > 60_000 {
            db.execute("UPDATE tokens SET last_used_at_ms = ?1 WHERE id = ?2", (now, &t.id))?;
        }
        Ok(Some(t))
    }
}

/// Checks a requested set of logins against an organisation's members.
pub fn require_members(reg: &Registry, org: &str, logins: &[String]) -> Result<(), Status> {
    let members: BTreeSet<String> = reg.members(org).map_err(internal)?.into_iter().map(|(l, _)| l).collect();
    if let Some(stranger) = logins.iter().find(|l| !members.contains(*l)) {
        return Err(Status::failed_precondition(format!("`{stranger}` is not a member of {org}; add them first")));
    }
    Ok(())
}

/// Repositories as a token names them must exist.
pub fn require_repositories(reg: &Registry, names: &[String]) -> Result<Vec<RepoRecord>, Status> {
    names
        .iter()
        .map(|n| {
            let key = RepoKey::parse(n)?;
            reg.get(&key)
                .map_err(internal)?
                .ok_or_else(|| Status::not_found(format!("no repository `{key}` on this server")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        Registry::open("memory").unwrap()
    }

    #[test]
    fn logins_are_safe() {
        for ok in ["kabir", "alice@corp.example", "agent/refactor-07", "bot/ci", "a.b+c"] {
            assert!(valid_login(ok), "{ok}");
        }
        for bad in ["", "a b", "/x", ".x", "x;y", "x\n", &"x".repeat(101)] {
            assert!(!valid_login(bad), "{bad:?}");
        }
        assert_eq!(kind_of("agent/x"), AccountKind::Agent);
        assert_eq!(kind_of("kabir"), AccountKind::Person);
    }

    #[test]
    fn roles_come_from_membership_grants_and_teams() {
        let r = registry();
        let fleet = RepoKey::parse("lumen/fleet").unwrap();
        let web = RepoKey::parse("lumen/web").unwrap();
        assert_eq!(r.held_role("mira", &fleet).unwrap(), Role::Unspecified);
        r.set_member("lumen", "mira", Role::Read).unwrap();
        assert_eq!(r.held_role("mira", &fleet).unwrap(), Role::Read);
        r.set_grant(&fleet, "mira", Role::Write).unwrap();
        assert_eq!(r.held_role("mira", &fleet).unwrap(), Role::Write);
        assert_eq!(r.held_role("mira", &web).unwrap(), Role::Read, "a grant is per repository");
        r.set_team(&TeamRec {
            org: "lumen".into(),
            slug: "platform".into(),
            name: "Platform".into(),
            description: String::new(),
            members: vec!["mira".into()],
        })
        .unwrap();
        r.set_grant(&web, "lumen/platform", Role::Maintain).unwrap();
        assert!(r.is_team("lumen/platform").unwrap());
        assert!(!r.is_team("agent/x").unwrap());
        assert_eq!(r.held_role("mira", &web).unwrap(), Role::Maintain, "through the team");
        // Leaving the organisation removes team places too.
        r.set_member("lumen", "mira", Role::Unspecified).unwrap();
        assert_eq!(r.held_role("mira", &web).unwrap(), Role::Unspecified);
        assert_eq!(r.held_role("mira", &fleet).unwrap(), Role::Write, "direct grants stay until removed");
        assert!(r.delete_team("lumen", "platform").unwrap());
        assert!(r.grants(&web).unwrap().is_empty(), "a deleted team's grants go with it");
    }

    #[test]
    fn cached_roles_change_the_moment_access_changes() {
        let r = registry();
        let fleet = RepoKey::parse("lumen/fleet").unwrap();
        assert_eq!(r.held_role("mira", &fleet).unwrap(), Role::Unspecified);
        r.set_member("lumen", "mira", Role::Write).unwrap();
        assert_eq!(r.held_role("mira", &fleet).unwrap(), Role::Write, "granted: seen at once");
        r.set_member("lumen", "mira", Role::Unspecified).unwrap();
        assert_eq!(r.held_role("mira", &fleet).unwrap(), Role::Unspecified, "revoked: seen at once");
    }

    #[test]
    fn tokens_are_stored_as_hashes_and_expire() {
        let r = registry();
        let now = now_ms();
        let rec = |expires| TokenRec {
            id: String::new(),
            account: "kabir".into(),
            name: "laptop".into(),
            acts_as: "kabir".into(),
            repositories: vec![],
            max_role: Role::Admin,
            created_at_ms: now,
            expires_at_ms: expires,
            last_used_at_ms: 0,
        };
        let (t, secret) = r.create_token(rec(now + 60_000)).unwrap();
        assert!(secret.starts_with(TOKEN_PREFIX) && secret.len() == TOKEN_PREFIX.len() + 64);
        let db = r.db.lock().unwrap();
        let stored: Vec<u8> = db.query_row("SELECT hash FROM tokens WHERE id = ?1", [&t.id], |row| row.get(0)).unwrap();
        drop(db);
        assert_ne!(stored, secret.as_bytes(), "only a hash is stored");
        let used = r.use_token(&secret).unwrap().unwrap();
        assert_eq!(used.id, t.id);
        assert!(used.last_used_at_ms == 0 && r.token(&t.id).unwrap().unwrap().last_used_at_ms > 0);
        assert!(r.use_token("pando_0000").unwrap().is_none());
        let (_, old) = r.create_token(rec(now - 1)).unwrap();
        assert!(r.use_token(&old).unwrap().is_none(), "an expired token is refused");
        assert!(r.revoke_token(&t.id).unwrap());
        assert!(r.use_token(&secret).unwrap().is_none(), "a revoked token is refused");
    }

    #[test]
    fn existing_repository_owners_become_organisations() {
        let r = registry();
        r.create(&RepoRecord {
            key: RepoKey::parse("acme/app").unwrap(),
            description: String::new(),
            visibility: 1,
            default_branch: "main".into(),
            created_at_ms: 5,
            archived: false,
            topics: vec![],
        })
        .unwrap();
        // Reopening applies the schema again, which records owners as organisations.
        r.migrate().unwrap();
        assert_eq!(r.organization("acme").unwrap().unwrap().created_at_ms, 5);
    }
}
