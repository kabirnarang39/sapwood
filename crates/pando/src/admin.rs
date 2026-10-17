//! `pando org`, `pando team`, `pando token`, `pando repo grant` and `pando admin`: who may use a server that
//! hosts many repositories (`pandod server --platform`).

use anyhow::{Context, Result, anyhow};
use clap::{Subcommand, ValueEnum};
use pando::remote::Ch;
use pando_proto::platform_client::PlatformClient;
use pando_proto::{
    CreateOrganizationRequest, CreateTokenRequest, Empty, LinkIdentityRequest, OrgName, RepositoryRef,
    RevokeTokenRequest, Role, SetGrantRequest, SetMemberRequest, SetSignupAllowRequest, Team, TeamRef,
};

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A role, as typed on the command line.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum RoleArg {
    Read,
    Triage,
    Write,
    Maintain,
    Admin,
    /// Removes the member or grant.
    None,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::Read => Role::Read,
            RoleArg::Triage => Role::Triage,
            RoleArg::Write => Role::Write,
            RoleArg::Maintain => Role::Maintain,
            RoleArg::Admin => Role::Admin,
            RoleArg::None => Role::Unspecified,
        }
    }
}

fn role_name(r: i32) -> &'static str {
    match Role::try_from(r).unwrap_or(Role::Unspecified) {
        Role::Unspecified => "-",
        Role::Read => "read",
        Role::Triage => "triage",
        Role::Write => "write",
        Role::Maintain => "maintain",
        Role::Admin => "admin",
    }
}

#[derive(Subcommand)]
pub enum OrgCmd {
    /// Organisations you belong to (all of them, for site administrators).
    List,
    /// Create an organisation; you become its administrator. Site administrators only.
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
    },
    /// List an organisation's members and their roles.
    Members { org: String },
    /// Add a member, change their role, or remove them with `none`.
    Member { org: String, login: String, role: RoleArg },
}

#[derive(Subcommand)]
pub enum TeamCmd {
    /// List an organisation's teams.
    List { org: String },
    /// Create a team, or replace its members: `pando team set lumen/platform --member mira`.
    Set {
        /// ORG/TEAM
        team: String,
        /// A member of the organisation (repeatable).
        #[arg(long = "member")]
        members: Vec<String>,
        #[arg(long, default_value = "")]
        name: String,
    },
    /// Delete a team and its grants.
    Delete {
        /// ORG/TEAM
        team: String,
    },
}

#[derive(Subcommand)]
pub enum WebhookCmd {
    /// A repository's webhooks: `pando webhook list lumen/fleet`.
    List {
        repo: String,
    },
    /// Call URL when something happens in the repository. Prints the signing secret once.
    Add {
        repo: String,
        url: String,
        /// Only these events (repeatable): push, change_request, review, comment, check.
        #[arg(long = "event")]
        events: Vec<String>,
    },
    /// Send a ping now and show how it went.
    Ping {
        id: String,
    },
    /// Recent deliveries and their answers.
    Log {
        id: String,
    },
    Remove {
        id: String,
    },
}

#[derive(Subcommand)]
pub enum TokenCmd {
    /// Your tokens.
    List,
    /// Create a token. Prints it once: store it as PANDO_TOKEN.
    Create {
        name: String,
        /// Act as an agent you answer for, e.g. `agent/refactor-07` (created if new).
        #[arg(long = "as")]
        acts_as: Option<String>,
        /// Only these repositories, OWNER/NAME (repeatable); default: all you can reach.
        #[arg(long = "repo")]
        repositories: Vec<String>,
        /// Highest role the token may use.
        #[arg(long, value_enum, default_value = "write")]
        role: RoleArg,
        /// Days until it expires (1–366).
        #[arg(long, default_value_t = 90)]
        days: i64,
    },
    /// Revoke a token by its id.
    Revoke { id: String },
}

#[derive(Subcommand)]
pub enum AdminCmd {
    /// Who may create an account by signing in (`pandod server --signup waitlist`).
    Signup {
        #[command(subcommand)]
        action: SignupCmd,
    },
    /// Ways people sign in from a browser.
    Identity {
        #[command(subcommand)]
        action: IdentityCmd,
    },
}

#[derive(Subcommand)]
pub enum IdentityCmd {
    /// Let an identity sign in as an existing account, e.g. the first administrator:
    /// `pando admin identity link kabir --provider email --subject kabir@example.com`.
    Link {
        login: String,
        /// `email`, or a sign-in provider's id such as `google`.
        #[arg(long)]
        provider: String,
        /// The email address, or the provider's `sub` for the person.
        #[arg(long)]
        subject: String,
    },
}

#[derive(Subcommand)]
pub enum SignupCmd {
    /// Let an email address, or everyone at `@domain`, create an account.
    Allow {
        entry: String,
    },
    /// Take an entry off the list (accounts already created stay).
    Remove {
        entry: String,
    },
    List,
}

fn explain(s: tonic::Status) -> anyhow::Error {
    if s.code() == tonic::Code::Unimplemented {
        anyhow!("this server hosts one repository; start pandod with --platform to manage organisations and tokens")
    } else {
        anyhow!("{}", s.message())
    }
}

fn split(s: &str, what: &str) -> Result<(String, String)> {
    let (a, b) = s.split_once('/').with_context(|| format!("give the {what} as OWNER/NAME"))?;
    Ok((a.to_owned(), b.to_owned()))
}

pub async fn org(mut p: PlatformClient<Ch>, cmd: OrgCmd) -> Result<()> {
    match cmd {
        OrgCmd::List => {
            for o in p.list_organizations(Empty {}).await.map_err(explain)?.into_inner().organizations {
                println!(
                    "{}\t{} repositories\t{} people\t{} agents\t{}",
                    o.login,
                    o.repositories,
                    o.members,
                    o.agents,
                    role_name(o.viewer_role)
                );
            }
        }
        OrgCmd::Create { name, description } => {
            let o = p
                .create_organization(CreateOrganizationRequest {
                    login: name,
                    display_name: String::new(),
                    description,
                })
                .await
                .map_err(explain)?
                .into_inner();
            println!("created {}; add people with: pando org member {} LOGIN write", o.login, o.login);
        }
        OrgCmd::Members { org } => {
            for m in p.list_members(OrgName { login: org }).await.map_err(explain)?.into_inner().members {
                let login = m.account.map(|a| a.login).unwrap_or_default();
                println!("{login}\t{}\t{}", role_name(m.role), m.teams.join(","));
            }
        }
        OrgCmd::Member { org, login, role } => {
            p.set_member(SetMemberRequest { org: org.clone(), login: login.clone(), role: Role::from(role) as i32 })
                .await
                .map_err(explain)?;
            match role {
                RoleArg::None => println!("removed {login} from {org}"),
                r => println!("{login} is now {} in {org}", role_name(Role::from(r) as i32)),
            }
        }
    }
    Ok(())
}

pub async fn team(mut p: PlatformClient<Ch>, cmd: TeamCmd) -> Result<()> {
    match cmd {
        TeamCmd::List { org } => {
            for t in p.list_teams(OrgName { login: org }).await.map_err(explain)?.into_inner().teams {
                println!("{}/{}\t{}\t{}", t.org, t.slug, t.name, t.members.join(","));
            }
        }
        TeamCmd::Set { team, members, name } => {
            let (org, slug) = split(&team, "team")?;
            let t = p
                .set_team(Team { org, slug, name, description: String::new(), members })
                .await
                .map_err(explain)?
                .into_inner();
            println!(
                "{}/{}: {}",
                t.org,
                t.slug,
                if t.members.is_empty() { "no members".into() } else { t.members.join(", ") }
            );
        }
        TeamCmd::Delete { team } => {
            let (org, slug) = split(&team, "team")?;
            p.delete_team(TeamRef { org, slug }).await.map_err(explain)?;
            println!("deleted {team}");
        }
    }
    Ok(())
}

/// `pando repo grant OWNER/NAME PRINCIPAL ROLE`; without a principal, lists the grants.
pub async fn grant(
    mut p: PlatformClient<Ch>,
    repo: &str,
    principal: Option<String>,
    role: Option<RoleArg>,
) -> Result<()> {
    let (owner, name) = split(repo, "repository")?;
    let r = RepositoryRef { owner, name };
    match (principal, role) {
        (Some(principal), Some(role)) => {
            p.set_grant(SetGrantRequest {
                repository: Some(r),
                principal: principal.clone(),
                role: Role::from(role) as i32,
            })
            .await
            .map_err(explain)?;
            match role {
                RoleArg::None => println!("removed {principal}'s access to {repo}"),
                r => println!("{principal} has {} access to {repo}", role_name(Role::from(r) as i32)),
            }
        }
        (None, None) => {
            for g in p.list_grants(r).await.map_err(explain)?.into_inner().grants {
                println!("{}\t{}", g.principal, role_name(g.role));
            }
        }
        _ => return Err(anyhow!("give both a principal and a role, or neither to list access")),
    }
    Ok(())
}

pub async fn token(mut p: PlatformClient<Ch>, cmd: TokenCmd) -> Result<()> {
    match cmd {
        TokenCmd::List => {
            let now = now_ms();
            for t in p.list_tokens(Empty {}).await.map_err(explain)?.into_inner().tokens {
                let days = ((t.expires_at_ms - now).max(0) + 86_399_999) / 86_400_000;
                let scope = if t.repositories.is_empty() { "all".to_owned() } else { t.repositories.join(",") };
                println!(
                    "{}\t{}\tas {}\t{}\t{scope}\texpires in {days} days",
                    t.id,
                    t.name,
                    t.acts_as,
                    role_name(t.max_role)
                );
            }
        }
        TokenCmd::Create { name, acts_as, repositories, role, days } => {
            anyhow::ensure!((1..=366).contains(&days), "--days must be between 1 and 366");
            let expires_at_ms = now_ms() + days * 86_400_000;
            let r = p
                .create_token(CreateTokenRequest {
                    name,
                    acts_as: acts_as.unwrap_or_default(),
                    repositories,
                    max_role: Role::from(role) as i32,
                    expires_at_ms,
                })
                .await
                .map_err(explain)?
                .into_inner();
            let t = r.token.unwrap_or_default();
            eprintln!("token {} acts as {}, expires in {days} days; it is shown once:", t.id, t.acts_as);
            println!("{}", r.secret);
        }
        TokenCmd::Revoke { id } => {
            p.revoke_token(RevokeTokenRequest { id: id.clone() }).await.map_err(explain)?;
            println!("revoked {id}");
        }
    }
    Ok(())
}

pub async fn webhook(mut p: PlatformClient<Ch>, cmd: WebhookCmd) -> Result<()> {
    use pando_proto::{CreateWebhookRequest, WebhookRef};
    let status = |s: i32| match s {
        0 => "not sent yet".to_owned(),
        -1 => "no answer".to_owned(),
        s => format!("HTTP {s}"),
    };
    match cmd {
        WebhookCmd::List { repo } => {
            let (owner, name) = split(&repo, "repository")?;
            for h in p.list_webhooks(RepositoryRef { owner, name }).await.map_err(explain)?.into_inner().webhooks {
                let events = if h.events.is_empty() { "every event".to_owned() } else { h.events.join(",") };
                println!("{}\t{}\t{events}\tlast: {}", h.id, h.url, status(h.last_status));
            }
        }
        WebhookCmd::Add { repo, url, events } => {
            let (owner, name) = split(&repo, "repository")?;
            let r = p
                .create_webhook(CreateWebhookRequest {
                    repository: Some(RepositoryRef { owner, name }),
                    url,
                    events,
                    secret: String::new(),
                })
                .await
                .map_err(explain)?
                .into_inner();
            let h = r.webhook.unwrap_or_default();
            eprintln!("webhook {} calls {}; verify X-Pando-Signature-256 with this secret, shown once:", h.id, h.url);
            println!("{}", r.secret);
        }
        WebhookCmd::Ping { id } => {
            let d = p.ping_webhook(WebhookRef { id }).await.map_err(explain)?.into_inner();
            println!(
                "{}{}",
                status(d.status),
                if d.error.is_empty() { String::new() } else { format!(": {}", d.error) }
            );
        }
        WebhookCmd::Log { id } => {
            for d in p.list_webhook_deliveries(WebhookRef { id }).await.map_err(explain)?.into_inner().deliveries {
                let state = if d.delivered {
                    "delivered"
                } else if d.attempts >= 8 {
                    "gave up"
                } else {
                    "retrying"
                };
                println!("{}\t{}\t{state}\t{}\t{} attempts\t{}", d.id, d.event, status(d.status), d.attempts, d.error);
            }
        }
        WebhookCmd::Remove { id } => {
            p.delete_webhook(WebhookRef { id: id.clone() }).await.map_err(explain)?;
            println!("removed webhook {id}");
        }
    }
    Ok(())
}

pub async fn admin(mut p: PlatformClient<Ch>, cmd: AdminCmd) -> Result<()> {
    let action = match cmd {
        AdminCmd::Signup { action } => action,
        AdminCmd::Identity { action: IdentityCmd::Link { login, provider, subject } } => {
            p.link_identity(LinkIdentityRequest {
                login: login.clone(),
                provider: provider.clone(),
                subject: subject.clone(),
            })
            .await
            .map_err(explain)?;
            println!("{provider} {subject} now signs in as {login}");
            return Ok(());
        }
    };
    match action {
        SignupCmd::Allow { entry } => {
            p.set_signup_allow(SetSignupAllowRequest { entry: entry.clone(), allowed: true }).await.map_err(explain)?;
            println!("{entry} may sign up");
        }
        SignupCmd::Remove { entry } => {
            p.set_signup_allow(SetSignupAllowRequest { entry: entry.clone(), allowed: false })
                .await
                .map_err(explain)?;
            println!("removed {entry}");
        }
        SignupCmd::List => {
            for e in p.list_signup_allow(Empty {}).await.map_err(explain)?.into_inner().entries {
                println!("{e}");
            }
        }
    }
    Ok(())
}
