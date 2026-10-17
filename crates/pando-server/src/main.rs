use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use pando_adapters::acl::RulesPolicy;
use pando_adapters::flags::SpecFlags;
use pando_core::acl::{AccessPolicy, AllowAllPolicy};
use pando_core::flags::{FeatureFlags, Flag};
use pando_core::ports::{LandCheck, NoChecks};
use pando_server::auth::{AllowAll, Authenticator, StaticTokens};
use pando_server::features::land::Land;
use pando_server::land_hook::WebhookCheck;
use pando_server::oidc::{FirstMatch, OidcAuthenticator, OidcConfig};
use pando_server::permissions::{Access, NoOtherAuth, ProtectedRefs};
use pando_server::{authority_routes, config, serve, telemetry, tier_routes};
use tonic::transport::{Identity, ServerTlsConfig};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "pandod", version, about = "Pando: source control server, regional cache and node daemon")]
struct Cli {
    #[command(subcommand)]
    role: Role,
    /// Prometheus metrics listen address, e.g. 0.0.0.0:9420.
    #[arg(long, global = true, env = "PANDO_METRICS")]
    metrics: Option<SocketAddr>,
    /// Emit JSON logs.
    #[arg(long, global = true, env = "PANDO_LOG_JSON")]
    log_json: bool,
    /// Append an audit trail (JSON lines: who read or changed what, from where, with what
    /// result) to this file. Off by default; it grows with every request.
    #[arg(long, global = true, env = "PANDO_AUDIT_LOG")]
    audit_log: Option<std::path::PathBuf>,
    /// Comma-separated origins allowed to call this server from a browser on another site,
    /// e.g. the web console's address; `*` allows any (development only).
    #[arg(long, global = true, env = "PANDO_WEB_ORIGINS", value_delimiter = ',')]
    web_origins: Vec<String>,
    /// Accept unauthenticated calls on a non-loopback address. Without tokens or OIDC, pandod
    /// otherwise listens only on localhost, so a server is never open to a network by accident.
    #[arg(long, global = true, env = "PANDO_ALLOW_ANONYMOUS", action = clap::ArgAction::SetTrue, value_parser = clap::builder::BoolishValueParser::new())]
    allow_anonymous: bool,
    /// Longest any one call may run, in seconds.
    #[arg(long, global = true, env = "PANDO_REQUEST_TIMEOUT", default_value_t = 600)]
    request_timeout: u64,
    /// Calls in progress at once across all clients; beyond this, calls are refused with
    /// Unavailable (clients retry) instead of queueing.
    #[arg(long, global = true, env = "PANDO_MAX_IN_FLIGHT", default_value_t = 4096)]
    max_in_flight: usize,
    /// Comma-separated bearer tokens accepted by this process. Unset = no auth (dev only).
    #[arg(long, global = true, env = "PANDO_TOKENS", hide_env_values = true)]
    tokens: Option<String>,
    /// OpenID Connect issuer URL; enables SSO bearer tokens (JWTs) alongside static tokens.
    #[arg(long, global = true, env = "PANDO_OIDC_ISSUER", requires = "oidc_audience")]
    oidc_issuer: Option<String>,
    /// Expected `aud` claim of OIDC tokens.
    #[arg(long, global = true, env = "PANDO_OIDC_AUDIENCE")]
    oidc_audience: Option<String>,
    /// Claim used as the principal for access rules (sub, email, preferred_username...).
    #[arg(long, global = true, env = "PANDO_OIDC_CLAIM", default_value = "sub")]
    oidc_claim: String,
    /// CLAIM=VALUE every OIDC token must carry (repeatable; all must match), e.g.
    /// `repository_owner=acme`, `hd=corp.example`, `email_verified=true`. Required for issuers
    /// that serve anyone (GitHub Actions, Google).
    #[arg(long = "oidc-require", global = true, env = "PANDO_OIDC_REQUIRE", value_delimiter = ',')]
    oidc_require: Vec<String>,
    /// Platform administrators who may sign in through OIDC (repeatable). Any other
    /// `--platform-admins` login is refused from an OIDC token, so an identity provider that
    /// lets users pick their name can't make someone an administrator.
    #[arg(long = "oidc-admin", global = true, env = "PANDO_OIDC_ADMINS", value_delimiter = ',')]
    oidc_admins: Vec<String>,
    /// PEM certificate and key for TLS.
    #[arg(long, global = true, env = "PANDO_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<std::path::PathBuf>,
    #[arg(long, global = true, env = "PANDO_TLS_KEY")]
    tls_key: Option<std::path::PathBuf>,
}

// Parsed once at startup; boxing the big variant would buy nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Role {
    /// Authoritative server: all features, durable storage.
    Server {
        #[arg(long, default_value = "127.0.0.1:7420")]
        listen: SocketAddr,
        /// memory | sqlite://PATH | postgres://...
        #[arg(long, env = "PANDO_METADATA", hide_env_values = true, default_value = "sqlite://./pando-data/meta.db")]
        metadata: String,
        /// metadata | file:///PATH | s3://BUCKET/PREFIX | gs://BUCKET | az://CONTAINER | memory:///
        #[arg(long, env = "PANDO_OBJECTS", hide_env_values = true, default_value = "metadata")]
        objects: String,
        /// JSON access rules (per-directory write and per-ref permissions). Unset = allow all.
        #[arg(long, env = "PANDO_ACL")]
        acl: Option<std::path::PathBuf>,
        /// Pre-land check: every land is POSTed here and proceeds only on a 2xx answer.
        #[arg(long, env = "PANDO_LAND_HOOK", hide_env_values = true)]
        land_hook: Option<String>,
        /// Bearer token sent to the land hook.
        #[arg(long, env = "PANDO_LAND_HOOK_TOKEN", hide_env_values = true, requires = "land_hook")]
        land_hook_token: Option<String>,
        /// Seconds to wait for the land hook before refusing the land.
        #[arg(long, default_value_t = 10)]
        land_hook_timeout: u64,
        /// Host many repositories: the registry of which exist (sqlite://PATH or memory).
        /// Without it the server hosts one repository, `--metadata` / `--objects`.
        #[arg(long, env = "PANDO_PLATFORM", hide_env_values = true)]
        platform: Option<String>,
        /// Storage for each hosted repository; `{repo}` becomes OWNER/NAME and `{repo_id}`
        /// OWNER--NAME, e.g. sqlite:///var/lib/pando/repos/{repo}.db
        #[arg(long, env = "PANDO_REPOS_METADATA", hide_env_values = true, requires = "platform")]
        repos_metadata: Option<String>,
        /// Objects for each hosted repository (same placeholders), or `metadata`.
        #[arg(long, env = "PANDO_REPOS_OBJECTS", hide_env_values = true, default_value = "metadata")]
        repos_objects: String,
        /// Logins that administer the whole server: create organisations, and act as an
        /// administrator of every organisation and repository.
        #[arg(long, env = "PANDO_PLATFORM_ADMINS", value_delimiter = ',')]
        platform_admins: Vec<String>,
        /// Serve the sign-in pages (`/login/*`: OpenID Connect providers such as Google, and
        /// email links) on this address, behind the same host name as the console.
        #[arg(long, env = "PANDO_LOGIN_LISTEN", requires_all = ["platform", "public_url"])]
        login_listen: Option<SocketAddr>,
        /// Where people reach this server, e.g. https://pando.example.com: the base of sign-in
        /// redirect addresses and email links.
        #[arg(long, env = "PANDO_PUBLIC_URL")]
        public_url: Option<String>,
        /// A sign-in provider, ID=ISSUER_URL (repeatable), e.g. google=https://accounts.google.com.
        /// Its client comes from PANDO_OIDC_<ID>_CLIENT_ID and PANDO_OIDC_<ID>_CLIENT_SECRET (or
        /// _FILE variants).
        #[arg(long = "oidc", value_name = "ID=ISSUER_URL")]
        oidc_providers: Vec<String>,
        /// Mail server for sign-in links: smtps://HOST:465 or smtp://HOST:587?tls=required.
        /// Credentials from PANDO_SMTP_USERNAME and PANDO_SMTP_PASSWORD (or _FILE variants).
        #[arg(long, env = "PANDO_SMTP_URL", hide_env_values = true)]
        smtp_url: Option<String>,
        /// Sender of sign-in links, e.g. "Pando <login@example.com>".
        #[arg(long, env = "PANDO_MAIL_FROM")]
        mail_from: Option<String>,
        /// Cloudflare Turnstile site key for the email form; its secret comes from
        /// PANDO_TURNSTILE_SECRET (or _FILE). Unset: no challenge.
        #[arg(long, env = "PANDO_TURNSTILE_SITE_KEY")]
        turnstile_site_key: Option<String>,
        /// Who may create an account by signing in: waitlist (`pando admin signup allow`),
        /// open, or closed. Existing accounts can always sign in.
        #[arg(long, env = "PANDO_SIGNUP", value_enum, default_value = "waitlist")]
        signup: pando_server::login::Signup,
    },
    /// Create an access token directly in a platform registry, without a running server: how
    /// the first administrator gets in. Prints the token once.
    Token {
        #[arg(long, env = "PANDO_PLATFORM", hide_env_values = true)]
        platform: String,
        /// The account the token belongs to and acts as (list it in --platform-admins to make
        /// it an administrator).
        #[arg(long)]
        account: String,
        #[arg(long, default_value = "bootstrap")]
        name: String,
        /// Days until it expires (1–366).
        #[arg(long, default_value_t = 30)]
        expires_days: i64,
    },
    /// Back up a platform server while it runs: a consistent snapshot of the registry and of
    /// every hosted repository's metadata database, with a manifest of where each belongs and
    /// where objects live. Restore by copying back while stopped (docs/deploy.md).
    Backup {
        #[arg(long, env = "PANDO_PLATFORM", hide_env_values = true)]
        platform: String,
        #[arg(long, env = "PANDO_REPOS_METADATA", hide_env_values = true)]
        repos_metadata: String,
        #[arg(long, env = "PANDO_REPOS_OBJECTS", hide_env_values = true, default_value = "metadata")]
        repos_objects: String,
        /// The server's default repository, backed up too when it is SQLite.
        #[arg(long, env = "PANDO_METADATA", hide_env_values = true)]
        metadata: Option<String>,
        /// A new or empty directory, or an object store URL (s3://BUCKET/PREFIX, gs://, az://).
        #[arg(long)]
        to: String,
    },
    /// Delta-compress stored blob versions (single writer; safe to run while serving).
    Compact {
        #[arg(long, env = "PANDO_METADATA", hide_env_values = true, default_value = "sqlite://./pando-data/meta.db")]
        metadata: String,
        #[arg(long, env = "PANDO_OBJECTS", hide_env_values = true, default_value = "metadata")]
        objects: String,
        /// Take over the lease of a compaction that crashed.
        #[arg(long)]
        force_unlock: bool,
    },
    /// Copy a repository to another store: a backup, a restore, or a move to another backend
    /// (e.g. SQLite to Postgres). Safe while the source serves; repeat it to copy only what
    /// is new.
    Copy {
        #[arg(long)]
        from_metadata: String,
        #[arg(long, default_value = "metadata")]
        from_objects: String,
        #[arg(long)]
        to_metadata: String,
        #[arg(long, default_value = "metadata")]
        to_objects: String,
    },
    /// Regional cache: stateless, memory-bounded, read-through to an upstream tier.
    Cache {
        #[arg(long, default_value = "127.0.0.1:7421")]
        listen: SocketAddr,
        #[arg(long, env = "PANDO_UPSTREAM", hide_env_values = true)]
        upstream: String,
        #[arg(long, default_value_t = 4096)]
        capacity_mb: u64,
    },
    /// Per-node daemon: memory + local disk cache shared by every job on the machine.
    Daemon {
        #[arg(long, default_value = "127.0.0.1:7422")]
        listen: SocketAddr,
        #[arg(long, env = "PANDO_UPSTREAM", hide_env_values = true)]
        upstream: String,
        #[arg(long, default_value = "./pando-daemon")]
        dir: String,
        #[arg(long, default_value_t = 512)]
        memory_mb: u64,
        /// Authoritative server, used to resolve `--prefetch` revisions.
        #[arg(long, env = "PANDO_SERVER", hide_env_values = true, requires = "prefetch")]
        server: Option<String>,
        /// Warm the cache with this revision (e.g. `main`) at startup.
        #[arg(long, requires = "server")]
        prefetch: Option<String>,
        /// Limit prefetch to these paths (repeatable).
        #[arg(long = "prefetch-path")]
        prefetch_paths: Vec<String>,
        /// Re-prefetch periodically (seconds) to follow a moving branch.
        #[arg(long, requires = "prefetch")]
        prefetch_interval: Option<u64>,
    },
}

fn create_token(platform: &str, account: &str, name: &str, days: i64) -> anyhow::Result<()> {
    use pando_server::directory::{TokenRec, valid_login};
    use pando_server::hosting::{Registry, now_ms};
    anyhow::ensure!(valid_login(account), "`{account}` is not a valid login");
    anyhow::ensure!((1..=366).contains(&days), "--expires-days must be between 1 and 366");
    let registry = Registry::open(platform)?;
    registry.ensure_account(account, "")?;
    let now = now_ms();
    let (t, secret) = registry.create_token(TokenRec {
        id: String::new(),
        account: account.to_owned(),
        name: name.to_owned(),
        acts_as: account.to_owned(),
        repositories: vec![],
        max_role: pando_proto::Role::Admin,
        created_at_ms: now,
        expires_at_ms: now + days * 86_400_000,
        last_used_at_ms: 0,
    })?;
    tracing::info!(target: telemetry::AUDIT, kind = "create_token", principal = "pandod token", target = %format!("{} as {account}", t.id));
    eprintln!("token {} for {account}, expires in {days} days; it is shown once:", t.id);
    println!("{secret}");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
    tracing::info!("shutting down");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    telemetry::init_logging(cli.log_json, cli.audit_log.as_deref())?;
    if let Some(addr) = cli.metrics {
        telemetry::init_metrics(addr)?;
    }
    if let Role::Token { platform, account, name, expires_days } = &cli.role {
        return create_token(platform, account, name, *expires_days);
    }
    if let Role::Backup { platform, repos_metadata, repos_objects, metadata, to } = &cli.role {
        let templates =
            pando_server::hosting::Templates { metadata: repos_metadata.clone(), objects: repos_objects.clone() };
        templates.validate()?;
        let s = pando_server::backup::backup(platform, &templates, metadata.as_deref(), to).await?;
        println!(
            "backed up the registry and {} repositories to {}: {}",
            s.repositories,
            config::redact(to),
            s.files.join(", ")
        );
        return Ok(());
    }
    let flags = Arc::new(SpecFlags::from_env()?);
    let web = pando_server::WebAccess {
        enabled: flags.enabled(pando_core::flags::Flag::Web),
        origins: cli.web_origins.iter().map(|o| o.trim().to_owned()).filter(|o| !o.is_empty()).collect(),
    };
    if web.origins.iter().any(|o| o == "*") {
        tracing::warn!("PANDO_WEB_ORIGINS=*: any website can call this server from a browser; use only in development");
    }
    let mut authenticators: Vec<Arc<dyn Authenticator>> = Vec::new();
    if let Some(t) = &cli.tokens {
        pando_server::auth::check_static_tokens(t)?;
        authenticators.push(Arc::new(StaticTokens::new(t.split(',').map(|s| s.trim().to_owned()))));
    }
    if let (Some(issuer), Some(audience)) = (&cli.oidc_issuer, &cli.oidc_audience) {
        if flags.enabled(Flag::Oidc) {
            let admins = match &cli.role {
                Role::Server { platform_admins, .. } => platform_admins.as_slice(),
                _ => &[],
            };
            let cfg = OidcConfig {
                issuer: issuer.clone(),
                audience: audience.clone(),
                principal_claim: cli.oidc_claim.clone(),
                require: cli.oidc_require.iter().map(|r| OidcConfig::parse_require(r)).collect::<Result<_, _>>()?,
                reserved: admins
                    .iter()
                    .map(|a| a.trim().to_owned())
                    .filter(|a| !a.is_empty() && !cli.oidc_admins.iter().any(|o| o.trim() == a))
                    .collect(),
            };
            cfg.check()?;
            authenticators.push(Arc::new(OidcAuthenticator::discover(cfg).await?));
            tracing::info!(%issuer, "OIDC authentication enabled");
        } else {
            tracing::warn!("--oidc-issuer ignored: feature `oidc` is disabled");
        }
    }
    let mut anonymous = authenticators.is_empty();
    let mut auth: Arc<dyn Authenticator> =
        if anonymous { Arc::new(AllowAll) } else { Arc::new(FirstMatch(authenticators)) };
    let tls = match (&cli.tls_cert, &cli.tls_key) {
        (Some(c), Some(k)) => {
            Some(ServerTlsConfig::new().identity(Identity::from_pem(std::fs::read(c)?, std::fs::read(k)?)))
        }
        _ => None,
    };
    let upstream_token = std::env::var("PANDO_UPSTREAM_TOKEN").ok();

    let mut hosting: Option<Arc<pando_server::hosting::Hosting>> = None;
    let (listen, routes) = match cli.role {
        Role::Server {
            listen,
            metadata,
            objects,
            acl,
            land_hook,
            land_hook_token,
            land_hook_timeout,
            platform,
            repos_metadata,
            repos_objects,
            platform_admins,
            login_listen,
            public_url,
            oidc_providers,
            smtp_url,
            mail_from,
            turnstile_site_key,
            signup,
        } => {
            let repo = config::open_repo(&metadata, &objects).await?;
            let policy: Arc<dyn AccessPolicy> = match &acl {
                Some(path) => Arc::new(RulesPolicy::load(path)?),
                None => Arc::new(AllowAllPolicy),
            };
            tracing::info!(%listen, metadata = %config::redact(&metadata), objects = %config::redact(&objects), acl = ?acl, "pandod server");
            let checks: Arc<dyn LandCheck> = match &land_hook {
                Some(url) => {
                    tracing::info!(hook = %config::redact(url), "pre-land checks enabled");
                    Arc::new(WebhookCheck::new(url, land_hook_token, Duration::from_secs(land_hook_timeout))?)
                }
                None => Arc::new(NoChecks),
            };
            if let Some(registry) = &platform {
                let templates = pando_server::hosting::Templates {
                    metadata: anyhow::Context::context(
                        repos_metadata.clone(),
                        "--platform needs --repos-metadata (e.g. sqlite:///var/lib/pando/repos/{repo}.db)",
                    )?,
                    objects: repos_objects.clone(),
                };
                let registry_db = Arc::new(pando_server::hosting::Registry::open(registry)?);
                // Platform tokens count as authentication: once one exists, every call needs one
                // (or a static token or single sign-on). With none of them, the server is open,
                // for local development.
                // With sign-in on, strangers can get accounts: the server is never open.
                let open = anonymous && !registry_db.has_tokens()? && login_listen.is_none();
                if anonymous && !open {
                    auth = Arc::new(NoOtherAuth);
                }
                anonymous = open;
                let admins: Vec<String> =
                    platform_admins.iter().map(|a| a.trim().to_owned()).filter(|a| !a.is_empty()).collect();
                if let Some(addr) = login_listen {
                    let settings = pando_server::login::Settings {
                        public_url: public_url.clone().unwrap_or_default(),
                        oidc: oidc_providers.clone(),
                        smtp_url: smtp_url.clone(),
                        mail_from: mail_from.clone(),
                        turnstile_site_key: turnstile_site_key.clone(),
                        signup,
                        reserved: admins.clone(),
                    };
                    let login = pando_server::login::Login::new(
                        settings,
                        registry_db.clone(),
                        &pando_server::login::env_secret,
                    )?;
                    let listener = tokio::net::TcpListener::bind(addr).await?;
                    tracing::info!(%addr, ?signup, "sign-in pages");
                    tokio::spawn(async move {
                        if let Err(e) = pando_server::login::serve(listener, Arc::new(login)).await {
                            tracing::error!(error = %e, "sign-in pages stopped");
                        }
                    });
                }
                let access = Arc::new(Access { open, admins });
                let (f, p, c, reg, acc) =
                    (flags.clone(), policy.clone(), checks.clone(), registry_db.clone(), access.clone());
                // Each repository's branches are protected by its own rules; change requests land
                // through their review instead.
                let build: pando_server::hosting::BuildRoutes = Arc::new(move |key, repo| {
                    let protected: Arc<dyn AccessPolicy> = Arc::new(ProtectedRefs {
                        inner: p.clone(),
                        registry: reg.clone(),
                        key: key.clone(),
                        access: acc.clone(),
                    });
                    pando_server::hosting::RepoServices {
                        routes: authority_routes(repo.clone(), f.clone(), protected, c.clone()),
                        review_land: Some(Land::new(repo, f.clone(), p.clone(), c.clone())),
                    }
                });
                hosting = Some(Arc::new(pando_server::hosting::Hosting::new(templates, registry_db, build, access)?));
                tracing::info!(registry = %config::redact(registry), open, "hosting many repositories");
            }
            (listen, authority_routes(repo, flags, policy, checks))
        }
        Role::Token { .. } | Role::Backup { .. } => unreachable!("handled before authentication is set up"),
        Role::Copy { from_metadata, from_objects, to_metadata, to_objects } => {
            let from = config::open_storage(&from_metadata, &from_objects).await?;
            let to = config::open_storage(&to_metadata, &to_objects).await?;
            let started = std::time::Instant::now();
            let s = pando_server::features::copy::copy(&from.raw, &to.raw).await?;
            println!(
                "copied {} refs, {} changesets, {} objects ({} already there), {} derived records in {:.1}s",
                s.refs,
                s.changesets,
                s.objects_copied,
                s.objects_present,
                s.derived,
                started.elapsed().as_secs_f64()
            );
            return Ok(());
        }
        Role::Compact { metadata, objects, force_unlock } => {
            let storage = config::open_storage(&metadata, &objects).await?;
            let started = std::time::Instant::now();
            let compactor = pando_server::features::compact::Compactor::new(storage.repo, storage.raw_objects, flags);
            let s = compactor.run(force_unlock).await?;
            if let Some(db) = storage.sqlite {
                db.vacuum().await?;
            }
            println!(
                "compacted {} of {} object versions ({} trees) in {:.1}s: {} -> {} bytes ({:.1}x); {} changesets scanned",
                s.converted,
                s.pairs,
                s.trees_converted,
                started.elapsed().as_secs_f64(),
                s.bytes_before,
                s.bytes_after,
                s.bytes_before as f64 / s.bytes_after.max(1) as f64,
                s.changesets
            );
            return Ok(());
        }
        Role::Cache { listen, upstream, capacity_mb } => {
            let store = config::cache_store(&upstream, upstream_token.as_deref(), capacity_mb << 20)?;
            tracing::info!(%listen, upstream = %config::redact(&upstream), capacity_mb, "pandod cache");
            (listen, tier_routes(store, flags))
        }
        Role::Daemon { listen, upstream, dir, memory_mb, server, prefetch, prefetch_paths, prefetch_interval } => {
            let store = config::daemon_store(&upstream, upstream_token.as_deref(), &dir, memory_mb << 20)?;
            tracing::info!(%listen, upstream = %config::redact(&upstream), %dir, "pandod daemon");
            if let (Some(server), Some(rev)) = (server, prefetch) {
                let p = pando_server::features::prefetch::Prefetcher::new(
                    &server,
                    upstream_token.as_deref(),
                    store.clone(),
                    flags.clone(),
                )?;
                // Warm in the background: the daemon serves (and fetches on demand) meanwhile.
                tokio::spawn(p.run(rev, prefetch_paths, prefetch_interval.map(std::time::Duration::from_secs)));
            }
            (listen, tier_routes(store, flags))
        }
    };
    if anonymous {
        tracing::warn!("no PANDO_TOKENS, OIDC issuer or platform token: authentication disabled");
    }
    if anonymous && !listen.ip().is_loopback() && !cli.allow_anonymous {
        anyhow::bail!(
            "refusing to serve {listen} without authentication: anyone who can reach it could read and change the repository. \
             Set PANDO_TOKENS (or --oidc-issuer), create a platform token with `pandod token`, listen on 127.0.0.1, \
             or set PANDO_ALLOW_ANONYMOUS=1 to accept anonymous access on purpose"
        );
    }
    let limits = pando_server::Limits {
        request_timeout: std::time::Duration::from_secs(cli.request_timeout),
        max_in_flight: cli.max_in_flight.max(1),
        ..Default::default()
    };
    let listener = tokio::net::TcpListener::bind(listen).await?;
    serve(listener, routes, auth, pando_server::ServeOptions { tls, web, limits, hosting }, shutdown_signal()).await
}
