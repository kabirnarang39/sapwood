mod admin;
mod cr;
mod issue;
mod migrate;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pando::features::{browse, clone, commit, diff, git, land, sync};
use pando::remote::{GrpcRemote, Remote};
use pando::workspace::{ChangeKind, Config, Workspace};
use pando_adapters::flags::SpecFlags;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(
    name = "pando",
    version,
    about = "Pando: source control for monorepos at agent scale",
    propagate_version = true
)]
struct Cli {
    /// Bearer token for the server ($PANDO_TOKEN).
    #[arg(long, global = true, env = "PANDO_TOKEN", hide_env_values = true)]
    token: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a workspace and check out a ref (lazily, and sparsely with --path).
    Clone {
        server: String,
        dir: PathBuf,
        #[arg(long = "ref", default_value = "main")]
        ref_name: String,
        /// Only materialise these paths (repeatable).
        #[arg(long = "path")]
        paths: Vec<String>,
        /// Fetch objects through a node daemon or regional cache.
        #[arg(long, env = "PANDO_OBJECTS")]
        objects: Option<String>,
    },
    /// Show working-copy changes.
    #[command(visible_alias = "st")]
    Status { paths: Vec<String> },
    /// Create a changeset on the server from working-copy changes (all, or PATHS).
    #[command(visible_alias = "ci")]
    Commit {
        #[arg(short, long)]
        message: String,
        /// Accepted for git muscle memory; Pando always commits all changes (or PATHS).
        #[arg(short = 'a', long = "all", hide = true)]
        _all: bool,
        paths: Vec<String>,
    },
    /// Land the committed work on the ref (server-side rebase + atomic ref update).
    #[command(visible_alias = "push")]
    Land,
    /// Update the working copy to the ref head (or REV).
    #[command(visible_alias = "pull")]
    Sync { rev: Option<String> },
    /// Switch to a ref or changeset; -b creates a ref at the current base.
    #[command(visible_alias = "switch")]
    Checkout {
        target: String,
        #[arg(short = 'b')]
        create: bool,
    },
    /// Changeset history (server-side; no local history needed).
    Log {
        /// Limit to a path.
        path: Option<String>,
        #[arg(long)]
        rev: Option<String>,
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        oneline: bool,
    },
    /// Diff the working copy, or two revisions (`pando diff A B`).
    Diff {
        revs: Vec<String>,
        #[arg(long = "name-only")]
        names_only: bool,
    },
    /// Show a changeset and its patch against its first parent.
    Show { rev: Option<String> },
    /// Print a file at a revision without checking anything out.
    Cat { rev: String, path: String },
    /// Lock files for exclusive editing (for files that cannot be merged). Others cannot land
    /// changes to them until you unlock.
    Lock {
        #[arg(required = true)]
        paths: Vec<String>,
    },
    /// Release your locks; --force releases someone else's (needs write access).
    Unlock {
        #[arg(required = true)]
        paths: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// List locks, optionally under a directory.
    Locks {
        #[arg(default_value = "")]
        prefix: String,
    },
    /// List a directory at a revision without checking anything out.
    Ls {
        rev: String,
        #[arg(default_value = "")]
        path: String,
    },
    /// Find files by path substring at a revision (server-side).
    Find {
        pattern: String,
        #[arg(long, default_value = "main")]
        rev: String,
    },
    /// Show which changeset last changed each line of a file.
    Blame {
        path: String,
        #[arg(long, default_value = "main")]
        rev: String,
    },
    /// List refs.
    #[command(visible_alias = "branch")]
    Refs,
    /// Best common ancestor of two revisions.
    MergeBase { a: String, b: String },
    /// No-op: Pando has no staging area. Use `pando commit [PATHS]`.
    #[command(hide = true)]
    Add { paths: Vec<String> },
    /// Import a git repository's history.
    ImportGit {
        git_dir: PathBuf,
        #[arg(long)]
        server: Option<String>,
        #[arg(long = "git-ref", default_value = "HEAD")]
        git_ref: String,
        #[arg(long = "ref", default_value = "main")]
        ref_name: String,
        #[arg(long)]
        force: bool,
    },
    /// Mount a revision read-only; files are fetched on first read (Linux, macOS, Windows).
    Mount {
        dir: PathBuf,
        #[arg(long)]
        server: Option<String>,
        /// Daemon or cache serving objects.
        #[arg(long)]
        objects: Option<String>,
        #[arg(long, default_value = "main")]
        rev: String,
        /// In-memory cache for file contents.
        #[arg(long, default_value_t = 256)]
        cache_mb: u64,
        /// Serve the checkout over NFS on localhost and print the command that mounts it,
        /// instead of mounting (for machines where only an administrator may mount, or
        /// Linux machines without FUSE).
        #[arg(long)]
        serve_only: bool,
    },
    /// Serve Pando as MCP tools over stdio for AI agents (Claude Code, Codex, Cursor...).
    Mcp {
        #[arg(long)]
        server: Option<String>,
        /// Serve the whole server to remote agents over HTTP at this address (e.g.
        /// 0.0.0.0:7430), instead of one workspace over stdio. Each request's bearer token is
        /// passed through to the server.
        #[arg(long, value_name = "ADDR")]
        http: Option<std::net::SocketAddr>,
        /// Host names clients use to reach the HTTP endpoint (repeatable); default: loopback
        /// only, against DNS rebinding.
        #[arg(long = "allowed-host")]
        allowed_hosts: Vec<String>,
    },
    /// Create and list repositories on a server that hosts many (`pandod server --platform`).
    Repo {
        #[command(subcommand)]
        action: RepoCmd,
    },
    /// Organisations and their members.
    Org {
        #[arg(long, global = true)]
        server: Option<String>,
        #[command(subcommand)]
        action: admin::OrgCmd,
    },
    /// Teams within an organisation, for granting access to many people at once.
    Team {
        #[arg(long, global = true)]
        server: Option<String>,
        #[command(subcommand)]
        action: admin::TeamCmd,
    },
    /// Change requests: propose a branch, review it, land it.
    Cr {
        /// The repository, SERVER/OWNER/NAME; defaults to the workspace's.
        #[arg(long, global = true)]
        server: Option<String>,
        #[command(subcommand)]
        action: cr::CrCmd,
    },
    /// Issues: work to do, assigned to people or agents; "fixes #N" in a change request closes
    /// one when it lands.
    Issue {
        /// The repository, SERVER/OWNER/NAME; defaults to the workspace's.
        #[arg(long, global = true)]
        server: Option<String>,
        #[command(subcommand)]
        action: issue::IssueCmd,
    },
    /// Protected branches: changes land on them only through a reviewed change request.
    Protect {
        #[arg(long, global = true)]
        server: Option<String>,
        #[command(subcommand)]
        action: cr::ProtectCmd,
    },
    /// Webhooks: call a URL (CI, chat, trackers) when something happens in a repository.
    Webhook {
        #[arg(long, global = true)]
        server: Option<String>,
        #[command(subcommand)]
        action: admin::WebhookCmd,
    },
    /// Access tokens for you and for agents you answer for.
    Token {
        #[arg(long, global = true)]
        server: Option<String>,
        #[command(subcommand)]
        action: admin::TokenCmd,
    },
    /// Server administration (site administrators only).
    Admin {
        #[arg(long, global = true)]
        server: Option<String>,
        #[command(subcommand)]
        action: admin::AdminCmd,
    },
    /// Move a repository from any git host to Pando: full history, and from GitHub, open pull
    /// requests (as change requests) and issues with their comments.
    Migrate {
        /// Where it is now: any URL git can clone.
        from: String,
        /// Where it goes: SERVER/OWNER/NAME.
        #[arg(long)]
        to: String,
        /// For private GitHub repositories, and to avoid GitHub's rate limit. Prefer the
        /// PANDO_GITHUB_TOKEN (or GITHUB_TOKEN) environment variable or --github-token-file: a
        /// value given here is visible to other users of the machine (`ps`).
        #[arg(long, env = "PANDO_GITHUB_TOKEN", hide_env_values = true)]
        github_token: Option<String>,
        /// Read the GitHub token from this file.
        #[arg(long, conflicts_with = "github_token")]
        github_token_file: Option<std::path::PathBuf>,
        /// Skip issues.
        #[arg(long)]
        no_issues: bool,
        /// Skip pull requests.
        #[arg(long)]
        no_pull_requests: bool,
        /// GitHub Enterprise Server's API, e.g. https://github.example.com/api/v3.
        #[arg(long)]
        github_api: Option<String>,
    },
    /// Keep a git repository (GitHub, GitLab, Bitbucket, any git remote) up to date with a
    /// branch: every landed change becomes the same git commit every time, pushed without force.
    Mirror {
        /// Where to push: any URL git accepts. Credentials come from git (SSH keys or a
        /// credential helper).
        #[arg(long)]
        to: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long, default_value = "main")]
        rev: String,
        #[arg(long = "git-ref", default_value = "main")]
        git_ref: String,
        /// The mirror's local copy (a bare git repository); defaults to the user cache.
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Mirror again every SECONDS until interrupted; without it, mirror once and exit.
        #[arg(long, value_name = "SECONDS")]
        every: Option<u64>,
    },
    /// Export first-parent history to a git repository.
    ExportGit {
        git_dir: PathBuf,
        #[arg(long)]
        server: Option<String>,
        #[arg(long, default_value = "main")]
        rev: String,
        #[arg(long = "git-ref", default_value = "main")]
        git_ref: String,
    },
}

#[derive(Subcommand)]
enum RepoCmd {
    /// Create OWNER/NAME. Then: `pando clone SERVER/OWNER/NAME`.
    Create {
        name: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// List repositories, optionally of one owner.
    List {
        #[arg(long, default_value = "")]
        owner: String,
        #[arg(long)]
        server: Option<String>,
    },
    /// Give a person, agent or team (ORG/TEAM) a role on a repository; `none` removes it.
    /// With only the repository, lists who has access.
    Grant {
        repo: String,
        principal: Option<String>,
        #[arg(value_enum)]
        role: Option<admin::RoleArg>,
        #[arg(long)]
        server: Option<String>,
    },
}

/// A path argument as a repository path: inside a workspace it is taken relative to the
/// current directory, elsewhere it is already repository-relative.
fn repo_path(arg: &str) -> Result<String> {
    let Ok(ws) = workspace() else { return Ok(arg.trim_matches('/').to_owned()) };
    let abs = std::env::current_dir()?.join(arg);
    let mut parts: Vec<String> = Vec::new();
    for c in abs.strip_prefix(std::fs::canonicalize(&ws.root)?).or_else(|_| abs.strip_prefix(&ws.root))?.components() {
        match c {
            std::path::Component::Normal(p) => parts.push(p.to_string_lossy().into_owned()),
            std::path::Component::ParentDir => {
                parts.pop();
            }
            _ => {}
        }
    }
    Ok(parts.join("/"))
}

fn workspace() -> Result<Workspace> {
    Workspace::find(Path::new("."))
}

fn connect(server: &str, objects: Option<&str>, token: Option<&str>) -> Result<Arc<dyn Remote>> {
    Ok(Arc::new(GrpcRemote::connect(server, objects, token)?))
}

fn ws_remote(ws: &Workspace, token: Option<&str>) -> Result<Arc<dyn Remote>> {
    connect(&ws.config.server, ws.config.objects.as_deref(), token)
}

/// The platform service of a server (its base URL, without any OWNER/NAME).
fn platform_client(
    server: Option<String>,
    token: Option<&str>,
) -> Result<pando_proto::platform_client::PlatformClient<pando::remote::Ch>> {
    let base = pando_proto::split_repo_url(&server_for(server)?).0;
    Ok(GrpcRemote::connect(&base, None, token)?.platform())
}

/// The review service and repository for `pando cr` and `pando protect`.
fn review_target(server: Option<String>, token: Option<&str>) -> Result<cr::Target> {
    let url = server_for(server)?;
    let (base, repo) = pando_proto::split_repo_url(&url);
    let repo = repo.context("name the repository: --server SERVER/OWNER/NAME")?;
    let (owner, name) = repo.split_once('/').context("give the repository as OWNER/NAME")?;
    Ok(cr::Target {
        client: GrpcRemote::connect(&base, None, token)?.reviews(),
        issues: GrpcRemote::connect(&base, None, token)?.issues(),
        repo: pando_proto::RepositoryRef { owner: owner.into(), name: name.into() },
        branch: workspace().ok().map(|ws| ws.config.ref_name),
    })
}

/// Server for workspace-free commands: $PANDO_SERVER, or the current workspace.
fn server_for(explicit: Option<String>) -> Result<String> {
    explicit
        .or_else(|| std::env::var("PANDO_SERVER").ok())
        .or_else(|| workspace().ok().map(|w| w.config.server))
        .context("no server: set PANDO_SERVER=URL or run inside a workspace")
}

fn short_message(m: &str) -> &str {
    m.lines().next().unwrap_or("")
}

fn fmt_time(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant), UTC.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", tod / 3600, tod % 3600 / 60)
}

fn main() {
    // Library logs (mounts, transports) only when asked for, e.g. PANDO_LOG=debug.
    if let Ok(filter) = std::env::var("PANDO_LOG") {
        let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
    }
    // The commands run on a thread with a roomy stack, and so do the runtime's workers: Windows
    // gives the main thread only 1 MB, which deep imports and migrations can exceed.
    let code = std::thread::Builder::new()
        .name("pando".into())
        .stack_size(16 << 20)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(8 << 20)
                .build()
                .expect("starting the async runtime");
            match runtime.block_on(Box::pin(run())) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    1
                }
            }
        })
        .expect("starting the main thread")
        .join()
        .unwrap_or(101);
    std::process::exit(code);
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let flags = SpecFlags::from_env()?;
    let token = cli.token.as_deref();
    let mut stdout = std::io::stdout().lock();
    match cli.cmd {
        Cmd::Clone { server, dir, ref_name, paths, objects } => {
            let remote = connect(&server, objects.as_deref(), token)?;
            let config = Config { server, objects, ref_name, sparse: paths };
            let ws = clone::run(remote.as_ref(), &flags, &dir, config).await?;
            match ws.base {
                Some(b) => println!("checked out {} files at {} into {}", ws.index.len(), b.short(), dir.display()),
                None => println!("cloned empty ref into {}", dir.display()),
            }
        }
        Cmd::Status { paths } => {
            let ws = workspace()?;
            let changes = ws.status(&paths)?;
            for c in &changes {
                let tag = match c.kind {
                    ChangeKind::Added => "A",
                    ChangeKind::Modified => "M",
                    ChangeKind::Deleted => "D",
                };
                writeln!(stdout, "{tag} {}", c.path)?;
            }
            if changes.is_empty() {
                writeln!(stdout, "clean (base {})", ws.base.map_or("none".into(), |b| b.short()))?;
            }
        }
        Cmd::Commit { message, paths, .. } => {
            let mut ws = workspace()?;
            let remote = ws_remote(&ws, token)?;
            match commit::run(remote.as_ref(), &mut ws, &message, &pando::default_author(), &paths).await? {
                Some(c) => println!(
                    "committed {} ({} files, {} new objects uploaded); run `pando land` to land on {}",
                    c.id.short(),
                    c.files,
                    c.uploaded,
                    ws.config.ref_name
                ),
                None => println!("nothing to commit"),
            }
        }
        Cmd::Land => {
            let mut ws = workspace()?;
            let remote = ws_remote(&ws, token)?;
            let out = match land::run(remote.as_ref(), &mut ws).await {
                Ok(out) => out,
                // A protected branch takes changes through review: propose this one instead.
                Err(e) if format!("{e:#}").contains("is protected") && ws.base.is_some() => {
                    let target = review_target(Some(ws.config.server.clone()), token).map_err(|_| e)?;
                    let (number, branch) = cr::propose(target, remote.as_ref(), &ws).await?;
                    println!(
                        "{} is protected, so this went for review: change request #{number} from {branch}.\n\
                         It lands once approved and its checks pass: pando cr view {number}",
                        ws.config.ref_name
                    );
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            println!(
                "landed {} on {}{}",
                out.landed.short(),
                ws.config.ref_name,
                if out.rebased { format!(" (rebased; {} incoming files synced)", out.synced) } else { String::new() }
            );
            if let Some(why) = out.behind {
                eprintln!("warning: working copy not updated: {why}");
            }
        }
        Cmd::Sync { rev } => {
            let mut ws = workspace()?;
            let remote = ws_remote(&ws, token)?;
            let out = sync::run(remote.as_ref(), &mut ws, rev.as_deref()).await?;
            println!("at {} ({} files changed)", out.to.short(), out.changed);
        }
        Cmd::Checkout { target, create } => {
            let mut ws = workspace()?;
            let remote = ws_remote(&ws, token)?;
            if create {
                sync::create_branch(remote.as_ref(), &mut ws, &target).await?;
                println!("created ref {target} at {}", ws.base.map_or("none".into(), |b| b.short()));
            } else {
                let out = sync::checkout(remote.as_ref(), &mut ws, &target).await?;
                println!("at {} ({} files changed)", out.to.short(), out.changed);
            }
        }
        Cmd::Log { path, rev, limit, oneline } => {
            let (remote, rev) = match workspace() {
                Ok(ws) => {
                    let rev = rev.or(ws.base.map(|b| b.to_hex())).unwrap_or(ws.config.ref_name.clone());
                    (ws_remote(&ws, token)?, rev)
                }
                Err(_) => (connect(&server_for(None)?, None, token)?, rev.unwrap_or("main".into())),
            };
            for c in browse::log(remote.as_ref(), &rev, path.as_deref().unwrap_or(""), limit).await? {
                if oneline {
                    writeln!(stdout, "{} {}", c.id.short(), short_message(&c.changeset.message))?;
                } else {
                    writeln!(stdout, "changeset {}", c.id)?;
                    writeln!(stdout, "Author: {}", c.changeset.author)?;
                    writeln!(stdout, "Date:   {}\n", fmt_time(c.changeset.timestamp_ms))?;
                    for l in c.changeset.message.trim_end().lines() {
                        writeln!(stdout, "    {l}")?;
                    }
                    writeln!(stdout)?;
                }
            }
        }
        Cmd::Diff { revs, names_only } => {
            let text = match revs.as_slice() {
                [] => {
                    let ws = workspace()?;
                    diff::working(ws_remote(&ws, token)?.as_ref(), &ws, &[], names_only).await?
                }
                [a, b] => diff::revisions(connect(&server_for(None)?, None, token)?.as_ref(), a, b, names_only).await?,
                _ => anyhow::bail!("usage: pando diff [FROM TO]"),
            };
            stdout.write_all(text.as_bytes())?;
        }
        Cmd::Show { rev } => {
            let ws = workspace().ok();
            let remote = match &ws {
                Some(w) => ws_remote(w, token)?,
                None => connect(&server_for(None)?, None, token)?,
            };
            let rev = rev.or(ws.and_then(|w| w.base.map(|b| b.to_hex()))).context("no revision")?;
            let c = remote.changeset(&rev).await?;
            writeln!(
                stdout,
                "changeset {}\nAuthor: {}\nDate:   {}\n",
                c.id,
                c.changeset.author,
                fmt_time(c.changeset.timestamp_ms)
            )?;
            for l in c.changeset.message.trim_end().lines() {
                writeln!(stdout, "    {l}")?;
            }
            writeln!(stdout)?;
            if let Some(p) = c.changeset.first_parent()? {
                stdout.write_all(
                    diff::revisions(remote.as_ref(), &p.to_hex(), &c.id.to_hex(), false).await?.as_bytes(),
                )?;
            }
        }
        Cmd::Lock { paths } => {
            let remote = connect(&server_for(None)?, None, token)?;
            for p in paths {
                let (path, owner, _) = remote.lock(&repo_path(&p)?).await?;
                writeln!(stdout, "locked {path} ({owner})")?;
            }
        }
        Cmd::Unlock { paths, force } => {
            let remote = connect(&server_for(None)?, None, token)?;
            for p in paths {
                let path = repo_path(&p)?;
                remote.unlock(&path, force).await?;
                writeln!(stdout, "unlocked {path}")?;
            }
        }
        Cmd::Locks { prefix } => {
            let remote = connect(&server_for(None)?, None, token)?;
            let prefix = if prefix.is_empty() { prefix } else { repo_path(&prefix)? };
            for (path, owner, at_ms) in remote.locks(&prefix).await? {
                let age = (pando::now_ms() - at_ms).max(0) / 60_000;
                writeln!(
                    stdout,
                    "{path}\t{owner}\t{}",
                    if age < 60 { format!("{age}m ago") } else { format!("{}h ago", age / 60) }
                )?;
            }
        }
        Cmd::Cat { rev, path } => {
            let remote = connect(&server_for(None)?, None, token)?;
            stdout.write_all(&browse::cat(remote.as_ref(), &rev, &path).await?)?;
        }
        Cmd::Ls { rev, path } => {
            let remote = connect(&server_for(None)?, None, token)?;
            for e in browse::ls(remote.as_ref(), &rev, &path).await? {
                writeln!(
                    stdout,
                    "{} {} {}",
                    browse::mode_char(e.mode),
                    e.id.map_or("-".into(), |i| i.short()),
                    e.name
                )?;
            }
        }
        Cmd::Find { pattern, rev } => {
            let remote = connect(&server_for(None)?, None, token)?;
            for p in remote.find(&rev, &pattern, 10_000).await? {
                writeln!(stdout, "{p}")?;
            }
        }
        Cmd::Blame { path, rev } => {
            let remote = connect(&server_for(None)?, None, token)?;
            for (i, (id, line)) in remote.blame(&rev, &path).await?.into_iter().enumerate() {
                writeln!(stdout, "{} {:>5} {line}", id.short(), i + 1)?;
            }
        }
        Cmd::Refs => {
            let remote = connect(&server_for(None)?, None, token)?;
            let current = workspace().ok().map(|w| w.config.ref_name);
            for (name, id) in remote.list_refs().await? {
                let mark = if current.as_deref() == Some(&name) { "*" } else { " " };
                writeln!(stdout, "{mark} {name} {}", id.short())?;
            }
        }
        Cmd::MergeBase { a, b } => {
            let remote = connect(&server_for(None)?, None, token)?;
            match remote.merge_base(&a, &b).await? {
                Some(id) => writeln!(stdout, "{id}")?,
                None => anyhow::bail!("no common ancestor"),
            }
        }
        Cmd::Add { .. } => {
            println!("pando has no staging area: `pando commit -m MSG [PATHS]` commits all changes (or just PATHS)");
        }
        Cmd::ImportGit { git_dir, server, git_ref, ref_name, force } => {
            let remote = connect(&server_for(server)?, None, token)?;
            let started = std::time::Instant::now();
            let out = git::import(remote.as_ref(), &flags, &git_dir, &git_ref, &ref_name, force).await?;
            println!(
                "imported {} commits, {} blobs ({} uploaded) in {:.1}s; {ref_name} -> {}{}",
                out.commits,
                out.blobs,
                out.uploaded,
                started.elapsed().as_secs_f64(),
                out.tip.map_or("none".into(), |t| t.short()),
                if out.skipped_submodules > 0 {
                    format!(" ({} submodule entries skipped)", out.skipped_submodules)
                } else {
                    String::new()
                }
            );
        }
        Cmd::Mount { dir, server, objects, rev, cache_mb, serve_only } => {
            pando_core::flags::require(&flags, pando_core::flags::Flag::VirtualCheckout)?;
            let remote = connect(&server_for(server)?, objects.as_deref(), token)?;
            let cs = remote.changeset(&rev).await?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let meta = std::fs::metadata(&dir)
                    .with_context(|| format!("{} must be an existing directory", dir.display()))?;
                let tree = Arc::new(pando::mount::VirtualTree::new(
                    remote.objects(),
                    tokio::runtime::Handle::current(),
                    cs.root_tree,
                    cache_mb << 20,
                ));
                if serve_only || cfg!(target_os = "macos") {
                    let port = pando::mount::nfs::serve(tree, meta.uid(), meta.gid()).await?;
                    if serve_only {
                        eprintln!("serving {rev} over NFS on 127.0.0.1:{port}; mount it with:");
                        println!("{}", pando::mount::nfs::mount_command(port, &dir));
                        tokio::signal::ctrl_c().await?;
                        return Ok(());
                    }
                    let target = dir.clone();
                    tokio::task::spawn_blocking(move || pando::mount::nfs::mount(port, &target)).await??;
                    eprintln!("mounted {rev} at {}; Ctrl-C to unmount", dir.display());
                    tokio::signal::ctrl_c().await?;
                    let target = dir.clone();
                    tokio::task::spawn_blocking(move || pando::mount::nfs::unmount(&target)).await??;
                } else {
                    #[cfg(target_os = "linux")]
                    {
                        let session = pando::mount::fuse::mount(tree, &dir)?;
                        eprintln!("mounted {rev} at {}; Ctrl-C to unmount", dir.display());
                        tokio::signal::ctrl_c().await?;
                        session.umount_and_join()?;
                    }
                }
            }
            #[cfg(windows)]
            {
                anyhow::ensure!(!serve_only, "--serve-only is for macOS and Linux; Windows projects files directly");
                let tree = Arc::new(pando::mount::VirtualTree::new(
                    remote.objects(),
                    tokio::runtime::Handle::current(),
                    cs.root_tree,
                    cache_mb << 20,
                ));
                let target = dir.clone();
                let session = tokio::task::spawn_blocking(move || pando::mount::projfs::mount(tree, &target)).await??;
                eprintln!("projecting {rev} into {}; Ctrl-C to stop (files already read stay on disk)", dir.display());
                tokio::signal::ctrl_c().await?;
                drop(session);
            }
            #[cfg(not(any(unix, windows)))]
            {
                let _ = (dir, cs, cache_mb, serve_only);
                anyhow::bail!(
                    "`pando mount` is not supported on this platform; use `pando clone --path` for a sparse checkout"
                );
            }
        }
        Cmd::Mcp { server, http: Some(listen), allowed_hosts } => {
            let base = pando_proto::split_repo_url(&server_for(server)?).0;
            pando::mcp_remote::RemoteMcp::new(base).serve_http(listen, allowed_hosts).await?;
        }
        Cmd::Mcp { server, .. } => {
            let ws = workspace().ok();
            let remote = match &ws {
                Some(w) if server.is_none() => ws_remote(w, token)?,
                _ => connect(&server_for(server)?, None, token)?,
            };
            drop(stdout);
            pando::mcp::SapMcp::new(remote, ws.map(|w| w.root)).serve_stdio().await?;
        }
        Cmd::Org { server, action } => admin::org(platform_client(server, token)?, action).await?,
        Cmd::Team { server, action } => admin::team(platform_client(server, token)?, action).await?,
        Cmd::Cr { server, action } => cr::cr(review_target(server, token)?, action).await?,
        Cmd::Issue { server, action } => {
            let t = review_target(server, token)?;
            issue::issue(t.issues, t.repo, action).await?
        }
        Cmd::Protect { server, action } => cr::protect(review_target(server, token)?, action).await?,
        Cmd::Webhook { server, action } => admin::webhook(platform_client(server, token)?, action).await?,
        Cmd::Token { server, action } => admin::token(platform_client(server, token)?, action).await?,
        Cmd::Admin { server, action } => admin::admin(platform_client(server, token)?, action).await?,
        Cmd::Repo { action } => {
            let server = match &action {
                RepoCmd::Create { server, .. } | RepoCmd::List { server, .. } | RepoCmd::Grant { server, .. } => {
                    server.clone()
                }
            };
            let base = pando_proto::split_repo_url(&server_for(server)?).0;
            let mut platform = GrpcRemote::connect(&base, None, token)?.platform();
            let unimplemented = |s: tonic::Status| {
                if s.code() == tonic::Code::Unimplemented {
                    anyhow::anyhow!("this server hosts one repository; start pandod with --platform to host many")
                } else {
                    anyhow::anyhow!("{}", s.message())
                }
            };
            match action {
                RepoCmd::Create { name, description, .. } => {
                    let (owner, repo) = name.split_once('/').context("give the repository as OWNER/NAME")?;
                    let r = platform
                        .create_repository(pando_proto::CreateRepositoryRequest {
                            owner: owner.into(),
                            name: repo.into(),
                            description,
                            ..Default::default()
                        })
                        .await
                        .map_err(unimplemented)?
                        .into_inner();
                    println!(
                        "created {}/{}; clone it with: pando clone {base}/{}/{}",
                        r.owner, r.name, r.owner, r.name
                    );
                }
                RepoCmd::List { owner, .. } => {
                    let rs = platform
                        .list_repositories(pando_proto::ListRepositoriesRequest { owner, ..Default::default() })
                        .await
                        .map_err(unimplemented)?
                        .into_inner()
                        .repositories;
                    for r in rs {
                        println!("{}/{}\t{} landed today\t{}", r.owner, r.name, r.lands_24h, r.description);
                    }
                }
                RepoCmd::Grant { repo, principal, role, .. } => admin::grant(platform, &repo, principal, role).await?,
            }
        }
        Cmd::Migrate { from, to, github_token, github_token_file, no_issues, no_pull_requests, github_api } => {
            if std::env::args().any(|a| a == "--github-token" || a.starts_with("--github-token=")) {
                eprintln!(
                    "warning: --github-token is visible to other users of this machine; set PANDO_GITHUB_TOKEN or use --github-token-file"
                );
            }
            let github_token = match github_token_file {
                Some(f) => Some(
                    std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?.trim().to_owned(),
                ),
                None => github_token.or_else(|| std::env::var("GITHUB_TOKEN").ok()),
            }
            .filter(|t| !t.is_empty());
            let m = migrate::Migration {
                from,
                to,
                github_token,
                issues: !no_issues,
                pull_requests: !no_pull_requests,
                github_api,
            };
            migrate::run(m, token, &flags).await?;
        }
        Cmd::Mirror { to, server, rev, git_ref, dir, every } => {
            let remote = connect(&server_for(server)?, None, token)?;
            let dir = dir.unwrap_or_else(|| git::default_mirror_dir(&to));
            let shown = git::redact(&to);
            loop {
                match git::mirror(remote.as_ref(), &flags, &rev, &dir, &git_ref, &to).await {
                    Ok(n) if n > 0 || every.is_none() => {
                        println!("mirrored {n} changes from {rev} to {shown} ({git_ref})")
                    }
                    Ok(_) => {}
                    // Keep running through network and server blips; the next round retries.
                    Err(e) if every.is_some() => eprintln!("pando: mirror to {shown}: {e:#}; retrying"),
                    Err(e) => return Err(e),
                }
                let Some(secs) = every else { break };
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(secs.max(1))) => {}
                    _ = tokio::signal::ctrl_c() => break,
                }
            }
        }
        Cmd::ExportGit { git_dir, server, rev, git_ref } => {
            let remote = connect(&server_for(server)?, None, token)?;
            let n = git::export(remote.as_ref(), &flags, &rev, &git_dir, &git_ref).await?;
            println!("exported {n} commits to {} ({git_ref})", git_dir.display());
        }
    }
    Ok(())
}
