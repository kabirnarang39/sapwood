//! Hosting many repositories on one server.
//!
//! Each repository gets its own storage, from templates such as
//! `sqlite:///var/lib/pando/repos/{repo}.db`, and its own set of services (including its own
//! landing queues), opened the first time it is used. A request names its repository with the
//! `x-pando-repo: OWNER/NAME` header; a request without it reaches the server's default
//! repository, so single-repository clients and servers are unchanged. Which repositories exist
//! is kept in a small registry database.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use pando_core::Repo;
use tokio::sync::OnceCell;
use tonic::Status;
use tonic::codegen::{BoxFuture, Bytes, StdError, http};
use tonic::service::Routes;
use tower::{Layer, Service, ServiceExt};

/// The request header that names the repository a call is about.
pub const REPO_HEADER: &str = "x-pando-repo";

/// `OWNER/NAME`, each 1–100 characters of letters, digits, `.`, `_` and `-`, not starting with
/// `.` (so names are safe in paths, URLs and database identifiers).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoKey {
    pub owner: String,
    pub name: String,
}

pub(crate) fn valid_part(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl RepoKey {
    pub fn new(owner: &str, name: &str) -> Result<Self, Status> {
        if !valid_part(owner) || !valid_part(name) {
            return Err(Status::invalid_argument(format!(
                "`{owner}/{name}` is not a valid repository name: use letters, digits, `.`, `_` and `-` (up to 100 each)"
            )));
        }
        Ok(Self { owner: owner.to_owned(), name: name.to_owned() })
    }

    pub fn parse(s: &str) -> Result<Self, Status> {
        match s.split_once('/') {
            Some((owner, name)) if !name.contains('/') => Self::new(owner, name),
            _ => Err(Status::invalid_argument(format!("`{s}` is not OWNER/NAME"))),
        }
    }

    /// A form safe as a single path segment or identifier: `owner--name`.
    pub fn id(&self) -> String {
        format!("{}--{}", self.owner, self.name)
    }
}

impl std::fmt::Display for RepoKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

/// Storage URLs for each repository: `{repo}` becomes `owner/name`, `{repo_id}` becomes
/// `owner--name`.
#[derive(Debug, Clone)]
pub struct Templates {
    pub metadata: String,
    pub objects: String,
}

impl Templates {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.metadata.contains("{repo}") && !self.metadata.contains("{repo_id}") {
            bail!("--repos-metadata must contain {{repo}} or {{repo_id}}, so each repository gets its own database");
        }
        if self.objects != "metadata" && !self.objects.contains("{repo}") && !self.objects.contains("{repo_id}") {
            bail!("--repos-objects must contain {{repo}} or {{repo_id}}, or be `metadata`");
        }
        Ok(())
    }

    pub fn render(&self, key: &RepoKey) -> (String, String) {
        let r = |t: &str| t.replace("{repo}", &key.to_string()).replace("{repo_id}", &key.id());
        (r(&self.metadata), r(&self.objects))
    }
}

/// One repository as the registry records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRecord {
    pub key: RepoKey,
    pub description: String,
    pub visibility: i32,
    pub default_branch: String,
    pub created_at_ms: i64,
    pub archived: bool,
    pub topics: Vec<String>,
}

/// Which repositories exist. SQLite, one small table; writes are rare (creating a repository).
pub struct Registry {
    pub(crate) db: Mutex<rusqlite::Connection>,
    /// Answers to the reads every request makes (a repository, a role, branch protection),
    /// dropped by any write that could change them (ADR-029).
    cache: quick_cache::sync::Cache<String, (Instant, Arc<dyn std::any::Any + Send + Sync>)>,
    /// Bumped by every invalidation, so an answer read before a write is never cached after it.
    generation: std::sync::atomic::AtomicU64,
}

/// How long a cached answer may be used: writes in this process clear the cache at once; this
/// bounds how long another replica's write can go unseen.
const CACHE_TTL: Duration = Duration::from_secs(5);

impl Registry {
    /// `sqlite:///abs/path.db`, `sqlite://rel/path.db` or `memory`.
    pub fn open(url: &str) -> anyhow::Result<Self> {
        let conn = if url == "memory" {
            rusqlite::Connection::open_in_memory()?
        } else {
            let path = url
                .strip_prefix("sqlite://")
                .with_context(|| format!("unsupported --platform `{url}` (sqlite://PATH | memory)"))?;
            if let Some(dir) = Path::new(path).parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)?;
            }
            rusqlite::Connection::open(path)?
        };
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS repositories (
               owner TEXT NOT NULL,
               name TEXT NOT NULL,
               description TEXT NOT NULL DEFAULT '',
               visibility INTEGER NOT NULL DEFAULT 1,
               default_branch TEXT NOT NULL DEFAULT 'main',
               created_at_ms INTEGER NOT NULL,
               archived INTEGER NOT NULL DEFAULT 0,
               topics TEXT NOT NULL DEFAULT '',
               PRIMARY KEY (owner, name)
             );",
        )?;
        let reg = Self {
            db: Mutex::new(conn),
            cache: quick_cache::sync::Cache::new(100_000),
            generation: Default::default(),
        };
        reg.migrate()?;
        Ok(reg)
    }

    /// `load()`, or its answer from the last few seconds.
    pub(crate) fn cached<T: Clone + Send + Sync + 'static>(
        &self,
        key: String,
        load: impl FnOnce() -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        if let Some((at, v)) = self.cache.get(&key)
            && at.elapsed() < CACHE_TTL
            && let Some(v) = v.downcast_ref::<T>()
        {
            return Ok(v.clone());
        }
        use std::sync::atomic::Ordering::SeqCst;
        let generation = self.generation.load(SeqCst);
        let v = load()?;
        self.cache.insert(key.clone(), (Instant::now(), Arc::new(v.clone())));
        // A write committed while we read: what we read may predate it, so don't keep it.
        if self.generation.load(SeqCst) != generation {
            self.cache.remove(&key);
        }
        Ok(v)
    }

    /// Forgets every cached answer; called after (never before) every write that changes who
    /// may do what, so a concurrent read can't re-cache the old answer.
    pub(crate) fn invalidate(&self) {
        self.generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.cache.clear();
    }

    /// Brings the schema up to date: accounts, organisations, teams, grants and tokens.
    pub(crate) fn migrate(&self) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute_batch(crate::directory::SCHEMA)?;
        db.execute_batch(crate::features::reviews::store::SCHEMA)?;
        db.execute_batch(crate::webhooks::SCHEMA)?;
        db.execute_batch(crate::features::issues::SCHEMA)?;
        db.execute_batch(crate::login::SCHEMA)?;
        Ok(())
    }

    fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RepoRecord> {
        let topics: String = r.get(7)?;
        Ok(RepoRecord {
            key: RepoKey { owner: r.get(0)?, name: r.get(1)? },
            description: r.get(2)?,
            visibility: r.get(3)?,
            default_branch: r.get(4)?,
            created_at_ms: r.get(5)?,
            archived: r.get::<_, i64>(6)? != 0,
            topics: topics.split(',').filter(|t| !t.is_empty()).map(str::to_owned).collect(),
        })
    }

    pub fn get(&self, key: &RepoKey) -> anyhow::Result<Option<RepoRecord>> {
        self.cached(format!("repo:{key}"), || self.get_uncached(key))
    }

    fn get_uncached(&self, key: &RepoKey) -> anyhow::Result<Option<RepoRecord>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached(
            "SELECT owner, name, description, visibility, default_branch, created_at_ms, archived, topics
             FROM repositories WHERE owner = ?1 AND name = ?2",
        )?;
        let mut rows = st.query_map((&key.owner, &key.name), Self::row)?;
        Ok(rows.next().transpose()?)
    }

    /// Every repository, or those of one owner, ordered by owner then name.
    pub fn list(&self, owner: Option<&str>) -> anyhow::Result<Vec<RepoRecord>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached(
            "SELECT owner, name, description, visibility, default_branch, created_at_ms, archived, topics
             FROM repositories WHERE ?1 IS NULL OR owner = ?1 ORDER BY owner, name",
        )?;
        let rows = st.query_map([owner], Self::row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Replaces a repository's settings (everything but its name and creation time).
    pub fn update(&self, rec: &RepoRecord) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute(
            "UPDATE repositories SET description = ?3, visibility = ?4, default_branch = ?5, archived = ?6, topics = ?7
             WHERE owner = ?1 AND name = ?2",
            (
                &rec.key.owner,
                &rec.key.name,
                &rec.description,
                rec.visibility,
                &rec.default_branch,
                rec.archived as i64,
                rec.topics.join(","),
            ),
        )?;
        self.invalidate();
        Ok(())
    }

    /// Adds a repository; false if it already exists.
    pub fn create(&self, rec: &RepoRecord) -> anyhow::Result<bool> {
        let db = self.db.lock().unwrap();
        let n = db.execute(
            "INSERT OR IGNORE INTO repositories (owner, name, description, visibility, default_branch, created_at_ms, archived, topics)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                &rec.key.owner,
                &rec.key.name,
                &rec.description,
                rec.visibility,
                &rec.default_branch,
                rec.created_at_ms,
                rec.archived as i64,
                rec.topics.join(","),
            ),
        )?;
        self.invalidate();
        Ok(n == 1)
    }
}

/// One repository's services, as [`BuildRoutes`] makes them.
pub struct RepoServices {
    /// Everything clients call on the repository.
    pub routes: Routes,
    /// Landing for change requests: their review is the gate, so it skips branch protection.
    pub review_land: Option<crate::features::land::Land>,
}

/// Builds one repository's services from its name and storage.
pub type BuildRoutes = Arc<dyn Fn(&RepoKey, Repo) -> RepoServices + Send + Sync>;

struct Hosted {
    repo: Repo,
    services: RepoServices,
}

/// Activity figures for listings, cached briefly: they walk history.
#[derive(Debug, Clone, Copy, Default)]
pub struct RepoStats {
    pub tip: Option<pando_core::Id>,
    pub tip_at_ms: i64,
    pub lands_24h: u32,
}

/// The repositories this server hosts, opened on first use.
pub struct Hosting {
    templates: Templates,
    pub registry: Arc<Registry>,
    build: BuildRoutes,
    open: Mutex<HashMap<RepoKey, Arc<OnceCell<Hosted>>>>,
    stats: Mutex<HashMap<RepoKey, (Instant, RepoStats)>>,
    /// Who may do what.
    pub access: Arc<crate::permissions::Access>,
}

impl Hosting {
    pub fn new(
        templates: Templates,
        registry: Arc<Registry>,
        build: BuildRoutes,
        access: Arc<crate::permissions::Access>,
    ) -> anyhow::Result<Self> {
        templates.validate()?;
        Ok(Self {
            templates,
            registry,
            build,
            open: Mutex::new(HashMap::new()),
            stats: Mutex::new(HashMap::new()),
            access,
        })
    }

    /// The repository's record, if `who` (limited by `scope`) has at least `need` on it.
    pub fn authorize(
        &self,
        key: &RepoKey,
        who: &pando_core::acl::Principal,
        scope: Option<&crate::auth::TokenScope>,
        need: pando_proto::Role,
    ) -> Result<RepoRecord, Status> {
        let rec = self
            .registry
            .get(key)
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("no repository `{key}` on this server")))?;
        self.access.check(&self.registry, who, scope, &rec, need)?;
        Ok(rec)
    }

    async fn hosted(&self, key: &RepoKey) -> Result<Arc<OnceCell<Hosted>>, Status> {
        let exists = self.registry.get(key).map_err(|e| Status::internal(e.to_string()))?.is_some();
        if !exists {
            return Err(Status::not_found(format!("no repository `{key}` on this server")));
        }
        let cell = self.open.lock().unwrap().entry(key.clone()).or_default().clone();
        cell.get_or_try_init(|| async {
            let (metadata, objects) = self.templates.render(key);
            if let Some(path) = metadata.strip_prefix("sqlite://")
                && let Some(dir) = Path::new(path).parent()
            {
                std::fs::create_dir_all(dir)
                    .map_err(|e| Status::internal(format!("creating storage for `{key}`: {e}")))?;
            }
            let repo = crate::config::open_repo(&metadata, &objects)
                .await
                .map_err(|e| Status::unavailable(format!("opening storage for `{key}`: {e:#}")))?;
            // Every branch move becomes a `push` webhook event.
            let refs = Arc::new(crate::webhooks::NotifyingRefs {
                inner: repo.refs.clone(),
                log: repo.log.clone(),
                registry: self.registry.clone(),
                key: key.clone(),
            });
            let repo = Repo { refs, ..repo };
            tracing::info!(repo = %key, "opened repository");
            Ok::<_, Status>(Hosted { services: (self.build)(key, repo.clone()), repo })
        })
        .await?;
        Ok(cell)
    }

    /// The services for `key`, opening its storage the first time.
    pub async fn routes(&self, key: &RepoKey) -> Result<Routes, Status> {
        let cell = self.hosted(key).await?;
        Ok(cell.get().expect("initialised above").services.routes.clone())
    }

    /// The repository's storage and its change-request landing, opening it the first time.
    pub async fn open_repo(&self, key: &RepoKey) -> Result<(Repo, Option<crate::features::land::Land>), Status> {
        let cell = self.hosted(key).await?;
        let h = cell.get().expect("initialised above");
        Ok((h.repo.clone(), h.services.review_land.clone()))
    }

    /// Creates the repository's storage and records it. Idempotent for an existing repository
    /// with the same name: returns false.
    pub async fn create(&self, rec: RepoRecord) -> Result<bool, Status> {
        let created = self.registry.create(&rec).map_err(|e| Status::internal(e.to_string()))?;
        // Open now so a storage problem surfaces at creation, not on first use.
        self.hosted(&rec.key).await?;
        Ok(created)
    }

    /// Tip, its time, and changes landed on the default branch in the last day. Cached per tip
    /// for up to 30 s: a landing always shows at once, and the day-long walk runs at most twice a
    /// minute per repository.
    pub async fn stats(&self, rec: &RepoRecord) -> RepoStats {
        let Ok(cell) = self.hosted(&rec.key).await else { return RepoStats::default() };
        let repo = &cell.get().expect("initialised").repo;
        let tip = repo.refs.get(&rec.default_branch).await.ok().flatten();
        if let Some((at, s)) = self.stats.lock().unwrap().get(&rec.key)
            && s.tip == tip
            && at.elapsed() < Duration::from_secs(30)
        {
            return *s;
        }
        let s = compute_stats(repo, &rec.default_branch).await.unwrap_or_default();
        self.stats.lock().unwrap().insert(rec.key.clone(), (Instant::now(), s));
        s
    }
}

async fn compute_stats(repo: &Repo, branch: &str) -> anyhow::Result<RepoStats> {
    use prost::Message;
    let Some(tip) = repo.refs.get(branch).await? else { return Ok(RepoStats::default()) };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
    let mut s = RepoStats { tip: Some(tip), ..Default::default() };
    let mut cur = Some(tip);
    // A day of history, walked along first parents; bounded so a listing stays cheap.
    for _ in 0..20_000 {
        let Some(id) = cur else { break };
        let Some(bytes) = repo.log.get(&id).await? else { break };
        let cs = pando_core::object::Changeset::decode(bytes.as_ref())?;
        if s.tip_at_ms == 0 {
            s.tip_at_ms = cs.timestamp_ms;
        }
        if cs.timestamp_ms < now - 86_400_000 {
            break;
        }
        s.lands_24h += 1;
        cur = cs.first_parent()?;
    }
    Ok(s)
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Routes calls that name a repository to that repository's services; everything else goes to
/// the default repository. Without hosting the header is ignored (one-repository servers).
#[derive(Clone)]
pub struct HostingLayer(pub Option<Arc<Hosting>>);

impl<S> Layer<S> for HostingLayer {
    type Service = HostingService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        HostingService { inner, hosting: self.0.clone() }
    }
}

#[derive(Clone)]
pub struct HostingService<S> {
    inner: S,
    hosting: Option<Arc<Hosting>>,
}

impl<S, B> Service<http::Request<B>> for HostingService<S>
where
    S: Service<http::Request<B>, Response = http::Response<tonic::body::Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: tonic::codegen::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<StdError>,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = S::Error;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        // Platform and review calls name their repository in the request itself.
        let path = req.uri().path();
        let central =
            ["/pando.v1.Platform/", "/pando.v1.Reviews/", "/pando.v1.Issues/"].iter().any(|p| path.starts_with(p));
        let named =
            req.headers().get(REPO_HEADER).and_then(|v| v.to_str().ok()).filter(|_| !central).map(str::to_owned);
        match (self.hosting.clone(), named) {
            (Some(hosting), Some(name)) => Box::pin(async move {
                let who = req
                    .extensions()
                    .get::<pando_core::acl::Principal>()
                    .cloned()
                    .unwrap_or_else(pando_core::acl::Principal::anonymous);
                let scope = req.extensions().get::<crate::auth::TokenScope>().cloned();
                let need = crate::permissions::required_role(req.uri().path());
                let routes = match RepoKey::parse(&name)
                    .and_then(|key| hosting.authorize(&key, &who, scope.as_ref(), need).map(|_| key))
                {
                    Ok(key) => hosting.routes(&key).await,
                    Err(e) => Err(e),
                };
                match routes {
                    Ok(routes) => match routes.oneshot(req).await {
                        Ok(resp) => Ok(resp),
                        Err(never) => match never {},
                    },
                    Err(status) => Ok(status.into_http()),
                }
            }),
            _ => {
                let fut = self.inner.call(req);
                Box::pin(fut)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_safe_in_paths_and_identifiers() {
        assert!(RepoKey::parse("lumen/fleet").is_ok());
        assert!(RepoKey::parse("a.b_c-d/x.y").is_ok());
        for bad in [
            "lumen",
            "lumen/",
            "/fleet",
            "a/b/c",
            "../etc",
            "a/..x",
            "a/.hidden",
            "a b/c",
            "a/b;drop",
            &format!("a/{}", "x".repeat(101)),
        ] {
            assert!(RepoKey::parse(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn templates_render_and_must_separate_repositories() {
        let t = Templates { metadata: "sqlite:///data/{repo}.db".into(), objects: "s3://bucket/{repo_id}".into() };
        let (m, o) = t.render(&RepoKey::parse("lumen/fleet").unwrap());
        assert_eq!(m, "sqlite:///data/lumen/fleet.db");
        assert_eq!(o, "s3://bucket/lumen--fleet");
        assert!(Templates { metadata: "sqlite:///data/one.db".into(), objects: "metadata".into() }.validate().is_err());
    }

    #[test]
    fn registry_creates_once_and_lists_by_owner() {
        let r = Registry::open("memory").unwrap();
        let rec = |o: &str, n: &str| RepoRecord {
            key: RepoKey::parse(&format!("{o}/{n}")).unwrap(),
            description: String::new(),
            visibility: 1,
            default_branch: "main".into(),
            created_at_ms: 1,
            archived: false,
            topics: vec!["rust".into()],
        };
        assert!(r.create(&rec("lumen", "fleet")).unwrap());
        assert!(!r.create(&rec("lumen", "fleet")).unwrap());
        assert!(r.create(&rec("lumen", "web")).unwrap());
        assert!(r.create(&rec("acme", "app")).unwrap());
        assert_eq!(r.list(Some("lumen")).unwrap().len(), 2);
        assert_eq!(r.list(None).unwrap().len(), 3);
        assert_eq!(r.get(&RepoKey::parse("lumen/fleet").unwrap()).unwrap().unwrap().topics, vec!["rust".to_string()]);
    }
}
