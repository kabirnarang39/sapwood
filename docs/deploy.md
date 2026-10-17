# Deploying Pando

A single `pandod server` with SQLite is enough for a team on one machine. For more, run
stateless servers on Postgres or CockroachDB with objects in S3, GCS or Azure, and put a
regional cache and a node daemon between CI machines and the servers.

## The whole topology with Docker Compose

The repository's [`docker-compose.yml`](https://github.com/kabirnarang39/pando/blob/main/docker-compose.yml)
starts Postgres, an S3-compatible store, a server, a regional cache and a node daemon:

```sh
docker compose up -d
pando clone http://localhost:7420 work --objects http://localhost:7422
```

`--objects` sends file reads through the node daemon; commits and lands still go to the
server.

## For free, on one machine

[`deploy/free-tier`](https://github.com/kabirnarang39/pando/tree/main/deploy/free-tier) sets up a
production server on Oracle Cloud's Always Free ARM machine: HTTPS by Caddy, a hardened systemd
service, and hourly incremental backups to a free Neon database and R2 bucket. It costs nothing
until usage outgrows the free tiers, and moves to Postgres and object storage with `pandod copy`
when it does.

## Hosting many repositories

One `pandod` can host any number of repositories, each with its own storage, for a whole
company: organisations, members, teams, per-repository roles and access tokens.

```sh
# 1. The first administrator's token, written straight into the registry (shown once).
pandod token --platform sqlite:///var/lib/pando/platform.db --account kabir > ~/.pando-admin-token

# 2. The server. With a platform token in the registry, every call needs a token.
pandod server --listen 0.0.0.0:7420 \
  --platform sqlite:///var/lib/pando/platform.db \
  --repos-metadata 'sqlite:///var/lib/pando/repos/{repo}.db' \
  --repos-objects 'file:///var/lib/pando/objects/{repo_id}' \
  --platform-admins kabir

# 3. An organisation, a repository, people and agents.
export PANDO_TOKEN=$(cat ~/.pando-admin-token) PANDO_SERVER=https://pando.example.com
pando org create lumen
pando repo create lumen/fleet
pando org member lumen mira@lumen.dev write
pando team set lumen/platform --member mira@lumen.dev
pando repo grant lumen/fleet lumen/platform admin
pando token create perf-fleet --as agent/perf-05 --repo lumen/fleet --role write
```

- `--platform` is the registry: which repositories exist, and who may use them.
  `--repos-metadata` and `--repos-objects` are templates: `{repo}` becomes `OWNER/NAME` and
  `{repo_id}` becomes `OWNER--NAME`. Each repository gets its own database and its own landing
  queues, so one busy repository never slows another, and a repository can be backed up, moved
  or deleted on its own.
- Clients name a repository by adding `/OWNER/NAME` to the server address; the web console lists
  them. A repository call that names none is refused: the server's own `--metadata` repository
  is not reachable in this mode. To keep a single-repository server's history, create the
  repository and copy it in with `pandod copy`.
- `--multi-tenant` (`PANDO_MULTI_TENANT=1`) is for a server that strangers share; see
  [Multi-tenant servers](platform.md#multi-tenant-servers). `--max-orgs-per-account` (default 3)
  caps how many organisations a person may create there.
- Webhooks never call loopback, private networks or cloud metadata addresses.
  `--webhook-allow-private` lets them call loopback and private networks (self-hosted CI on an
  internal network); it can't be combined with `--multi-tenant`.

### Who may do what

| Role | Read | Write (land, push objects, lock) | Administer (access, settings) |
|---|---|---|---|
| Read, Triage | yes | | |
| Write, Maintain | yes | yes | |
| Admin | yes | yes | yes |

- A person's role on a repository is the highest of: their organisation role, grants to them,
  and grants to their teams. Internal and public repositories are readable by everyone with an
  account on the server. Repositories are private unless made otherwise.
- `--platform-admins` administer the whole server: they create organisations and act as
  administrators everywhere. An organisation's administrators add members, teams and
  repositories.
- An agent (`agent/NAME`) answers to the person who issued its first token and works with that
  person's role, or with its own if it has been given one.
- A token acts as you or as an agent you answer for. It can be limited to some repositories and
  to a highest role, and expires within a year (90 days by default). The server stores only a
  hash; tokens start with `pando_`, so secret scanners can find leaked ones.
- People who sign in with single sign-on or a static token get an account automatically; give
  them a role with `pando org member`.
- Someone who can't read a repository is told it does not exist, so private names don't leak.
  Every change to access is in the audit log.
- With no static tokens, single sign-on or platform tokens, the server is open, for local
  development; it refuses to listen beyond 127.0.0.1 that way unless `PANDO_ALLOW_ANONYMOUS=1`.
- Caches and node daemons serve the default repository only.

### Change requests and protected branches

```sh
pando protect set main --approvals 1 --check build --bypass admins   # repository admins
pando checkout -b lower-rate && $EDITOR tax.rs && pando commit -m "Lower the rate" && pando land
pando cr create --title "Lower the tax rate" --reviewer mira@lumen.dev
pando cr review 7 approve -m "Matches the regulation"                # mira
pando cr check 7 build passed --url https://ci.example.com/runs/91   # CI, with a write token
pando cr land 7
```

- A protected branch is updated only by those its protection lets bypass review (a login, a team
  `org/team`, or `admins`), and by agents when it lets agents land directly. Everyone else lands
  through a change request; a direct land is refused with a message saying so.
- A change request lands when nothing blocks it: enough approvals from people other than its
  author, every required check passed, no requested changes, no conflicts, not a draft. Each
  blocker is shown in words. With "a new version needs new approvals" (the default), pushing to
  the branch makes earlier approvals and requested changes stale.
- It lands as one changeset, rebased onto the target's tip file by file like any other land, with
  the title, description and approvers in its message. `pando cr rebase` replays a change request
  on its target's tip when they changed different files.
- Checks belong to a version of the change: CI reports them with `pando cr check` (or the
  `ReportCheck` call) and a new push starts with none.
- Reading needs Read; commenting needs Read; opening a change request needs Triage; approving,
  requesting changes, reporting checks and landing need Write; protecting branches needs Admin.

## Roles

| Process | Command | Runs where | State |
|---|---|---|---|
| Server | `pandod server` | behind a load balancer, any number | none; everything is in the stores |
| Regional cache | `pandod cache --upstream URL` | one or more per region | memory only |
| Node daemon | `pandod daemon --upstream URL` | one per CI machine | memory and local disk |
| Compaction | `pandod compact --metadata URL` | a scheduled job | none; safe while serving |

Objects are immutable and named by their BLAKE3 hash, so caches never need invalidating
and every tier verifies what it receives. Only branch pointers change, and only the
server changes them.

## Configuration

| Setting | Flag / environment | Default |
|---|---|---|
| Metadata store | `--metadata` / `PANDO_METADATA` | `sqlite://./pando-data/meta.db`; also `memory`, `postgres://…` |
| Object store | `--objects` / `PANDO_OBJECTS` | `metadata` (in the metadata store); also `file:///…`, `s3://…`, `gs://…`, `az://…` |
| Bearer tokens | `--tokens` / `PANDO_TOKENS` | none; e.g. `alice:tok1,ci:tok2`. Without tokens or OIDC, pandod listens only on a loopback address unless `--allow-anonymous` / `PANDO_ALLOW_ANONYMOUS=1` says otherwise |
| Request limits | `--request-timeout` / `PANDO_REQUEST_TIMEOUT`, `--max-in-flight` / `PANDO_MAX_IN_FLIGHT` | 600 s per call; 4,096 calls in progress, beyond which calls are refused with Unavailable so clients back off; 256 per connection |
| Browser access | `--web-origins` / `PANDO_WEB_ORIGINS` | same-origin only; list the sites that host the web console |
| Single sign-on | `--oidc-issuer`, `--oidc-audience`, `--oidc-claim` | off; works with Okta, Entra ID, Google, Auth0, Keycloak |
| Access rules | `--acl` / `PANDO_ACL` | allow everything |
| Pre-land check | `--land-hook URL`, `--land-hook-token`, `--land-hook-timeout` | off |
| TLS | `--tls-cert`, `--tls-key` | off |
| Metrics | `--metrics` / `PANDO_METRICS` | off; e.g. `0.0.0.0:9420` |
| Feature flags | `PANDO_FLAGS` | all on; e.g. `land=off,git-import=off` |

Run `pandod server --help` for every option.

## Authentication and permissions

Without `--tokens` or `--oidc-issuer` the server accepts everyone and logs a warning. In
production, set at least one. With OpenID Connect, the claim named by `--oidc-claim` (for
example `email`) becomes the principal that access rules refer to.

Access rules grant read and write per directory and per branch. Principals who can read
only part of the repository get path-scoped checkouts, search and history, with changes
outside their scope removed. The rule format and the security model are in
[SECURITY.md](https://github.com/kabirnarang39/pando/blob/main/SECURITY.md).

## Pre-land checks

With `--land-hook`, the server sends each proposed land to your URL before it moves the
branch: who is landing, the branch, the changeset and its paths. Any 2xx answer lets it
land; anything else, including a timeout, refuses it. Use it to require green CI or an
approved review. The payload is described in [Architecture](ARCHITECTURE.md#land-checks).

## Storage maintenance

Run `pandod compact` on a schedule. It stores old file versions as deltas against newer
ones and returns space to the filesystem; on git/git's history this takes the store from
4.6 GB to 369 MB. Runs are incremental and safe while the server is serving.

## Backups, restores and moving between backends

`pandod copy` copies a repository from one store to another. The same command makes a
backup, restores one, and moves a repository to another backend:

```sh
# Back up the production database to a SQLite file
pandod copy --from-metadata postgres://pando@db/pando --from-objects s3://pando-objects \
            --to-metadata sqlite:///backups/pando.db

# Move a single-node server from SQLite to Postgres and S3
pandod copy --from-metadata sqlite:///var/lib/pando/meta.db \
            --to-metadata postgres://pando@db/pando --to-objects s3://pando-objects
```

It is safe while the source is serving: branch pointers are read first and written to
the destination last, and everything they point to was stored before them, so the copy
is always consistent. Objects are copied as stored, so compacted history stays compact,
and whole objects are verified against their hashes on the way. Anything the destination
already holds is skipped, so running the same copy again only moves what is new: on
git/git's history (84,050 changesets, 330,000 objects) a first copy to SQLite takes 13 s
and a repeat 3.5 s. Run it on a schedule for incremental backups. System pointers such as
the compaction lease are not copied.

## Audit log

`--audit-log FILE` (or `PANDO_AUDIT_LOG`) appends one JSON line per event: who read or
changed what, from which address, with what result. It is off by default because it grows
with every request; rotate it like any log file.

```json
{"timestamp":"2026-10-16T09:06:02.695Z","kind":"land","principal":"alice","ref":"main","changeset":"0844d2dc…","landed":"0844d2dc…","rebased":false}
{"timestamp":"2026-10-16T09:06:02.702Z","kind":"read_file","principal":"ci","rev":"main","path":"README"}
{"timestamp":"2026-10-16T09:06:02.702Z","kind":"rpc","principal":"ci","peer":"10.0.4.17","method":"/pando.v1.Browse/ReadFile","status":"0","ms":0}
{"timestamp":"2026-10-16T09:06:58.112Z","kind":"auth_failed","peer":"10.0.9.2","presented":true,"reason":"invalid token"}
```

| `kind` | Recorded for |
|---|---|
| `rpc` | every authenticated request: principal, client address, method, gRPC status, duration |
| `auth_failed` | every rejected request: client address, whether a token was presented, why (never the token) |
| `land` | each land: branch, changeset, and the landed id or the refusal |
| `set_ref` | branch moves through the refs API |
| `read_file`, `list_dir`, `checkout`, `find` | content reads, with revision and paths |
| `log`, `blame` | history queries, with revision and path |

Audit events never appear in the normal log, and the normal log never appears in the
audit file.

## Monitoring

`--metrics` exposes Prometheus metrics: request counts and latencies per RPC
(`pando_rpc_total`, `pando_rpc_seconds`), lands, refused lands, attempts and batch sizes
(`pando_land_*`), and objects warmed by node daemons (`pando_prefetch_objects_total`). `--log-json` writes structured logs. The server
implements the standard gRPC health check.
