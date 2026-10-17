# Architecture Decision Records

Each record states the decision, the alternatives considered and why they lost.

## ADR-001: Rust for every component

**Decision.** Server, tiers and client are written in Rust (edition 2024).
**Alternatives.** Go (fast to write, GC pauses on large heaps, larger memory per cached
object); C++ (performance parity, memory-safety risk in a network-facing parser-heavy
system); mixed Go server + Rust client (two toolchains, duplicated domain code).
**Why.** Predictable latency with no GC on hot cache paths, memory safety for code that
parses untrusted trees and streams, one domain crate shared by server and client.

## ADR-002: BLAKE3 content addressing

**Decision.** Object ids are BLAKE3-256 over `kind ‖ content`.
**Alternatives.** SHA-1 (git; broken collision resistance, SHAttered 2017); SHA-256 (git's
migration target; 3-6x slower than BLAKE3 on modern CPUs without SHA extensions).
**Why.** Cryptographic strength with SIMD throughput of several GB/s per core; domain
separation byte prevents blob/tree/changeset id confusion.

## ADR-003: zstd level 3 for stored objects, hash over uncompressed bytes

**Decision.** Store `kind ‖ zstd(content)`; hash the uncompressed content.
**Alternatives.** zlib (git; slower and worse ratio); LZ4 (faster, ~30% worse ratio);
higher zstd levels (marginal ratio, much slower writes).
**Why.** Best ratio/speed balance; hashing raw content keeps ids stable if compression
changes; every tier ships stored bytes as-is with no recompression.

## ADR-004: Changesets list changes; trees are derived data

**Decision.** A changeset records file changes relative to its first parent. Root trees
are computed by the generic derived-data mechanism.
**Alternatives.** git-style commits pointing at a full tree.
**Why.** Changeset creation cost scales with change size; derived data can be computed
eagerly or lazily and re-defined without touching clients.

## ADR-005: gRPC (tonic) over HTTP/2

**Decision.** One protobuf schema, gRPC transport, identical `Objects` service on every tier.
**Alternatives.** git smart-HTTP protocol (negotiates on what the client *has*, packfiles
are monolithic and not resumable); REST/JSON (no streaming, larger payloads).
**Why.** Streaming with backpressure, multiplexing, codegen for every language (so CI tools
in Python/Go/TS can call the API), reflection and health checking out of the box.

## ADR-006: Lock-free landing via CAS + server-side rebase

**Decision.** Refs move only by compare-and-swap; the server rebases on conflict-free races.
**Alternatives.** Merge queue with a global lock (serialises all merges; large monorepo operators
report removing exactly this); client-side rebase + push retry loop (git; each retry is a fetch).
**Why.** Throughput scales with disjointness of changes, not with a lock.

## ADR-007: Ports and adapters with contract tests

**Decision.** Every infrastructure dependency is a trait in `pando-core::ports`; each
adapter must pass a shared contract suite.
**Why.** Infrastructure is replaceable (SQLite → Postgres → CockroachDB; disk → S3) without
touching features; the contract suite turns "implements the trait" into "behaves identically".

## ADR-008: SQLite default, Postgres for HA, object_store for blobs

**Decision.** Default deployment is a single binary with SQLite (WAL). Postgres (and
Postgres-wire databases such as CockroachDB) for multi-replica deployments. Objects may
live in the metadata DB or in any `object_store` backend (S3, GCS, Azure, local).
**Alternatives.** Spanner only (not available to most users); FoundationDB
(excellent, but operationally rare); RocksDB (single-node only, no SQL ops tooling).
**Why.** Zero-setup start, standard managed services for scale, one adapter for every cloud.

## ADR-009: quick_cache for tier memory

**Decision.** Byte-weighted, sharded cache with CLOCK-Pro-style eviction.
**Alternatives.** `lru` (global lock, scan-sensitive); moka (excellent, heavier, async
eviction listeners not needed here).
**Why.** Low per-op overhead under high concurrency; resists one-off scans (CI checkouts)
evicting the hot set.

## ADR-010: git fast-export for import, fast-import for export

**Decision.** Stream git history through `git fast-export`/`fast-import`.
**Alternatives.** libgit2 / gitoxide object walking (requires re-diffing every commit).
**Why.** fast-export already emits changes relative to the first parent, which is the
changeset model. Single process, streaming, battle-tested by git itself. Import is
deterministic, so re-imports are idempotent and incremental.

## ADR-011: Feature flags on every slice

**Decision.** Each slice checks a flag at its entry; flags come from a port.
**Why.** Operators can disable a feature (e.g. `land` during an incident) without a
deploy; new features can ship dark.

## ADR-012: MCP server via the official Rust SDK

**Decision.** `pando mcp` exposes read/commit/land tools over stdio using `rmcp`.
**Why.** Agent-agnostic integration: any MCP client can drive Pando without bespoke
glue. The official SDK tracks the protocol specification.

## ADR-015: Path-scoped reads without object-level ACLs

**Decision.** A principal with restricted read access may not read objects by id at all.
The server serves them path-filtered views: a streaming `Checkout`, filtered `ListDir`/`Find`,
diffs limited to readable paths, and redacted changesets (marked `redacted`, so clients
know they cannot hash-verify them). `pando` detects the scope via `WhoAmI` and switches to
these APIs automatically.
**Alternatives.** Per-object ACLs (an object can be reachable from many paths and
revisions, so every read would need a reverse index); per-principal projected trees (new
tree ids per principal break content addressing and caching).
**Why.** Nothing a restricted reader receives names content they cannot read (unreadable
directory ids are blanked in listings), the content-addressed core stays untouched, and
full-read principals keep the fast object paths.

## ADR-013: v1 permissions scope

**Decision.** v1 enforces per-directory **write** permissions and per-ref permissions.
Read access is repository-wide.
**Why.** Content-addressed objects are reachable through parent trees, so path-scoped
reads require object-level authorization (tracked on the roadmap). Shipping write
protection now covers the OWNERS-style use case without a leaky read model.

## ADR-014: Delta storage via an offline, single-writer compaction job

**Decision.** Blob versions are delta-encoded in storage by `pandod compact`: zstd
"patch-from" frames (the previous version of the same path as a raw-content prefix, with
long-distance matching), chain depth ≤ 50 (git's default `pack.depth`). Trees are
delta-encoded the same way; they dominate storage because every changeset writes a new root. Live servers only *read* deltas: the
`DeltaObjects` decorator reconstructs and hash-verifies every object before it leaves the
storage layer, so the wire protocol, tiers and clients are unchanged.

**Alternatives.**
* Delta-encode at write time on every server: concurrent replicas can create delta cycles
  (A→B and B→A) that make both objects unreadable. Rejected: data loss is unacceptable.
* git-style packfiles: repacking requires global maintenance windows and breaks the
  "every request is one immutable object" property that makes caching trivial.
* zstd dictionaries trained per repository: ~2x, versus 20x+ for per-path deltas.

**Why this is safe.**
* One compactor at a time (lease = CAS on a reserved system ref).
* A base is *pinned* before anything is stored against it, and pinned objects are never
  converted; chains never change after something depends on them (depth headers exact,
  no cycles). A chain check guards against cycles as a second line of defence.
* Each delta is decoded and compared with the original in memory before the atomic
  `replace`; readers re-verify the BLAKE3 id on every reconstruction.
* Readers accept chains up to 256 frames (5x what compaction creates), so an unexpected
  chain can only slow a read, never make data unreadable.

**Measured.** Level 3 + long-distance matching: a one-line edit to a 22 KB source file
deltas to 45 bytes (vs 6.9 KB for standalone zstd) at the same speed as plain level 3;
higher levels cost 50-500x more time for <10% gain. On git/git (82,443 commits) compaction
converts 312k object versions (159k of them trees) in 15 minutes: storage 4.6 GB -> 369 MB
(git's own pack: 333 MB), and all 24,380 mainline commits read back with identical content.

## ADR-016: Pre-land checks as a fail-closed webhook, run before rebase

**Decision.** Landing calls a `LandCheck` port once, after authorization and before the
rebase/compare-and-swap loop. The shipped adapter POSTs the proposal to a URL; only a 2xx
answer lands, and timeouts or errors refuse the land.
**Why.** A webhook lets any CI system or review tool gate landing without Pando owning a
review database. Checking before rebase keeps the hook off the contended retry path, and is
sound because a server-side rebase only happens when no changed path conflicts, so the
approved file changes are exactly what lands. Failing closed means an outage of the gate
cannot let unreviewed code onto a protected branch.

## ADR-017: Batch concurrent lands per ref instead of retrying compare-and-swap

**Decision.** Within one server process, lands to the same ref join a queue. The land that
takes the ref's turn rebases everything queued as one chain over an in-memory overlay,
writes the chain and advances the ref with a single compare-and-swap. Checks that depend
only on the starting head run concurrently; the conflict check compares base and tip only
along the changeset's own paths.
**Why.** The original loop (read head, rebase, compare-and-swap, retry on loss) is
lock-free but does quadratic work under contention: with N landers, N-1 lose each swap and
rebase again. Measured on one machine it fell from 105 lands/s at 16 agents to 10 lands/s
with 237 "too contended" errors at 200 agents. Batched, the same machine sustains 758-1,012
lands/s at 16-200 agents and 504 at 1,000, with no errors. The compare-and-swap stays as
the arbiter between replicas, so correctness does not depend on the queue, and a
conflicting change fails without affecting the rest of its batch. A randomized test checks
the path-scoped conflict check against the previous full-diff rule.

## ADR-018: Test landing by deterministic simulation; write in dependency order

**Decision.** The landing protocol is tested by a seeded simulation: several replicas share
a store that fails, delays and loses replies, replicas crash and restart, and clients land
changes, some conflicting, on random replicas. One seed drives a single-threaded runtime
with a paused clock, so any failure replays exactly. After each run four invariants are
checked: no change lands twice, every acknowledged land is in history, the tree equals
replaying history, and no change lands over a conflicting change it never saw. It runs 200
seeds in every CI build and 50,000 new seeds nightly.
**Why.** Landing is where a bug loses work, and its failure cases (a reply lost after a
write was applied, a crash halfway through a batch) are hard to reach with example tests.
The first runs found three real bugs: a batch failed entirely on one transient storage
error; a flush that failed halfway could leave a record naming a tree or changeset that
was never written, which a later land recreating the same changeset would trust; and a
change rebased by a land whose reply was lost was applied a second time when retried.
The fixes: batches retry storage errors from the current head; staged writes go out in
dependency order (objects, then changesets, then derived records); and each rebased
change records the id it landed as, so a retry reports that landing instead of repeating
it. Scope: this simulates the landing protocol over in-memory stores, not the whole system
(network, disk and SQLite are real code paths it does not exercise).

**Addendum (2.1.3).** A black-box chaos test against real replicas on Postgres
(`bench/chaos.sh`) found that the landed-as record is not enough: two replicas landing the
same retried change both write it, and the replica that loses the race can overwrite the
winner's record, so a later retry lands the change again. The fix that holds without
bookkeeping: a change rebased onto a tip that already holds all of its changes is reported
as landed at that tip instead of becoming an empty commit, which is also what `git rebase`
does with commits that become empty. The landed-as record stays as a fast path. The
simulation's clients now give up waiting and retry on other replicas, and it catches this
race at the second seed when the fix is removed.

## ADR-019: File locks are system refs moved by compare-and-swap

**Decision.** A lock on `path` is the system ref `_lock/<hash of path>`, pointing at a
small record object (path, owner, time). Taking a lock is a compare-and-swap from absent
(or released) to the record; releasing swaps it to a fixed "unlocked" id, since refs
cannot be deleted. Landing lists the lock refs once and refuses changes to paths locked by
someone else. Locking and forced unlocking need write access to the path.
**Why.** Teams with binary assets (games, film, hardware) need exclusive checkout, which is
why many stay on Perforce; Git LFS added a locking API for the same reason. Refs already
give an atomic, replicated compare-and-swap in every backend, so locks need no new storage
port, and two people can never hold one lock, across server replicas too. User ref names
cannot contain `_`, so clients cannot forge or move a lock through the refs API. The check
runs when a land arrives, as Git LFS checks at push: a lock taken while a land is already
being applied does not stop that land.

## ADR-020: Virtual checkouts use NFS on macOS and ProjFS on Windows

**Decision.** One platform-independent `VirtualTree` serves every platform. Linux mounts it
with FUSE. macOS mounts a read-only NFSv3 server that `pando` runs on localhost (the
`nfsserve` crate) with the system's own `mount_nfs`. Windows projects it with the Projected
File System, whose library is loaded at run time.
**Why.** On macOS, FUSE needs macFUSE's kernel extension, which users must approve in
recovery settings; its newer FSKit backend is opt-in and lacks features. A localhost NFS
server needs nothing installed, and it is where Meta's EdenFS moved as Apple deprecated
kernel extensions; XetHub mounts multi-terabyte repositories the same way. NFS never says
when the client drops a file handle, so every inode stays valid for the life of the mount,
which `VirtualTree` already guarantees. On Windows, ProjFS is built in (the mechanism behind
VFS for Git and EdenFS there) and needs no driver. Loading its library at run time keeps
`pando` starting on machines where the optional feature is off. Both mounts are tested in
CI against the real kernels: a stock macOS runner mounts without admin rights, and a Windows
runner projects with ProjFS, each compared file by file with `pando clone`. On managed Macs
whose policy forbids user mounts, `--serve-only` prints the command for an administrator.

## ADR-021: The web console and the platform contract

**Decision.** The console is a static React 19 app (React Compiler, React Aria, TanStack
Router and Query, Connect-ES over gRPC-Web, Shiki in a worker) that talks to `pandod`
directly. Hosting features (organisations, repositories, accounts, change requests, reviews,
protected branches) are specified first as `pando_platform.proto`, implemented by an
in-browser demo, then by the server. Repository-scoped calls name their repository in the
`x-pando-repo` header; a call without it reaches the default repository.
**Why.** Solid, Svelte and Leptos were compared. Rendering cost is bounded by what is on
screen, not by the framework, so the deciding factors were accessible components (React Aria
has the most complete keyboard and screen-reader behaviour) and contributors. A static app with
no backend of its own has nothing to operate and can be hosted anywhere, including for free. Contract
first lets the whole interface be built, tested and demonstrated before the server work lands,
and the header keeps every existing client working when a server starts hosting several
repositories. Servers without the platform service answer `Unimplemented`, and the console
shows their one repository. The cost is about 107 KB of gzipped JavaScript for React, the
router and the gRPC-Web runtime before any interface code; the build enforces a budget for the
first screen.

## ADR-022: Hosting many repositories by dispatching to one set of services per repository

**Decision.** A server started with `--platform` keeps a small registry of repositories and opens
each one's storage from templates (`{repo}`, `{repo_id}`) the first time it is used. A layer
inside authentication reads the `x-pando-repo` header and hands the call to that repository's own
services, built by the same `authority_routes` as a single-repository server. Calls without the
header reach the default repository.
**Why.** Nothing in the features had to change: every repository gets the code that is already
tested, simulated and chaos-tested, including its own landing queues, so a busy repository cannot
slow another. Separate storage per repository is the isolation a hosted, multi-tenant service needs
(backup, move, delete or place one repository on its own), and the content-addressed object store
can still be shared by pointing every template at one bucket. Putting the dispatch inside
authentication means the principal is known before any repository is opened, and the header
keeps every existing client working. The cost is one open database per active repository, which
is why repositories open lazily.

## ADR-023: Accounts, roles and tokens live in the platform registry

**Decision.** A platform server keeps accounts, organisations, members, teams, grants and access
tokens in the registry database next to the list of repositories. Every call that names a
repository is checked in the hosting layer, after authentication and before the repository
opens: methods that only read need the Read role, everything else needs Write. The read list is
explicit, so a method added later needs Write until someone decides otherwise. A caller who may
not read a repository gets NotFound, the same answer as for a repository that doesn't exist.

A role is the highest of organisation membership, direct grants and team grants; internal and
public repositories add Read for every account. Agents act with their owner's role unless given
their own. Tokens are 32 random bytes, prefixed `pando_` for secret scanners, stored as a BLAKE3
hash, scoped to repositories and a highest role, and expire within a year. A token made with a
token can't reach further than the one used to make it.

Platform tokens are checked before the server's other authentication; anyone who signs in
another way gets an account, with no role until an administrator gives one. `pandod token`
writes the first token straight into the registry, so a server can run on platform tokens alone
and nobody has to configure a shared secret.

**Why.** GitHub and Bitbucket model access the same way (organisation base role, repository
collaborators, teams), so administrators already know it. Keeping it in the registry means one
small database to back up per server, and the check needs no network call. Treating unknown
methods as writes, and unreadable repositories as missing, fails safe.

**Trade-offs.** The check reads SQLite on every repository call: a few indexed lookups under one
mutex, measured well below the cost of a land; a cache comes if profiles show it. Servers with
no authentication at all stay open, for local development, as before. Repositories created in
phase 1 become private to their organisation's members: administrators add members after
upgrading.

## ADR-024: Change requests land as one rebased changeset; protection is an access policy

**Decision.** A change request proposes a branch (the source) for a target. It records the
source's merge base with the target, follows the source branch as it moves, and lands as one
changeset: everything the source changed since its base, landed through the same server-side,
per-file rebase as any other land. Reviews, comments, checks, protections and an activity log
live in the platform registry beside accounts and grants.

Branch protection is an access policy wrapped around each repository's own: updating a protected
branch is allowed only to those it lets bypass review (and to agents when it lets agents land
directly). Change requests land through a separate land path without that wrapper, so their
review is the gate. Checks are recorded per version of the source, so a new push starts with
none; approvals made on an older version stop counting when the protection says so.

**Why.** Landing a single rebased changeset needs no new merge machinery and inherits the
landing guarantees already tested by simulation and chaos runs. Putting protection in the access
policy covers every way to move a branch (land and compare-and-swap) with one check, and the
refusal says how to proceed.

**Trade-offs.** The landed changeset is a squash: the branch's own changesets are not replayed
one by one. Conflicts are computed from two tree diffs on each read of an open change request,
proportional to what changed; a cache comes if listings of hundreds of open requests get slow.
An agent's land on a protected branch is refused rather than turned into a change request
automatically; `pando cr create` is one command away.

## ADR-025: Webhooks are a signed, leased delivery queue in the registry

**Decision.** Events are written to a `deliveries` table in the platform registry, one row per
interested webhook, and a worker in every server process claims due rows with a single
`UPDATE … RETURNING` that pushes their next attempt a minute ahead (a lease), posts them, and
records the outcome; failures retry with exponential backoff, eight attempts in all. Bodies are
signed with HMAC-SHA256 in GitHub's `sha256=` format. Push events come from a wrapper around
each hosted repository's ref store, the one place every branch move passes through.

**Why.** A queue in the database survives restarts and needs no broker to run or pay for. The
lease makes any number of replicas safe without coordination. GitHub's signature format means
receivers reuse the code they already have. Wrapping the ref store catches lands, pushes and
rebases alike, including ways to move a branch added later.

**Trade-offs.** Addresses are checked when resolved, not pinned for the connection, so a DNS
answer that changes in between could reach an address that was refused; webhooks are set up by
repository administrators, and link-local addresses are refused at both points that matter in
practice. Secrets are stored as given, because signing needs them.

## ADR-026: Remote MCP is a stateless gateway that passes the caller's token through

**Decision.** `pando mcp --http` serves Model Context Protocol tools for a whole server over
streamable HTTP, statelessly (MCP 2026-07-28; no sessions). Each request's bearer token is
forwarded to the server for every call the tool makes, so the gateway holds no credentials and
an agent can do exactly what its token allows. Writing files lands them as one changeset on a
branch; on a protected branch the change goes to a `review/` branch and a change request opens.
An agent's change request asks the person the agent answers to for review.

**Why.** Agents shouldn't need a clone, a workspace or a git client to change code: a URL and
a token is the whole setup, which is what makes Pando usable from hosted agents. Passing the
token through avoids a confused deputy and reuses every permission check, token limit and
audit record the server already has. Statelessness matches the server: gateways scale
horizontally behind any load balancer and need nothing to coordinate.

**Trade-offs.** A gateway is a second process to run (it can share the server's host or
container). Changesets with no author are attributed to the authenticated caller; a client can
still claim another author name, as in git, which a later change will restrict on platform
servers.

## ADR-027: Issues share numbering with change requests and close from "fixes #N"

**Decision.** Issues live in the platform registry beside change requests and take numbers from
the same per-repository sequence, so `#12` names one thing. Anyone who can read a repository
may open an issue and comment; assigning, labelling and closing someone else's issue take
triage, as on GitHub. A change request whose title or description says "fixes", "closes" or
"resolves" `#N` closes that issue as done when it lands. Issues assigned to you are in your
inbox, and `issue` webhook events (opened, assigned, closed, reopened) let an agent runner start
work the moment an issue is assigned to an agent.

**Why.** The agent loop (assign, work, propose, review, land, done) needs no glue: an agent reads
its inbox over MCP, opens a change request that fixes the issue, and landing it closes the loop.
Shared numbers and GitHub's keywords keep habits and links working for people moving from
GitHub.

**Trade-offs.** No milestones, projects or issue templates yet; labels are free text. Which
change requests fix an issue is worked out when the issue is read, by scanning the repository's
change requests, which a link table will replace if repositories reach many thousands of them.

## ADR-028: Migration imports history with git and the rest through GitHub's API

**Decision.** `pando migrate FROM --to SERVER/OWNER/NAME` mirror-clones the source with git,
imports the default branch first and then every other branch with the existing incremental
importer, and, when the source is on GitHub (or `--github-api` names a GitHub Enterprise
Server), brings open pull requests across as change requests from `github/pr-N` branches and
issues with their comments, labels and state. It finishes by printing the `pando mirror`
command that keeps the old host current.

**Why.** Moving must be one command and reversible, or nobody tries it: git already knows how to
fetch everything, the importer is already deterministic and incremental, and the mirror turns
"migrate" into "try it side by side". Pull requests and issues are what teams lose most often in
moves, so they come too.

**Trade-offs.** Commit ids change. Imported issues and change requests are posted by the person
running the migration, with the original author named and linked, because Pando accounts don't
map to GitHub logins. Only open pull requests move; review comments on them don't yet. Each
branch is imported separately, so a repository with very many branches takes longer.

## ADR-029: Access answers are cached per process and dropped by every write

**Decision.** The reads every repository call makes against the platform registry (the
repository's record, a caller's role, an agent's owner, team membership, branch protection, and
whether any webhook wants pushes) are cached in memory. Every write that could change an answer
(membership, grants, teams, repositories, protections, webhooks, new accounts) clears the cache
at once; entries also expire after five seconds, which bounds how long a write on another
replica can go unseen. Push events are prepared off the landing path, and only when a webhook
wants them.

**Why.** Measured with 200 agents landing on one branch (release build, one laptop): through a
hosted repository with access checks, throughput fell from about 1,140 to 770–960 changes a
second and p99 latency rose from 0.3 s to 2.8–3.8 s. With the cache and the push change it is
1,010–1,150 changes a second with p99 0.22–0.25 s, the same as a server without the platform
(also with a non-administrator token, zero errors).

**Trade-offs.** A revoked grant is enforced at once on the replica that made the change and
within five seconds on others. Webhook lists in the console are read uncached, so delivery
status stays current.

## ADR-030: Reviews and checks come from someone else; platform servers are single-node

**Decision.** A change request's author, the person an agent author answers to (followed up any
chain of agents), and every agent that person answers for count as one person. That person
can't approve or request changes on the change, their approvals don't count towards a protected
branch, and they can't report the change's checks. Checks are otherwise reported by anyone with
Write, so CI runs as its own account or agent. `--oidc-require CLAIM=VALUE` binds single sign-on
to a tenant, and pandod refuses to start with a multi-tenant issuer (GitHub Actions, Google)
without such a rule; single sign-on can't claim a platform administrator's login (unless listed
with `--oidc-admin`) or an `agent/` or `bot/` login. Paths named `.git` or `.pando` in any case
or Windows spelling are invalid everywhere. A platform server is one process over one SQLite
registry, backed up with `pandod backup` and restored by copying back while stopped.

**Why.** A production review showed a single developer token could ship to a protected branch:
mint an agent, approve as the agent, report `build: passed`. Agents already record their owner,
so the rule needs no new state. OIDC issuers such as GitHub Actions sign tokens for anyone with
a workflow, so validating `iss`/`aud` alone admits the internet. A tracked `.git/hooks` file
runs code on the next `git` command in a colocated checkout (git's own CVE-2014-9390).

**Trade-offs.** An agent's work needs a human other than its owner to approve it, and a team of
one can't use required approvals. Checks aren't bound to a named reporter yet; naming one per
required check (`build@bot/ci`) is the next step if CI identities need pinning. Existing history
with `.git` or `.pando` paths can't be read or checked out. Scaling a platform server out needs a
shared registry (Postgres), which doesn't exist yet.

## ADR-031: Sign-in issues platform tokens

**Decision.** Browser sign-in is a separate listener inside `pandod` (`--login-listen`) that
turns a verified identity into an ordinary platform token ("browser session", 30 days, Admin
ceiling, every repository), handed to the console in the URL fragment. Providers are generic
OpenID Connect (authorization code, PKCE S256, state, nonce), with Google first; email links are
the provider-free alternative. Identities are keyed by provider and subject in `identities`,
never by email, and a new identity is never attached to an existing account by matching email;
a site administrator links one explicitly (`LinkIdentity`). New accounts need a verified email
and the signup policy's consent (`--signup waitlist` by default, `signup_allow` by address or
`@domain`). Sign-in state, nonces and email links are stored only as hashes, for one use.

**Why.** Every RPC already authorises platform tokens (ADR-023), so sign-in adds no second
session mechanism: revoking the token signs the browser out, and the token list shows browser
sessions next to the rest. Generic OIDC covers Google, Okta, Entra and Keycloak with one
reviewed path (ID tokens are checked by the same code as SSO bearer tokens); not depending on
GitHub matters because Pando competes with it. A fragment never reaches servers or logs.

**Trade-offs.** The console holds a bearer token in browser storage rather than an HttpOnly
cookie, so cross-site scripting in the console could read it; a strict CSP on the console,
the 30-day lifetime and revocation limit that. Providers that omit `email_verified` (some Entra setups)
can't create accounts. Request limits are per process.
