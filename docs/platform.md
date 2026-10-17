# Pando platform: hosting, review and the web app

Pando's web app grows from a read-only console into a full hosting platform: organisations,
repositories, people and agents, change requests with review, protected branches and the
activity of an agent fleet, on top of the Pando server. This page records which flows it covers,
how they compare with GitHub's, and the order they are built in.

## How the flows were mapped

GitHub's public pages for a busy repository (`tokio-rs/tokio`) were captured in a scripted
browser and their structure read from the accessibility tree: repository home, pull request list,
a pull request's conversation and changed files, commits, a commit, blame, a file, issues, an
issue, compare, releases, actions, branches and the organisation page. Pages that need an
account (creating repositories and organisations, settings, rulesets, tokens, notifications,
submitting a review, the merge queue) were not observed; their flows come from GitHub's
documentation and are marked *documented* below. Nothing from GitHub's code, design or assets is
reused; only the list of jobs people do.

## What GitHub's pages are made of (observed)

| Page | What is on it |
|---|---|
| Pull request list | query box with qualifier syntax (`is:pr state:open`); filters for author, label, project, milestone, reviews, assignee; sort; comfortable or compact density; check status per row ("91/92"); labels; stack position ("2 of 2") |
| Pull request | split into Conversation, Commits, Checks and Files changed tabs; sidebar forms for reviewers, assignees, labels, projects, milestone and linked issues; participants |
| Files changed | commit range picker ("Changes from all commits"), file filter, conversations, jump to file, diff settings, collapse and expand all |
| Commits | branch, author and date filters; grouped by day; copy SHA; expand description |
| Commit | file tree with filter; one collapsible region per file with copy-path and options; commit comments |
| Blame and file | branch picker, path breadcrumbs, raw/blame/history actions, symbols |
| Issues and issue | the same query-and-filters list; timeline with sidebar metadata |
| Compare, releases, actions, branches, organisation | base/head pickers; release notes with assets; workflow runs; branch list with ahead/behind; organisation repositories and people |

## Where GitHub is weak, and what Pando does instead

| GitHub today | Pando |
|---|---|
| A pull request is four tabs; reviewing means switching between the conversation, the diff and checks | One review page: the file tree, the diff, comments and checks side by side, with keyboard navigation through files and threads |
| Large diffs are cut off ("Load diff", files hidden) and big pull requests get slow | Diffs render only what is on screen and highlight off the main thread; nothing is hidden behind a button except deliberately huge generated files |
| Lists go stale until you reload | Everything live: lists, review state and branch tips update as they change, without moving what you are reading |
| Agents are ordinary users; a fleet opening hundreds of pull requests floods the list | Agents are first-class: marked as agents, grouped by fleet, with a timeline per agent and filters for people versus agents |
| Merge conflicts surface late; the merge queue is a separate feature | Pando lands with path-scoped conflict checks (1,012 lands/s at 200 agents against git's 2); a change request merges by landing, and conflicts are known per path before anyone reviews |
| Branch protection and rulesets live in settings pages far from the code | Protection is shown where it applies: on the branch, on the change request and in the land result, with the reason a land was refused |
| Monorepo work: slow clones, history of a directory is slow, CODEOWNERS is a text file | Clone in 0.46 s instead of 19.1 s (git/git), mount any revision, path history is a server query, owners per path are part of the repository's settings |
| Notifications are one stream for everything | A review inbox: what waits on you, what you wait on, and what agents need approved, in that order |

## Flows, in build order

Each phase ships behind a feature flag, with server and web app together, tests, docs and a
demo that runs in the browser.

1. **Repositories and organisations** (done in 3.1). One server hosts many repositories, each with its own
   storage (a `{repo}` template in the storage URLs). Requests name their repository; an older
   client that names none reaches the default repository. Organisation and repository pages,
   repository creation, a home page with your repositories and their activity.
2. **Coexistence with GitHub, GitLab and Bitbucket** (done in 3.1: `pando mirror`). A continuous mirror of every landed change
   to an existing host, so CI, integrations and audit archives keep working while agents land in
   Pando. This is how an enterprise adopts Pando without replacing anything.
3. **People, agents and access** (done in 3.2, ADR-023). Accounts from the identity provider (OIDC is already
   supported), personal and agent tokens, organisation members, teams, and per-repository roles
   (read, write, maintain, admin). Agents are accounts marked as agents and owned by a person or
   team.
4. **Change requests and review** (done in 3.3, ADR-024). Open a change request from a branch, review with comments on
   lines, suggestions, approvals and requests for changes; merge by landing. Protected branches
   with required approvals and checks; an agent's land on a protected branch becomes a change
   request automatically.
5. **Inbox, checks and integrations.** Review inbox and notifications, check runs reported by CI,
   webhooks, and an audit view.
6. **Issues and releases** *(documented flows)*. Issues with the same live lists, labels and
   linking to change requests; releases with notes and assets.

## UX audit of the web app (2026-10-17)

Fixed in this round: the review page can collapse files; landing asks for confirmation and names
the branch; a conflict offers a rebase, which re-applies the change when edits don't overlap
and otherwise names the files; errors start with a capital and say what to do next; the code
view has a visible "Go to file"; live views load an hour of history; the command menu no longer
loses the first key typed; effects can no longer hand React a Promise as cleanup.

Still open, in priority order:

1. **Open a change request from the app.** Compare two branches and open one (GitHub's
   "Compare & pull request"). Today agents open them by landing on a protected branch.
2. **Profiles.** Clicking a person or agent should open their page: activity, repositories,
   owned agents.
3. **Create a repository and an organisation** from the app.
4. **Mark files as viewed** in a review, with progress, so large reviews can be resumed.
5. **Syntax highlighting inside diffs.**
6. **Search inside files.** The server's `Find` matches paths only.
7. **Edit settings** (protection, access) once the server implements them; the demo shows them
   read-only.
8. **Notifications** beyond the inbox: email or webhook delivery.

## Sign-in

People sign in from a browser with Google (or any OpenID Connect provider) or with a link sent by
email. `pandod server --platform … --login-listen 127.0.0.1:7430` serves the pages under
`/login/*`; put it behind the same host name as the console (Caddy routes `/login/*` to it).
A successful sign-in creates an ordinary platform token, "browser session" (30 days, Admin
ceiling, every repository), and sends the browser to `{public-url}{next}#pando_session=TOKEN`.
The console reads the token from the fragment and wipes it from the address bar. Revoking the
token signs the browser out (ADR-031).

**Google.** In Google Cloud Console, create an OAuth client of type "Web application" with the
authorized redirect URI `{public-url}/login/oidc/google/callback`, then:

```sh
export PANDO_OIDC_GOOGLE_CLIENT_ID=….apps.googleusercontent.com
export PANDO_OIDC_GOOGLE_CLIENT_SECRET_FILE=/run/secrets/google-client-secret
pandod server --platform sqlite:///var/lib/pando/registry.db --repos-metadata … \
  --login-listen 127.0.0.1:7430 --public-url https://pando.example.com \
  --oidc google=https://accounts.google.com
```

Any other OpenID Connect provider works the same way: `--oidc ID=ISSUER_URL` with
`PANDO_OIDC_<ID>_CLIENT_ID` and `PANDO_OIDC_<ID>_CLIENT_SECRET` (or `_FILE`), and the redirect
URI `{public-url}/login/oidc/ID/callback`. A provider must report `email_verified: true` for
a new account to be created; some Microsoft Entra ID setups don't send that claim, so their
users can't sign up (link them to an account instead, below).

**Email links.** `--smtp-url smtps://smtp.example.com:465` (or `smtp://HOST:587?tls=required`),
`--mail-from "Pando <login@example.com>"`, with `PANDO_SMTP_USERNAME` and `PANDO_SMTP_PASSWORD`
(or `_FILE`). A link works once, within 15 minutes; opening it shows a "Sign in" button, so mail
scanners that fetch links don't use it up. The form answers the same whether or not the
address may sign in. Add `--turnstile-site-key` and `PANDO_TURNSTILE_SECRET` to put a
Cloudflare Turnstile challenge on it.

**Who may sign up.** `--signup waitlist` (the default) lets only listed addresses and domains
create accounts; `open` lets anyone; `closed` lets nobody. People with an account can always sign
in. Site administrators manage the list:

```sh
pando admin signup allow mira@example.com
pando admin signup allow @example.com
pando admin signup list
pando admin signup remove @example.com
```

**Accounts.** The first sign-in creates a person's account, named after the email's local part
(`mira`, then `mira-2`… if taken by an account or organisation; site administrators' logins and
names like `admin`, `api`, `login` and `settings` are never handed out). A sign-in is never
attached to an existing account because the email matches. To let the first administrator
(created with `pandod token`) sign in from a browser, a site administrator links an identity:

```sh
pando admin identity link kabir --provider email --subject kabir@example.com
```

`GET /login/providers` lists the sign-in buttons for the console:
`{"providers":[{"id":"google","name":"Google","url":"/login/oidc/google"}],"email":true}`.

## The web app's foundation

React 19 with the React Compiler, React Aria for accessible components, TanStack Router and Query,
Connect-ES over gRPC-Web, and Shiki in a worker. Every view's state is in its URL. The server
contract is written first (protobuf), implemented by an in-browser demo server so the whole app
can be built and tested, then implemented by `pandod`.
