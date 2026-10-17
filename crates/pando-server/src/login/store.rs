//! What sign-in keeps in the registry: who signed in with what, who may sign up, and the
//! short-lived state of sign-ins in progress (stored as hashes only).

use anyhow::Context as _;
use pando_proto::AccountKind;

use crate::hosting::{Registry, now_ms};

pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS identities (
  provider TEXT NOT NULL,
  subject TEXT NOT NULL,
  login TEXT NOT NULL,
  email TEXT,
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (provider, subject)
);
CREATE TABLE IF NOT EXISTS signup_allow (
  entry TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS login_states (
  key_hash BLOB PRIMARY KEY,
  provider TEXT NOT NULL,
  nonce TEXT NOT NULL,
  verifier TEXT NOT NULL,
  next TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS email_logins (
  token_hash BLOB PRIMARY KEY,
  email TEXT NOT NULL,
  next TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
";

/// Names sign-in never hands out: they look like the console's and the site's own pages.
const RESERVED: &[&str] = &[
    "admin", "api", "login", "settings", "new", "explore", "www", "mail", "support", "help", "security", "status",
    "docs", "pando",
];

/// A login proposed from an email address: its local part, lowercased, with anything but
/// letters, digits, `.`, `_` and `-` turned into `-`, so it is also a valid organisation name.
fn proposed_login(email: &str) -> String {
    let local = email.split('@').next().unwrap_or_default().to_ascii_lowercase();
    let s: String = local
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .take(39)
        .collect();
    let s = s.trim_matches(['.', '-']);
    if s.is_empty() { "user".to_owned() } else { s.to_owned() }
}

impl Registry {
    /// Whether the waitlist lets `email` (lowercased) create an account: the address itself or
    /// its `@domain` is listed.
    pub fn signup_allowed(&self, email: &str) -> anyhow::Result<bool> {
        let domain = email.rsplit_once('@').map(|(_, d)| format!("@{d}")).unwrap_or_default();
        let db = self.db.lock().unwrap();
        Ok(db.query_row(
            "SELECT EXISTS (SELECT 1 FROM signup_allow WHERE entry = ?1 OR entry = ?2)",
            (email, domain),
            |r| r.get(0),
        )?)
    }

    pub fn signup_entries(&self) -> anyhow::Result<Vec<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached("SELECT entry FROM signup_allow ORDER BY entry")?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Adds or removes a waitlist entry (already normalised by [`super::signup_entry`]).
    pub fn set_signup_entry(&self, entry: &str, allowed: bool) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        if allowed {
            db.execute("INSERT INTO signup_allow (entry) VALUES (?1) ON CONFLICT DO NOTHING", [entry])?;
        } else {
            db.execute("DELETE FROM signup_allow WHERE entry = ?1", [entry])?;
        }
        Ok(())
    }

    /// The account a provider's subject signs in as, if it has signed in before.
    pub fn identity_login(&self, provider: &str, subject: &str) -> anyhow::Result<Option<String>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached("SELECT login FROM identities WHERE provider = ?1 AND subject = ?2")?;
        Ok(st.query_map((provider, subject), |r| r.get(0))?.next().transpose()?)
    }

    /// Creates a person's account for a first sign-in and records the identity; returns the
    /// login. The login comes from the email's local part, suffixed `-2`, `-3`… when an
    /// account, organisation or `reserved` name already has it. An identity that already
    /// exists keeps its account.
    pub fn create_person(
        &self,
        provider: &str,
        subject: &str,
        email: &str,
        reserved: &[String],
    ) -> anyhow::Result<String> {
        let base = proposed_login(email);
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let known: Option<String> = tx
            .query_row("SELECT login FROM identities WHERE provider = ?1 AND subject = ?2", (provider, subject), |r| {
                r.get(0)
            })
            .ok();
        if let Some(login) = known {
            return Ok(login);
        }
        let now = now_ms();
        let mut login = base.clone();
        for n in 2.. {
            let taken: bool = reserved.contains(&login)
                || RESERVED.contains(&login.as_str())
                || tx.query_row(
                    "SELECT EXISTS (SELECT 1 FROM accounts WHERE login = ?1)
                       OR EXISTS (SELECT 1 FROM organizations WHERE login = ?1)",
                    [&login],
                    |r| r.get(0),
                )?;
            if !taken {
                break;
            }
            anyhow::ensure!(n < 10_000, "no free login for {base}");
            login = format!("{base}-{n}");
        }
        tx.execute(
            "INSERT INTO accounts (login, display_name, kind, owner, created_at_ms) VALUES (?1, ?1, ?2, '', ?3)",
            (&login, AccountKind::Person as i32, now),
        )?;
        tx.execute(
            "INSERT INTO identities (provider, subject, login, email, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
            (provider, subject, &login, email, now),
        )?;
        tx.commit()?;
        drop(db);
        self.invalidate();
        Ok(login)
    }

    /// Lets `provider`'s `subject` sign in as the existing account `login` (how the first
    /// administrator, made with `pandod token`, signs in from a browser). False if that
    /// identity already belongs to another account.
    pub fn link_identity(&self, login: &str, provider: &str, subject: &str) -> anyhow::Result<bool> {
        let email = (provider == "email").then_some(subject);
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO identities (provider, subject, login, email, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT DO NOTHING",
            (provider, subject, login, email, now_ms()),
        )?;
        let owner: String = db.query_row(
            "SELECT login FROM identities WHERE provider = ?1 AND subject = ?2",
            (provider, subject),
            |r| r.get(0),
        )?;
        Ok(owner == login)
    }

    pub(crate) fn put_login_state(
        &self,
        key_hash: &[u8],
        provider: &str,
        nonce: &str,
        verifier: &str,
        next: &str,
        expires_at_ms: i64,
    ) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM login_states WHERE expires_at_ms < ?1", [now_ms()])?;
        db.execute(
            "INSERT INTO login_states (key_hash, provider, nonce, verifier, next, expires_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (key_hash, provider, nonce, verifier, next, expires_at_ms),
        )
        .context("recording a sign-in")?;
        Ok(())
    }

    /// Removes and returns a sign-in in progress (nonce, PKCE verifier, next path), if it is
    /// for `provider` and has not expired. Each can be used once.
    pub(crate) fn take_login_state(
        &self,
        key_hash: &[u8],
        provider: &str,
    ) -> anyhow::Result<Option<(String, String, String)>> {
        let db = self.db.lock().unwrap();
        let mut st = db.prepare_cached(
            "DELETE FROM login_states WHERE key_hash = ?1 RETURNING provider, nonce, verifier, next, expires_at_ms",
        )?;
        let row = st
            .query_map([key_hash], |r| {
                Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)?))
            })?
            .next()
            .transpose()?;
        Ok(row.filter(|r| r.0 == provider && r.4 > now_ms()).map(|r| (r.1, r.2, r.3)))
    }

    pub(crate) fn put_email_login(
        &self,
        token_hash: &[u8],
        email: &str,
        next: &str,
        expires_at_ms: i64,
    ) -> anyhow::Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM email_logins WHERE expires_at_ms < ?1", [now_ms()])?;
        db.execute(
            "INSERT INTO email_logins (token_hash, email, next, expires_at_ms) VALUES (?1, ?2, ?3, ?4)",
            (token_hash, email, next, expires_at_ms),
        )?;
        Ok(())
    }

    /// Removes and returns an email link's address and next path, if it has not expired.
    pub(crate) fn take_email_login(&self, token_hash: &[u8]) -> anyhow::Result<Option<(String, String)>> {
        let db = self.db.lock().unwrap();
        let mut st =
            db.prepare_cached("DELETE FROM email_logins WHERE token_hash = ?1 RETURNING email, next, expires_at_ms")?;
        let row = st
            .query_map([token_hash], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))?
            .next()
            .transpose()?;
        Ok(row.filter(|r| r.2 > now_ms()).map(|r| (r.0, r.1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logins_are_proposed_from_the_address_and_suffixed_when_taken() {
        assert_eq!(proposed_login("Kabir.Narang+x@example.com"), "kabir.narang-x");
        assert_eq!(proposed_login(".-@example.com"), "user");
        let r = Registry::open("memory").unwrap();
        r.ensure_account("mira", "").unwrap();
        let org = crate::directory::OrgRec {
            login: "mira-2".into(),
            display_name: String::new(),
            description: String::new(),
            created_at_ms: 0,
        };
        r.create_organization(&org).unwrap();
        assert_eq!(r.create_person("google", "1", "mira@a.example", &[]).unwrap(), "mira-3");
        assert_eq!(r.create_person("google", "1", "other@a.example", &[]).unwrap(), "mira-3", "same identity");
        assert_eq!(r.create_person("email", "root@a.example", "root@a.example", &["root".into()]).unwrap(), "root-2");
        assert_eq!(r.identity_login("google", "1").unwrap().as_deref(), Some("mira-3"));
        assert_eq!(
            r.create_person("email", "a@x.example", "admin@x.example", &[]).unwrap(),
            "admin-2",
            "route-like names"
        );
        assert!(r.link_identity("mira", "email", "mira@b.example").unwrap());
        assert!(r.link_identity("mira", "email", "mira@b.example").unwrap(), "again: no change");
        assert!(!r.link_identity("mira-3", "email", "mira@b.example").unwrap(), "belongs to someone else");
    }

    #[test]
    fn sign_ins_in_progress_are_single_use_and_expire() {
        let r = Registry::open("memory").unwrap();
        let later = now_ms() + 60_000;
        r.put_login_state(b"k1", "google", "n", "v", "/", later).unwrap();
        assert!(r.take_login_state(b"k1", "other").unwrap().is_none(), "for another provider");
        r.put_login_state(b"k2", "google", "n", "v", "/x", later).unwrap();
        assert_eq!(r.take_login_state(b"k2", "google").unwrap(), Some(("n".into(), "v".into(), "/x".into())));
        assert!(r.take_login_state(b"k2", "google").unwrap().is_none(), "used");
        r.put_login_state(b"k3", "google", "n", "v", "/", now_ms() - 1).unwrap();
        assert!(r.take_login_state(b"k3", "google").unwrap().is_none(), "expired");

        r.put_email_login(b"t1", "a@b.example", "/", later).unwrap();
        assert_eq!(r.take_email_login(b"t1").unwrap(), Some(("a@b.example".into(), "/".into())));
        assert!(r.take_email_login(b"t1").unwrap().is_none(), "used");
        r.put_email_login(b"t2", "a@b.example", "/", now_ms() - 1).unwrap();
        assert!(r.take_email_login(b"t2").unwrap().is_none(), "expired");
    }

    #[test]
    fn waitlist_matches_addresses_and_domains() {
        let r = Registry::open("memory").unwrap();
        r.set_signup_entry("mira@a.example", true).unwrap();
        r.set_signup_entry("@corp.example", true).unwrap();
        assert!(r.signup_allowed("mira@a.example").unwrap());
        assert!(r.signup_allowed("anyone@corp.example").unwrap());
        assert!(!r.signup_allowed("eve@a.example").unwrap());
        assert!(!r.signup_allowed("eve@sub.corp.example").unwrap());
        r.set_signup_entry("@corp.example", false).unwrap();
        assert_eq!(r.signup_entries().unwrap(), vec!["mira@a.example".to_owned()]);
    }
}
