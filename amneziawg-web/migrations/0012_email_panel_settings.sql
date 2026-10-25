-- Empty means the operator's environment remains authoritative. A full row is
-- created only by an explicit authenticated Save, never by migration/startup.
-- This table contains a secret: the application requires private storage before
-- reading/writing it. It must never be included in panel/configuration exports.
CREATE TABLE email_panel_settings (
 id INTEGER PRIMARY KEY CHECK(id=1),
 revision INTEGER NOT NULL CHECK(revision>0),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 host TEXT NOT NULL,
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 tls TEXT NOT NULL CHECK(tls IN ('starttls','implicit')),
 authenticate INTEGER NOT NULL CHECK(authenticate IN (0,1)),
 username TEXT NOT NULL,
 password TEXT NOT NULL,
 from_address TEXT NOT NULL,
 reply_to TEXT,
 public_base TEXT,
 ttl_seconds INTEGER NOT NULL CHECK(ttl_seconds BETWEEN 300 AND 604800)
);

-- Existing jobs keep their former 24h default. Future previews bind the chosen
-- lifetime so later settings changes cannot silently alter an admitted mail.
ALTER TABLE email_jobs ADD COLUMN link_ttl_seconds INTEGER NOT NULL DEFAULT 86400
 CHECK(link_ttl_seconds BETWEEN 300 AND 604800);

-- Explicit harmless test messages have durable deduplication and honest unknown
-- recovery. No VPN configuration or SMTP credential is stored in this table.
CREATE TABLE email_test_attempts (
 id TEXT PRIMARY KEY,
 settings_revision INTEGER NOT NULL,
 recipient TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('sending','accepted','failed','unknown')),
 created_at INTEGER NOT NULL,
 error_code TEXT
);
CREATE INDEX email_test_attempts_time ON email_test_attempts(created_at);
