-- Preserve existing complete settings and revision; never implicitly downgrade.
CREATE TABLE email_panel_settings_next (
 id INTEGER PRIMARY KEY CHECK(id=1),
 revision INTEGER NOT NULL CHECK(revision>0),
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 host TEXT NOT NULL,
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 tls TEXT NOT NULL CHECK(tls IN ('starttls','implicit','none')),
 authenticate INTEGER NOT NULL CHECK(authenticate IN (0,1)),
 username TEXT NOT NULL,
 password TEXT NOT NULL,
 from_address TEXT NOT NULL,
 reply_to TEXT,
 public_base TEXT,
 ttl_seconds INTEGER NOT NULL CHECK(ttl_seconds BETWEEN 300 AND 604800),
 CHECK(tls<>'none' OR (authenticate=0 AND username='' AND password=''))
);
INSERT INTO email_panel_settings_next SELECT * FROM email_panel_settings;
DROP TABLE email_panel_settings;
ALTER TABLE email_panel_settings_next RENAME TO email_panel_settings;

-- Durable rate budget only: no credentials, recipient, message or error detail.
CREATE TABLE smtp_connection_checks (
 id INTEGER PRIMARY KEY,
 created_at INTEGER NOT NULL
);
