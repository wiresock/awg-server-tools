-- Contact identity deliberately survives a peer row; no name/IP inheritance.
CREATE TABLE delivery_clients (
 id TEXT PRIMARY KEY, peer_id INTEGER UNIQUE REFERENCES peers(id) ON DELETE SET NULL,
 interface TEXT NOT NULL, managed_name TEXT NOT NULL, last_public_key TEXT NOT NULL,
 email TEXT, binding_version INTEGER NOT NULL DEFAULT 1,
 export_digest BLOB, retired_at INTEGER
);
CREATE TABLE email_jobs (
 id TEXT PRIMARY KEY, client_id TEXT NOT NULL REFERENCES delivery_clients(id) ON DELETE CASCADE,
 request_id TEXT NOT NULL, actor TEXT NOT NULL, recipient TEXT NOT NULL,
 mode TEXT NOT NULL CHECK(mode IN ('direct','link')), formats TEXT NOT NULL,
 binding_version INTEGER NOT NULL, export_digest BLOB NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('queued','sending','accepted','failed','unknown','cancelled','stale')),
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL, error_code TEXT, invalidated_at INTEGER, invalidation_code TEXT,
 UNIQUE(request_id,client_id)
);
CREATE INDEX email_jobs_due ON email_jobs(state,next_attempt_at);
CREATE TABLE delivery_grants (
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES email_jobs(id) ON DELETE CASCADE,
 token_hash BLOB NOT NULL UNIQUE, binding_version INTEGER NOT NULL, export_digest BLOB NOT NULL,
 expires_at INTEGER NOT NULL, redeemed_at INTEGER, revoked_at INTEGER
);
CREATE INDEX delivery_grants_expiry ON delivery_grants(expires_at);
CREATE TABLE delivery_sessions (
 id_hash BLOB PRIMARY KEY, grant_id TEXT NOT NULL REFERENCES delivery_grants(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, remaining INTEGER NOT NULL CHECK(remaining >= 0)
);
CREATE TABLE delivery_settings (id INTEGER PRIMARY KEY CHECK(id=1), config_fingerprint BLOB NOT NULL);
CREATE TABLE delivery_send_budget (
 id INTEGER PRIMARY KEY, client_id TEXT NOT NULL, actor TEXT NOT NULL, at INTEGER NOT NULL
);
CREATE INDEX delivery_budget_time ON delivery_send_budget(at);

-- Triggers protect every existing writer, including cleanup and non-HTTP updates.
-- Transient mapping clears are intentionally excluded: fresh ownership/digest
-- checks happen inside admission, not from the poller's intermediate state.
CREATE TRIGGER delivery_peer_invalidated AFTER UPDATE OF disabled,archived,removal_pending,expires_at,public_key ON peers
WHEN OLD.disabled IS NOT NEW.disabled OR OLD.archived IS NOT NEW.archived
 OR OLD.removal_pending IS NOT NEW.removal_pending OR OLD.expires_at IS NOT NEW.expires_at
 OR OLD.public_key IS NOT NEW.public_key
BEGIN
 UPDATE delivery_clients SET binding_version=binding_version+1,
   retired_at=CASE WHEN NEW.removal_pending=1 THEN unixepoch() ELSE retired_at END,
   peer_id=CASE WHEN OLD.public_key IS NOT NEW.public_key THEN NULL ELSE peer_id END
 WHERE peer_id=NEW.id;
END;
CREATE TRIGGER delivery_peer_deleted BEFORE DELETE ON peers BEGIN
 UPDATE delivery_clients SET peer_id=NULL, binding_version=binding_version+1 WHERE peer_id=OLD.id;
END;
CREATE TRIGGER delivery_contact_invalidated AFTER UPDATE OF binding_version ON delivery_clients
WHEN OLD.binding_version != NEW.binding_version
BEGIN
 UPDATE email_jobs SET state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,
   invalidated_at=COALESCE(invalidated_at,unixepoch()),
   invalidation_code=COALESCE(invalidation_code,'binding_changed') WHERE client_id=NEW.id;
 UPDATE delivery_grants SET revoked_at=COALESCE(revoked_at,unixepoch())
 WHERE job_id IN (SELECT id FROM email_jobs WHERE client_id=NEW.id);
END;
