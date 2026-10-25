-- Clearing is a presentation marker on one outcome, never job/token deletion.
ALTER TABLE email_jobs ADD COLUMN activity_cleared_at INTEGER;
CREATE INDEX email_jobs_visible_activity ON email_jobs(created_at DESC)
 WHERE activity_cleared_at IS NULL;

-- Bind dismissal to the exact observed outcome. A later completion, retry or
-- invalidation becomes visible, even if its timestamp equals the cleared one.
CREATE TRIGGER email_activity_outcome_changed
AFTER UPDATE OF state,attempts,accepted_at,error_code,invalidated_at,invalidation_code ON email_jobs
WHEN OLD.state IS NOT NEW.state OR OLD.attempts IS NOT NEW.attempts
 OR OLD.accepted_at IS NOT NEW.accepted_at OR OLD.error_code IS NOT NEW.error_code
 OR OLD.invalidated_at IS NOT NEW.invalidated_at OR OLD.invalidation_code IS NOT NEW.invalidation_code
BEGIN
 UPDATE email_jobs SET activity_cleared_at=NULL WHERE id=NEW.id;
END;
