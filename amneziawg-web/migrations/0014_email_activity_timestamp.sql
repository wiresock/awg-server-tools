-- Legacy accepted jobs have no known completion time; do not invent one.
ALTER TABLE email_jobs ADD COLUMN accepted_at INTEGER;
