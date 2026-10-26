# Explicit email delivery

Email is optional contact metadata. Open a peer page to send its config, or
select peers and choose **Bulk actions > Send configs by email**. **Edit Peer >
Save email** edits one recipient without sending; email and peer details have
separate forms and save actions. An address can also be saved during client
creation. Saving, editing, regenerating or rotating a client
never sends mail. Select up to 50 clients, preview named recipients and skip reasons, then
confirm. The preview identifies skipped ineligible clients. If anything changes
after preview, create a fresh preview. A repeated confirmation uses the same
request ID and does not enqueue twice.

Direct mode attaches selected existing `.conf`, QR SVG and/or `vpn://` text
representations. Every representation contains the client private key. Link mode
sends a revocable capability URL. SMTP TLS protects the relay connection, not
the recipient's mailbox end to end. Status **accepted by SMTP** does not mean
delivered. No bounce tracking or delivery receipts are provided.

## Email settings and storage

The **Settings** tab edits host, port, explicit transport security, authentication,
username, From, optional Reply-to, public HTTPS base and link lifetime. Save and
Check SMTP and Test email are separate actions. Password starts blank: **Keep** preserves its
current value only for the same SMTP host (case-insensitive), port, TLS mode,
username and authentication mode. Changing any of those requires **Replace** or
**Clear** for Save as well as testing, even for a disabled profile. **Replace**
requires a new value, and **Clear** removes it. An empty
replacement never silently resets the secret. No saved password is returned to
the browser or included in API/config exports. Stale saves are rejected by revision;
an uncertain save requires reloading the durable profile before editing again.

Until the first explicit Save, the entire environment profile remains authoritative.
First Save creates a complete panel override in SQLite; subsequent starts load that
whole row with no fieldwise environment fallback. Clearing a stored password cannot
resurrect its environment value. No operator env file is edited or silently imported.

The existing database now contains a plaintext SMTP credential if one is saved.
Before reading/saving the profile, the app requires a canonical non-symlink database
path in a private service-owned directory and service-owned regular private database,
WAL, SHM and rollback-journal files without hardlinks. Use directory0700 and file0600;
unsafe storage is rejected, never automatically chmod/chowned. Windows persistence
fails closed rather than treating POSIX mode bits as ACL protection. Legacy env-only
installations keep working before first Save. Backups and old WAL/pages are also
secret-bearing: Clear removes the active value, not historical copies. Protect and
retire those copies under the operator's backup policy.

If a saved profile fails the private-storage guard at startup, the peer panel
continues with email quarantined. No saved secret is read, environment SMTP fallback
used, transport constructed, worker started or public retrieval route exposed.
Settings shows a redacted diagnostic and disables Save/Check/Test. The operator must
repair the storage prerequisite and restart the panel; a page reload or ordinary
runtime recovery cannot lift this startup block. The application never changes
permissions automatically. Genuine database, migration and lifecycle-path failures
remain startup errors. Existing queued state and bindings are left untouched while
quarantined; a successful restart performs the usual recovery before admission.

With panel authentication disabled, email profiles are not loaded and email actions,
contact inputs and activity are omitted. Settings explains this prerequisite without
exposing SMTP data; email APIs still require authentication. Ordinary peer management
and Bulk Delete remain available under their existing access rules.

**Check SMTP** and **Test email** use the current form without saving it or
enabling the saved profile. Keep resolves the stored password on the server;
Replace uses the entered password only for that attempt; Clear tests without it.
With a stored password, Keep is rejected if host (case-insensitive), port, TLS,
username or authentication mode changes. Explicitly Replace or Clear to test a
new endpoint. Draft credentials are never stored in SQLite, browser storage or
responses. A manually entered replacement stays only in the input for a later
explicit Save; saving or leaving/reloading the page clears that input.

A draft is bound to the saved revision and rechecked under admission guards.
A concurrent save before admission rejects it; an admitted operation keeps its
original immutable transport. Later saves do not cancel or redirect it, and its
result does not validate newer settings or edits to the form.

Check SMTP connects with the selected TLS/authentication settings, sends SMTP
NOOP and closes; it never issues MAIL FROM, RCPT TO or DATA. Success confirms
connection/configured authentication, not sender permission or inbox delivery.
TLS errors and an explicit SMTP535 authentication rejection are
reported when available; other connection/protocol/authentication failures remain
a generic sanitized result, without invented stage progress or server text.

Checks share the single test-operation slot with test email, have a30-second
deadline and a separate durable five-check/hour budget. No automatic check/retry
runs on Save, navigation or reload. The immutable transport is captured under
short admission guards; settings changes remain responsive during network work.
An interrupted browser request may leave its bounded check running, but no mail
can be submitted by it. Connection results are not persisted as a tested badge.

**None (plaintext relay)** is an explicit opt-in, never an automatic fallback.
It exposes message bodies, configurations/private keys and temporary-link tokens
on the SMTP transport. Use only a trusted local relay. SMTP AUTH is forbidden,
including a nonempty username or retained password, even if sending is disabled.
Uncheck authentication, empty the username and explicitly Clear the password;
the panel never discards a saved secret for you. Every plaintext Save or test requires
an explicit warning acknowledgment. Required STARTTLS remains the default and
implicit TLS remains supported, both with normal certificate validation.
Migration0013 preserves an existing profile/revision without changing its mode.

Test email sends a fixed message with no VPN material using the confirmed draft.
The UI reports Sent - accepted by SMTP, failed, or unknown; it has no inbox-delivery badge.
It shares one test-operation slot with Check SMTP and allows five admissions/hour, with a30-second SMTP deadline.
Request IDs/outcomes are retained30days; there is no automatic retry. Interrupted
attempts become unknown. After reload, **Check previous test status** is a read-only
authenticated lookup and never sends mail. Review the result before explicitly
starting another test. Browser session storage retains only selected peer IDs and
opaque confirmed send/test request IDs, never recipients, credentials or configs.

Contact recovery/rebinding and revocation remain in **Email → Contact recovery &
revocation**. Changing any panel profile field, including password, invalidates all
pending mail and old links. Admitted SMTP work retains its original transport,
recipient and message; late acceptance is recorded honestly and cannot revive links.

## Environment fallback and public routing

The feature defaults off. Set `AWG_EMAIL_ENABLED=true` only with panel
authentication enabled. Configure `AWG_SMTP_HOST`, `AWG_SMTP_FROM` (one bare email
address), `AWG_SMTP_PORT`, and `AWG_SMTP_TLS=starttls`, `implicit`, or explicit `none`.
For `none`, also set `AWG_SMTP_ALLOW_PLAINTEXT=true` and leave username and
password empty. This applies only while the environment is authoritative. STARTTLS is
mandatory when selected; there is no plaintext fallback or certificate-validation
bypass. Username/password are optional for a relay that permits unauthenticated
TLS submission. Keep credentials in the existing root-owned mode-0600 environment
file, never command arguments or logs. The installer already
sets these permissions; email adds no privileged-helper commands.

Start with direct-only delivery. To enable links, explicitly provision a dedicated
HTTPS reverse proxy and set `AWG_DELIVERY_PUBLIC_BASE_URL`, for example
`https://download.example.org/share`. It is independent of the private panel's
`AWG_WEB_BASE_PATH`. Only a canonical HTTPS DNS host, optional port and normalized
path prefix are accepted. User information, query/fragment, dot segments,
backslashes and encoded separators are rejected. Links are never built from
request Host or Forwarded headers. This setting changes no listener or network
security configuration.

The backend public routes are exactly `/delivery/`, `/delivery/app.js`,
`/delivery/redeem` and `/delivery/export`, outside the admin mount. Here is an
**example for an already configured dedicated TLS nginx server**. Provision its
certificate independently; do not copy a catch-all proxy to the public hostname.

```nginx
# AWG_DELIVERY_PUBLIC_BASE_URL=https://download.example.org/share
location ~ ^/share/delivery/(|app\.js|redeem|export)$ {
    rewrite ^/share(/delivery/.*)$ $1 break;
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host download.example.org;
    proxy_cache off;
    proxy_no_cache 1;
    access_log off;
    error_log /var/log/nginx/delivery-error.log warn;
    client_max_body_size 4k;
}
location / { return 404; }
```

Keep the backend listener and admin hostname private through the deployment's
existing access controls. Test that public `/api/peers`, the private admin prefix,
and every other public path are unavailable. Disable proxy body/header debug
logging, analytics and caching on these routes. Do not log cookies or request
bodies. The app uses no third-party assets and supplies no-store, no-referrer,
CSP and nosniff headers. The public rate limiter uses the actual socket IP and
ignores forwarded IP headers: users behind one reverse proxy share that IP limit.
There is no trusted-proxy header configuration in this version.

## Validity, retry and recovery

A logical contact survives deletion/replacement of its peer row. Same-name or
same-address creation starts without email. To transfer an unbound contact,
review old/new public keys and explicitly rebind it to a freshly verified peer.
Deliberate peer removal retires the contact. Forget contact clears the address
and retires its binding while retaining pending submission outcomes.

Every preview, enqueue, send admission, redemption and export verifies current
binding/state, on-disk ownership, private-to-public-key derivation, sanitized
server peer block and exact config digest. Disabled, archived, removal-pending,
expired, monitoring-only and unverified peers are excluded; offline alone is
allowed. Observed changes permanently invalidate previous grants. Restoring an
old file or re-enabling a peer cannot revive one.

Admission buffers immutable mail input, marks the attempt sending and releases
all state/lifecycle/mapping guards and database transactions **before SMTP**.
Revocation and rotation remain responsive. Already admitted direct mail may
reach the relay after revocation and cannot be recalled. Late success never
reactivates a revoked link. Public export admission similarly checks and buffers
bytes under short guards; bytes already released cannot be recalled. Arbitrary
root edits bypass advisory locks and cannot be made atomically synchronized.

Only definite transient SMTP rejection may retry (at most three attempts, after
1 minute and 5 minutes). Retry revalidates the original version/recipient and
generates a new token. The database stores token/session hashes and intent, never
raw tokens, MIME or config snapshots. Timeouts/disconnects and abandoned sending
attempts become **unknown**, with no automatic retry. Reissue explicitly after
reviewing possible duplicate-mail consequences. If outcome persistence fails,
delivery stops accepting new sends/retrievals until restart/recovery; inspect
the operational status and repair database availability first. Recovery after
uncertain persistence conservatively revokes old bindings before reopening admission;
old links/queued mail may therefore need explicit reissue even after a rolled-back save.

GET/HEAD only return a generic shell and do not consume tokens. The browser
keeps the URL fragment in memory, clears the address bar and waits for explicit
retrieval. POST plus Origin/CSRF checks expresses intent, not proof of a human;
a scanner performing the whole interaction can redeem. One redemption creates
a secure HttpOnly session permitting all representations, with ten successful
exports over at most ten minutes. Losing the redemption response requires a new
link. `AWG_DELIVERY_TTL_SECS` defaults to 24 hours and accepts 300–604800 seconds.

Other limits: five-minute previews, 50 clients per batch, 500 queued/sending
jobs, one worker, 30-second SMTP attempts, five admitted attempts per client/hour
and 100 per administrator/hour (including retries), 10 public POSTs/socket-IP/minute
and 100 globally. Queued first attempts reserve confirmation capacity; admission
checks the durable budget again. A retry that reaches the limit fails visibly
with `send_limit`; it does not wait indefinitely or bypass the budget.
Preview and queue confirmation each have one two-second budget for the complete
batch, including lock/database waits, ownership helpers and validation. Timeout
returns `admission_timeout`, cancels unfinished work and releases the lifecycle
guards; cancelled helpers are killed and reaped. Use smaller batches on slower
hosts. If confirmation loses its response at commit, retry the same preview ID
and inspect submission status: the transaction is atomic and that ID is
deduplicated; a timeout is not proof that nothing was queued. The worker still
revalidates every admitted version and recipient before SMTP.
All config exports use the same bounded reader: regular `.conf` files directly
inside the trusted client directory, no symlink targets, maximum 256 KiB. The
directory and its ancestors must remain administrator-controlled.
Terminal jobs expire after 30 days; expired grants/sessions are purged daily.
Audit output contains IDs and bounded status codes, not addresses, private keys,
raw SMTP replies, tokens or credentials.

## Rollout and rollback

With public delivery enabled, `/delivery` and every descendant are reserved;
an overlapping `AWG_WEB_BASE_PATH` is rejected before worker startup. Existing
base-path validation also rejects encoded, dot-segment, repeated-slash and
trailing-slash aliases. Empty/root and separate private prefixes remain valid.
Direct-only mode retains the existing admin-prefix choices.

Back up SQLite before upgrade. Migrations0011/0012 are additive and existing clients
have no email by default. A lifetime worker lock prevents duplicate ownership
of the persistent state directory. Changing non-secret relay/public settings,
or disabling email, cancels queued work and revokes capabilities at startup.
Password-only environment changes preserve valid capabilities at startup; every
panel Save, including password-only, revokes them. Restart after changing env
settings while environment control is active. Panel saves apply without restart.
Disabling the feature cannot recall already submitted mail.

For operator recovery, stop the panel before offline maintenance and take a
consistent private SQLite backup including live WAL contents. Restore proper file
ownership/permissions explicitly if needed. To deliberately return to environment
control, invalidate all client bindings and delete only the settings singleton in
the same offline transaction; do not restore an old whole VPN database merely to
reset SMTP. No reset-to-env button or automatic permission repair is provided.

Rollback requires a pre-upgrade database backup; migration reversal is not
assumed. Keep the feature off during initial rollout, confirm private admin
access and direct-only relay behavior in a controlled environment, then provision
the isolated public route if desired. This implementation's automated tests use
temporary databases, injected transports and loopback TLS fixtures; they do not
establish deliverability through a production relay or correctness of a deployed
proxy configuration.


### Bulk deletion from Peers

The Peers and Email tabs show the active section. Select up to 50 peers in the
main table, then use **Bulk actions → Delete selected peers**. The confirmation
lists names and a count; Cancel is focused by default and an unchecked destructive
acknowledgment must be selected before Delete is enabled. No deletion occurs on
selection, navigation, or Cancel.

Removal runs sequentially through the existing managed-client removal API. A
SHA-256 public-key fingerprint binds each reviewed row to its identity; the server
rechecks the actual key under the lifecycle lock and in its SQL removal claim.
The existing removal triggers revoke queued delivery jobs, grants and sessions.
Already submitted mail and exported bytes cannot be recalled. Each client reports
its own outcome; failed or uncertain clients remain selected for review, while
successfully removed or already absent clients leave the list. This is not an
all-or-nothing batch.

During removal **Stop remaining** (or Escape) stops future requests. The currently
admitted removal may still finish. A 30-second client wait limit reports an unknown
outcome and stops the remainder; it does not roll back server work or retry it.
Reload and check an uncertain peer before explicitly reviewing another attempt.


### Peer detail and future channels

The compact Peers / Email settings tabs wrap when space is limited. **Send config
by email** on a peer detail page opens the existing shared recipient review for
that peer; navigation alone never sends. The dialog links back to the peer,
directly to its email form when missing, or to contact recovery if unbound.
SMTP setup preserves the intended peer without replacing the table selection.
Cancel closes the preview; Back to peer returns to the original detail page.

Future consideration only: messenger delivery should consume the same verified,
version-bound export snapshot through a channel-specific transport. A messenger
recipient must be explicitly verified in that channel, not inferred from an email,
display name or phone number. Each channel needs recipient preview, explicit
confirmation, honest acceptance/retry semantics and credential protection. No
messenger framework, bot, account, API key or external call is implemented here.

### Bulk selection and recent activity

After a confirmed bulk send is queued, only its eligible, unchanged selections
are cleared. Skipped peers, failed or uncertain requests, and peers selected again
after confirmation remain selected. Cancel preserves the selection. Bulk deletion
keeps its existing per-client outcome behavior described above.

Recent email activity displays local-device timestamps. Migration 0014 adds a
nullable `accepted_at`, recorded in the transaction that stores SMTP acceptance.
It is not an inbox-delivery timestamp. No completion time is backfilled for older
records. Successful, non-invalidated entries hide ten minutes after acceptance;
pending, failed, unknown and invalidated entries do not automatically expire.
Legacy successes without a completion time remain until explicitly cleared.

**Clear history** clears completed activity for all administrators and devices,
including failed and terminal unknown outcomes. After confirmation, authenticated
`POST /api/admin/delivery/history/clear` marks every currently terminal, uncleared
job, including entries outside the latest 200-row display window. Cookie requests
require CSRF. A single SQLite write defines the clear snapshot: completion before
that write is eligible; work still queued/sending at the write remains visible
when it finishes. New jobs and changed outcomes are not covered by an earlier clear.

Migration 0015 adds a per-job `activity_cleared_at` marker and resets it on an
actual outcome change, including retry or revocation. It is not a timestamp cutoff.
The operation has a two-second database budget, holds no lifecycle/SMTP lock,
and never deletes jobs, links or tokens, retries a send, or resets unresolved
request recovery or sending limits. Unknown remains unknown even when dismissed.
Operational records retain the existing retention policy: terminal jobs older
than 30 days are purged by the enabled delivery worker; clearing is not secure
erasure. Existing migrations are unchanged. Rollback after applying 0015 requires
the operator's consistent pre-migration database backup, not checksum edits.

**Show older successes** reveals only automatic ten-minute hiding; server-cleared
results cannot be restored through that control. The API returns the latest 200
uncleared jobs. Other open pages see a clear on refresh or the next visible poll
(at most once per minute); reload and Back/Forward fetch the shared state. The
browser stops waiting after ten seconds and never automatically repeats a clear
whose result is uncertain: use Refresh status before deciding to clear again.
Old tab-only dismissal preferences are no longer used.

This operation covers Recent email activity and the same jobs list in contact
recovery. It does not clear the last SMTP-check/test result in Settings, test-mail
recovery IDs, connection-check rate limits, VPN traffic history or audit records.
