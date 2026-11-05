# Security model and limitations

## Scope and trust

One trusted local machine, one AuthSense process, loopback browser access and a
fictional demo vault. This is not an OS login replacement or a system-wide monitor.
No camera, microphone, global keyboard hook, external AI service or mouse tracking
is used. All decisions and account ownership checks are on the server.

Initial access requires a password plus TOTP or an unused recovery code. A normal
behavior score cannot log someone in, clear a pending challenge, change credentials,
export data, enroll, train, promote or roll back a model. A compromised browser or
stolen active session can still fabricate normal summary features. This residual
risk is fundamental to this untrusted collector; nonce/sequence checks prevent
specific replay, not arbitrary fabrication, mimicry or endpoint compromise.

## Server risk policy

| State, evaluated in precedence order | Risk/action |
| --- | --- |
| Missing/expired/non-active session | High; authenticate before any protected action |
| Two consecutive anomalous scored windows, latched | High; restrict sensitive actions until fresh verification |
| One anomalous window, invalid evidence, or an outstanding challenge | Medium; require step-up verification |
| Successful strong factor verification within 120 seconds, no challenge | Low; continue |
| Missing/incompatible/corrupt model, stale or insufficient evidence, wrong model version | Medium; factor fallback |
| Fresh normal observation (≤45 seconds) for current model in an active, unchallenged session | Low; continue |

Any first anomaly sets a persistent medium-risk challenge. A normal later window
cannot clear it. Two consecutive anomalies set the high-risk latch. Fresh password
plus TOTP/recovery rotates the session and clears these states. Invalid telemetry
cannot refresh trust. Observations from a replaced/rolled-back model cannot refresh
trust. Missing models do not lock users out of conventional factor verification.
Workspace, status and recovery remain reachable while the vault is restricted.

A verified passkey assertion may authorize **one** vault access even while a
behavioral challenge remains. It expires after 60 seconds, is account/session/
credential/action-bound, and is consumed atomically. It does not clear the global
challenge or authorize enrollment/maintenance/other sensitive endpoints.

## Account/session controls retained

- Werkzeug scrypt `32768:8:1`, per-password salts, 15–128 character passwords.
- PyOTP six-digit TOTP, 30-second periods, one period permitted skew; atomic
  monotonically increasing counter consumption across sessions.
- Five random 128-bit recovery codes hashed with SHA-256, each consumed once.
  They replace the second factor only, never the password.
- Random opaque session IDs; only their hashes are stored server-side. Rotation
  on sign-in/step-up, logout revocation, eight-hour absolute and 30-minute idle
  expiry. Status polling does not extend idle lifetime.
- Signed HttpOnly, SameSite=Strict cookies; CSRF required on mutations; local
  Host allowlist; parameterized SQL; CSP without remote scripts or unsafe-eval;
  no-store, frame denial and bounded request bodies.
- Persistent fixed-window account/source throttles; telemetry and WebAuthn limits.
  These are local controls, not distributed abuse or denial-of-service protection.
- Server-scoped, one-use, 120-second verification grants for account/profile actions.
- TOTP replacement revokes every session and recovery code before fresh setup.

HTTP and non-Secure cookies are local development defaults. Public deployment is
outside scope and requires HTTPS, Secure cookies, appropriate origin/RP settings,
operational hardening and independent review. Do not expose the port through a tunnel.

## Record encryption and keys

- `session.key`: independent random 32-byte cookie-signing secret.
- `encryption.key`: existing Fernet key for authenticated encryption of TOTP secrets.
- `profiles.key`: independent 32-byte AES-GCM key for behavioral records and
  integrity-bound passkey public keys/counters.
- `feature-alias.key`: separate 32-byte HMAC key for per-profile feature aliases.

Keys are generated locally with OS randomness, written with mode 0600 and fsync.
Loading rejects symlinks, non-regular files, wrong ownership, group/world-readable
permissions and invalid lengths. The instance directory is private (0700). An
existing version-2 database with missing keys fails startup instead of generating
replacement keys. Do not delete keys to fix an error or print them in reports.

AES-GCM uses a fresh random 96-bit nonce for every write. Associated data binds
schema, record kind, user and record ID/version, preventing simple ciphertext
swaps across users/records. Profile metadata is compared with its encrypted copy.
The active version must match retained history; restoring an older record through
the API creates a new version. No external trusted monotonic counter exists:
rolling back the entire database/history, stealing database plus keys, or owning
the server process remains outside the defense. Keys are not held in a TPM/HSM;
there is no automatic key-rotation service or remote recovery escrow.

## Consent, collection and privacy

The registration notice is supplemented by an explicit collection toggle and a
server-side consent/session flag. Revoking consent stops collection authorization
for all sessions and invalidates behavioral evidence. Each new session starts with
collection off. Re-enabling in one session does not silently start other sessions.

Only the dedicated textarea receives key event handlers. Printable character/key
identity is used ephemerally to pair events; no character identity, typed text or
raw event stream is sent, stored in SQLite, or logged. The browser transmits the
12 aggregate features, counts, duration and protocol identifiers. It clears its
textarea/buffers after submission/reset. Password entry naturally goes to the
password verification endpoint; the no-text promise concerns behavioral collection.
Do not type secrets into the practice area. Browser extensions, memory snapshots,
clipboard managers and a compromised browser are outside this guarantee.

Enrollment, maintenance and probe vectors are sensitive data despite aggregation.
They are encrypted at rest; authorized CSV exports are plaintext sensitive files.
Ordinary live vectors are scored in memory and not persisted. Audit records contain
bounded event/outcome information, policy/model versions where relevant, and limited
numeric summaries, never passwords, OTPs, keys, text or raw events. Audit history is
bounded to 500 events/account and pruned beyond 30 days when audit events are written.

Profile/account deletion removes application records; it is not secure erasure
of filesystem/SQLite free pages, WAL, snapshots or backups. Initial encryption of
legacy plaintext records cannot erase old disk copies. Stop and back up before
migration; use full-disk encryption and a backup-retention policy for the machine.
Trusted enrollment/probe data persist until reset/deletion. Maintenance rounds and
development imports have seven-day eligibility; staged candidates have one-hour
eligibility. Expired records cannot be used and may remain encrypted until the next
maintenance operation, overwrite, reset or deletion.

## Guarded adaptation and poisoning boundary

Only freshly verified maintenance rounds for the active version can stage samples.
Every staged vector passes quality checks and the current model; anomalous vectors
are rejected. Live and evaluation-probe rows cannot enter this path. A candidate
keeps 20 original anchors, caps fitting data at 120, and keeps calibration separate.
Exact duplicates and overlapping development/training/maintenance sessions fail.

A trusted local operator imports at least 20 genuine and 100 impostor independent
**development** windows. These counts are practical minimums, not statistical proof.
The candidate must show development FAR ≤0.05, FAR increase ≤0.01 and FRR increase
≤0.02 against the active model. A fresh candidate-building grant is needed; a
second fresh promotion grant commits a still-current candidate within one hour.
The active version changes atomically, evidence is invalidated and older versions
are retained for verified rollback. Rollback requires a valid retained version;
it cannot make arbitrary client JSON into a model.

These gates reduce obvious poisoning; they cannot prove honest enrollment, correct
labels or representative data, and do not prevent all slow/adaptive poisoning.
Large legitimate drift may fail admission and require deliberate reset/re-enrollment.
Repeated development-set reuse can overfit; never reuse it as final test evidence.

## WebAuthn boundaries

The maintained `webauthn` verifier checks challenges, origin, RP ID, user presence,
user verification and signatures. Challenges expire after 120 seconds and are
session/account/purpose-bound and consumed on a well-formed failed attempt too.
Credential ownership, optional returned user handle and counter integrity are
checked. Nonzero counter replay is rejected; synced credentials may legitimately
use zero counters, so counters alone are not clone detection. Attestation is `none`:
no hardware provenance claim is made. Registration/revocation require fresh password
plus TOTP/recovery; registration limit is five credentials. Revocation clears
outstanding ceremonies/grants and challenges sessions.

Tests use signed software fixtures and Chromium's virtual authenticator. Physical
security keys, OS passkey providers and recovery across devices were not validated.

## Remaining threats

No independent penetration test, formal verification, real-participant study,
adversarial ML study, accessibility study, production load test or secure-enclave
attestation was performed. TOTP phishing, malicious extensions, stolen active
sessions, timing synthesis, hardware/task differences, and actions occurring before
a full observation window remain risks. Never claim perfect accuracy or security.
