# Architecture and feature specification

## Retained architecture

The browser serves locally rendered Flask pages with same-origin JavaScript.
Password + TOTP/recovery establish an active server session. The collector sends
only summary telemetry from one opt-in textarea. The Flask backend validates
consent, session, CSRF, nonce, sequence, schema and limits before scoring. The risk
engine reads authoritative session/model state. `/vault/open` independently checks
that policy or consumes a scoped passkey grant; changing the dashboard cannot
change authorization. SQLite stores accounts, bounded records, versions and audit.

## Twelve-feature schema (version 2)

For completed pairs ordered by **keydown**, let `d_i` be keydown and `u_i` keyup,
in monotonic browser milliseconds:

- `D_i = u_i - d_i` (n dwell measurements).
- `F_i = d_(i+1) - u_i` (n−1 signed flight measurements).
- `I_i = d_(i+1) - d_i` (n−1 keydown intervals).

Negative flight time is valid when keys overlap. Do not sort by keyup or clip F
at zero. Quantiles use linear interpolation at `(n−1)*p`, matching NumPy's default.

| Order | JSON/CSV feature | Definition/unit |
| --- | --- | --- |
| 1 | dwell_median_ms | median(D), ms |
| 2 | dwell_iqr_ms | Q75(D) − Q25(D), ms |
| 3 | dwell_p90_ms | Q90(D), ms |
| 4 | flight_median_ms | median(F), signed ms |
| 5 | flight_iqr_ms | Q75(F) − Q25(F), ms |
| 6 | flight_p90_ms | Q90(F), signed ms |
| 7 | interval_median_ms | median(I), ms |
| 8 | interval_iqr_ms | Q75(I) − Q25(I), ms |
| 9 | interval_p90_ms | Q90(I), ms |
| 10 | dwell_interval_ratio | median(D) / median(I) |
| 11 | interval_iqr_ratio | IQR(I) / median(I) |
| 12 | typing_rate_hz | n / ((max(u) − first(d))/1000), keys/active second |

No added epsilon changes the ratio definitions: valid median(I) is at least 5 ms.
An accepted window has 24–200 complete pairs, 5–90 seconds of active span,
D/I within 5–2000 ms and F within −2000–2000 ms. Pauses above two seconds,
incomplete pairs, blur, tab changes and composition reset the unfinished window.
Pasted content creates no timing pairs. The browser waits for every held key to
be released before submission; window buffers and textarea text are cleared.

The server accepts exactly `v, nonce, seq, count, interval_count, duration_ms,
features`, and optional `round_id`. It rejects text/extra fields, booleans where
numbers are required, nonfinite values, wrong counts, invalid ranges/quantiles,
inconsistent ratios/rate, wrong dimensions and old schema versions. Summaries
cannot prove their own physical provenance; these checks are not attestation.

## Normalization, models and calibration

At least three verified rounds of 10–40 windows are required (30–160 total).
Earlier rounds provide at least 20 fitting windows; the last complete round
provides at least 10 calibration windows. Exact duplicates across fitting and
calibration are rejected. The supplied order defines chronological order; the
researcher must collect and label independent sessions honestly.

For each feature, the center is the fitting median. The scale is `1.4826*MAD`,
with `IQR/1.349` substituted when unscaled MAD is below its floor; the result is
floored at 5 ms for timing summaries, 0.01 for ratios, and 0.2 keys/s for rate.
The final calibration/probe windows never fit these transformations. Values are
not clipped during classification.

The baseline is median absolute normalized deviation over 12 features. The
100-tree Isolation Forest uses normalized values, deterministic seed 42,
`max_samples=min(256,n_fit)`, no bootstrap and one job. Production IF input uses
per-profile HMAC aliases and signed FeatureHasher with 32 buckets. Alternatives
64/128 and unhashed input are available for offline comparisons. Hash collision
counts are recorded. Aliasing/hashing are not encryption or one-way biometric
protection; AES-GCM is the storage protection.

Each detector uses the higher empirical 95th percentile of the genuine
calibration scores, with only a numerical zero floor. Combined anomaly means
**either** threshold is exceeded. The combined ratio is the maximum of the two
score/threshold ratios; the displayed index is bounded `round(50*ratio)` and is
not a probability or confidence in identity. With ten calibration samples the
95th percentile is effectively the maximum. Calibration is small and genuine-only:
it does not establish a 5% FAR, a guaranteed FRR, or a production threshold.

Models are bounded encrypted JSON containing fitting/calibration vectors, aliases,
pipeline/schema/dependency versions, groups and configuration. They are refit
deterministically in a small memory cache; no pickle/joblib is loaded. NumPy or
scikit-learn version mismatch causes factor fallback until explicit retraining.
The active version and two previous encrypted versions are retained. Rollback
writes a new increasing version and invalidates old behavioral evidence.

## Data paths

- **Enrollment:** fresh scoped factor verification → bounded round → consent →
  quality checks → encrypted schema-2 samples → separate training verification.
- **Live:** consent → nonce/schema checks → model/risk update; no saved vectors
  and no changes to fitting data.
- **Probes:** fresh `probe` verification → independent, unfiltered valid windows;
  export separately. Probe rows are never eligible for training.
- **Maintenance:** fresh `adapt` verification → current-version normal windows
  only → development gates → encrypted candidate → fresh promotion verification.
- **Passkey:** fresh password/factor verification to register; later signed
  user-verified assertion grants one vault action for at most 60 seconds.

## Database and migration

Original tables remain: users, sessions, recovery_codes, rounds, samples, profiles,
audit and limits. Additions include consent/collection flags, nonce timestamp,
model version, challenge-pending state, round purpose/schema/base-version, and
profile_versions, candidates, validation_sets, passkeys and ceremonies tables.
Migration is additive and transactional (`PRAGMA user_version=2`); no real database
was included in the uploaded source, so migration was exercised on a legacy fixture.

Legacy vectors remain encrypted and marked schema 1; they do not count against
schema-2 enrollment limits or get padded with invented flight features. Account
and factor records remain. New/current samples are limited by purpose: enrollment
160, maintenance 100, probes 1000 per user; a round accepts at most 40. Server
transactions serialize nonce consumption, profile writes and sensitive decisions.
