# AuthSense incremental upgrade report

Prepared 26 October 2026. The existing working prototype was extended in place;
its Flask application factory, SQLite store, JavaScript interface, account flows,
statistical baseline and Isolation Forest remain. The original uploaded archive
is preserved byte-for-byte in the release.

## Inputs and review boundary

Reviewed the uploaded `AuthSense-Prototype(1).zip` (43 files), its Python routes,
security/model/database code, templates, browser scripts/styles, tests, dependency
files, README/layout and security/evaluation/Kali documentation. Compared those
against the available 20-page trend-enhanced AuthSense synopsis. No actual runtime
SQLite database, keys or real participant dataset was included. Database findings
therefore concern source schema/queries and a tested legacy migration fixture,
not inspection of private account records or measured human behavior.

Original archive SHA-256:
`6a6763599baa258d47c282ef0c880a46a9c87816a5c60f1cdf427d5ee4500148`.

## Main findings and implemented changes

| Area | Original finding/gap | Upgrade |
| --- | --- | --- |
| Feature contract | Eight D/I features; no signed flight or required ratios | Exact D/F/I median/IQR/p90 plus two ratios and rate; shared Python/JS golden tests |
| Collector quality | Skipped interruptions and incomplete ordering could distort windows | Keydown-ordered complete pairs, signed overlap, whole-window discard, no submission while keys remain held |
| Backend schema | Old shape and weaker consistency checks | Exact schema/version, finite/range/quantile/count/rate/ratio checks; reject text/extra fields |
| Normalization | IF consumed unscaled features; baseline used broad floors | Fitting-only robust normalization, signed numeric hashing for IF and uncompressed baseline |
| Calibration | Genuine calibration with arbitrary padding | Explicit held-out empirical quantiles, version/fingerprint/config records; no claimed validated FAR |
| Risk | First anomaly could be masked by recent MFA; implicit policy | Pure low/medium/high engine; first anomaly requires step-up; subsequent telemetry cannot clear a pending challenge |
| Profile storage | Behavioral sample/model JSON in plaintext | AES-GCM records with separate key, user/type/version binding, metadata integrity and fail-closed key loading |
| Consent/replay | Toggle mainly in browser; nonce lacked age bound | Persistent server consent + per-session opt-in; atomic one-use sequence/nonce with 90-second age limit |
| Profile updates | No guarded adaptation/history; live learning avoided | Retain no live learning; add verified staging, 20 anchors, bounded fitting pool, independent development gates, separate promotion and rollback |
| Passkeys | Absent | User-verified WebAuthn for one vault action, expiring single-use challenges/grants, origin/RP/signature/ownership checks and revocation |
| Drift | Absent | Offline ADWIN versus 20-window rolling-median comparison; alerts cannot grant trust/adapt |
| Evaluation | Basic FAR/FRR only; probe collection conflicted with training | Separate unfiltered probe rounds/export; frozen deployed-profile evaluation; EER diagnostics, challenge-window rates and scoped latency |
| Existing security | Useful password/TOTP/recovery/session/CSRF/throttle/audit controls | Preserved and regression-tested, with additional tamper/replay/poisoning/authorization cases |
| Documentation/UI | Eight-feature descriptions and incomplete enhancement/limitation guidance | Risk labels, actionable errors, passkey/maintenance/probe controls, exact schema, Kali migration guide and honest validation record |

This implements the synopsis's practical local pipeline, privacy controls,
independent evaluation path and modern authentication/drift enhancements. Its pilot
FAR/FRR goals remain goals. A VEPT score or high-accuracy authentication claim cannot
be inferred from code/tests without the corresponding real study.

## Profile adaptation safeguards

Fresh password + factor verification opens a ten-minute maintenance round for the
current profile version. Only quality-valid observations accepted by that model
are staged. Normal live data and evaluation probes never enter trusted fitting.

A local operator supplies independent development genuine/impostor windows. The
candidate keeps the initial 20 anchors, uses at most 120 fitting windows, leaves
calibration separate, rejects duplicate/overlapping data and checks development
FAR ≤5%, FAR increase ≤1 percentage point and FRR increase ≤2 percentage points.
Those are admission rules, not measured generalization guarantees. A separate
fresh verification promotes the reviewed candidate; stale/base-version-mismatched
candidates fail. Rollback restores valid retained contents under a new version.
No-data/failed-gate conditions leave the active profile unchanged.

## Compatibility and migration

The original code/archive is untouched. New code uses additive schema migration,
preserving existing accounts and factor records while encrypting legacy records.
Old eight-feature vectors cannot reconstruct F and must not be padded or relabeled:
new enrollment is required. Legacy records remain encrypted, excluded from fitting
and from current-schema collection limits. Stop/back up the entire old instance
before migration. The release includes no runtime database or credentials.

Fresh strong factors remain a fallback if the model is missing, incompatible or
corrupt. A model/schema/dependency change invalidates old behavioral evidence.
Existing password hashing, TOTP, recovery, CSRF, session lifetime, throttling,
audit and per-account authorization are retained.

## Executed validation

The original 31 backend tests passed before edits, and the original browser flow
passed after installing Chromium. Regression milestones passed at 46 and 60 tests.
The final complete suite passed **74 tests, with zero failures/errors/skips**,
including two Chromium tests. A further Settings layout/passkey rerun passed.

The phase-4 suite exposed a browser-test wait conflicting with CSP; its assertion
was fixed and CSP retained. The full final suite and new signed WebAuthn fixtures
then passed. Waitress startup/HTTP authorization smoke checks, JavaScript parsing,
Python parsing, `pip check` and synthetic evaluation/score/drift CLI checks passed.
Detailed commands, environment, limitations and phase results are in `VALIDATION.md`;
JUnit XML and clearly labeled synthetic JSON are under `release/validation/`.

No human accuracy result is invented. The artificial fixture produced a substantial
challenge rate (15/40 artificial genuine windows flagged), illustrating why a small
genuine-only calibration set needs further real evaluation. No detector thresholds
were adjusted after looking at final probe labels. ADWIN measurements are also
explicitly synthetic, not takeover-detection claims.

## Kali installation/execution

See `KALI_GUIDE.md` for preservation/migration, complete setup, enrollment, passkeys,
maintenance, recovery and troubleshooting. From the extracted `AuthSense/` folder:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nodejs unzip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --only-binary=:all: -r requirements.txt
python -m pip install --only-binary=:all: -r requirements-dev.txt
python -m pytest --ignore=tests/test_browser.py
python run.py
```

Open **http://localhost:5000**. Optional browser test installation:

```bash
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
python -m pytest tests/test_browser.py
```

The executed environment was Linux/Python 3.12, not the user's own Kali machine.
Use `requirements-tested.txt` for exact compatible versions or the documented
runtime ranges; do not silently change ML versions during an experiment.

## Remaining limitations

1. Browser data is untrusted. Nonces, CSRF, validation, factors and admission gates
   reduce specific attacks but cannot attest human typing or defeat all fabricated
   telemetry, stolen active sessions, mimicry or slow poisoning.
2. No representative real-user dataset, measured real FAR/FRR, accessibility study,
   independent security audit, or production/load validation exists in this release.
3. Calibration is small and genuine-only. The combined rule can interrupt genuine
   users; device/task/health changes need explicit evaluation. Large drift may
   require re-enrollment rather than passing guarded adaptation.
4. ADWIN is an offline comparison. Neural networks and mouse dynamics were not
   added merely for demonstration; no camera/global keylogger is included.
5. Local files hold keys. Root/server compromise, stolen keys with the DB, complete
   database rollback, backup copies and secure deletion are outside AES-GCM's defense.
6. Physical/synced passkey providers are not validated by virtual-authenticator tests.
   Initial password/TOTP is still phishable; one-action WebAuthn is not a claim that
   the entire authentication system is phishing-resistant.
7. Loopback HTTP is the deployment boundary. Public hosting needs separate HTTPS,
   identity, key/backup, monitoring, recovery and security engineering.
8. Human challenge burden and end-to-end takeover latency are not supplied. The
   evaluator reports scoped processing latency and explicitly labeled simulations.

## Changed files

The table below lists all source/document/test differences against the preserved
prototype. A machine-readable manifest with SHA-256 values and unified source patch
are in `release/`. No original source file was deleted.

| Path | Change |
| --- | --- |
| `README.md` | Modified |
| `STRUCTURE.md` | Modified |
| `authsense/__init__.py` | Modified |
| `authsense/behavior.py` | Modified |
| `authsense/db.py` | Modified |
| `authsense/drift.py` | Added |
| `authsense/maintenance.py` | Added |
| `authsense/passkeys.py` | Added |
| `authsense/risk.py` | Added |
| `authsense/security.py` | Modified |
| `authsense/static/app.js` | Modified |
| `authsense/static/collector.js` | Modified |
| `authsense/static/features.js` | Added |
| `authsense/static/maintenance.js` | Added |
| `authsense/static/passkeys.js` | Added |
| `authsense/static/style.css` | Modified |
| `authsense/storage.py` | Added |
| `authsense/templates/base.html` | Modified |
| `authsense/templates/dashboard.html` | Modified |
| `authsense/templates/enroll.html` | Modified |
| `authsense/templates/settings.html` | Modified |
| `authsense/views.py` | Modified |
| `docs/ARCHITECTURE.md` | Added |
| `docs/EVALUATION.md` | Modified |
| `docs/KALI_GUIDE.md` | Modified |
| `docs/SECURITY.md` | Modified |
| `docs/UPGRADE_REPORT.md` | Added |
| `docs/VALIDATION.md` | Modified |
| `requirements-tested.txt` | Modified |
| `requirements.txt` | Modified |
| `run.py` | Modified |
| `scripts/compare_drift.py` | Added |
| `scripts/evaluate.py` | Modified |
| `scripts/import_validation.py` | Added |
| `scripts/score_stream.py` | Added |
| `scripts/synthetic_check.py` | Modified |
| `tests/conftest.py` | Modified |
| `tests/test_browser.py` | Modified |
| `tests/test_drift.py` | Added |
| `tests/test_evaluation.py` | Modified |
| `tests/test_hardening.py` | Added |
| `tests/test_maintenance.py` | Added |
| `tests/test_passkeys.py` | Added |
| `tests/test_pipeline_v2.py` | Added |
| `tests/test_security.py` | Modified |
