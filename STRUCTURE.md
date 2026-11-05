# AuthSense source layout

The existing application/factory/blueprint/templates structure is retained.

| Path | Responsibility |
| --- | --- |
| `run.py` | Loopback Waitress launcher, port/instance arguments and WebAuthn origin |
| `authsense/__init__.py` | Factory, strict key loading, local defaults, headers and errors |
| `authsense/db.py` | Original schema, additive migration, transactions and bounded audit log |
| `authsense/security.py` | Scrypt, Fernet TOTP, recovery, CSRF, sessions and throttles |
| `authsense/behavior.py` | Twelve-feature validation, reference extraction, normalization, model/calibration |
| `authsense/risk.py` | Deterministic server-side low/medium/high risk decisions |
| `authsense/storage.py` | AES-GCM context binding, integrity checks and versioned profile writes |
| `authsense/views.py` | Existing account, workspace, enrollment, vault and data-management routes |
| `authsense/maintenance.py` | Verified staging, development gates, promotion and rollback |
| `authsense/passkeys.py` | WebAuthn registration, assertion, revocation and one-use vault grant |
| `authsense/drift.py` | Offline ADWIN and rolling-median comparison |
| `authsense/static/features.js` | Numeric-only extractor, also exercised from Node.js |
| `authsense/static/collector.js` | Opt-in textarea-only timing collection and resets |
| `authsense/static/app.js` | Status, enrollment, maintenance and probe collection controls |
| `authsense/static/passkeys.js` | Browser WebAuthn API and byte/base64url conversion |
| `authsense/static/maintenance.js` | Candidate review/promotion/rollback controls |
| `authsense/templates/`, `static/style.css` | Existing responsive UI, expanded controls and explanations |
| `scripts/evaluate.py` | Offline refit or frozen-profile evaluation on independent probes |
| `scripts/score_stream.py` | Ordered independent CSV observations to drift score stream |
| `scripts/compare_drift.py` | Drift comparison, explicitly labeled optional synthetic example |
| `scripts/import_validation.py` | Trusted local operator imports independent development data |
| `scripts/synthetic_check.py` | Seeded numeric software fixture, never real authentication results |
| `tests/` | Preserved regressions plus feature, encryption, risk, maintenance and passkey tests |
| `docs/` | Installation, architecture, security, evaluation and upgrade evidence |
| `instance/` | Private runtime database and four keys; never distribute |

The release also contains the byte-identical original uploaded ZIP, a unified
source patch, a changed-file manifest and machine-readable validation outputs.
