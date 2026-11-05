# AuthSense 2.0

AI-assisted continuous authentication using keystroke dynamics. This is an
incremental upgrade of the existing Flask/SQLite/JavaScript application, retaining
password + TOTP authentication, recovery, the statistical baseline and Isolation
Forest. It runs locally on CPU; no cloud AI service or GPU is required.

**Research prototype, not a validated identity product.** A browser can fabricate
telemetry. Behavioral scores assist an already authenticated session; they never
create a login, clear a pending challenge, or authorize profile changes by themselves.

## Start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --only-binary=:all: -r requirements.txt
python run.py
```

Open **http://localhost:5000**, create an account, confirm TOTP, and save the recovery
codes. Use the same hostname consistently. The launcher binds to loopback only;
WebAuthn is configured for `localhost` and the selected port.

- [Kali installation and complete walkthrough](docs/KALI_GUIDE.md)
- [Upgrade report, changed files and limitations](docs/UPGRADE_REPORT.md)
- [Architecture and schema](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Evaluation protocol](docs/EVALUATION.md)
- [Executed checks and evidence](docs/VALIDATION.md)
- [Source layout](STRUCTURE.md)

## Implemented

- Twelve features: median, IQR and p90 of dwell, signed flight and keydown interval;
  dwell/interval median ratio, interval variability ratio and typing rate.
- Opt-in field-scoped collection; no typed text or key identities in telemetry.
- Strict backend schema, one-use expiring nonces, atomic sequence checks, consent
  enforcement and no persistence of ordinary live vectors.
- Fitting-only median/MAD normalization with IQR fallback and scale floors;
  baseline plus normalized signed-hashed Isolation Forest; separate calibration.
- Explicit low/medium/high server policy. A pending behavioral challenge requires
  fresh verification. Two consecutive anomalies restrict sensitive actions.
- AES-GCM encrypted/context-bound samples, models, development data and candidates;
  separate private local keys, version history and guarded rollback.
- Verified maintenance rounds, immutable anchors, bounded candidate data and
  development FAR/FRR gates; separate verification to promote. No automatic learning.
- WebAuthn registration and a one-use passkey verification for the demo vault.
- Separate evaluation-probe rounds, authenticated CSV export, frozen-profile
  evaluation, FAR/FRR/approximate EER, challenge-window rates and processing latency.
- Offline ADWIN versus rolling-median drift comparison. Alerts never grant access
  or update the model. Mouse dynamics are not enabled; no cameras/global keylogger.

## Upgrade an existing installation

Stop the original server and back up **the complete `instance/` directory** before
copying it into this new source directory. Keep the original project. Startup
adds columns/tables and encrypts old summary records transactionally. Existing
accounts and factors remain; old eight-feature vectors cannot supply signed flight
times, so they are retained as encrypted legacy data and excluded from new fitting.
Re-enroll with the current collector. Missing existing keys fail closed.

Read the detailed migration and key-backup steps in the Kali guide first. Do not
open the migrated database with the old code. A complete database rollback is not
prevented by local authenticated encryption.

## Check

Node.js is required for the Python/JavaScript extraction parity test.

```bash
python -m pip install --only-binary=:all: -r requirements-dev.txt
python -m pytest --ignore=tests/test_browser.py
python scripts/synthetic_check.py
python scripts/compare_drift.py --synthetic
```

Optional browser checks:

```bash
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
python -m pytest tests/test_browser.py
```

`requirements-tested.txt` records the exact test environment, including optional
browser dependencies. Runtime keys, databases, accounts and real biometric data
are never included in this distribution. Synthetic checks are software evidence,
not real-world FAR/FRR or accuracy. See the validation record for the tested OS.
