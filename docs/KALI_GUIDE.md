# AuthSense 2.0 on Kali Linux

Run as a normal user on one trusted local machine. Tested in a Linux x86_64
container with Python 3.12; the user's Kali VM, hardware keyboard and physical
passkey provider were not tested. No GPU, cloud key, camera or OS keylogger is used.

## 1. Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nodejs unzip
python3 --version
```

Node.js is for the extraction parity test, not the running server. Use a Python
version with binary wheels for the selected dependency releases. Python 3.12 is the
recorded interpreter. Do not use `sudo pip`, `--break-system-packages`, or install
into Kali's OS-managed Python environment.

## 2. Preserve the old project and extract the upgrade

Stop the old AuthSense server. Leave its project directory intact. Download
`AuthSense-Upgrade.zip`, then choose a **new, empty** project directory:

```bash
mkdir -p ~/Projects/authsense-v2
unzip ~/Downloads/AuthSense-Upgrade.zip -d ~/Projects/authsense-v2
cd ~/Projects/authsense-v2/AuthSense
```

The ZIP contains upgraded `AuthSense/`, the byte-identical original source ZIP
under `original/`, and validation/change evidence under `release/`. No runtime
accounts, keys, database, virtualenv or real observations are included.

For a fresh installation, proceed to step 3. For an existing account database,
back up the **entire** old `instance/` while the server is stopped, then copy it
into the new project. Substitute your actual old project path:

```bash
umask 077
cp -a /path/to/old/AuthSense/instance ~/authsense-instance-backup-before-v2
cp -a /path/to/old/AuthSense/instance ./instance
```

Never copy only the SQLite file or replace missing keys with newly generated ones.
Preserve database, WAL/SHM if present and all original keys together. Protect the
backup: it may contain plaintext legacy behavioral records. Do not put it in a
public repo or include it with the source project submission.

First startup applies an additive transactional migration, encrypts old records,
and retains accounts, TOTP/recovery and old observations. Eight-feature data cannot
be converted to signed flight times: **re-enroll the new profile**. Legacy records
remain encrypted and do not count against current enrollment limits. Do not use
old code against the migrated database. If reverting the entire application,
restore the separate pre-upgrade directory/backup instead.

## 3. Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install --only-binary=:all: -r requirements.txt
python -m pip check
```

The first install needs internet. Normal application use is local and loads no
CDNs, remote fonts, AI APIs or trackers. For the exact recorded test environment on
compatible Python/platform versions, use `requirements-tested.txt` instead. It
includes optional browser dependencies. Updating NumPy/scikit-learn deliberately
invalidates old models until verified retraining; do not update mid-experiment.

## 4. Test before enrolling real data

```bash
python -m pip install --only-binary=:all: -r requirements-dev.txt
python -m pytest --ignore=tests/test_browser.py
python scripts/synthetic_check.py
python scripts/compare_drift.py --synthetic
```

Tests use temporary databases and artificial observations. They do not alter your
real instance. Synthetic error rates are not real authentication performance.

Optional real Chromium/virtual-passkey checks:

```bash
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
python -m pytest tests/test_browser.py
```

If Chromium reports missing system libraries, on a supported installation:

```bash
python -m playwright install-deps chromium
```

That installer may request sudo. Browser-download/system-library problems do not
prevent using AuthSense with your installed browser. Do not weaken CSP to make a
test pass; WebAuthn needs a capable browser and appropriate user verification.

## 5. Start

```bash
python run.py
```

Open **http://localhost:5000** inside the same Kali machine/VM. Keep the terminal
open; stop with Ctrl+C. Use the same hostname throughout. `127.0.0.1` also reaches
the normal app, but the supplied passkey configuration uses the RP ID `localhost`.
The launcher binds only to 127.0.0.1 and disables the Flask debugger.

```bash
python run.py --port 5001
```

Then use **http://localhost:5001**; the launcher adjusts the allowed WebAuthn origin
for that port. To select another private runtime directory:

```bash
python run.py --instance ~/authsense-private-instance --port 5001
```

Use one server process and one active collector tab. In a VM, localhost in your
host browser refers to the host, not the Kali guest. Do not expose this lab server.

## 6. Account and recovery

Create a unique local account (3–32 lowercase letters/digits/underscores, starting
with a letter) and a 15–128 character passphrase. Accept the data notice, scan or
manually enter the TOTP secret, confirm the current code and save the five recovery
codes. No default account/password exists. Recovery codes appear once.

Each TOTP code works only once across all sessions/actions. Wait for the next code
before verifying another action. Keep device time synchronized. A recovery code
replaces only the second factor; your password is still required. Lost password
or all second factors have no built-in bypass or email reset.

## 7. Enrollment and training

1. Workspace → Collect an enrollment round → Verify to start a round.
2. Enter password and a fresh TOTP or unused recovery code.
3. Start verified round within two minutes, then enable the collection checkbox.
4. Type naturally in the field. Each window needs at least 24 complete key pairs
   and five seconds; text clears after submission/reset. Do not type secrets.
5. Collect ten or more windows and click Finish this round within ten minutes.
6. Repeat for at least three separate rounds, preferably on different days.
7. Settings → Train profile → Verify for this action → Train now.

Fitting uses earlier rounds (at least 20 windows); the last round supplies at least
ten calibration windows. Live typing never trains. Three rapid synthetic rounds
can test the workflow but do not establish a representative profile.

Only the designated field is monitored. Switching tabs/fields, long pauses,
composition and incomplete key pairs discard the partial window. Paste/autofill
and held-key repetition do not create ordinary keystrokes. Signed negative flight
time from overlapping keys is valid. Consent is also checked by the server.

A valid active profile cannot be overwritten through Train. Use guarded
maintenance or verified reset. Incompatible legacy/dependency-version profiles
can be explicitly trained from sufficient current-schema enrollment records.

## 8. Exercise risk decisions

Enable collection in Workspace and type normally. The dashboard reports low,
medium or high risk and a reason. The experimental index is not identity confidence.
Open protected vault to exercise the server authorization endpoint.

- Low: recent strong verification (120 seconds), or fresh normal current-model
  evidence (45 seconds) in an authenticated unchallenged session.
- Medium: one anomaly, invalid/missing/stale evidence or an outstanding challenge.
- High: two consecutive scored anomalies latch a sensitive-action restriction.

A raised challenge persists despite later normal telemetry. Use Verify again with
password and a fresh factor. Signing out, model changes and nonce expiry cannot
turn old observations into new trust. Status polling does not keep a session alive.
The ordinary maximum lifetime is eight hours with a 30-minute idle limit.

## 9. Passkey for one vault action

At the configured localhost origin, Settings → Verify to register passkey. Verify
with your password and second factor, then Register passkey and complete your
browser/device's user verification. Up to five credentials can be registered.

Workspace → Verify with passkey and open vault performs a signed challenge and
opens the vault once. It does not clear an overall behavioral challenge or grant
other account/profile permissions. If no passkey provider is available, continue
using password + TOTP/recovery. Settings also offers separately verified revocation.
The included browser test uses a virtual authenticator, not a physical security key.

## 10. Independent evaluation

Settings → Verify for evaluation probes collects valid windows separately from
training, including anomalous windows. Export using Settings → Export enrollment
data → Verify → select **Evaluation probes** or **Enrollment** and optional latest
round only. The exported CSV has `session_id` and twelve features, no text.

Obtain honestly labeled later genuine and consenting impostor data. Keep separate
files for development and untouched final testing. See `EVALUATION.md` for protocol,
metadata, device/task controls and interpretation.

```bash
python scripts/evaluate.py \
  --instance instance --username student_01 \
  --genuine research/test-genuine.csv \
  --impostor research/test-impostor.csv \
  --output evaluation-output/results.json
```

Use `--enrollment research/enrollment.csv` instead of `--instance/--username` for a
reproducible offline refit. Offline aliases may differ from the deployed profile;
the frozen-profile mode measures that exact local model. No result is meaningful
without valid labels and independent sessions.

## 11. Guarded adaptation and rollback

1. Settings → Verify for maintenance round; collect and finish at least ten
   quality windows. Anomalous windows are rejected, rather than learned as normal.
2. Local operator imports independent development data for the current version:

```bash
python scripts/import_validation.py \
  --instance instance --username student_01 \
  --genuine research/dev-genuine.csv \
  --impostor research/dev-impostor.csv
```

3. Settings → Verify: Build and review candidate. Click the action and inspect
   development FAR/FRR and all gate results. Without adequate data, staging fails
   safely and leaves the active profile unchanged.
4. Verify separately for Promote staged candidate; promote within one hour.
5. To revert, verify for Restore older version, select a retained version and
   confirm. Restoration creates a new version; it does not reuse an old number.

The first 20 fitting windows remain anchors; at most 120 fitting windows are used.
The active and two prior versions are retained. Calibration and probes never become
maintenance fitting data. No automatic model update is triggered by drift alerts.

## 12. Data management and restart

Reset profile deletes behavioral samples (including probes/legacy records), model
history/candidates/development data while retaining the account. Delete account
removes account-associated application records. Both require fresh scoped factors.
Logical deletion does not erase old disk pages/backups.

To replace a lost authenticator, sign in with password + recovery code, verify the
replacement with another fresh factor, and confirm new TOTP setup. Replacement
revokes sessions/recovery codes. Save the newly issued recovery codes.

```bash
cd ~/Projects/authsense-v2/AuthSense
source .venv/bin/activate
python run.py
```

Keep the complete private `instance/` and its four keys together. Missing keys cause
startup failure; restore the correct complete backup rather than generating new
keys. Keys are owner-only files. No runtime directory should be distributed.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Externally managed Python | Activate `.venv`; use its `python -m pip` |
| No compatible wheel | Use a supported interpreter/platform; do not blindly force obsolete pins |
| Port in use | Stop the old process or choose `--port 5001` |
| CSRF/nonce conflict | Use one collector tab; reload after session rotation and collect a fresh window |
| TOTP rejected | Wait for an unused code; check selected account and `timedatectl status` |
| Collection does not progress | Enable consent, keep focus, use ordinary typing; partial/paused windows reset |
| HTTP 429 | Pause; the relevant fixed-window throttle must expire |
| Model unavailable | Verify conventionally; restore compatible dependency versions or explicitly retrain |
| Key permission/ownership error | Use the original normal user; restore correct private files, never delete keys |
| WebAuthn origin/RP failure | Use `localhost` with the launcher's port, not an IP or alternate hostname |
| Candidate rejected | Inspect the specific gate; use representative independent data, not relaxed thresholds |
| Frequent false challenges | Record failures and evaluate task/device variation; do not claim reliable accuracy |

Primary installation references:
https://www.kali.org/docs/general-use/python3-external-packages/
and https://flask.palletsprojects.com/en/stable/installation/ .
