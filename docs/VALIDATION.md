# Validation record — 26 October 2026

These are executed software checks, not security certification or human biometric
validation. No real participant dataset or runtime database was supplied.

## Environment

Linux x86_64 container, kernel 6.18.55, glibc 2.39, Python 3.12.14. An isolated
virtual environment was used. Runtime versions include Flask 3.1.3, Werkzeug 3.1.9,
NumPy 2.5.4, scikit-learn 1.9.1, cryptography 50.0.2, PyOTP 2.10.0,
webauthn 3.0.1, River 0.26.1 and Waitress 3.0.2. Exact dependencies are recorded in
`requirements-tested.txt`. `pip check` reported no broken requirements.

Browser checks used Playwright 1.55.0 and Chromium 140.0.7339.16. The initial
browser check could not start because Chromium was absent; installing the browser
resolved that environmental failure. A stale duplicate Playwright distribution
metadata entry was removed and pyee pinned to 13.0.0 in the actual test environment
before final testing. The frozen requirements reflect the corrected environment.
No browser binaries are distributed.

## Incremental results

| Check | Result | Evidence in release/validation |
| --- | --- | --- |
| Original backend suite, before edits | 31 passed | baseline-tests.xml |
| Original browser workflow | 1 passed | baseline-browser-final.xml |
| Corrected phase-1 feature/model/evaluation checks | 12 passed | phase1-corrected.xml |
| Phase-2 original backend regressions | 31 passed | phase2-tests.xml |
| Phase-2 expanded privacy/encryption/feature checks | 46 passed | phase2-expanded.xml |
| Phase-3 passkeys and maintenance | 60 passed | phase3-tests.xml |
| Phase-4 initial full run | 66 passed, 1 browser assertion failed | phase4-tests.xml |
| Corrected phase-4 browser checks | 2 passed | phase4-browser-fixed.xml |
| Phase-5 integrated evaluation/probe workflow | 73 passed | phase5-tests.xml |
| Final complete suite | **74 passed, 0 failed, 0 errors, 0 skipped** | final-tests.xml |
| Additional Settings desktop/mobile + virtual passkey check | 1 passed | settings-browser.xml |

The phase-4 failure was the test's string-evaluation wait conflicting with CSP.
It was corrected to a locator assertion; CSP was not weakened. Passkey registration
itself had succeeded. The final suite completed in about 63.7 seconds in this
container. The extra Settings check repeats an existing test, not a 75th unique test.
Subsequent edits only clarified UI wording/spacing and documentation.

## What the suite covers

- Original password validation/hashing, mandatory TOTP, TOTP replay prevention,
  recovery-code one-use, authenticator replacement and session revocation.
- CSRF, local Host restriction, cookie/security headers, account/source throttles,
  session rotation/logout/idle expiry and polling that cannot extend idle lifetime.
- Exact 12-feature extraction and Python/Node.js parity, negative flight-time
  golden example, quantiles/ratios, invalid values/counts and dimension/version checks.
- Fitting-only normalization, no clipping, deterministic signed hashing, per-profile
  aliases, insufficient rounds and duplicate fitting/calibration leakage rejection.
- Server consent, expiring one-use nonce/sequence, invalid evidence, first-anomaly
  step-up, persistent challenge/high-risk latch and stale evidence fallback.
- AES-GCM ciphertext confidentiality/context binding/tampering, metadata/history
  integrity, missing/insecure/symlinked keys and additive legacy migration fixture.
- Ordinary live/probe data cannot update trusted profiles. Enrollment grants are
  scoped. Maintenance rejects anomalies/duplicates/insufficient or overlapping
  development evidence, requires separate promotion, versions updates and rolls back.
- Cross-account isolation, export, reset/deletion, unauthorized/stale updates and
  protected vault authorization/recovery.
- Real ECDSA-signed software WebAuthn fixtures: origin/RP/UV, signature, challenge,
  counter/replay, session/user binding, expiry, revocation and one-action grant.
- Chromium: signup/QR/TOTP/recovery, verified collection, outgoing text-free
  12-feature telemetry, desktop/mobile layout, and virtual-authenticator passkey
  registration/assertion/vault flow. No uncaught page errors in successful runs.
- FAR/FRR/EER arithmetic, partition overlap rejection, exact frozen-model evaluation,
  challenge-rate semantics, latency outputs and synthetic ADWIN comparison.

## Launcher and scripts

`python run.py --instance <temporary directory> --port <local test port>` launched
Waitress successfully. Landing/login/registration and new JavaScript resources
returned 200; unauthenticated status returned 401; an untrusted Host returned 400.
No server errors appeared in that smoke run (`smoke-results.json`).

All Python source files parsed; all browser JavaScript files passed `node --check`.
The synthetic evaluation, CSV evaluator, ordered score-stream generator and
ADWIN CSV comparison commands completed on generated input. The local CLI data
flows use the same validation/model functions exercised by the integration tests.
Screenshots of Workspace and Settings at desktop/mobile widths were inspected;
there was no horizontal overflow. Screenshots are not packaged.

## Synthetic observations, explicitly not human results

The seeded timing fixture (`scripts/synthetic_check.py`, seed 2026) deliberately
separates artificial timing distributions. The combined fixed-threshold check
flagged 15/40 artificial genuine windows and accepted 0/40 artificial impostor
windows in the recorded run. These counts are **not real FRR/FAR** and are not
accuracy claims. The high synthetic challenge count also shows why small
calibration sets and real usability validation matter. No thresholds were changed
to make this fixture look better. Diagnostic test-set EER is not a deployable threshold.

The synthetic step-change stream gave ADWIN a 46-window delay and the rolling
median a 9-window delay, with zero alerts outside the defined transition horizon
in that artificial stream. Six-second cadence converts those delays to simulated
seconds only. These are not takeover detection results. Raw software-check JSON
is included, with explicit synthetic origin labels.

Reported timing is environment-dependent processing time, including feature/model/
risk computations but excluding browser collection, HTTP/DB, contention and human
verification. It is neither an SLA nor proof of real-time takeover prevention.

## Unverified boundaries

The user's actual Kali installation/database/hardware, physical passkeys, real
participants, mobile/IME accessibility, adversarial mimicry/poisoning, concurrency
load, key rotation and independent penetration testing remain unvalidated. The
migration fixture proves tested schema behavior; it is not a substitute for backing
up and testing a user's real database. Tests cannot guarantee error-free software.
