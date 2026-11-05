# Evaluation protocol

No real-world authentication results are included. Synthetic fixtures test code
paths and arithmetic only. Model calibration is not held-out evaluation.

## Plan the study before collecting

Use consenting, pseudonymized participants, multiple days/tasks, real pauses and
both same-keyboard and changed-keyboard conditions. A pilot of 15–30 participants
can test feasibility, but does not establish a production error rate. Record
participant, session/day, device, task, accessibility and collection conditions in
a separate consented research log. Do not put names or typed content in telemetry.

Split by whole session and time before transformations. Use earlier target-user
sessions for fitting, a separate later enrollment round for calibration, separate
genuine/impostor **development** sessions for adaptation/model choices, and untouched
later genuine/impostor **test** sessions. Attackers used for development should be
separate from final-test attackers where the protocol permits. Changing an ID does
not make repeated observations independent. Raw-window overlap also causes leakage.

## Collect/export usable CSV files

1. Target user: complete three or more verified enrollment rounds. Train once and
   freeze that profile. Export the **Enrollment** dataset from Settings.
2. Later genuine observations: Settings → Verify for evaluation probes. Complete
   fresh rounds with the genuine user. These are saved separately and never train
   or calibrate the model. Export **Evaluation probes**, optionally latest only.
3. Other consenting participants: use their own local accounts/probe rounds on the
   same task/device. Export their probe data as impostor observations relative to
   the target. They do not need a trained profile or access to the target's account.
4. Preserve unique session IDs when combining CSV bodies below one header. Keep
   development files separate from final-test files. Export counts are not identity
   labels; the researcher must supply and verify the labels.

CSV requires `session_id` plus exactly the twelve feature names in
`ARCHITECTURE.md`. Optional `duration_ms` may be added from a separately collected
consented research log; exports do not retain durations. Do not fabricate missing
durations. Absence produces `null` for prompts-per-hour simulation, not a guess.

## Evaluate the actual frozen web profile

This mode uses the same fitting data, aliases, collisions and calibrated thresholds
as the deployed local profile, without exporting its decrypted model. Use an
existing instance and its original keys, under its owner account. Pause profile
changes during an experiment and record the model fingerprint/version.

```bash
python scripts/evaluate.py \
  --instance instance --username student_01 \
  --genuine research/test-genuine.csv \
  --impostor research/test-impostor.csv \
  --output evaluation-output/frozen-profile.json
```

An incompatible dependency version fails rather than silently interpreting a
model under a different library implementation.

## Reproduce an offline experiment

```bash
python scripts/evaluate.py \
  --enrollment research/enrollment.csv \
  --genuine research/test-genuine.csv \
  --impostor research/test-impostor.csv \
  --buckets 32 --alias-seed study-seed-01 \
  --output evaluation-output/offline-32.json
```

The last enrollment group calibrates; earlier groups fit. Whole groups, exact
vectors and model fitting/calibration records must not overlap test partitions.
The evaluator also rejects genuine/impostor exact-vector overlap. Files are bounded
to 20,000 rows; enrollment has the stricter training minimum/maximum. It cannot
verify honest labels, chronology, subject identity or hidden near-duplicate leakage.

Offline alias seeds are public reproducibility parameters, not production secrets.
The actual web profile uses per-account secret aliases. Its collision pattern can
differ, so offline-refit results are not automatically that web profile's results.
Compare `--buckets 0` (unhashed), 32, 64 and 128 on **development** data if desired;
freeze the selection before final testing. Never select the best final-test result
and report it as an unbiased estimate. The seed and fingerprint accompany results.

## Metrics

Three comparisons are reported: median-distance baseline, Isolation Forest alone,
and their combined OR rule. At their **fixed calibration thresholds**:

- FAR = accepted impostor windows / all impostor windows.
- FRR = rejected genuine windows / all genuine windows.
- Numerators, denominators and session counts accompany rates.
- Approximate EER is the nearest discrete ROC point, with FAR/FRR at that point
  and the diagnostic threshold. Ties/discrete data may not have an exactly equal
  point. This test-label sweep is descriptive: **do not deploy its threshold**.
- Genuine challenge-window rate counts anomalous windows. The optional simulated
  prompts/active-hour assumes immediate successful verification after every
  anomaly and known window durations. It is not measured user interruption burden.
  `measured_prompts_per_hour` stays null without an actual study.
- Processing latency p50/p95/max uses `perf_counter` around feature validation,
  fitting-derived normalization, both model scores and the pure server risk
  decision. Model-build time is separate. It excludes browser observation time,
  HTTP/DB work, contention, network and human verification; it is not takeover
  detection latency or a production SLA.

Measure end-to-end action/detection delay and real challenges per participant-hour
separately using a timed takeover protocol and action/audit events. Include missed
takeovers and user response time. Window metrics are not whole-system authentication
FAR/FRR: existing factors, pending-challenge state and action timing matter.

Report per-participant/per-session results, not just pooled windows. Use suitable
participant/session resampling for uncertainty; correlated windows are not
independent trials. Zero observed errors do not mean a true zero error rate. Targets
such as FAR ≤5% and FRR ≤10% remain **pilot targets**, not measured outcomes here.

## Guarded adaptation development protocol

After at least ten accepted, verified maintenance windows, an operator can import
independent **development** data (20 genuine/100 impostor windows minimum):

```bash
python scripts/import_validation.py \
  --instance instance --username student_01 \
  --genuine research/dev-genuine.csv \
  --impostor research/dev-impostor.csv
```

This CLI has local filesystem authority and is not a public upload API. Import is
encrypted and tied to the current version, valid for seven days. It changes no
model. In Settings verify to build/review a candidate, inspect its development
FAR/FRR and gates, then verify separately to promote it within one hour. Failure
leaves the active profile unchanged. Promotion consumes the development record;
fresh independent evidence is required for subsequent versions. A final untouched
test set is still needed. Repeated use of a development set can overfit it.

## ADWIN comparison

Drift is distribution change, not proof that a different person is typing.
Neither detector is wired to grant access, clear challenges or retrain profiles.

Produce an ordered independent score stream using the same fixed offline seed:

```bash
python scripts/score_stream.py \
  --enrollment research/enrollment.csv \
  --observations research/chronological-probes.csv \
  --buckets 32 --alias-seed study-seed-01 \
  --output evaluation-output/scores.csv
python scripts/compare_drift.py \
  --scores evaluation-output/scores.csv \
  --changes 600 --seconds-per-window 6 \
  --output evaluation-output/drift.json
```

Here `600` and six seconds are example protocol values: replace them with known
zero-based change indices and actual constant cadence, or omit them. Without
change labels, false-alert/delay/missed-change metrics are null. Do not concatenate
unrelated participant files and pretend their boundary is naturally observed drift.
Variable cadence requires a separate timestamp-aware delay analysis.

ADWIN uses delta .002, clock 1, minimum window 10, grace 30 and bounded input
`min(ratio,4)/4`; classifier scores remain unclipped. The comparison examines
median shifts between two adjacent 20-window blocks using a floor/MAD threshold
and 20-window cooldown. Detection horizon is 200 windows per declared change.
Outside labeled transition horizons, alerts count toward false-alert rate per
100 stable windows. This labeling convention and parameters are printed in output.

```bash
python scripts/synthetic_check.py
python scripts/compare_drift.py --synthetic --seconds-per-window 6
```

These commands deliberately generate artificial separable timing/score sequences.
Their FAR/FRR/EER and drift delays are **software fixtures, not human authentication
performance**. Never substitute them for study results.

## Primary implementation references

- https://scikit-learn.org/stable/common_pitfalls.html
- https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- https://riverml.xyz/dev/api/drift/ADWIN/
- https://duo-labs.github.io/py_webauthn/authentication.html
- https://cryptography.io/en/latest/hazmat/primitives/aead/
