"""Offline drift comparison only. Neither detector grants access or updates profiles."""
from collections import deque
import math
import numpy as np
from river.drift import ADWIN


def compare(scores,changes=(),seconds_per_window=None):
    values=[float(v) for v in scores]
    if len(values)<40 or any(not math.isfinite(v) or v<0 for v in values):raise ValueError('Need at least 40 finite nonnegative anomaly ratios.')
    changes=sorted(set(changes))
    if any(type(v) is not int or not 40<=v<len(values) for v in changes):raise ValueError('Changes are zero-based indices after the initial 40 windows.')
    if seconds_per_window is not None and (not math.isfinite(seconds_per_window) or seconds_per_window<=0):raise ValueError('Invalid window cadence.')
    detector=ADWIN(delta=.002,clock=1,min_window_length=10,grace_period=30)
    history=deque(maxlen=40);alerts={'ADWIN':[],'rolling_median_20':[]};cooldown=-1
    for i,value in enumerate(values):
        # Bound drift input only; classifier scores themselves are NOT clipped.
        detector.update(min(4.,value)/4.)
        if detector.drift_detected:alerts['ADWIN'].append(i)
        history.append(value)
        if len(history)==40 and i>cooldown:
            prior=np.array(list(history)[:20]);recent=np.array(list(history)[20:])
            med=float(np.median(prior));mad=float(np.median(np.abs(prior-med)))
            if abs(float(np.median(recent))-med)>max(.15,3*1.4826*mad):
                alerts['rolling_median_20'].append(i);cooldown=i+20
    reports={}
    # A declared change has a fixed 200-window detection horizon. With no labels,
    # false-alert and delay rates are unknown rather than silently invented.
    for name,found in alerts.items():
        used=set();delays=[]
        for j,change in enumerate(changes):
            end=min(len(values),change+200,changes[j+1] if j+1<len(changes) else len(values))
            candidates=[a for a in found if change<=a<end]
            used.update(candidates);delay=min(candidates)-change if candidates else None
            delays.append({'change_index':change,'delay_windows':delay,
                'delay_seconds':delay*seconds_per_window if delay is not None and seconds_per_window else None})
        transition={i for c in changes for i in range(c,min(c+200,len(values)))}
        stable=len(values)-len(transition)
        reports[name]={'alert_indices':found,'delay':delays,'missed_changes':sum(d['delay_windows'] is None for d in delays) if changes else None,
            'false_alerts_per_100_stable_windows':100*len([a for a in found if a not in used])/stable if changes and stable else None}
    return {'detectors':reports,'ADWIN':{'delta':.002,'clock':1,'min_window_length':10,'grace_period':30,'input':'min(score_ratio,4)/4'},
        'rolling_median':{'reference_windows':20,'recent_windows':20,'threshold':'max(0.15, 3 * 1.4826 * prior MAD)','cooldown_windows':20},
        'scope':'Offline monitoring comparison; not identity proof, attack detection accuracy, or permission to adapt.',
        'detection_horizon_windows':200}
