"""Frozen-model evaluation on disjoint labeled sessions; never tune on test data."""
import argparse
import csv
import hashlib
import json
import platform
from pathlib import Path
import sys
from time import perf_counter

import numpy as np
from sklearn.metrics import roc_curve

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from authsense.behavior import FEATURES,feature_vector,get_model,train_profile
from authsense.maintenance import disjoint
from authsense.risk import decide


def load_rows(path):
    with Path(path).open(newline='',encoding='utf-8-sig') as source:
        reader=csv.DictReader(source)
        required={'session_id',*FEATURES}
        if set(reader.fieldnames or []) not in (required,required|{'duration_ms'}):
            raise ValueError(f'{path}: expected session_id and all twelve feature columns; duration_ms is optional.')
        rows=[]
        for index,row in enumerate(reader,start=2):
            if not row['session_id'] or len(row['session_id'])>100:raise ValueError(f'{path}:{index}: invalid session ID.')
            features={key:float(row[key]) for key in FEATURES};feature_vector(features)
            record={'session_id':row['session_id'],'features':features}
            if 'duration_ms' in row:
                value=float(row['duration_ms'])
                if not np.isfinite(value) or not 5000<=value<=90000:raise ValueError('Invalid window duration.')
                record['duration_ms']=value
            rows.append(record)
            if len(rows)>20000:raise ValueError('Maximum 20,000 rows per file.')
    if not rows:raise ValueError(f'{path}: no windows found.')
    return rows


def eer(genuine_scores,impostor_scores):
    # A diagnostic sweep on TEST labels: do not deploy the threshold selected here.
    labels=[0]*len(genuine_scores)+[1]*len(impostor_scores)
    frr,tpr,thresholds=roc_curve(labels,genuine_scores+impostor_scores,drop_intermediate=False)
    far=1-tpr;index=int(np.argmin(np.abs(frr-far)));threshold=float(thresholds[index])
    return {'approximate_EER':float((frr[index]+far[index])/2),'FAR_at_point':float(far[index]),
            'FRR_at_point':float(frr[index]),'threshold':threshold if np.isfinite(threshold) else None,
            'method':'nearest discrete ROC point; anomaly >= threshold; diagnostic only, not a calibrated operating point'}


def policy_simulation(rows,scores):
    # Explicit simulation: a challenge immediately succeeds, with no typing during
    # its unspecified human response time. Thus this is NOT measured usability.
    sessions={};challenges=0;total_ms=0
    for row,score in zip(rows,scores):
        state=sessions.setdefault(row['session_id'],{'strikes':0,'latched':False})
        if score['anomalous']:
            challenges+=1
            state['strikes']=0;state['latched']=False # assumed immediate verification
        if 'duration_ms' in row:total_ms+=row['duration_ms']
    complete=all('duration_ms' in r for r in rows)
    return {'challenge_windows':challenges,'challenge_window_rate':challenges/len(rows),
            'simulated_prompts_per_active_hour':challenges/(total_ms/3600000) if complete and total_ms else None,
            'assumption':'Immediate successful verification after every anomalous window; active typing time only. Not measured prompts/hour.',
            'measured_prompts_per_hour':None}


def evaluate(enrollment,genuine,impostor,*,buckets=32,alias_seed='evaluation-2026',frozen=None):
    started=perf_counter()
    if frozen is None:
        disjoint([enrollment,genuine,impostor])
        payload,stats=train_profile(enrollment,hash_key=hashlib.sha256(alias_seed.encode()).digest() if buckets else None,buckets=buckets or 32)
        model=get_model(payload)
    else:
        payload,stats=frozen;model=get_model(payload)
        from authsense.maintenance import model_rows
        disjoint([model_rows(model),genuine,impostor])
        used=set(model.document['fit_groups'])|{model.document['calibration_group']}
        if used & {r['session_id'] for r in genuine+impostor}:raise ValueError('Test sessions overlap the frozen model.')
        buckets=stats['hash_buckets'];alias_seed=None
    build_ms=(perf_counter()-started)*1000
    latency=[];scores=[]
    for group in (genuine,impostor):
        values=[]
        for row in group:
            t=perf_counter();result=model.assess(feature_vector(row['features']))
            policy_row={'stage':'active','expires_at':2000,'must_verify':0,'step_up_required':int(result['anomalous']),
                'observation':'unusual' if result['anomalous'] else 'normal','strong_at':0,'last_sample':1000,'last_model_version':1}
            decide(policy_row,now=1000,model_ready=True,model_version=1)
            latency.append((perf_counter()-t)*1000);values.append(result)
        scores.append(values)
    checks={'distance_baseline':('distance',model.distance_limit),'isolation_forest':('forest_score',model.forest_limit),'combined':('ratio',1.)}
    metrics={}
    for name,(key,limit) in checks.items():
        gs=[s[key] for s in scores[0]];ips=[s[key] for s in scores[1]]
        fr=sum(s>limit for s in gs);fa=sum(s<=limit for s in ips)
        metrics[name]={'genuine_windows':len(genuine),'impostor_windows':len(impostor),
            'false_rejections':fr,'false_acceptances':fa,'FRR':fr/len(genuine),'FAR':fa/len(impostor),
            'operating_threshold':limit,'diagnostic':eer(gs,ips)}
    return {'data_origin':'USER-SUPPLIED LABELS; provenance and independence not automatically verified',
        'unit':'individual timing window','schema':2,'training':stats,
        'evaluation_source':'frozen local profile' if frozen else 'offline enrollment refit with fixed evaluation aliases',
        'genuine_sessions':len({r['session_id'] for r in genuine}),'impostor_sessions':len({r['session_id'] for r in impostor}),
        'metrics':metrics,'genuine_challenges':policy_simulation(genuine,scores[0]),
        'latency_ms':{'scope':'feature validation + normalization + both model scores + pure risk decision; excludes browser, network, DB, and human verification',
            'n':len(latency),'p50':float(np.quantile(latency,.5)),'p95':float(np.quantile(latency,.95)),'maximum':max(latency),
            'model_build':build_ms},
        'reproducibility':{'python':platform.python_version(),'platform':platform.platform(),'alias_seed':alias_seed,
            'hash_buckets':buckets,'forest_seed':42},
        'limitations':['Thresholds use enrollment calibration only; test EER thresholds must not be deployed.',
            'Genuine-only calibration does not establish a target FAR. Hash collisions depend on the alias seed.',
            'Windows in a session are correlated; these are not population-level confidence guarantees.',
            'Session labels, subject identity, chronology, and hardware must be checked by the researcher.',
            'No real takeover delay or human challenge burden is measured. Zero observed errors do not establish a zero error rate.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    source=parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--enrollment',type=Path);source.add_argument('--instance',type=Path)
    parser.add_argument('--username')
    for name in ('genuine','impostor'):parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--output',type=Path);parser.add_argument('--buckets',type=int,choices=[0,32,64,128],default=32)
    parser.add_argument('--alias-seed',default='evaluation-2026')
    args=parser.parse_args()
    try:
        genuine=load_rows(args.genuine);impostor=load_rows(args.impostor)
        if args.instance:
            if not args.username or not (args.instance/'authsense.sqlite3').is_file():raise ValueError('Provide --username and an existing --instance directory.')
            from authsense import create_app
            from authsense.db import get_db
            from authsense.storage import read_profile
            app=create_app({'INSTANCE_PATH':args.instance.resolve()})
            with app.app_context():
                row=get_db().execute('SELECT p.* FROM profiles p JOIN users u ON u.id=p.user_id WHERE u.username=?',(args.username,)).fetchone()
                if row is None:raise ValueError('No profile found for that account.')
                frozen=(read_profile(row),json.loads(row['stats']))
            result=evaluate(None,genuine,impostor,frozen=frozen)
        else:result=evaluate(load_rows(args.enrollment),genuine,impostor,buckets=args.buckets,alias_seed=args.alias_seed)
    except (ValueError,KeyError,OSError,TypeError) as e:parser.error(str(e))
    report=json.dumps(result,indent=2,allow_nan=False)
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(report+'\n',encoding='utf-8')
    print(report)

if __name__=='__main__':main()
