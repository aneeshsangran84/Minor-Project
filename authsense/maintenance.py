"""Explicit, verified profile maintenance. Ordinary live traffic never trains."""
import hashlib
import json
import secrets

from flask import Blueprint, abort, current_app, g, jsonify, request

from .behavior import FEATURES, canonical, feature_vector, get_model
from .db import get_db, now, atomic, audit
from .security import require_stage, consume_grant
from .storage import seal, unseal, read_profile, read_sample, write_profile

bp=Blueprint('maintenance',__name__)
VALIDATION_DAYS=7


def active(user_id):
    row=get_db().execute('SELECT * FROM profiles WHERE user_id=?',(user_id,)).fetchone()
    if row is None:raise ValueError('Train a current profile first.')
    return row,get_model(read_profile(row))


def disjoint(groups):
    vectors=[];sessions=[]
    for rows in groups:
        if not rows:raise ValueError('Each dataset must contain observations.')
        vectors.append({tuple(feature_vector(r['features'])) for r in rows})
        sessions.append({str(r['session_id']) for r in rows})
    for i in range(len(groups)):
        for j in range(i):
            if vectors[i]&vectors[j] or sessions[i]&sessions[j]:raise ValueError('Datasets overlap in session IDs or exact feature vectors.')


def model_rows(model):
    doc=model.document
    return [{'session_id':group,'features':dict(zip(FEATURES,v))} for group,values in
        [('__fit__',doc['fit']),(doc['calibration_group'],doc['calibration'])] for v in values]


def import_validation(user_id,genuine,impostor):
    """Local operator CLI only. Development evidence, never a final test set."""
    row,model=active(user_id)
    if not 20<=len(genuine)<=5000 or not 100<=len(impostor)<=5000:
        raise ValueError('Development evidence requires 20–5000 genuine and 100–5000 impostor windows.')
    disjoint([model_rows(model),genuine,impostor])
    used=set(model.document['fit_groups'])|{model.document['calibration_group']}
    if used & {r['session_id'] for r in genuine+impostor}:raise ValueError('Development sessions overlap fitting/calibration.')
    value={'base_version':row['version'],'genuine':genuine,'impostor':impostor,
           'fingerprint':hashlib.sha256(canonical([genuine,impostor]).encode()).hexdigest(),
           'purpose':'development_gate_not_final_evaluation'}
    db=get_db()
    db.execute('INSERT INTO validation_sets VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET created_at=excluded.created_at,payload=excluded.payload',
        (user_id,now(),seal(value,'validation',user_id,'current')))
    audit('development_validation_imported',{'genuine':len(genuine),'impostor':len(impostor),'base_version':row['version']},user_id=user_id)


def rates(model,genuine,impostor):
    return {'FRR':sum(model.assess(feature_vector(r['features']))['anomalous'] for r in genuine)/len(genuine),
            'FAR':sum(not model.assess(feature_vector(r['features']))['anomalous'] for r in impostor)/len(impostor)}


def candidate_for(user_id):
    row,old=active(user_id);db=get_db()
    vr=db.execute('SELECT * FROM validation_sets WHERE user_id=?',(user_id,)).fetchone()
    if vr is None or vr['created_at']<now()-VALIDATION_DAYS*86400:
        raise ValueError('Independent development validation is required; import it using the local operator CLI.')
    validation=unseal(vr['payload'],'validation',user_id,'current')
    if validation['base_version']!=row['version']:raise ValueError('Validation must reference the current profile version.')
    rounds=db.execute("SELECT * FROM rounds WHERE user_id=? AND purpose='adapt' AND completed=1 AND base_version=? AND started_at>? ORDER BY started_at",(user_id,row['version'],now()-7*86400)).fetchall()
    observations=[]
    for r in rounds:
        for s in db.execute('SELECT * FROM samples WHERE round_id=? ORDER BY id',(r['id'],)):
            observations.append({'session_id':r['id'],'features':read_sample(s)})
    if not 10<=len(observations)<=100:raise ValueError('Complete 10–100 verified maintenance windows for the current version.')
    disjoint([model_rows(old),observations,validation['genuine'],validation['impostor']])
    vectors=[feature_vector(r['features']) for r in observations]
    if len({tuple(v) for v in vectors})!=len(vectors):raise ValueError('Duplicate maintenance observations are rejected.')
    if any(old.assess(v)['anomalous'] for v in vectors):raise ValueError('Anomalous maintenance cannot update a trusted profile.')
    doc=json.loads(canonical(old.document));anchors=doc.get('anchors',doc['fit'][:20])
    doc['anchors']=anchors
    doc['fit']=anchors+(doc['fit'][len(anchors):]+vectors)[-100:]
    doc['fit_groups']=list(dict.fromkeys(doc['fit_groups']+[r['id'] for r in rounds]))
    payload=canonical(doc);new=get_model(payload)
    before=rates(old,validation['genuine'],validation['impostor']);after=rates(new,validation['genuine'],validation['impostor'])
    gates={'FAR_at_most_0_05':after['FAR']<=.05,'FAR_increase_at_most_0_01':after['FAR']<=before['FAR']+.01+1e-12,
           'FRR_increase_at_most_0_02':after['FRR']<=before['FRR']+.02+1e-12}
    stats=json.loads(row['stats']);stats.update(fit_windows=len(doc['fit']),rounds=len(doc['fit_groups'])+1,
        fingerprint=hashlib.sha256(payload.encode()).hexdigest(),distance_limit=new.distance_limit,forest_limit=new.forest_limit,
        calibration_flagged=sum(new.assess(v)['anomalous'] for v in doc['calibration']),
        maintenance={'before':before,'after':after,'gates':gates,'genuine':len(validation['genuine']),
                     'impostor':len(validation['impostor']),'validation_fingerprint':validation['fingerprint']})
    if not all(gates.values()):raise ValueError('Candidate failed development FAR/FRR regression gates. Active profile is unchanged.')
    candidate={'base_version':row['version'],'payload':payload,'stats':stats,'rounds':[r['id'] for r in rounds]}
    return candidate


@bp.post('/api/adapt/start')
@require_stage()
@atomic
def start():
    if not consume_grant('adapt'):return jsonify(error='verification_required'),403
    try:p,_=active(g.user['id'])
    except ValueError as e:return jsonify(error='profile_unavailable',message=str(e)),409
    db=get_db();db.execute("DELETE FROM rounds WHERE user_id=? AND purpose='adapt' AND (completed=0 OR started_at<?)",(g.user['id'],now()-7*86400))
    identifier=secrets.token_urlsafe(20)
    db.execute("INSERT INTO rounds(id,user_id,session_hash,started_at,expires_at,purpose,schema_version,base_version) VALUES(?,?,?,?,?,'adapt',2,?)",
        (identifier,g.user['id'],g.session_hash,now(),now()+600,p['version']))
    audit('maintenance_started',{'base_version':p['version']})
    return jsonify(round_id=identifier,minimum=10)


@bp.post('/api/adapt/candidate')
@require_stage()
@atomic
def build():
    if not consume_grant('candidate'):return jsonify(error='verification_required'),403
    try:candidate=candidate_for(g.user['id'])
    except (ValueError,KeyError,TypeError) as e:return jsonify(error='candidate_rejected',message=str(e)),409
    get_db().execute('INSERT INTO candidates VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET base_version=excluded.base_version,created_at=excluded.created_at,payload=excluded.payload',
        (g.user['id'],candidate['base_version'],now(),seal(candidate,'candidate',g.user['id'],candidate['base_version'])))
    audit('candidate_staged',{'base_version':candidate['base_version']})
    return jsonify(staged=True,review=candidate['stats']['maintenance'],message='Candidate staged for one hour. Verify separately to promote.')


@bp.post('/api/adapt/promote')
@require_stage()
@atomic
def promote():
    if not consume_grant('promote'):return jsonify(error='verification_required'),403
    db=get_db();row=db.execute('SELECT * FROM candidates WHERE user_id=?',(g.user['id'],)).fetchone()
    try:
        p,_=active(g.user['id'])
        if row is None or row['created_at']<now()-3600 or row['base_version']!=p['version']:raise ValueError('Candidate expired or its base version changed.')
        value=unseal(row['payload'],'candidate',g.user['id'],row['base_version'])
        if value['base_version']!=p['version'] or not all(value['stats']['maintenance']['gates'].values()):raise ValueError('Invalid candidate approval evidence.')
        get_model(value['payload'])
    except (ValueError,KeyError,TypeError) as e:return jsonify(error='promotion_rejected',message=str(e)),409
    version=write_profile(g.user['id'],value['payload'],value['stats'])
    db.execute('DELETE FROM candidates WHERE user_id=?',(g.user['id'],))
    db.execute('DELETE FROM validation_sets WHERE user_id=?',(g.user['id'],))
    db.execute("DELETE FROM rounds WHERE user_id=? AND purpose='adapt'",(g.user['id'],))
    audit('profile_promoted',{'version':version,'previous_version':p['version']})
    return jsonify(promoted=True,version=version)


@bp.post('/api/adapt/rollback')
@require_stage()
@atomic
def rollback():
    if not consume_grant('rollback'):return jsonify(error='verification_required'),403
    data=request.get_json(silent=True)
    if not isinstance(data,dict) or set(data)!={'version'} or type(data['version']) is not int:abort(400)
    db=get_db();p=db.execute('SELECT * FROM profiles WHERE user_id=?',(g.user['id'],)).fetchone()
    row=db.execute('SELECT * FROM profile_versions WHERE user_id=? AND version=?',(g.user['id'],data['version'])).fetchone()
    try:
        if p is None or row is None or row['version']>=p['version']:raise ValueError('Select an older retained profile version.')
        payload=read_profile(row,history=True);get_model(payload)
    except (ValueError,KeyError,TypeError) as e:return jsonify(error='rollback_rejected',message=str(e)),409
    stats=json.loads(row['stats']);stats['restored_from']=row['version']
    version=write_profile(g.user['id'],payload,stats)
    db.execute('DELETE FROM candidates WHERE user_id=?',(g.user['id'],))
    db.execute('DELETE FROM validation_sets WHERE user_id=?',(g.user['id'],))
    audit('profile_rolled_back',{'restored_from':row['version'],'new_version':version})
    return jsonify(rolled_back=True,version=version)
