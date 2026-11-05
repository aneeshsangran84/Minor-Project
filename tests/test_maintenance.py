import json
import pytest
from authsense.behavior import FEATURES, get_model, feature_vector
from authsense.db import get_db
from authsense.storage import read_profile, write_profile, unseal, seal
from authsense.maintenance import import_validation
from conftest import register, enroll_train, verify, post, window, features


def current(app):
    with app.app_context():
        row=get_db().execute('SELECT * FROM profiles WHERE user_id=1').fetchone()
        return get_model(read_profile(row)),row['version']


def near_model(model,n):
    # Deterministic arithmetic fixtures only, not measured human observations.
    for v in model.document['fit']:
        if not model.assess(v)['anomalous']:
            f=dict(zip(FEATURES,v));f['flight_median_ms']+=n*.00001
            if not model.assess(feature_vector(f))['anomalous']:return f
    raise AssertionError('No normal fixture')


def maintenance_round(app,client):
    model,_=current(app)
    verify(app,client,'adapt');r=post(client,'/api/adapt/start',json={});assert r.status_code==200
    rid=r.get_json()['round_id']
    bad=window(client,alien=True,round_id=rid)
    assert post(client,'/api/telemetry',json=bad).status_code==400
    for i in range(10):
        payload=window(client,round_id=rid);payload['features']=near_model(model,100+i)
        assert post(client,'/api/telemetry',json=payload).status_code==200
    assert post(client,'/api/enroll/finish',json={'round_id':rid}).status_code==200
    return rid


def test_maintenance_requires_verification_validation_and_cannot_poison(app,client):
    register(app,client);enroll_train(app,client)
    model,version=current(app)
    assert post(client,'/api/adapt/start',json={}).status_code==403
    assert post(client,'/api/adapt/promote',json={}).status_code==403
    maintenance_round(app,client)
    verify(app,client,'candidate')
    result=post(client,'/api/adapt/candidate',json={})
    assert result.status_code==409 and 'Independent' in result.get_json()['message']
    assert current(app)[1]==version
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM samples s JOIN rounds r ON r.id=s.round_id WHERE r.purpose='adapt'").fetchone()[0]==10


def test_candidate_promotion_rollback_and_stale_candidate(app,client):
    register(app,client);enroll_train(app,client);maintenance_round(app,client)
    model,_=current(app)
    genuine=[{'session_id':'dev-genuine','features':near_model(model,1000+i)} for i in range(20)]
    impostor=[{'session_id':'dev-impostor','features':features(1000+i,True)} for i in range(100)]
    with app.app_context():import_validation(1,genuine,impostor)
    verify(app,client,'candidate');r=post(client,'/api/adapt/candidate',json={})
    assert r.status_code==200,r.get_json()
    assert current(app)[1]==1
    assert post(client,'/api/adapt/promote',json={}).status_code==403
    verify(app,client,'promote');assert post(client,'/api/adapt/promote',json={}).get_json()['version']==2
    assert current(app)[1]==2
    assert len(current(app)[0].document['anchors'])==20
    assert post(client,'/api/adapt/promote',json={}).status_code==403
    verify(app,client,'rollback');r=post(client,'/api/adapt/rollback',json={'version':1})
    assert r.status_code==200 and r.get_json()['version']==3
    assert current(app)[0].document['fit']==model.document['fit']
    with app.app_context():
        db=get_db();assert db.execute('SELECT COUNT(*) FROM profile_versions').fetchone()[0]==3
        assert db.execute('SELECT COUNT(*) FROM candidates').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM validation_sets').fetchone()[0]==0
    verify(app,client,'promote');assert post(client,'/api/adapt/promote',json={}).status_code==409


def test_validation_rejects_overlap_and_insufficient_evidence(app,client):
    register(app,client);enroll_train(app,client)
    model,_=current(app)
    gen=[{'session_id':model.document['calibration_group'],'features':near_model(model,2000+i)} for i in range(20)]
    imp=[{'session_id':'independent-impostor','features':features(2000+i,True)} for i in range(100)]
    with app.app_context():
        with pytest.raises(ValueError,match='overlap'):import_validation(1,gen,imp)
        with pytest.raises(ValueError,match='requires'):import_validation(1,gen[:2],imp)


def test_cross_account_and_modified_validation_cannot_promote(app,client):
    register(app,client);enroll_train(app,client)
    other=app.test_client();register(app,other,'bob');verify(app,other,'rollback','bob')
    assert post(other,'/api/adapt/rollback',json={'version':1}).status_code==409
    maintenance_round(app,client)
    with app.app_context():
        db=get_db();db.execute('INSERT INTO validation_sets VALUES(?,?,?)',(1,app.test_clock[0],seal({},'validation',2,'current')))
    verify(app,client,'candidate');assert post(client,'/api/adapt/candidate',json={}).status_code==409
    assert current(app)[1]==1


def test_evaluation_probes_are_unfiltered_and_never_training(app,client):
    register(app,client);enroll_train(app,client);model,version=current(app)
    verify(app,client,'probe');rid=post(client,'/api/probes/start',json={}).get_json()['round_id']
    for i in range(10):
        assert post(client,'/api/telemetry',json=window(client,800+i,alien=True,round_id=rid)).status_code==200
    assert post(client,'/api/enroll/finish',json={'round_id':rid}).status_code==200
    assert client.get('/api/status').json['progress']['windows']==30
    assert current(app)[0].document==model.document and current(app)[1]==version
    verify(app,client,'export');r=post(client,'/data/export',{'dataset':'probe'})
    assert len(r.data.splitlines())==11 and b'authsense-probe.csv' in r.headers['Content-Disposition'].encode()
