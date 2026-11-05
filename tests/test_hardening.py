import json
import os
import pytest
from authsense import create_app
from authsense.db import get_db
from authsense.storage import read_profile,read_sample,unseal,seal
from conftest import register,enroll_train,window,post,verify


def test_consent_is_server_enforced_and_revocable(app,client):
    register(app,client)
    post(client,'/api/consent',json={'enabled':False})
    assert post(client,'/api/telemetry',json=window(client)).status_code==403
    assert post(client,'/api/consent',json={'enabled':'true'}).status_code==400


def test_one_anomaly_overrides_grace_and_invalid_input_clears_evidence(app,client):
    register(app,client);enroll_train(app,client)
    post(client,'/api/telemetry',json=window(client,alien=True))
    s=client.get('/api/status').json
    assert s['risk_level']=='medium' and not s['allowed']
    assert post(client,'/vault/open').status_code==403
    p=window(client);p['features']['typing_rate_hz']=999
    assert post(client,'/api/telemetry',json=p).status_code==400
    assert client.get('/api/status').json['reason_code']=='INSUFFICIENT_EVIDENCE'


def test_records_encrypted_and_bound_to_context(app,client):
    register(app,client);enroll_train(app,client)
    with app.app_context():
        db=get_db();sample=db.execute('SELECT * FROM samples LIMIT 1').fetchone();profile=db.execute('SELECT * FROM profiles').fetchone()
        assert sample['features'].startswith('aesgcm2:') and profile['payload'].startswith('aesgcm2:')
        assert 'dwell' not in sample['features'] and 'fit' not in profile['payload']
        assert len(read_sample(sample))==12 and '"fit"' in read_profile(profile)
        with pytest.raises(ValueError):unseal(sample['features'],'sample',sample['user_id']+1,sample['id'])
        with pytest.raises(ValueError):unseal(sample['features'],'sample',sample['user_id'],sample['id']+1)
        bad=sample['features'][:-4]+'AAAA'
        with pytest.raises(ValueError):unseal(bad,'sample',sample['user_id'],sample['id'])
        db.execute("UPDATE profiles SET stats='{}'")
    app.test_clock[0]+=121
    assert not client.get('/api/status').json['allowed']


def test_live_windows_never_mutate_profiles_and_training_requires_reset(app,client):
    register(app,client);enroll_train(app,client)
    with app.app_context():before=tuple(get_db().execute('SELECT payload,version FROM profiles').fetchone())
    for i in range(3):post(client,'/api/telemetry',json=window(client,i,alien=True))
    with app.app_context():assert tuple(get_db().execute('SELECT payload,version FROM profiles').fetchone())==before
    verify(app,client,'train');assert post(client,'/model/train').status_code==409


def test_expired_nonce_is_rejected(app,client):
    register(app,client);p=window(client);app.test_clock[0]+=91
    assert post(client,'/api/telemetry',json=p).status_code==409
    assert post(client,'/api/telemetry',json=window(client)).status_code==200


def test_key_permissions_and_symlinks_fail_closed(tmp_path):
    app=create_app({'TESTING':True,'INSTANCE_PATH':tmp_path})
    (tmp_path/'profiles.key').chmod(0o644)
    with pytest.raises(RuntimeError):create_app({'TESTING':True,'INSTANCE_PATH':tmp_path})
    (tmp_path/'profiles.key').chmod(0o600)
    (tmp_path/'session.key').unlink();(tmp_path/'session.key').symlink_to(tmp_path/'profiles.key')
    with pytest.raises(OSError):create_app({'TESTING':True,'INSTANCE_PATH':tmp_path})


def test_legacy_migration_preserves_accounts_and_encrypts_old_vectors(tmp_path):
    import sqlite3
    from cryptography.fernet import Fernet
    from authsense.db import SCHEMA
    for name,value in [('session.key',os.urandom(32)),('encryption.key',Fernet.generate_key())]:
        p=tmp_path/name;p.write_bytes(value);p.chmod(0o600)
    db=sqlite3.connect(tmp_path/'authsense.sqlite3');db.executescript(SCHEMA)
    db.execute("INSERT INTO users(id,username,password_hash,totp_secret,created_at) VALUES(1,'legacy','HASH','SECRET',1)")
    db.execute("INSERT INTO rounds VALUES('r',1,'s',1,2,1)")
    db.execute("INSERT INTO samples VALUES(1,1,'r',1,?)",(json.dumps({'old_feature':1}),))
    db.commit();db.close()
    app=create_app({'TESTING':True,'INSTANCE_PATH':tmp_path})
    with app.app_context():
        assert get_db().execute('SELECT username FROM users').fetchone()[0]=='legacy'
        row=get_db().execute('SELECT * FROM samples').fetchone()
        assert row['schema_version']==1 and read_sample(row)=={'old_feature':1}


def test_single_challenge_cannot_be_cleared_by_browser_telemetry(app,client):
    register(app,client);enroll_train(app,client)
    post(client,'/api/telemetry',json=window(client,alien=True))
    post(client,'/api/telemetry',json=window(client,200))
    state=client.get('/api/status').json
    assert state['risk_level']=='medium' and state['reason_code']=='STEP_UP_PENDING'
    assert post(client,'/vault/open').status_code==403
    verify(app,client);assert post(client,'/vault/open').status_code==200


def test_missing_profile_key_is_not_silently_regenerated(tmp_path):
    create_app({'TESTING':True,'INSTANCE_PATH':tmp_path})
    (tmp_path/'profiles.key').unlink()
    with pytest.raises(RuntimeError,match='original profiles.key'):create_app({'TESTING':True,'INSTANCE_PATH':tmp_path})
    assert not (tmp_path/'profiles.key').exists()


def test_older_record_cannot_replace_active_profile_without_rollback_flow(app,client):
    from authsense.storage import write_profile
    register(app,client);enroll_train(app,client)
    with app.app_context():
        db=get_db();old=db.execute('SELECT * FROM profiles').fetchone()
        write_profile(1,read_profile(old),json.loads(old['stats']))
        db.execute('UPDATE profiles SET version=?,payload=?,stats=? WHERE user_id=1',(old['version'],old['payload'],old['stats']))
        with pytest.raises(ValueError,match='history'):read_profile(db.execute('SELECT * FROM profiles').fetchone())
    app.test_clock[0]+=121
    assert post(client,'/vault/open').status_code==403
