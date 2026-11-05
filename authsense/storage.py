"""Authenticated, context-bound encryption for biometric records (not telemetry attestation)."""
import base64
import json
import secrets
from flask import current_app
from cryptography.exceptions import InvalidTag

PREFIX='aesgcm2:'


def seal(value, kind, user_id, record_id):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    nonce=secrets.token_bytes(12)
    aad=json.dumps([2,kind,int(user_id),str(record_id)],separators=(',',':')).encode()
    ciphertext=current_app.extensions['profile_aead'].encrypt(nonce,raw,aad)
    return PREFIX+base64.urlsafe_b64encode(nonce+ciphertext).decode()


def unseal(value, kind, user_id, record_id):
    if not isinstance(value,str) or not value.startswith(PREFIX):raise ValueError('Encrypted record required.')
    try:
        raw=base64.b64decode(value[len(PREFIX):],altchars=b'-_',validate=True)
        aad=json.dumps([2,kind,int(user_id),str(record_id)],separators=(',',':')).encode()
        return json.loads(current_app.extensions['profile_aead'].decrypt(raw[:12],raw[12:],aad))
    except (ValueError,InvalidTag,TypeError,UnicodeError) as e:
        raise ValueError('Record integrity check failed.') from e


def read_sample(row):return unseal(row['features'],'sample',row['user_id'],row['id'])

def read_profile(row, *, history=False):
    if not history:
        from .db import get_db
        latest=get_db().execute('SELECT MAX(version) FROM profile_versions WHERE user_id=?',(row['user_id'],)).fetchone()[0]
        if latest is not None and latest!=row['version']:raise ValueError('Active profile version is inconsistent with retained history.')
    value=unseal(row['payload'],'profile',row['user_id'],row['version'])
    if value['stats']!=json.loads(row['stats']):raise ValueError('Profile metadata integrity check failed.')
    return value['payload']


def write_profile(user_id,payload,stats):
    """Caller holds a write transaction; version numbers never reused on rollback."""
    from .db import get_db,now
    from .behavior import get_model
    db=get_db()
    version=db.execute('SELECT COALESCE(MAX(version),0)+1 FROM profile_versions WHERE user_id=?',(user_id,)).fetchone()[0]
    encoded=seal({'payload':payload,'stats':stats},'profile',user_id,version)
    args=(user_id,version,now(),encoded,json.dumps(stats))
    db.execute('INSERT INTO profile_versions(user_id,version,created_at,payload,stats) VALUES(?,?,?,?,?)',args)
    db.execute('INSERT INTO profiles(user_id,version,created_at,payload,stats) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET version=excluded.version,created_at=excluded.created_at,payload=excluded.payload,stats=excluded.stats',args)
    db.execute('DELETE FROM profile_versions WHERE user_id=? AND version NOT IN (SELECT version FROM profile_versions WHERE user_id=? ORDER BY version DESC LIMIT 3)',(user_id,user_id))
    db.execute("UPDATE sessions SET observation='unknown',last_sample=NULL,last_model_version=NULL WHERE user_id=?",(user_id,))
    get_model.cache_clear()
    return version
