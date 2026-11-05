"""Real signed WebAuthn fixtures, not mocked verification success."""
import hashlib
import json
import os
import struct

import cbor2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from authsense.db import get_db
from authsense.passkeys import b64, unb64
from conftest import register, verify, post


class Authenticator:
    def __init__(self):
        self.private=ec.generate_private_key(ec.SECP256R1());self.id=os.urandom(24);self.counter=0
    def client_data(self,options,kind,origin):
        return json.dumps({'type':kind,'challenge':options['publicKey']['challenge'],'origin':origin,'crossOrigin':False},separators=(',',':')).encode()
    def registration(self,options,origin='http://localhost:5000',uv=True,rp='localhost'):
        numbers=self.private.public_key().public_numbers()
        key=cbor2.dumps({1:2,3:-7,-1:1,-2:numbers.x.to_bytes(32,'big'),-3:numbers.y.to_bytes(32,'big')})
        auth=hashlib.sha256(rp.encode()).digest()+bytes([0x41 | (4 if uv else 0)])+struct.pack('>I',0)+bytes(16)+struct.pack('>H',len(self.id))+self.id+key
        att=cbor2.dumps({'fmt':'none','authData':auth,'attStmt':{}})
        return {'ceremony_id':options['ceremony_id'],'credential':{'id':b64(self.id),'rawId':b64(self.id),'type':'public-key',
            'response':{'clientDataJSON':b64(self.client_data(options,'webauthn.create',origin)),'attestationObject':b64(att)}}}
    def assertion(self,options,origin='http://localhost:5000',uv=True,rp='localhost',handle=None):
        self.counter+=1
        client=self.client_data(options,'webauthn.get',origin)
        auth=hashlib.sha256(rp.encode()).digest()+bytes([1 | (4 if uv else 0)])+struct.pack('>I',self.counter)
        signature=self.private.sign(auth+hashlib.sha256(client).digest(),ec.ECDSA(hashes.SHA256()))
        return {'ceremony_id':options['ceremony_id'],'credential':{'id':b64(self.id),'rawId':b64(self.id),'type':'public-key',
            'response':{'clientDataJSON':b64(client),'authenticatorData':b64(auth),'signature':b64(signature),'userHandle':handle}}}


def add_passkey(app,client):
    verify(app,client,'passkey');a=Authenticator()
    options=post(client,'/api/passkeys/register/options',json={}).get_json()
    assert post(client,'/api/passkeys/register/verify',json=a.registration(options)).status_code==200
    return a


def test_one_use_passkey_overrides_only_one_vault_action(app,client):
    register(app,client);a=add_passkey(app,client)
    with app.app_context():get_db().execute('UPDATE sessions SET must_verify=1')
    assert post(client,'/vault/open').status_code==403
    options=post(client,'/api/passkeys/vault/options',json={}).get_json();payload=a.assertion(options)
    assert post(client,'/api/passkeys/vault/verify',json=payload).status_code==200
    assert post(client,'/vault/open').status_code==200
    assert post(client,'/vault/open').status_code==403
    assert post(client,'/api/passkeys/vault/verify',json=payload).status_code==400
    assert client.get('/api/status').get_json()['risk_level']=='high'
    assert post(client,'/api/adapt/start',json={}).status_code in (403,404)


@pytest.mark.parametrize('bad',[{'uv':False},{'rp':'evil.example'},{'origin':'https://evil.example'},{'handle':b64(b'wrong')}])
def test_assertion_rejects_bad_context_and_consumes_challenge(app,client,bad):
    register(app,client);a=add_passkey(app,client)
    options=post(client,'/api/passkeys/vault/options',json={}).get_json()
    assert post(client,'/api/passkeys/vault/verify',json=a.assertion(options,**bad)).status_code==400
    assert post(client,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==400


@pytest.mark.parametrize('bad',[{'uv':False},{'rp':'evil.example'},{'origin':'https://evil.example'}])
def test_registration_requires_user_verification_origin_and_rp(app,client,bad):
    register(app,client);verify(app,client,'passkey');a=Authenticator()
    options=post(client,'/api/passkeys/register/options',json={}).get_json()
    assert post(client,'/api/passkeys/register/verify',json=a.registration(options,**bad)).status_code==400
    with app.app_context():assert get_db().execute('SELECT COUNT(*) FROM passkeys').fetchone()[0]==0


def test_passkey_requires_grant_and_expires(app,client):
    register(app,client)
    assert post(client,'/api/passkeys/register/options',json={}).status_code==403
    a=add_passkey(app,client)
    options=post(client,'/api/passkeys/vault/options',json={}).get_json();app.test_clock[0]+=121
    assert post(client,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==400
    options=post(client,'/api/passkeys/vault/options',json={}).get_json()
    assert post(client,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==200
    app.test_clock[0]+=61
    assert post(client,'/vault/open').status_code==403


def test_wrong_account_revocation_and_counter_integrity(app,client):
    register(app,client);a=add_passkey(app,client)
    other=app.test_client();register(app,other,'bob');b=add_passkey_for_bob(app,other)
    options=post(other,'/api/passkeys/vault/options',json={}).get_json()
    assert post(other,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==400
    with app.app_context():get_db().execute('UPDATE passkeys SET sign_count=9 WHERE id=?',(b64(a.id),))
    options=post(client,'/api/passkeys/vault/options',json={}).get_json()
    assert post(client,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==400
    verify(app,client,'revoke_passkeys')
    assert post(client,'/api/passkeys/revoke',json={}).status_code==200
    assert post(client,'/api/passkeys/vault/options',json={}).status_code==409


def add_passkey_for_bob(app,client):
    verify(app,client,'passkey','bob');a=Authenticator()
    options=post(client,'/api/passkeys/register/options',json={}).get_json()
    assert post(client,'/api/passkeys/register/verify',json=a.registration(options)).status_code==200
    return a


def test_signature_challenge_and_counter_replay(app,client):
    register(app,client);a=add_passkey(app,client)
    options=post(client,'/api/passkeys/vault/options',json={}).get_json()
    payload=a.assertion(options);payload['credential']['response']['signature']=b64(bytes(70))
    assert post(client,'/api/passkeys/vault/verify',json=payload).status_code==400
    wrong=post(client,'/api/passkeys/vault/options',json={}).get_json()
    payload=a.assertion(options);payload['ceremony_id']=wrong['ceremony_id']
    assert post(client,'/api/passkeys/vault/verify',json=payload).status_code==400
    options=post(client,'/api/passkeys/vault/options',json={}).get_json()
    assert post(client,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==200
    options=post(client,'/api/passkeys/vault/options',json={}).get_json();a.counter=0
    assert post(client,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==400


def test_passkey_challenge_bound_to_session(app,client):
    from conftest import PASSWORD,code
    register(app,client);a=add_passkey(app,client)
    options=post(client,'/api/passkeys/vault/options',json={}).get_json()
    other=app.test_client();post(other,'/login',{'username':'alice','password':PASSWORD});post(other,'/mfa',{'code':code(app)})
    assert post(other,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==400
    assert post(client,'/api/passkeys/vault/verify',json=a.assertion(options)).status_code==200
