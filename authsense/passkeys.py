"""One-action WebAuthn step-up. Password/TOTP login remains unchanged."""
import base64
import hashlib
import hmac
import secrets

from flask import Blueprint, current_app, g, jsonify, request
from webauthn import (generate_registration_options, verify_registration_response,
                      generate_authentication_options, verify_authentication_response,
                      options_to_json)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria,
    UserVerificationRequirement, PublicKeyCredentialDescriptor)

from .db import atomic, audit, get_db, now
from .security import require_stage, consume_grant, throttle
from .storage import seal, unseal

bp=Blueprint('passkeys',__name__)


def b64(value):return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
def unb64(value):return base64.b64decode(value+'='*(-len(value)%4),altchars=b'-_',validate=True)


def user_handle(user_id):
    return hmac.new(current_app.config['SECRET_KEY'],f'webauthn:{user_id}'.encode(),hashlib.sha256).digest()


def credential_rows():
    return get_db().execute('SELECT * FROM passkeys WHERE user_id=?',(g.user['id'],)).fetchall()


def challenge(purpose):
    db=get_db();db.execute('DELETE FROM ceremonies WHERE expires_at<=? OR session_hash=?',(now(),g.session_hash))
    identifier=secrets.token_urlsafe(24);value=secrets.token_bytes(32)
    db.execute('INSERT INTO ceremonies VALUES(?,?,?,?,?,?)',
        (identifier,g.session_hash,g.user['id'],purpose,b64(value),now()+120))
    return identifier,value


def take_challenge(data,purpose):
    if not isinstance(data,dict) or set(data)!={'ceremony_id','credential'} or not isinstance(data['ceremony_id'],str):
        raise ValueError('Malformed passkey response.')
    # Remove even a failed response; exceptions are handled inside the transaction.
    row=get_db().execute('DELETE FROM ceremonies WHERE id=? AND session_hash=? AND user_id=? AND purpose=? RETURNING *',
        (data['ceremony_id'],g.session_hash,g.user['id'],purpose)).fetchone()
    if row is None or row['expires_at']<=now():raise ValueError('Passkey challenge expired or already used.')
    return unb64(row['challenge'])


def failure(event):
    audit(event)
    return jsonify(error='passkey_failed',message='Passkey verification failed or expired. Start again, or use password and your second factor.'),400


@bp.post('/api/passkeys/register/options')
@require_stage()
@atomic
def register_options():
    if not throttle('passkey-register:'+str(g.user['id']),5):return jsonify(error='rate_limited'),429
    if not consume_grant('passkey'):return jsonify(error='verification_required'),403
    rows=credential_rows()
    if len(rows)>=5:return jsonify(error='credential_limit',message='Revoke existing passkeys before registering more.'),409
    identifier,value=challenge('register')
    options=generate_registration_options(rp_id=current_app.config['WEBAUTHN_RP_ID'],rp_name='AuthSense Local',
        user_name=g.user['username'],user_id=user_handle(g.user['id']),challenge=value,
        authenticator_selection=AuthenticatorSelectionCriteria(user_verification=UserVerificationRequirement.REQUIRED),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=unb64(row['id'])) for row in rows])
    import json
    return jsonify(ceremony_id=identifier,publicKey=json.loads(options_to_json(options)))


@bp.post('/api/passkeys/register/verify')
@require_stage()
@atomic
def register_verify():
    data=request.get_json(silent=True)
    try:
        value=take_challenge(data,'register')
        verified=verify_registration_response(credential=data['credential'],expected_challenge=value,
            expected_rp_id=current_app.config['WEBAUTHN_RP_ID'],expected_origin=current_app.config['WEBAUTHN_ORIGIN'],
            require_user_verification=True)
        if len(credential_rows())>=5:raise ValueError('Credential limit reached.')
        identifier=b64(verified.credential_id)
        if get_db().execute('SELECT 1 FROM passkeys WHERE id=?',(identifier,)).fetchone():raise ValueError('Credential already exists.')
        payload=seal({'key':b64(verified.credential_public_key),'count':verified.sign_count},'passkey',g.user['id'],identifier)
        get_db().execute('INSERT INTO passkeys VALUES(?,?,?,?,?)',(identifier,g.user['id'],payload,verified.sign_count,now()))
    except Exception as error:
        # Library parsing/signature errors contain untrusted input; do not echo or log it.
        current_app.logger.info('Passkey registration rejected (%s)',type(error).__name__)
        return failure('passkey_registration_failed')
    audit('passkey_registered')
    return jsonify(registered=True)


@bp.post('/api/passkeys/vault/options')
@require_stage()
@atomic
def vault_options():
    if not throttle('passkey-use:'+g.session_hash,10):return jsonify(error='rate_limited'),429
    rows=credential_rows()
    if not rows:return jsonify(error='no_passkey',message='Register a passkey in Settings first.'),409
    identifier,value=challenge('vault')
    options=generate_authentication_options(rp_id=current_app.config['WEBAUTHN_RP_ID'],challenge=value,
        allow_credentials=[PublicKeyCredentialDescriptor(id=unb64(row['id'])) for row in rows],
        user_verification=UserVerificationRequirement.REQUIRED)
    import json
    return jsonify(ceremony_id=identifier,publicKey=json.loads(options_to_json(options)))


@bp.post('/api/passkeys/vault/verify')
@require_stage()
@atomic
def vault_verify():
    data=request.get_json(silent=True)
    try:
        value=take_challenge(data,'vault');credential=data['credential']
        row=get_db().execute('SELECT * FROM passkeys WHERE id=? AND user_id=?',
            (credential['id'],g.user['id'])).fetchone()
        if row is None:raise ValueError('Unknown credential.')
        record=unseal(row['public_key'],'passkey',row['user_id'],row['id'])
        if record['count']!=row['sign_count']:raise ValueError('Counter integrity failure.')
        handle=credential['response'].get('userHandle')
        if handle is not None and not hmac.compare_digest(unb64(handle),user_handle(g.user['id'])):
            raise ValueError('Wrong user handle.')
        verified=verify_authentication_response(credential=credential,expected_challenge=value,
            expected_rp_id=current_app.config['WEBAUTHN_RP_ID'],expected_origin=current_app.config['WEBAUTHN_ORIGIN'],
            credential_public_key=unb64(record['key']),credential_current_sign_count=row['sign_count'],
            require_user_verification=True)
        payload=seal({'key':record['key'],'count':verified.new_sign_count},'passkey',g.user['id'],row['id'])
        get_db().execute('UPDATE passkeys SET public_key=?,sign_count=? WHERE id=?',(payload,verified.new_sign_count,row['id']))
        get_db().execute("UPDATE sessions SET grant_scope='vault_passkey',grant_until=?,grant_credential=? WHERE token_hash=?",
            (now()+60,row['id'],g.session_hash))
    except Exception as error:
        current_app.logger.info('Passkey assertion rejected (%s)',type(error).__name__)
        return failure('passkey_assertion_failed')
    audit('passkey_action_verified',{'action':'vault'})
    return jsonify(verified=True,action='/vault/open',expires_in=60)


@bp.post('/api/passkeys/revoke')
@require_stage()
@atomic
def revoke():
    if not consume_grant('revoke_passkeys'):return jsonify(error='verification_required'),403
    db=get_db();db.execute('DELETE FROM passkeys WHERE user_id=?',(g.user['id'],))
    db.execute('DELETE FROM ceremonies WHERE user_id=?',(g.user['id'],))
    db.execute('UPDATE sessions SET grant_scope=NULL,grant_until=0,grant_credential=NULL,must_verify=1 WHERE user_id=?',(g.user['id'],))
    audit('passkeys_revoked');return jsonify(revoked=True)


def consume_vault_grant():
    db=get_db()
    row=db.execute("UPDATE sessions SET grant_scope=NULL,grant_until=0,grant_credential=NULL WHERE token_hash=? "
        "AND grant_scope='vault_passkey' AND grant_until>? AND EXISTS(SELECT 1 FROM passkeys p WHERE p.id=sessions.grant_credential AND p.user_id=sessions.user_id) RETURNING user_id",(g.session_hash,now())).fetchone()
    return row is not None
