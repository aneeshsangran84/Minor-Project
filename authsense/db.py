"""Small transactional SQLite store. Values are always bound parameters."""
import json
import sqlite3

from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL,
 totp_enabled INTEGER NOT NULL DEFAULT 0, last_totp_counter INTEGER NOT NULL DEFAULT -1,
 created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 stage TEXT NOT NULL, created_at REAL NOT NULL, last_activity REAL NOT NULL,
 expires_at REAL NOT NULL, strong_at REAL NOT NULL DEFAULT 0,
 must_verify INTEGER NOT NULL DEFAULT 0, strikes INTEGER NOT NULL DEFAULT 0,
 last_sample REAL, observation TEXT NOT NULL DEFAULT 'unknown', risk_index INTEGER,
 reasons TEXT NOT NULL DEFAULT '[]', nonce TEXT NOT NULL, sequence INTEGER NOT NULL DEFAULT 0,
 grant_scope TEXT, grant_until REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS recovery_codes (
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL, PRIMARY KEY(user_id, code_hash)
);
CREATE TABLE IF NOT EXISTS rounds (
 id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 session_hash TEXT NOT NULL, started_at REAL NOT NULL, expires_at REAL NOT NULL,
 completed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS samples (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 round_id TEXT NOT NULL REFERENCES rounds(id) ON DELETE CASCADE,
 created_at REAL NOT NULL, features TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 version INTEGER NOT NULL, created_at REAL NOT NULL, payload TEXT NOT NULL,
 stats TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
 created_at REAL NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS limits (
 bucket TEXT PRIMARY KEY, start REAL NOT NULL, count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS samples_user ON samples(user_id, id);
CREATE INDEX IF NOT EXISTS audit_user ON audit(user_id, id);
"""


def now():
    return float(current_app.config["CLOCK"]())


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"], timeout=15, isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA busy_timeout=15000")
    return g.db


def init_db():
    db = get_db()
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(SCHEMA)
    migrate(db)


def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def audit(event, detail="", user_id=None):
    if user_id is None and getattr(g, "user", None) is not None:
        user_id = g.user["id"]
    if not isinstance(detail, str):
        detail = json.dumps(detail, separators=(",", ":"), allow_nan=False)
    db = get_db()
    db.execute("INSERT INTO audit(user_id,created_at,event,detail) VALUES(?,?,?,?)",
               (user_id, now(), event, detail[:1000]))
    db.execute('DELETE FROM audit WHERE created_at<?', (now()-30*86400,))
    # Bounded account-local history; no passwords, OTPs, text, IPs or raw events.
    if user_id is not None:
        db.execute("DELETE FROM audit WHERE user_id=? AND id NOT IN "
                   "(SELECT id FROM audit WHERE user_id=? ORDER BY id DESC LIMIT 500)",
                   (user_id, user_id))


def migrate(db):
    """Additive, transactional migration. Legacy vectors are encrypted, not invented."""
    from .storage import seal,PREFIX
    db.execute('BEGIN IMMEDIATE')
    try:
        additions={'users':{'behavior_consent':'INTEGER NOT NULL DEFAULT 0'},
          'sessions':{'step_up_required':'INTEGER NOT NULL DEFAULT 0','collecting':'INTEGER NOT NULL DEFAULT 0','last_model_version':'INTEGER',
                      'nonce_issued':'REAL NOT NULL DEFAULT 0','grant_credential':'TEXT'},
          'rounds':{'purpose':"TEXT NOT NULL DEFAULT 'enroll'",'schema_version':'INTEGER NOT NULL DEFAULT 1','base_version':'INTEGER'},
          'samples':{'schema_version':'INTEGER NOT NULL DEFAULT 1'}}
        for table,columns in additions.items():
            known={r[1] for r in db.execute('PRAGMA table_info('+table+')')}
            for col,sql in columns.items():
                if col not in known:db.execute(f'ALTER TABLE {table} ADD COLUMN {col} {sql}')
        for sql in [
          'CREATE TABLE IF NOT EXISTS profile_versions(user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,version INTEGER,created_at REAL,payload TEXT,stats TEXT,PRIMARY KEY(user_id,version))',
          'CREATE TABLE IF NOT EXISTS candidates(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,base_version INTEGER,created_at REAL,payload TEXT NOT NULL)',
          'CREATE TABLE IF NOT EXISTS validation_sets(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,created_at REAL,payload TEXT NOT NULL)',
          'CREATE TABLE IF NOT EXISTS passkeys(id TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,public_key TEXT NOT NULL,sign_count INTEGER NOT NULL,created_at REAL NOT NULL)',
          'CREATE TABLE IF NOT EXISTS ceremonies(id TEXT PRIMARY KEY,session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,purpose TEXT NOT NULL,challenge TEXT NOT NULL,expires_at REAL NOT NULL)']:
            db.execute(sql)
        for row in db.execute('SELECT * FROM samples').fetchall():
            if not row['features'].startswith(PREFIX):
                db.execute('UPDATE samples SET features=? WHERE id=?',(seal(json.loads(row['features']),'sample',row['user_id'],row['id']),row['id']))
        for row in db.execute('SELECT * FROM profiles').fetchall():
            encrypted=row['payload']
            if not encrypted.startswith(PREFIX):
                encrypted=seal({'payload':row['payload'],'stats':json.loads(row['stats'])},'profile',row['user_id'],row['version'])
                db.execute('UPDATE profiles SET payload=? WHERE user_id=?',(encrypted,row['user_id']))
            db.execute('INSERT OR IGNORE INTO profile_versions VALUES(?,?,?,?,?)',(row['user_id'],row['version'],row['created_at'],encrypted,row['stats']))
        db.execute('PRAGMA user_version=2')
        db.execute('COMMIT')
    except Exception:
        db.execute('ROLLBACK');raise


def atomic(fn):
    """Serialize security state transitions, including nonce consumption and scoring."""
    from functools import wraps
    from flask import abort
    @wraps(fn)
    def wrapped(*args,**kwargs):
        db=get_db();db.execute('BEGIN IMMEDIATE')
        try:
            row=db.execute('SELECT * FROM sessions WHERE token_hash=?',(g.session_hash,)).fetchone()
            if row is None or row['stage']!='active' or row['expires_at']<=now():abort(401)
            g.auth=row
            result=fn(*args,**kwargs);db.execute('COMMIT');return result
        except Exception:
            db.execute('ROLLBACK');raise
    return wrapped
