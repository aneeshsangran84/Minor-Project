"""Local operator imports independent DEVELOPMENT data for maintenance gates."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from authsense import create_app
from authsense.db import get_db
from authsense.maintenance import import_validation
from evaluate import load_rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--instance',type=Path,default=Path(__file__).resolve().parents[1]/'instance')
    parser.add_argument('--username',required=True)
    parser.add_argument('--genuine',required=True,type=Path)
    parser.add_argument('--impostor',required=True,type=Path)
    args=parser.parse_args()
    if not (args.instance/'authsense.sqlite3').is_file():parser.error('Use an existing AuthSense instance.')
    try:
        genuine=load_rows(args.genuine);impostor=load_rows(args.impostor)
        app=create_app({'INSTANCE_PATH':args.instance.resolve()})
        with app.app_context():
            db=get_db();user=db.execute('SELECT id FROM users WHERE username=?',(args.username,)).fetchone()
            if user is None:raise ValueError('Unknown local account.')
            db.execute('BEGIN IMMEDIATE')
            try:import_validation(user['id'],genuine,impostor);db.execute('COMMIT')
            except Exception:db.execute('ROLLBACK');raise
    except (ValueError,OSError) as e:parser.error(str(e))
    print('Development evidence imported. No model was changed. Verify in Settings to build and review a candidate.')

if __name__=='__main__':main()
