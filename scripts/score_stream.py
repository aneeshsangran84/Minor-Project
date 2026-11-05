"""Score an ordered, independent feature stream for offline drift comparison."""
import argparse
import csv
import hashlib
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from authsense.behavior import feature_vector,train_profile,get_model
from authsense.maintenance import disjoint
from evaluate import load_rows


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--enrollment',type=Path,required=True);p.add_argument('--observations',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--buckets',type=int,choices=[32,64,128],default=32);p.add_argument('--alias-seed',default='evaluation-2026')
    args=p.parse_args()
    try:
        training=load_rows(args.enrollment);stream=load_rows(args.observations);disjoint([training,stream])
        payload,_=train_profile(training,hash_key=hashlib.sha256(args.alias_seed.encode()).digest(),buckets=args.buckets)
        model=get_model(payload);args.output.parent.mkdir(parents=True,exist_ok=True)
        with args.output.open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=['window_index','session_id','score_ratio']);w.writeheader()
            for i,row in enumerate(stream):w.writerow({'window_index':i,'session_id':row['session_id'],'score_ratio':model.assess(feature_vector(row['features']))['ratio']})
    except (OSError,ValueError,KeyError) as e:p.error(str(e))
    print('Scores written in input order. Preserve true chronology; drift does not prove identity.')

if __name__=='__main__':main()
