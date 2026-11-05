"""Compare ADWIN and rolling median on score streams; optional explicit synthetic demo."""
import argparse
import csv
import json
from pathlib import Path
import sys
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from authsense.drift import compare


def main():
    p=argparse.ArgumentParser(description=__doc__);group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--scores',type=Path);group.add_argument('--synthetic',action='store_true')
    p.add_argument('--changes',type=int,nargs='*',default=[]);p.add_argument('--seconds-per-window',type=float)
    p.add_argument('--output',type=Path);args=p.parse_args()
    try:
        if args.synthetic:
            rng=np.random.default_rng(2026);values=np.r_[rng.normal(.6,.03,600),rng.normal(1.4,.03,600)].tolist();changes=[600]
        else:
            with args.scores.open(newline='') as f:values=[float(r['score_ratio']) for r in csv.DictReader(f)]
            changes=args.changes
        report=compare(values,changes,args.seconds_per_window)
    except (ValueError,OSError,KeyError) as e:p.error(str(e))
    report['data_origin']='SYNTHETIC SOFTWARE CHECK; NOT AUTHENTICATION RESULTS' if args.synthetic else 'USER-SUPPLIED SCORE STREAM'
    out=json.dumps(report,indent=2,allow_nan=False)
    if args.output:args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(out+'\n')
    print(out)

if __name__=='__main__':main()
