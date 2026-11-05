"""Deterministic SOFTWARE fixtures, not human biometric or security measurements."""
import json
from pathlib import Path
import sys
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from authsense.behavior import extract_features
from evaluate import evaluate


def datasets():
    rng=np.random.default_rng(2026)
    def row(group,shifted=False):
        intervals=rng.normal(250 if not shifted else 700,25,29)
        down=np.r_[0,np.cumsum(intervals)]
        dwell=rng.normal(100 if not shifted else 400,15,30)
        pairs=np.c_[down,down+dwell]
        return {'session_id':group,'features':extract_features(pairs),'duration_ms':float(max(pairs[:,1]))}
    return ([row(f'enrollment-{i//10}') for i in range(30)],
            [row(f'genuine-{i//10}') for i in range(40)],
            [row(f'impostor-{i//10}',True) for i in range(40)])


def main():
    result=evaluate(*datasets());result['data_origin']='SYNTHETIC SOFTWARE CHECK; NOT REAL AUTHENTICATION PERFORMANCE'
    result['generator_seed']=2026
    print(json.dumps(result,indent=2,allow_nan=False))

if __name__=='__main__':main()
