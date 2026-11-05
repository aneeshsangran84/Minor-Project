import json
import subprocess
import numpy as np
import pytest
from authsense.behavior import FEATURES,extract_features,feature_vector,train_profile,get_model
from conftest import features


def test_signed_overlap_golden_vector_and_javascript_parity():
    pairs=[[i*220,i*220+300] for i in range(24)]
    f=extract_features(pairs)
    assert list(f)==list(FEATURES) and len(f)==12
    assert list(f.values())[:9]==[300,0,300,-80,0,-80,220,0,220]
    assert f['typing_rate_hz']==pytest.approx(24000/5360)
    program="const f=require('./authsense/static/features.js');console.log(JSON.stringify(f.extract("+json.dumps(pairs)+")));"
    js=json.loads(subprocess.check_output(['node','-e',program],text=True))
    assert js['features']==pytest.approx(f)


@pytest.mark.parametrize('change',[lambda x:x.__setitem__(0,[0,2]),lambda x:x.__setitem__(2,[9000,9100]),lambda x:x.pop()])
def test_invalid_pair_windows(change):
    pairs=[[i*220,i*220+100] for i in range(25)]
    change(pairs)
    if len(pairs)==24: pairs[0][1]=float('nan')
    with pytest.raises(ValueError):extract_features(pairs)


def test_ratios_and_signed_flight_validation():
    f=features();f['flight_median_ms']=-40
    feature_vector(f)
    f['dwell_interval_ratio']=100
    with pytest.raises(ValueError,match='ratios'):feature_vector(f)


def test_training_only_scaler_and_no_clipping():
    rows=[{'session_id':str(i//10),'features':features(i)} for i in range(30)]
    p,_=train_profile(rows);a=get_model(p)
    for i,r in enumerate(rows[20:]):r['features']=features(100+i,True)
    p,_=train_profile(rows);b=get_model(p)
    np.testing.assert_equal(a.center,b.center);np.testing.assert_equal(a.scale,b.scale)
    assert np.max(np.abs(a.transform([feature_vector(features(200,True))])))>10


def test_signed_hashing_is_numeric_deterministic_and_profile_specific():
    rows=[{'session_id':str(i//10),'features':features(i)} for i in range(30)]
    p,s=train_profile(rows,hash_key=b'a'*32,profile_id='a')
    q,_=train_profile(rows,hash_key=b'a'*32,profile_id='b')
    m=get_model(p);n=get_model(q)
    assert m.transform([feature_vector(features())]).shape==(1,32)
    assert m.aliases!=n.aliases and s['hash_buckets']==32
    assert p==train_profile(rows,hash_key=b'a'*32,profile_id='a')[0]


def test_identical_calibration_leakage_rejected():
    rows=[{'session_id':str(i//10),'features':features(i)} for i in range(30)]
    rows[-1]['features']=rows[0]['features']
    with pytest.raises(ValueError,match='identical'):train_profile(rows)
