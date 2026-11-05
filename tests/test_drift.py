import numpy as np
import pytest
from authsense.drift import compare


def test_offline_drift_detects_explicit_synthetic_shift():
    rng=np.random.default_rng(2026)
    scores=np.r_[rng.normal(.6,.03,600),rng.normal(1.4,.03,600)]
    result=compare(scores,[600],6)
    for name,report in result['detectors'].items():
        assert report['missed_changes']==0,name
        assert report['delay'][0]['delay_seconds']>=0
    assert compare([.6]*100)['detectors']['ADWIN']['false_alerts_per_100_stable_windows'] is None


@pytest.mark.parametrize('values',[[1]*10,[float('nan')]*50,[-1]*50])
def test_invalid_drift_observations_rejected(values):
    with pytest.raises(ValueError):compare(values)
