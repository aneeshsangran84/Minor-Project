import importlib.util
from pathlib import Path

import pytest

from conftest import features

spec = importlib.util.spec_from_file_location("evaluate", Path(__file__).parents[1] / "scripts/evaluate.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_evaluation_partition_and_metrics():
    enrollment = [{"session_id": f"fit-{i // 10}", "features": features(i)} for i in range(30)]
    genuine = [{"session_id": "later", "features": features(i)} for i in range(100, 110)]
    impostor = [{"session_id": "different-person", "features": features(i, True)} for i in range(100, 110)]
    result = module.evaluate(enrollment, genuine, impostor)
    assert result["metrics"]["combined"]["false_acceptances"] == 0
    impostor[0]["session_id"] = "fit-0"
    with pytest.raises(ValueError, match="overlap"):
        module.evaluate(enrollment, genuine, impostor)


def test_eer_overlap_and_challenge_latency():
    assert module.eer([.2,.3],[1.2,1.3])['approximate_EER']==0
    equal=module.eer([1,1],[1,1]);assert equal['approximate_EER']==.5
    enrollment=[{'session_id':f'fit-{i//10}','features':features(i)} for i in range(30)]
    genuine=[{'session_id':'real-later','features':features(500+i),'duration_ms':6500} for i in range(20)]
    impostor=[{'session_id':'other-person','features':features(500+i,True),'duration_ms':6500} for i in range(20)]
    result=module.evaluate(enrollment,genuine,impostor)
    assert result['latency_ms']['n']==40 and result['latency_ms']['p95']>=result['latency_ms']['p50']>0
    assert result['genuine_challenges']['simulated_prompts_per_active_hour'] is not None
    assert result['genuine_challenges']['measured_prompts_per_hour'] is None
    impostor[0]['features']=genuine[0]['features']
    with pytest.raises(ValueError,match='overlap'):module.evaluate(enrollment,genuine,impostor)


def test_frozen_profile_evaluation_matches_deployed_aliases():
    from authsense.behavior import train_profile
    enrollment=[{'session_id':f'fit-{i//10}','features':features(i)} for i in range(30)]
    frozen=train_profile(enrollment,hash_key=b'private-test-key',profile_id='user-1')
    genuine=[{'session_id':'later-genuine','features':features(1200+i)} for i in range(10)]
    impostor=[{'session_id':'later-impostor','features':features(1200+i,True)} for i in range(10)]
    r=module.evaluate(None,genuine,impostor,frozen=frozen)
    assert r['evaluation_source']=='frozen local profile' and r['training']['fingerprint']==frozen[1]['fingerprint']
    assert r['reproducibility']['alias_seed'] is None
    genuine[0]['session_id']='fit-0'
    with pytest.raises(ValueError,match='overlap'):module.evaluate(None,genuine,impostor,frozen=frozen)
