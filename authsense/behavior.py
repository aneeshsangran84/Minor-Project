"""Versioned 12-feature timing pipeline; all calibration precedes evaluation."""
import hashlib
import hmac
import json
import math
from functools import lru_cache

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction import FeatureHasher

FEATURES = tuple(f'{group}_{stat}_ms' for group in ('dwell', 'flight', 'interval')
                 for stat in ('median', 'iqr', 'p90')) + (
    'dwell_interval_ratio', 'interval_iqr_ratio', 'typing_rate_hz')
SCHEMA_VERSION = 2
PIPELINE_VERSION = '2.0'
MIN_EVENTS = 24
FLOORS = np.array([5.] * 9 + [.01, .01, .2])


def finite_number(value, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError('Feature values must be numbers.')
    try:
        number = float(value)
    except OverflowError as error:
        raise ValueError('Feature value is too large.') from error
    if not math.isfinite(number) or not low <= number <= high:
        raise ValueError('Feature value is outside the permitted range.')
    return number


def feature_vector(features):
    if not isinstance(features, dict) or set(features) != set(FEATURES):
        raise ValueError('Unexpected feature schema. Re-enroll with the current collector.')
    limits = [(5,2000),(0,1995),(5,2000),(-2000,2000),(0,4000),(-2000,2000),
              (5,2000),(0,1995),(5,2000),(.0025,400),(0,399),(0,40)]
    v = [finite_number(features[k], *limits[i]) for i,k in enumerate(FEATURES)]
    if any(v[i] > v[i+2] for i in (0,3,6)):
        raise ValueError('Invalid feature quantiles.')
    if not math.isclose(v[9],v[0]/v[6],rel_tol=1e-5,abs_tol=1e-6) or not math.isclose(v[10],v[7]/v[6],rel_tol=1e-5,abs_tol=1e-6):
        raise ValueError('Inconsistent feature ratios.')
    return v


def extract_features(pairs):
    """Offline/reference extractor. Pairs are numeric (down_ms, up_ms), no text."""
    a = np.asarray(pairs,dtype=float)
    if a.ndim != 2 or a.shape[1] != 2 or not 24 <= len(a) <= 200 or not np.isfinite(a).all():
        raise ValueError('Invalid complete key pairs.')
    d=a[:,1]-a[:,0]; i=np.diff(a[:,0]); f=a[1:,0]-a[:-1,1]
    duration=float(np.max(a[:,1])-a[0,0])
    if not 5000 <= duration <= 90000 or np.any((d<5)|(d>2000)) or np.any((i<5)|(i>2000)) or np.any(np.abs(f)>2000):
        raise ValueError('Insufficient or interrupted timing window.')
    v=[]
    for values in (d,f,i):
        v.extend([float(np.median(values)),float(np.quantile(values,.75)-np.quantile(values,.25)),float(np.quantile(values,.9))])
    v += [v[0]/v[6],v[7]/v[6],len(a)*1000/duration]
    result=dict(zip(FEATURES,v)); feature_vector(result)
    return result


def validate_window(payload):
    if not isinstance(payload,dict): raise ValueError('Expected a JSON object.')
    required={'v','nonce','seq','count','interval_count','duration_ms','features'}
    if set(payload) not in (required,required|{'round_id'}):
        raise ValueError('Unexpected telemetry fields. Typed text is not accepted.')
    if type(payload['v']) is not int or payload['v']!=SCHEMA_VERSION:
        raise ValueError('Unsupported collector version. Reload and re-enroll legacy profiles.')
    if type(payload['seq']) is not int or not 1<=payload['seq']<=2**53:
        raise ValueError('Invalid sequence number.')
    if type(payload['count']) is not int or not MIN_EVENTS<=payload['count']<=200:
        raise ValueError('Too few observations or an oversized window.')
    if type(payload['interval_count']) is not int or payload['interval_count']!=payload['count']-1:
        raise ValueError('Intervals must join consecutive complete pairs.')
    duration=finite_number(payload['duration_ms'],5000,90000)
    if not isinstance(payload['nonce'],str) or not 1<=len(payload['nonce'])<=100:
        raise ValueError('Invalid nonce.')
    if 'round_id' in payload and (not isinstance(payload['round_id'],str) or not 1<=len(payload['round_id'])<=100):
        raise ValueError('Invalid enrollment round.')
    vector=feature_vector(payload['features'])
    if not math.isclose(vector[-1],payload['count']*1000/duration,rel_tol=1e-5,abs_tol=1e-6):
        raise ValueError('Inconsistent typing rate.')
    return vector


def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def train_profile(rows, minimum_samples=30, minimum_rounds=3, *, hash_key=None, profile_id='offline', buckets=32):
    if len(rows)<minimum_samples or len(rows)>160: raise ValueError(f'Collect at least {minimum_samples} windows (maximum 160).')
    groups=list(dict.fromkeys(str(r['session_id']) for r in rows))
    if len(groups)<minimum_rounds: raise ValueError(f'Complete at least {minimum_rounds} separate enrollment rounds.')
    if any(not 10<=sum(str(r['session_id'])==group for r in rows)<=40 for group in groups):
        raise ValueError('Each enrollment round needs 10–40 windows.')
    fit=[feature_vector(r['features']) for r in rows if str(r['session_id'])!=groups[-1]]
    cal=[feature_vector(r['features']) for r in rows if str(r['session_id'])==groups[-1]]
    if len(fit)<20 or len(cal)<10: raise ValueError('Need 20 fitting and 10 separate calibration windows.')
    if {tuple(x) for x in fit}&{tuple(x) for x in cal}: raise ValueError('Fitting and calibration contain identical windows.')
    aliases=None
    if hash_key is not None:
        aliases=[hmac.new(hash_key,canonical([profile_id,SCHEMA_VERSION,k]).encode(),hashlib.sha256).hexdigest() for k in FEATURES]
    doc={'schema':SCHEMA_VERSION,'pipeline':PIPELINE_VERSION,'sklearn':sklearn.__version__,'numpy':np.__version__,
         'features':list(FEATURES),'fit':fit,'calibration':cal,'fit_groups':groups[:-1],'calibration_group':groups[-1],
         'aliases':aliases,'buckets':buckets,'seed':42,'calibration_note':'genuine-only; FAR not established'}
    payload=canonical(doc);model=get_model(payload)
    stats={'fit_windows':len(fit),'calibration_windows':len(cal),'rounds':len(groups),
           'calibration_flagged':sum(model.assess(x)['anomalous'] for x in cal),
           'note':'Genuine-only calibration; not held-out accuracy or a validated FAR.',
           'sklearn_version':sklearn.__version__,'schema':SCHEMA_VERSION,'pipeline':PIPELINE_VERSION,
           'fingerprint':hashlib.sha256(payload.encode()).hexdigest(),
           'hash_buckets':buckets if aliases else 0,'hash_collisions':model.collisions,
           'distance_limit':model.distance_limit,'forest_limit':model.forest_limit}
    return payload,stats


class TimingModel:
    def __init__(self,doc):
        if doc.get('schema')!=SCHEMA_VERSION or doc.get('pipeline')!=PIPELINE_VERSION or doc.get('features')!=list(FEATURES):
            raise ValueError('The model schema changed. Re-enroll your profile.')
        if doc.get('sklearn')!=sklearn.__version__ or doc.get('numpy')!=np.__version__:
            raise ValueError('The ML dependency version changed. Retrain your profile.')
        self.document=doc
        fit=np.asarray(doc['fit'],float);cal=np.asarray(doc['calibration'],float)
        for data,n in [(fit,20),(cal,10)]:
            if data.ndim!=2 or data.shape[1]!=12 or not n<=len(data)<=160 or not np.isfinite(data).all():
                raise ValueError('Invalid saved model data.')
            for v in data:feature_vector(dict(zip(FEATURES,v.tolist())))
        self.center=np.median(fit,axis=0)
        mad=np.median(np.abs(fit-self.center),axis=0)
        iqr=np.quantile(fit,.75,axis=0)-np.quantile(fit,.25,axis=0)
        self.scale=np.maximum(np.where(mad<FLOORS,iqr/1.349,1.4826*mad),FLOORS)
        self.aliases=doc.get('aliases');self.collisions=0
        self.hasher=None
        if self.aliases is not None:
            if len(self.aliases)!=12 or any(not isinstance(x,str) or len(x)!=64 for x in self.aliases) or doc['buckets'] not in (32,64,128):
                raise ValueError('Invalid signed hashing configuration.')
            self.hasher=FeatureHasher(n_features=doc['buckets'],input_type='dict',alternate_sign=True)
            positions=[self.hasher.transform([{k:1.}]).indices[0] for k in self.aliases]
            self.collisions=12-len(set(positions))
        self.forest=IsolationForest(n_estimators=100,max_samples=min(256,len(fit)),max_features=1.0,
             bootstrap=False,contamination='auto',random_state=42,n_jobs=1).fit(self.transform(fit))
        distances=np.median(np.abs((cal-self.center)/self.scale),axis=1)
        raw=-self.forest.score_samples(self.transform(cal))
        # Empirical upper quantile, no arbitrary threshold padding. Each detector
        # uses the last verified round; this is not impostor-based FAR calibration.
        self.distance_limit=max(1e-9,float(np.quantile(distances,.95,method='higher')))
        self.forest_limit=max(1e-9,float(np.quantile(raw,.95,method='higher')))

    def transform(self,values):
        z=(np.asarray(values)-self.center)/self.scale
        if self.hasher is None:return z
        return self.hasher.transform([dict(zip(self.aliases,row)) for row in z]).toarray()

    def assess(self,vector):
        v=np.asarray(feature_vector(dict(zip(FEATURES,list(vector)))) if len(vector)==12 else [],float)
        if v.shape!=(12,):raise ValueError('Invalid model input dimension.')
        distance=float(np.median(np.abs((v-self.center)/self.scale)))
        forest=float(-self.forest.score_samples(self.transform([v]))[0])
        ratio=max(distance/self.distance_limit,forest/self.forest_limit)
        return {'anomalous':ratio>1,'risk_index':min(100,round(ratio*50)),
                'distance':distance,'forest_score':forest,'ratio':ratio,
                'reasons':['BEHAVIORAL_ANOMALY' if ratio>1 else 'NORMAL_OBSERVATION']}


@lru_cache(maxsize=16)
def get_model(payload):
    if len(payload)>150000:raise ValueError('Saved model is too large.')
    return TimingModel(json.loads(payload))
