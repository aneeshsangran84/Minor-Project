"""Deterministic server policy. A model observation is never a login credential."""
POLICY_VERSION='2.0'

def decide(row, *, now, model_ready, model_version=None, fresh_seconds=120, ttl=45):
    def result(level,code,reason):
        return {'risk_level':level,'allowed':level=='low','action':{'low':'continue','medium':'step_up','high':'restrict_sensitive_actions'}[level],
                'reason_code':code,'policy_reason':reason,'policy_version':POLICY_VERSION,'model_version':model_version}
    if not row or row['stage']!='active' or row['expires_at']<=now:
        return result('high','AUTHENTICATION_REQUIRED','Sign in with your established factors')
    if row['must_verify']:return result('high','CHALLENGE_LATCHED','Consecutive anomalies require fresh verification')
    if row['observation']=='unusual':return result('medium','BEHAVIORAL_ANOMALY','An unusual window requires verification')
    if row['observation']=='invalid':return result('medium','INSUFFICIENT_EVIDENCE','Invalid observations cannot provide trust')
    if row['step_up_required'] and row['observation']!='unusual':
        return result('medium','STEP_UP_PENDING','Complete fresh verification to clear the pending challenge')
    if row['strong_at']>0 and now-row['strong_at']<=fresh_seconds:
        return result('low','RECENT_STRONG_VERIFICATION','Recent successful factor verification')
    if not model_ready:return result('medium','MODEL_UNAVAILABLE','Model unavailable; verify with an established factor')
    if row['last_sample'] is None or now-row['last_sample']>ttl:
        return result('medium','STALE_EVIDENCE','Behavioral evidence is missing or stale')
    if row['last_model_version']!=model_version:
        return result('medium','MODEL_VERSION_CHANGED','Provide evidence for the current model or verify again')
    if row['observation']!='normal':return result('medium','INSUFFICIENT_EVIDENCE','Behavioral evidence is uncertain')
    return result('low','NORMAL_OBSERVATION','Fresh evidence within experimental thresholds')
