"use strict";
(() => {
 const message=document.getElementById('passkey-message');
 const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
 const encode=buffer=>btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 function options(raw){
  const o={...raw,challenge:decode(raw.challenge)};
  if(o.user)o.user={...o.user,id:decode(o.user.id)};
  for(const field of ['allowCredentials','excludeCredentials'])if(o[field])o[field]=o[field].map(c=>({...c,id:decode(c.id)}));
  return o;
 }
 function credential(c){
  const r=c.response,response={clientDataJSON:encode(r.clientDataJSON)};
  for(const field of ['attestationObject','authenticatorData','signature','userHandle'])if(r[field])response[field]=encode(r[field]);
  return {id:c.id,rawId:encode(c.rawId),type:c.type,response};
 }
 for(const button of document.querySelectorAll('[data-passkey]'))button.addEventListener('click',async()=>{
  button.disabled=true;
  try{
   if(!window.isSecureContext||!window.PublicKeyCredential)throw new Error('Use a WebAuthn-capable browser at the configured localhost origin.');
   const action=button.dataset.passkey;
   if(action==='revoke'){
    await window.AuthSense.api('/api/passkeys/revoke',{method:'POST',body:'{}'});
    message.textContent='Passkeys revoked. Verify again before protected actions.';return;
   }
   const o=await window.AuthSense.api(`/api/passkeys/${action}/options`,{method:'POST',body:'{}'});
   const result=action==='register'?await navigator.credentials.create({publicKey:options(o.publicKey)}):await navigator.credentials.get({publicKey:options(o.publicKey)});
   if(!result)throw new Error('No credential was returned.');
   await window.AuthSense.api(`/api/passkeys/${action}/verify`,{method:'POST',body:JSON.stringify({ceremony_id:o.ceremony_id,credential:credential(result)})});
   message.textContent=action==='register'?'Passkey registered. Use it from the protected vault panel.':'Verified for this action.';
   if(action==='vault')document.getElementById('vault-form').requestSubmit();
  }catch(e){message.textContent=e.name==='NotAllowedError'?'Passkey request was cancelled, unavailable, or timed out. Verify with your password and second factor if needed.':e.message;}
  finally{button.disabled=false;}
 });
})();
