"use strict";
(() => {
 const area=document.querySelector('textarea[data-collector]'),toggle=document.getElementById('collect-toggle');
 if(!area||!toggle)return;
 const progress=document.getElementById('window-progress'),message=document.getElementById('collector-message'),badge=document.getElementById('collector-state');
 let held=new Map(),pairs=[],sending=false;
 function reset(clear=true){held.clear();pairs=[];if(clear)area.value='';progress.textContent='0 / 24 completed keystrokes';}
 function enabled(){return toggle.checked&&!document.hidden&&(!area.dataset.enrollment||window.AuthSense.round!==null);}
 function invalid(){reset();message.textContent='Incomplete or interrupted window discarded. Start typing again.';}
 async function maybeSend(){
  if(!enabled()||sending||held.size||pairs.length<24)return;
  if(Math.max(...pairs.map(p=>p[1]))-pairs[0][0]<5000)return;
  let payload;
  try{payload=window.AuthSenseFeatures.extract(pairs);}catch(_){invalid();return;}
  if(area.dataset.enrollment)payload.round_id=window.AuthSense.round;
  reset();sending=true;
  try{
   const state=await window.AuthSense.api('/api/status');payload.nonce=state.nonce;payload.seq=state.seq+1;
   const data=await window.AuthSense.api('/api/telemetry',{method:'POST',body:JSON.stringify(payload)});
   message.textContent=Number.isInteger(data.enrollment_count)?`Saved timing window ${data.enrollment_count}. Text was discarded.`:`Window assessed: ${data.observation}.`;
   window.dispatchEvent(new CustomEvent('authsense:window',{detail:data}));
  }catch(e){message.textContent=`${e.message} This window was discarded.`;}
  finally{sending=false;}
 }
 area.addEventListener('keydown',e=>{
  if(!enabled()||sending||!e.isTrusted||e.repeat||e.isComposing||e.ctrlKey||e.altKey||e.metaKey||e.key.length!==1)return;
  const t=performance.now();
  if(held.has(e.code)||pairs.length>=200){invalid();return;}
  if(pairs.length&& (t-pairs.at(-1)[0]>2000 || t-pairs.at(-1)[0]<5))invalid();
  const pair=[t,null];pairs.push(pair);held.set(e.code,pair);
 });
 area.addEventListener('keyup',e=>{
  if(!enabled()||sending||!e.isTrusted)return;
  if(!held.has(e.code)){if(e.key.length===1&&!e.repeat)invalid();return;}
  const p=held.get(e.code);held.delete(e.code);p[1]=performance.now();
  if(p[1]-p[0]<5||p[1]-p[0]>2000){invalid();return;}
  progress.textContent=`${pairs.filter(p=>p[1]!==null).length} / 24 completed keystrokes`;maybeSend();
 });
 area.addEventListener('blur',()=>reset());
 area.addEventListener('paste',()=>reset());
 area.addEventListener('compositionstart',()=>reset());
 document.addEventListener('visibilitychange',()=>reset());
 toggle.addEventListener('change',async()=>{
  reset();if(badge)badge.textContent=toggle.checked?'Collection on':'Collection off';
  try{await window.AuthSense.api('/api/consent',{method:'POST',body:JSON.stringify({enabled:toggle.checked})});}
  catch(e){toggle.checked=false;message.textContent=e.message;return;}
  message.textContent=toggle.checked?'Collection enabled in this area only. Type naturally.':'Collection stopped; unsent observations discarded.';
  if(toggle.checked)area.focus();
 });
 document.getElementById('clear-text')?.addEventListener('click',()=>reset());
 setInterval(()=>{if(pairs.length&&performance.now()-pairs.at(-1)[0]>2000)reset();},500);
})();
