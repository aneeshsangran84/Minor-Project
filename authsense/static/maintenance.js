"use strict";
(() => {
 const message=document.getElementById('maintenance-message');
 for(const button of document.querySelectorAll('[data-maintenance]'))button.addEventListener('click',async()=>{
  button.disabled=true;
  try{
   const action=button.dataset.maintenance;
   const body=action==='rollback'?{version:Number(document.getElementById('rollback-version').value)}:{};
   const result=await window.AuthSense.api(`/api/adapt/${action}`,{method:'POST',body:JSON.stringify(body)});
   message.textContent=JSON.stringify(result,null,2);
  }catch(e){message.textContent=e.message+' Active profile is unchanged. Obtain a new action-specific verification before retrying.';}
 });
})();
