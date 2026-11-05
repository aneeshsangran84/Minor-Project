"use strict";
/* Numeric-only, shared with Node golden tests. Never handles character content. */
(function(root) {
  function q(a,p) { const s=[...a].sort((x,y)=>x-y), k=(s.length-1)*p, i=Math.floor(k); return s[i]+(s[Math.min(i+1,s.length-1)]-s[i])*(k-i); }
  function extract(pairs) {
    if (!Array.isArray(pairs)||pairs.length<24||pairs.length>200||pairs.some(p=>p.length!==2||!p.every(Number.isFinite))) throw Error("Incomplete window");
    const d=pairs.map(p=>p[1]-p[0]), i=pairs.slice(1).map((p,k)=>p[0]-pairs[k][0]), f=pairs.slice(1).map((p,k)=>p[0]-pairs[k][1]);
    const duration=Math.max(...pairs.map(p=>p[1]))-pairs[0][0];
    if (duration<5000||duration>90000||[...d,...i].some(x=>x<5||x>2000)||f.some(x=>Math.abs(x)>2000)) throw Error("Interrupted or invalid timing window");
    const features={};
    for (const [name,a] of [["dwell",d],["flight",f],["interval",i]]) {
      features[`${name}_median_ms`]=q(a,.5);features[`${name}_iqr_ms`]=q(a,.75)-q(a,.25);features[`${name}_p90_ms`]=q(a,.9);
    }
    features.dwell_interval_ratio=features.dwell_median_ms/features.interval_median_ms;
    features.interval_iqr_ratio=features.interval_iqr_ms/features.interval_median_ms;
    features.typing_rate_hz=pairs.length*1000/duration;
    return {v:2,count:pairs.length,interval_count:i.length,duration_ms:duration,features};
  }
  if (typeof module!=="undefined") module.exports={extract,q}; else root.AuthSenseFeatures={extract,q};
})(typeof window!=="undefined"?window:globalThis);
