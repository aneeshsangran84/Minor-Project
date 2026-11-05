"use strict";
(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  async function api(path, options = {}) {
    const response = await fetch(path, {
      credentials: "same-origin", cache: "no-store", ...options,
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf, ...(options.headers || {})}
    });
    let data;
    try { data = await response.json(); }
    catch (_) { throw new Error("Session or server unavailable. Reload and sign in if necessary."); }
    if (!response.ok) {
      const error = new Error(data.message || data.error || "Request could not be completed.");
      error.status = response.status;
      error.data = data;
      throw error;
    }
    return data;
  }
  window.AuthSense = {api, round: null};
  const state = document.getElementById("policy-state");
  let polling = false;
  async function refreshStatus() {
    if (!state || polling || document.hidden) return;
    polling = true;
    try {
      const data = await api("/api/status");
      state.textContent = {low:"Low · Access available",medium:"Medium · Verify again",high:"High · Sensitive actions restricted"}[data.risk_level];
      state.className = data.allowed ? "allow" : "deny";
      document.getElementById("policy-reason").textContent = data.policy_reason;
      document.getElementById("observation").textContent = data.must_verify ? "Verification required" : data.observation;
      document.getElementById("risk-index").textContent = data.risk_index === null ? "—" : `${data.risk_index} / 100`;
    } catch (error) {
      state.textContent = "Unavailable";
      state.className = "deny";
      document.getElementById("policy-reason").textContent = error.message;
    } finally { polling = false; }
  }
  refreshStatus();
  setInterval(refreshStatus, 5000);
  window.addEventListener("authsense:window", refreshStatus);
  const start = document.getElementById("start-round");
  const finish = document.getElementById("finish-round");
  const message = document.getElementById("enrollment-message");
  if (start) start.addEventListener("click", async () => {
    start.disabled = true;
    try {
      const data = await api(start.dataset.mode === "adapt" ? "/api/adapt/start" : start.dataset.mode === "probe" ? "/api/probes/start" : "/api/enroll/start", {method: "POST", body: "{}"});
      window.AuthSense.round = data.round_id;
      document.getElementById("enrollment-controls").hidden = false;
      start.hidden = true;
      message.textContent = "Round started. Enable collection, then type normally. Complete at least ten windows.";
    } catch (error) { message.textContent = `${error.message} Verify again if the grant expired.`; }
  });
  window.addEventListener("authsense:window", event => {
    if (!finish || !Number.isInteger(event.detail.enrollment_count)) return;
    const count = event.detail.enrollment_count;
    document.getElementById("round-progress").textContent = `${count} / 10 windows`;
    finish.disabled = count < 10;
  });
  if (finish) finish.addEventListener("click", async () => {
    finish.disabled = true;
    const toggle = document.getElementById("collect-toggle");
    toggle.checked = false;
    toggle.dispatchEvent(new Event("change"));
    try {
      const data = await api("/api/enroll/finish", {method: "POST", body: JSON.stringify({round_id: window.AuthSense.round})});
      window.AuthSense.round = null;
      document.getElementById("enrollment-controls").hidden = true;
      message.textContent = `Round saved. ${data.progress.rounds} enrollment rounds, ${data.progress.windows} enrollment windows. Maintenance windows are staged separately. Continue in Settings.`;
    } catch (error) {
      message.textContent = error.message;
      finish.disabled = false;
    }
  });
})();
