/* Local wallet UI. No secret is stored in URLs, logs or browser storage. */
/* Epoch guard is independently exercised without a browser or wallet secrets. */
((root) => {
  "use strict";
  function create(now = () => performance.now()) {
    let epoch = 0, active = false, idle = 0, maximum = 0;
    const pending = new Set();
    function invalidate() { epoch++; active=false; idle=maximum=0; for(const c of pending)c.abort(); pending.clear(); }
    function alive() { return active && now()<idle && now()<maximum; }
    return Object.freeze({
      activate() { invalidate(); active=true;maximum=now()+3600000;idle=now()+600000;return epoch; },
      invalidate, alive, epoch:()=>epoch,
      capture(login=false) { const controller=new AbortController();pending.add(controller);return {epoch,controller,login}; },
      current(ticket) { return ticket.epoch===epoch && (ticket.login || alive()); },
      finish(ticket) { pending.delete(ticket.controller); },
      renew() { if(alive())idle=Math.min(now()+600000,maximum); },
      remaining() { return alive()?Math.max(0,Math.min(idle,maximum)-now()):0; },
      accepts(value) { return alive() && value && value.__walletEpoch===epoch; }
    });
  }
  root.SiworldWalletSession=Object.freeze({create});
})(globalThis);
/* Exact private balance presentation; no local state is retained here. */
((root) => {
  "use strict";
  const SIP = "0".repeat(64), MAX_ATOMS = (1n << 128n) - 1n;
  function atoms(value) {
    if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,38})$/.test(value)) throw new Error("Invalid integer balance");
    const amount = BigInt(value);
    if (amount > MAX_ATOMS) throw new Error("Balance exceeds the supported integer range");
    return amount;
  }
  function asset(id) {
    if (typeof id !== "string" || !/^[0-9a-f]{64}$/.test(id)) throw new Error("Invalid asset identifier");
    return id === SIP ? "SIP" : id;
  }
  function formatAmount(id, value) {
    const label = asset(id), amount = atoms(value);
    return label === "SIP" ? `${amount / 100000000n}.${(amount % 100000000n).toString().padStart(8, "0")} SIP` : `${amount} atom`;
  }
  function summary(values) {
    if (!Array.isArray(values)) throw new Error("Verified balance summary is missing");
    const seen = new Set();
    return values.map(row => {
      if (!row || typeof row !== "object") throw new Error("Invalid balance summary");
      asset(row.asset_id);
      if (seen.has(row.asset_id)) throw new Error("Repeated asset in balance summary");
      seen.add(row.asset_id);
      const keys = ["confirmed_owned_atoms", "consensus_mature_atoms", "chain_locked_atoms", "privacy_pending_atoms", "policy_ready_atoms"];
      const amounts = Object.fromEntries(keys.map(key => [key, atoms(row[key])]));
      if (amounts.confirmed_owned_atoms !== amounts.consensus_mature_atoms + amounts.chain_locked_atoms ||
          amounts.consensus_mature_atoms !== amounts.privacy_pending_atoms + amounts.policy_ready_atoms) {
        throw new Error("Balance summary relationships do not match");
      }
      return Object.freeze({asset_id: row.asset_id, ...Object.fromEntries(keys.map(key => [key, amounts[key].toString()]))});
    });
  }
  function privacyPolicy(value) {
    if (!value || !["engineering", "testnet", "mainnet"].includes(value.network_class) ||
        typeof value.enhanced_privacy !== "boolean" || typeof value.background_delay !== "boolean" ||
        !Number.isSafeInteger(value.maximum_delay_seconds) || value.maximum_delay_seconds < 0 || value.maximum_delay_seconds > 21600) {
      throw new Error("Invalid wallet privacy policy");
    }
    return Object.freeze({network_class: value.network_class, enhanced_privacy: value.enhanced_privacy,
      background_delay: value.background_delay, maximum_delay_seconds: value.maximum_delay_seconds});
  }
  root.SiworldWalletBalance = Object.freeze({asset, formatAmount, summary, privacyPolicy});
})(globalThis);
(() => {
  "use strict";
  if (typeof document === "undefined") return;
  const $ = id => document.getElementById(id);
  const miner = location.pathname === "/miner-startup";
  const balances = globalThis.SiworldWalletBalance;
  const guard = globalThis.SiworldWalletSession.create();
  let csrf = "", instance = "", busy = false, timer, expiryTimer;
  function obsolete() { const error = new Error("Session changed or expired"); error.sessionChanged = true; return error; }
  function clearDrafts() { for (const id of ["passphrase", "token"]) $(id).value = ""; }
  function phase(value, detail) { window.SiworldStartup?.setState({phase: value, message: detail}); }
  function message(text) { $("message").textContent = String(text).slice(0, 320); }
  function clearBalances() {
    $("address").value = "";
    $("copy-address").disabled = true;
    $("balances").replaceChildren();
    $("tranches").replaceChildren();
    $("next-unlock").textContent = "";
    $("privacy-policy").textContent = "";
    $("privacy-warning").textContent = "";
    $("privacy-warning").hidden = true;
    $("payment-gate").textContent = "";
    $("payment-gate").hidden = true;
    $("balance-explanation").hidden = true;
    $("balance-placeholder").hidden = false;
    $("verification").textContent = "Balances unknown. Run a verified rescan.";
  }
  function unauthenticate() {
    guard.invalidate(); csrf = ""; instance = "";
    clearTimeout(timer); clearTimeout(expiryTimer);
    clearDrafts(); clearBalances(); $("miner-details").replaceChildren();
    $("wallet-state").textContent = "Locked";
    $("private-panel").hidden = true; $("login-panel").hidden = false;
    phase("auth");
  }
  function scheduleExpiry() {
    clearTimeout(expiryTimer);
    expiryTimer = setTimeout(() => { unauthenticate(); message("Local session expired. Authenticate again to view this wallet."); }, guard.remaining());
  }
  async function post(path, body = {}) {
    const login = path === "/api/login", ticket = guard.capture(login);
    if (!login && !guard.alive()) { guard.finish(ticket); unauthenticate(); throw obsolete(); }
    if (!login && !["/api/status", "/api/miner-status"].includes(path)) { guard.renew(); scheduleExpiry(); }
    try {
      const response = await fetch(path, {method: "POST", credentials: "same-origin", cache: "no-store", signal: ticket.controller.signal,
        headers: {"Content-Type": "application/json", ...(csrf ? {"X-Wallet-CSRF": csrf} : {})}, body: JSON.stringify(body)});
      const result = await response.json();
      if (!guard.current(ticket)) { if (ticket.epoch === guard.epoch()) unauthenticate(); throw obsolete(); }
      if (!response.ok) {
        const error = new Error(result.error || "Local request failed");
        if (response.status === 401) { unauthenticate(); error.currentSessionFailure = true; }
        throw error;
      }
      if (!login) scheduleExpiry();
      Object.defineProperty(result, "__walletEpoch", {value: ticket.epoch});
      return result;
    } catch (error) {
      if (!error.currentSessionFailure && (!guard.current(ticket) || error.name === "AbortError")) throw obsolete();
      throw error;
    } finally { guard.finish(ticket); }
  }
  function height(value) {
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("Invalid snapshot height");
    return value;
  }
  function table(headers, rows) {
    const el = document.createElement("table"), head = document.createElement("thead"), tr = document.createElement("tr");
    for (const label of headers) { const th = document.createElement("th"); th.scope = "col"; th.textContent = label; tr.append(th); }
    head.append(tr); el.append(head);
    const body = document.createElement("tbody");
    for (const row of rows) {
      const line = document.createElement("tr");
      for (const value of row) { const cell = document.createElement("td"); cell.textContent = String(value); line.append(cell); }
      body.append(line);
    }
    el.append(body); return el;
  }
  function summarySection(row) {
    const section = document.createElement("section"), title = document.createElement("h3"), grid = document.createElement("dl");
    section.className = "asset-summary"; title.textContent = balances.asset(row.asset_id); grid.className = "balance-grid";
    for (const [label, key] of [
      ["Confirmed balance", "confirmed_owned_atoms"], ["Awaiting block unlock", "chain_locked_atoms"],
      ["Manual privacy delay pending", "privacy_pending_atoms"], ["Eligible for manual input selection", "policy_ready_atoms"]
    ]) {
      const card = document.createElement("div"), term = document.createElement("dt"), value = document.createElement("dd");
      card.className = "balance-card"; term.textContent = label; value.textContent = balances.formatAmount(row.asset_id, row[key]);
      card.append(term, value); grid.append(card);
    }
    const subtotal = document.createElement("p"); subtotal.className = "mature-subtotal";
    subtotal.textContent = `Block unlock reached: ${balances.formatAmount(row.asset_id, row.consensus_mature_atoms)}. Includes manual privacy delay pending and eligible for manual input selection.`;
    section.append(title, grid, subtotal); return section;
  }
  function render(state) {
    if (!guard.accepts(state)) throw obsolete();
    clearBalances();
    if (miner) return;
    instance = state.instance_id;
    const locked = state.locked !== false, vault = state.vault_exists === true;
    $("wallet-state").textContent = locked ? "Locked" : "Unlocked";
    $("unlock-form").hidden = !locked || !vault;
    $("vault-notice").hidden = vault;
    $("unlock").disabled = !vault || !locked;
    $("passphrase").disabled = !vault || !locked;
    $("rescan").disabled = locked; $("lock").disabled = locked;
    if (locked) { phase("locked", "Unlock the protected wallet to scan accepted history."); return; }
    if (typeof state.address_hex === "string") { $("address").value = state.address_hex; $("copy-address").disabled = !state.address_hex; }
    if (state.balance_status !== "verified") { phase("unlocked", "Verify and rescan accepted history to obtain a balance."); return; }
    const rows = balances.summary(state.balance_summary), snapshotHeight = height(state.height);
    const privacy = balances.privacyPolicy(state.privacy_policy);
    if (typeof state.immediate_spend_privacy_warning !== "boolean") throw new Error("Immediate-spend privacy warning is missing");
    if (!privacy.enhanced_privacy && rows.some(row => row.privacy_pending_atoms !== "0")) throw new Error("Manual delay is inconsistent with the configured privacy policy");
    if (typeof state.tip !== "string" || !/^[0-9a-f]{64}$/.test(state.tip)) throw new Error("Invalid verified snapshot tip");
    if (typeof state.payment_submission_blocked_by_pending_journal !== "boolean") throw new Error("Payment journal status is missing");
    const tranches = (state.tranches || []).map(tranche => {
      const unlock = height(tranche.unlock_height);
      let date = "Unavailable";
      if (tranche.estimated_timestamp !== null) {
        if (!Number.isSafeInteger(tranche.estimated_timestamp) || tranche.estimated_timestamp < 0) throw new Error("Invalid unlock estimate");
        date = new Date(tranche.estimated_timestamp * 1000).toISOString();
      }
      return [balances.asset(tranche.asset_id), balances.formatAmount(tranche.asset_id, tranche.atoms), unlock, date];
    });
    const nextUnlock = state.next_unlock_height === null ? "No pending block unlock." : `Next block unlock at height ${height(state.next_unlock_height)}.`;
    $("verification").textContent = `Verified snapshot at height ${snapshotHeight}. Tip ${state.tip}`;
    $("balance-placeholder").hidden = true; $("balance-explanation").hidden = false;
    const limit = privacy.maximum_delay_seconds === 21600 ? "6 hours" : `${privacy.maximum_delay_seconds} seconds`;
    $("privacy-policy").textContent = `Wallet policy (${privacy.network_class}). Manual transfers: ${privacy.enhanced_privacy ? `enhanced privacy, randomized delay up to ${limit}` : "immediate after consensus unlock"}. Background selection: ${privacy.background_delay ? `randomized delay up to ${limit}` : "delay disabled"}. Consensus block maturity is unchanged. Sending is unavailable in this view; configure policy with the native wallet tool.`;
    if (state.immediate_spend_privacy_warning && !privacy.enhanced_privacy) {
      $("privacy-warning").textContent = "Spending immediately may reduce privacy. Recently received or unlocked notes are present. The native payment command requires confirmation when it selects such notes. Sending is unavailable in this view.";
      $("privacy-warning").hidden = false;
    }
    $("balances").append(...rows.map(summarySection));
    if (!rows.length) $("balances").textContent = "No confirmed owned unspent notes were found in the verified history.";
    if (state.payment_submission_blocked_by_pending_journal) {
      $("payment-gate").textContent = "New payments are blocked by an unresolved payment journal entry. Confirmed ownership remains shown.";
      $("payment-gate").hidden = false;
    }
    $("tranches").append(tranches.length ? table(["Asset", "Amount", "Unlock height", "Estimated date"], tranches) : document.createTextNode("No locked batches."));
    $("next-unlock").textContent = nextUnlock; phase("ready");
  }
  async function action(fn) {
    if (busy) return; busy = true;
    try { await fn(); }
    catch (error) { if (!error.sessionChanged) { clearDrafts(); clearBalances(); message(error.message); phase("error", error.message); } }
    finally { busy = false; }
  }
  $("login-form").addEventListener("submit", event => {
    event.preventDefault();
    return action(async () => {
      const token = $("token").value; unauthenticate();
      const state = await post("/api/login", {token});
      guard.activate(); csrf = state.csrf; scheduleExpiry(); instance = state.instance_id;
      $("login-panel").hidden = true; $("private-panel").hidden = false;
      $("wallet-panel").hidden = miner; $("miner-panel").hidden = !miner;
      message("Local session authenticated.");
      if (miner) await refreshMiner(); else render(await post("/api/status"));
    });
  });
  $("unlock-form").addEventListener("submit", event => {
    event.preventDefault(); const passphrase = $("passphrase").value; $("passphrase").value = "";
    return action(async () => { render(await post("/api/unlock", {passphrase})); message("Wallet unlocked. Verify and rescan to view confirmed ownership."); });
  });
  $("rescan").addEventListener("click", () => action(async () => {
    clearBalances(); phase("rescanning"); message("Independent verification and wallet scan are running. Balances remain unknown until completion.");
    render(await post("/api/rescan")); message("Independent replay and wallet scan completed.");
  }));
  $("lock").addEventListener("click", () => {
    const capturedCsrf = csrf;
    // Clear local secrets independently of in-progress requests and transport.
    unauthenticate(); const lockEpoch = guard.epoch(); phase("locked");
    message("Local private view locked. Requesting backend lock; an in-progress synchronous proof may finish first.");
    if (!capturedCsrf) return;
    try {
      return Promise.resolve(fetch("/api/lock", {method: "POST", credentials: "same-origin", cache: "no-store", headers: {"Content-Type": "application/json", "X-Wallet-CSRF": capturedCsrf}, body: "{}"}))
        .then(response => { if (guard.epoch() === lockEpoch && !guard.alive()) message(response.ok ? "Backend wallet lock confirmed. Authenticate again to reopen it." : "Local view remains locked; backend lock was not confirmed. The backend session deadline still applies."); })
        .catch(() => { if (guard.epoch() === lockEpoch && !guard.alive()) message("Local view remains locked; backend lock request failed. The backend session deadline still applies."); });
    } catch (_error) { message("Local view remains locked; backend lock request failed."); }
  });
  $("refresh").addEventListener("click", () => action(async () => render(await post("/api/status"))));
  $("copy-address").addEventListener("click", () => action(async () => {
    if (!$("address").value) throw new Error("Unlock a wallet before copying its address.");
    await navigator.clipboard.writeText($("address").value); message("Payment address copied.");
  }));
  $("shutdown").addEventListener("click", () => action(async () => {
    await post("/api/shutdown", {instance_id: instance}); unauthenticate(); phase("locked", "This wallet service has stopped."); message("Wallet locked and local wallet service stopped.");
  }));
  async function refreshMiner() {
    clearTimeout(timer);
    try {
      const state = await post("/api/miner-status"); if (!guard.accepts(state)) throw obsolete();
      const details = $("miner-details"); details.replaceChildren();
      for (const [key, value] of [["Phase", state.phase], ["Freshness", state.fresh ? `${state.age_ms} ms old` : "Stale — progress is not confirmed"], ["Failure", state.has_failure ? "Attention required" : "No reported failure"]]) {
        const term = document.createElement("dt"), item = document.createElement("dd"); term.textContent = key; item.textContent = String(value); details.append(term, item);
      }
      const stages = {starting: 0, replaying: 1, preparing: 2, refilling: 2, mining: 4, committing: 3, stopping: 3, stopped: 3, error: 0};
      const failed = !state.fresh || state.has_failure || state.phase === "error";
      window.SiworldStartup?.update({stage: stages[state.phase] ?? 0, state: failed ? "error" : state.phase === "mining" ? "ready" : "active", label: failed ? "Mining observation requires attention" : `Observed mining export: ${state.phase}`, detail: state.fresh ? "Export observation only; operating-system process liveness is not established." : "Export is stale; no progress is inferred."});
      message(failed ? "Service status is stale or reports a failure." : "Authenticated local service observation.");
    } catch (error) {
      if (error.sessionChanged) return;
      clearBalances(); $("miner-details").replaceChildren();
      window.SiworldStartup?.update({stage: 0, state: "error", label: "Mining status unavailable", detail: error.message}); message(error.message);
    }
    if (csrf && !document.hidden) timer = setTimeout(refreshMiner, 5000);
  }
  $("refresh-miner").addEventListener("click", () => action(refreshMiner));
  document.addEventListener("visibilitychange", () => { if (document.hidden) clearTimeout(timer); else if (miner && csrf) refreshMiner(); });
  if (miner) $("scope").textContent = "Authenticated read-only view for the configured local mining service. Private balances and lifecycle controls are not provided here.";
  phase("auth");
})();
