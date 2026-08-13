"use strict";

const params = new URLSearchParams(window.location.search);
const token = params.get("token") || sessionStorage.getItem("veloce-token") || "";
if (token) sessionStorage.setItem("veloce-token", token);
history.replaceState({}, "", "/");

let activeJob = null;

const byId = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function api(path, options = {}) {
  const headers = Object.assign({"X-Veloce-Token": token}, options.headers || {});
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, Object.assign({}, options, {headers}));
  const payload = await response.json().catch(() => ({error: "Invalid local response"}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function showToast(message) {
  const toast = byId("toast");
  toast.textContent = message;
  toast.classList.remove("hidden");
  window.setTimeout(() => toast.classList.add("hidden"), 6500);
}

function setText(id, value) {
  byId(id).textContent = value === undefined || value === null || value === "" ? "—" : String(value);
}

function setValueState(id, state) {
  const element = byId(id);
  element.classList.remove("value-good", "value-bad", "value-warn");
  if (state) element.classList.add(`value-${state}`);
}

function switchPage(page) {
  document.querySelectorAll(".page").forEach((item) => item.classList.toggle("active", item.id === `${page}-page`));
  document.querySelectorAll(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
  setText("page-title", page === "dashboard" ? "Security dashboard" : "qSearch discovery");
}

function addRecordRow(list, label, value) {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  const detail = document.createElement("dd");
  term.textContent = label;
  detail.textContent = value || "Not available";
  row.append(term, detail);
  list.append(row);
}

function renderValidationItem(container, title, detail, code, state) {
  const row = document.createElement("div");
  row.className = "validation-item";
  const dot = document.createElement("span");
  dot.className = `status-dot ${state || ""}`;
  const copy = document.createElement("div");
  const heading = document.createElement("strong");
  const description = document.createElement("p");
  const evidence = document.createElement("code");
  heading.textContent = title;
  description.textContent = detail || "No detail reported";
  evidence.textContent = code || "";
  copy.append(heading, description);
  row.append(dot, copy, evidence);
  container.append(row);
}

function renderFips(snapshot) {
  const livePill = document.querySelector(".live-pill");
  livePill.classList.toggle("live", snapshot.live && snapshot.approved_mode);
  livePill.classList.toggle("failed", snapshot.live && !snapshot.approved_mode);
  setText("live-label", snapshot.live ? (snapshot.approved_mode ? "Agent healthy" : "Agent degraded") : "Agent unavailable");
  setText("fips-message", snapshot.message);

  setText("approved-value", snapshot.live ? (snapshot.approved_mode ? "ON" : "OFF") : "UNAVAILABLE");
  setValueState("approved-value", snapshot.approved_mode ? "good" : (snapshot.live ? "bad" : "warn"));
  setText("approved-detail", snapshot.live ? `Runtime state: ${snapshot.state}` : "Requires the native agent");

  const status = snapshot.status || {};
  const version = snapshot.version || {};
  const record = snapshot.fips_record || {};
  const certificate = version.fips_certificate || record.fips_certificate || "Not reported";
  const moduleVersion = version.fips_module_version || record.fips_module_version || "Unknown version";
  setText("fips-value", certificate);
  setValueState("fips-value", snapshot.approved_mode ? "good" : "warn");
  setText("fips-detail", `wolfCrypt module ${moduleVersion}`);

  const entropy = status.entropy || {};
  setText("entropy-value", snapshot.live ? (entropy.healthy ? "HEALTHY" : "FAILED") : "NO LIVE DATA");
  setValueState("entropy-value", snapshot.live ? (entropy.healthy ? "good" : "bad") : "warn");
  setText("entropy-detail", entropy.source || record.entropy_source || "wolfEntropy record unavailable");

  const pqcOk = status.pqc_provider && String(status.pqc_provider).includes("passed");
  setText("pqc-value", snapshot.live ? (pqcOk ? "PASSED" : "UNAVAILABLE") : "NO LIVE DATA");
  setValueState("pqc-value", snapshot.live ? (pqcOk ? "good" : "bad") : "warn");

  const validation = snapshot.validation || {};
  const items = Array.isArray(validation.items) ? validation.items : [];
  const validationList = byId("validation-items");
  validationList.replaceChildren();
  setText("validation-source", snapshot.live ? "Live agent evidence" : "Recorded metadata only");
  if (items.length) {
    items.forEach((item) => {
      let state = "";
      if (item.item === "fips_module") state = item.status_code === 0 && item.sha256_verified_before_load ? "good" : "bad";
      if (item.item === "entropy_source") state = String(item.health || "").startsWith("RCT") ? "good" : "bad";
      if (item.item === "pqc_provider") state = item.self_test === "passed" ? "good" : "bad";
      renderValidationItem(validationList, item.name || String(item.item || "Validation item").replaceAll("_", " "),
        item.self_tests || item.health || item.validation || item.note || item.state,
        item.sha256 || item.certificate || "", state);
    });
  } else {
    renderValidationItem(validationList, "Native agent not connected",
      "Install and start the platform-native Veloce runtime to obtain live self-test, entropy, hash, and approved-mode evidence.", "", "");
    if (record.fips_certificate) {
      renderValidationItem(validationList, "Packaged module record",
        `${record.source_version || "wolfCrypt"}; this record alone does not establish live approved mode.`,
        record.sha256 || record.fips_certificate, "");
    }
  }

  const recordList = byId("module-record");
  recordList.replaceChildren();
  addRecordRow(recordList, "Certificate", certificate);
  addRecordRow(recordList, "Module version", moduleVersion);
  addRecordRow(recordList, "Library", record.library || (items.find((i) => i.item === "fips_module") || {}).library);
  addRecordRow(recordList, "SHA-256", record.sha256 || (items.find((i) => i.item === "fips_module") || {}).sha256);
  addRecordRow(recordList, "Environment", record.operating_environment || "Live platform record unavailable");
  addRecordRow(recordList, "PQC boundary", (snapshot.pqc_record || {}).pqc_inside_fips_boundary === true ? "Inside" : "Outside FIPS v5 boundary");
}

async function refreshFips() {
  byId("refresh-fips").disabled = true;
  try {
    renderFips(await api("/api/fips"));
  } catch (error) {
    showToast(error.message);
  } finally {
    byId("refresh-fips").disabled = false;
  }
}

async function runSelfTests() {
  const button = byId("run-self-test");
  button.disabled = true;
  button.textContent = "Running…";
  try {
    const result = await api("/api/fips/self-test", {method: "POST", body: "{}"});
    byId("self-test-panel").classList.remove("hidden");
    setText("self-test-output", JSON.stringify(result, null, 2));
    await refreshFips();
  } catch (error) {
    showToast(error.message);
  } finally {
    button.disabled = false;
    button.textContent = "Run self-tests";
  }
}

function classificationClass(value) {
  if (value === "quantum-vulnerable") return "vulnerable";
  if (value === "pqc-ready") return "ready";
  return "context";
}

function renderScan(job) {
  const result = job.result;
  activeJob = job.id;
  setText("scan-location", `${result.scan_root}  →  ${job.output}`);
  setText("files-count", result.files_scanned);
  setText("vulnerable-count", result.counts.quantum_vulnerable);
  setText("high-count", result.counts.high_risk);
  setText("pqc-count", result.counts.pqc_ready);
  setText("findings-note", result.findings_truncated ? `First ${result.findings.length} of ${result.counts.total}` : `${result.counts.total} findings`);

  const chart = byId("algorithm-chart");
  chart.replaceChildren();
  const max = Math.max(1, ...result.top_algorithms.map((item) => item.count));
  result.top_algorithms.forEach((item) => {
    const row = document.createElement("div"); row.className = "bar-row";
    const label = document.createElement("span"); label.className = "bar-label"; label.textContent = item.algorithm; label.title = item.algorithm;
    const track = document.createElement("div"); track.className = "bar-track";
    const fill = document.createElement("div");
    const widthBucket = Math.max(10, Math.ceil((item.count / max * 100) / 10) * 10);
    fill.className = `bar-fill width-${widthBucket}`;
    track.append(fill);
    const count = document.createElement("span"); count.className = "bar-count"; count.textContent = item.count;
    row.append(label, track, count); chart.append(row);
  });

  const body = byId("findings-body");
  body.replaceChildren();
  result.findings.forEach((finding) => {
    const row = document.createElement("tr");
    const algorithm = document.createElement("td"); algorithm.textContent = finding.algorithm;
    const classificationCell = document.createElement("td");
    const classification = document.createElement("span"); classification.className = `classification ${classificationClass(finding.classification)}`; classification.textContent = finding.classification; classificationCell.append(classification);
    const risk = document.createElement("td"); risk.textContent = finding.risk;
    const asset = document.createElement("td"); asset.textContent = finding.asset; asset.title = finding.evidence;
    row.append(algorithm, classificationCell, risk, asset); body.append(row);
  });
  byId("scan-results").classList.remove("hidden");
}

async function pollJob(jobId) {
  while (true) {
    const job = await api(`/api/qsearch/job?id=${encodeURIComponent(jobId)}`);
    if (job.state === "complete") {
      byId("scan-progress").classList.add("hidden");
      byId("start-scan").disabled = false;
      renderScan(job);
      return;
    }
    if (job.state === "failed") throw new Error(job.error || "qSearch failed");
    await sleep(800);
  }
}

async function startScan() {
  const target = byId("scan-path").value.trim();
  if (!target) { showToast("Choose a folder before starting qSearch."); return; }
  byId("start-scan").disabled = true;
  byId("scan-results").classList.add("hidden");
  byId("scan-progress").classList.remove("hidden");
  setText("scan-progress-text", target);
  try {
    const job = await api("/api/qsearch/run", {method: "POST", body: JSON.stringify({target})});
    await pollJob(job.id);
  } catch (error) {
    byId("scan-progress").classList.add("hidden");
    byId("start-scan").disabled = false;
    showToast(error.message);
  }
}

async function chooseFolder() {
  byId("choose-folder").disabled = true;
  try {
    const result = await api("/api/qsearch/select-directory", {method: "POST", body: "{}"});
    if (result.path) byId("scan-path").value = result.path;
  } catch (error) {
    showToast(error.message);
  } finally {
    byId("choose-folder").disabled = false;
  }
}

async function initialize() {
  if (!token) { showToast("The desktop security token is missing. Restart Veloce Desktop."); return; }
  try {
    const info = await api("/api/platform");
    setText("platform-label", `${info.platform} ${info.machine}\nVeloce Desktop ${info.app_version}`);
    byId("start-scan").disabled = !info.qsearch_available;
    if (!info.qsearch_available) showToast("qSearch is not bundled with this desktop build.");
  } catch (error) {
    showToast(error.message);
  }
  await refreshFips();
}

document.querySelectorAll(".nav-item").forEach((item) => item.addEventListener("click", () => switchPage(item.dataset.page)));
byId("refresh-fips").addEventListener("click", refreshFips);
byId("run-self-test").addEventListener("click", runSelfTests);
byId("choose-folder").addEventListener("click", chooseFolder);
byId("start-scan").addEventListener("click", startScan);
byId("open-report").addEventListener("click", async () => {
  if (!activeJob) return;
  try { await api("/api/qsearch/open-report", {method: "POST", body: JSON.stringify({job_id: activeJob})}); }
  catch (error) { showToast(error.message); }
});
byId("quit-button").addEventListener("click", async () => {
  try { await api("/api/shutdown", {method: "POST", body: "{}"}); }
  finally { document.body.textContent = "Veloce Desktop has stopped. You may close this tab."; }
});

initialize();
