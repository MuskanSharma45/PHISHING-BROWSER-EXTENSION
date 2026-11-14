const API_URL = "http://127.0.0.1:5000/predict";
const API_TIMEOUT_MS = 10000;

const $ = (id) => document.getElementById(id);

const BLOCKED_SCHEMES = [
  "chrome://", "chrome-extension://", "about:", "file://", "data:", "javascript:"
];

function showOnly(cardId) {
  ["resultCard", "errorCard", "loadingCard"].forEach((id) => {
    const el = $(id);
    if (el) el.classList.toggle("hidden", id !== cardId);
  });
}

function setError(msg) {
  $("errorMessage").textContent = msg;
  showOnly("errorCard");
  $("scanBtn").disabled = false;
  $("scanBtnText").textContent = "🔍 Scan This Website";
}

function setLoading() {
  showOnly("loadingCard");
  $("scanBtn").disabled = true;
  $("scanBtnText").textContent = "Scanning...";
}

function renderResult(data) {
  const { prediction, risk_score, message, recommendation, reasons } = data;

  const badge = $("statusBadge");
  if (badge) badge.className = `status-badge ${prediction}`;

  const icons  = { safe: "✅", suspicious: "⚠️", phishing: "🚨" };
  const labels = { safe: "SAFE", suspicious: "SUSPICIOUS", phishing: "PHISHING" };

  $("statusIcon").textContent = icons[prediction]  || "❓";
  $("statusText").textContent = labels[prediction] || String(prediction).toUpperCase();

  const score = Number(risk_score).toFixed(1);
  $("riskValue").textContent = `${score}%`;

  const fill = $("riskBarFill");
  fill.style.width = `${score}%`;
  fill.className = `risk-bar-fill ${prediction}`;

  $("resultMessage").textContent = message || "Website analysis completed.";
  $("recommendation").textContent = recommendation || "";

  // Show reasons if any
  const reasonsBox  = $("reasonsBox");
  const reasonsList = $("reasonsList");
  if (reasons && reasons.length > 0) {
    reasonsList.innerHTML = "";
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      reasonsList.appendChild(li);
    });
    reasonsBox.classList.remove("hidden");
  } else {
    reasonsBox.classList.add("hidden");
  }

  // Warning box only for phishing
  const warningBox = $("warningBox");
  if (warningBox) warningBox.classList.toggle("hidden", prediction !== "phishing");

  showOnly("resultCard");
  $("scanBtn").disabled = false;
  $("scanBtnText").textContent = "🔍 Scan Again";
}

async function getCurrentTab() {
  return new Promise((resolve, reject) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!tabs || tabs.length === 0) return reject(new Error("No active tab found."));
      resolve(tabs[0]);
    });
  });
}

function isAnalyzable(url) {
  if (!url) return { ok: false, reason: "No URL found on this tab." };
  if (BLOCKED_SCHEMES.some((s) => url.startsWith(s)))
    return { ok: false, reason: "This page type cannot be analyzed." };
  if (!url.startsWith("http://") && !url.startsWith("https://"))
    return { ok: false, reason: "Only HTTP and HTTPS pages can be analyzed." };
  return { ok: true };
}

async function scanUrl(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Server error (${response.status})`);
    return data;
  } catch (err) {
    clearTimeout(timer);
    if (err.name === "AbortError")
      throw new Error("Request timed out. Make sure the Flask server is running.");
    if (err.message.includes("Failed to fetch") || err.message.includes("NetworkError"))
      throw new Error("Cannot reach the server. Run: python app.py in the backend folder.");
    throw err;
  }
}

async function handleScan() {
  setLoading();
  let tab;
  try {
    tab = await getCurrentTab();
  } catch (error) {
    setError("Unable to read the current tab. " + error.message);
    return;
  }

  const url = tab.url || "";
  const check = isAnalyzable(url);
  if (!check.ok) { setError(check.reason); return; }

  try {
    const result = await scanUrl(url);
    renderResult(result);
  } catch (error) {
    setError(error.message || "An unexpected error occurred.");
  }
}

async function init() {
  $("scanBtn").addEventListener("click", handleScan);
  $("retryBtn").addEventListener("click", handleScan);

  try {
    const tab = await getCurrentTab();
    const url = tab.url || "";
    if (!url) { $("siteDomain").textContent = "Unknown"; return; }
    try {
      $("siteDomain").textContent = new URL(url).hostname || "Unknown";
    } catch {
      $("siteDomain").textContent = url.slice(0, 50);
    }
  } catch (error) {
    $("siteDomain").textContent = "Unable to read site";
  }
}

document.addEventListener("DOMContentLoaded", init);
