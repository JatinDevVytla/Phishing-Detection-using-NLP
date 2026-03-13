/**
 * popup.js
 * ─────────────────────────────────────────────────────────────
 * Controls the extension popup UI.
 *
 * Responsibilities:
 *  1. Check if the FastAPI backend is reachable
 *  2. Ask the content script (content.js) to extract email data
 *     from the active Gmail tab
 *  3. Send the email data to the backend /analyze endpoint
 *  4. Render the phishing/safe verdict + risk flags in the popup
 */

const BACKEND_URL = "http://localhost:8000";

// ── DOM refs ──────────────────────────────────────────────────────────────────
const scanBtn       = document.getElementById("scanBtn");
const statusCard    = document.getElementById("statusCard");
const statusEmoji   = document.getElementById("statusEmoji");
const statusLabel   = document.getElementById("statusLabel");
const statusSub     = document.getElementById("statusSub");
const confSection   = document.getElementById("confSection");
const confValue     = document.getElementById("confValue");
const confBar       = document.getElementById("confBar");
const flagsSection  = document.getElementById("flagsSection");
const flagList      = document.getElementById("flagList");
const placeholder   = document.getElementById("placeholder");
const backendDot    = document.getElementById("backendDot");
const backendStatus = document.getElementById("backendStatus");
const liveDot       = document.getElementById("liveDot");
const reportLink    = document.getElementById("reportLink");


// ── Utility: update status card ───────────────────────────────────────────────

/**
 * @param {'idle'|'scanning'|'safe'|'phishing'} state
 * @param {string} label   - bold heading text
 * @param {string} sub     - sub-description text
 * @param {number} [conf]  - confidence 0–1 (shown when state is safe/phishing)
 */
function setStatus(state, label, sub, conf = null) {
  // Reset card classes
  statusCard.className = `status-card ${state}`;

  // Emoji map
  const emojis = {
    idle:     "📭",
    scanning: "🔄",
    safe:     "✅",
    phishing: "🚨",
  };
  statusEmoji.textContent = emojis[state] ?? "❓";

  // Label
  statusLabel.className = `status-label ${state}`;
  statusLabel.textContent = label;

  // Sub text
  statusSub.textContent = sub;

  // Confidence bar
  if (conf !== null) {
    confSection.style.display = "block";
    const pct = Math.round(conf * 100);
    confValue.textContent = `${pct}%`;
    confBar.style.width = `${pct}%`;
    confBar.className = `conf-bar-fill ${state}`;
  } else {
    confSection.style.display = "none";
  }
}


// ── Check backend health ──────────────────────────────────────────────────────

async function checkBackend() {
  try {
    const res = await fetch(`${BACKEND_URL}/health`, {
      method: "GET",
      signal: AbortSignal.timeout(3000),
    });

    if (res.ok) {
      backendDot.className = "backend-dot online";
      backendStatus.textContent = "Backend connected · localhost:8000";
      liveDot.style.background = "var(--safe)";
      liveDot.style.boxShadow  = "0 0 6px var(--safe)";
      return true;
    }
  } catch {
    // fall through to offline state
  }

  backendDot.className = "backend-dot offline";
  backendStatus.textContent = "Backend offline — run: uvicorn main:app --reload";
  liveDot.style.background = "var(--danger)";
  liveDot.style.boxShadow  = "0 0 6px var(--danger)";
  return false;
}


// ── Ask content.js to extract email from Gmail tab ────────────────────────────

function extractEmailFromTab(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(
      tabId,
      { action: "extractEmail" },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else if (!response || !response.body) {
          reject(new Error("no_email"));
        } else {
          resolve(response);
        }
      }
    );
  });
}


// ── Send email data to backend ────────────────────────────────────────────────

async function analyzeEmail(emailData) {
  const res = await fetch(`${BACKEND_URL}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(emailData),
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) throw new Error(`Backend error: ${res.status}`);
  return res.json();
}


// ── Render risk flags ─────────────────────────────────────────────────────────

function renderFlags(flags) {
  flagList.innerHTML = "";

  if (!flags || flags.length === 0) {
    flagsSection.style.display = "none";
    return;
  }

  flagsSection.style.display = "block";

  flags.forEach((flag, i) => {
    const item = document.createElement("div");
    item.className = "flag-item";
    item.style.animationDelay = `${i * 60}ms`;

    // Split emoji from text (first char is usually the emoji)
    const parts = flag.match(/^(\S+)\s+(.+)$/);
    if (parts) {
      item.innerHTML = `
        <span class="flag-icon">${parts[1]}</span>
        <span>${parts[2]}</span>
      `;
    } else {
      item.textContent = flag;
    }

    flagList.appendChild(item);
  });
}


// ── Main scan handler ─────────────────────────────────────────────────────────

scanBtn.addEventListener("click", async () => {
  scanBtn.disabled = true;
  placeholder.style.display  = "none";
  flagsSection.style.display = "none";

  // Step 1 — Check backend
  setStatus("scanning", "Connecting…", "Checking backend availability.");
  const backendOk = await checkBackend();
  if (!backendOk) {
    setStatus(
      "idle",
      "Backend offline",
      "Start your FastAPI server:\n  uvicorn main:app --reload"
    );
    scanBtn.disabled = false;
    return;
  }

  // Step 2 — Get active tab
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab?.url?.includes("mail.google.com")) {
    setStatus(
      "idle",
      "Not Gmail",
      "Navigate to Gmail and open an email first."
    );
    placeholder.style.display = "block";
    scanBtn.disabled = false;
    return;
  }

  // Step 3 — Extract email from Gmail DOM
  setStatus("scanning", "Reading email…", "Extracting content from Gmail.");
  let emailData;
  try {
    emailData = await extractEmailFromTab(tab.id);
  } catch (err) {
    if (err.message === "no_email") {
      setStatus(
        "idle",
        "No email found",
        "Open a specific email thread in Gmail, then scan."
      );
      placeholder.style.display = "block";
    } else {
      setStatus(
        "idle",
        "Content script error",
        "Try refreshing Gmail and scanning again."
      );
    }
    scanBtn.disabled = false;
    return;
  }

  // Step 4 — Send to BERT backend
  setStatus("scanning", "Analysing…", "Running AI phishing detection.");
  let result;
  try {
    result = await analyzeEmail(emailData);
  } catch (err) {
    setStatus(
      "idle",
      "Analysis failed",
      `Error: ${err.message}`
    );
    scanBtn.disabled = false;
    return;
  }

  // Step 5 — Display result
  const isPhishing = result.label === "PHISHING";

  if (isPhishing) {
    setStatus(
      "phishing",
      "⚠ Phishing Detected",
      "This email shows signs of a phishing attempt. Do not click any links or provide personal information.",
      result.confidence
    );
  } else {
    setStatus(
      "safe",
      "Email looks safe",
      "No phishing signals detected. Always stay cautious with unexpected emails.",
      result.confidence
    );
  }

  renderFlags(result.reasons ?? []);
  scanBtn.disabled = false;
  scanBtn.textContent = "🔍 Scan Again";
});


// ── Report false result ───────────────────────────────────────────────────────

reportLink.addEventListener("click", () => {
  chrome.tabs.create({
    url: "https://github.com/your-username/phishing-detector/issues/new?template=false_result.md",
  });
});


// ── On popup open: check backend + auto-detect Gmail ─────────────────────────

(async () => {
  await checkBackend();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (tab?.url?.includes("mail.google.com")) {
    placeholder.style.display = "none";
    setStatus(
      "idle",
      "Gmail detected",
      "Open an email and click Scan to analyse it."
    );
  }
})();
