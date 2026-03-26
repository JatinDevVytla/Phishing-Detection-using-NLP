// ─── Listen for messages from popup.js ───
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extractEmail") {
    const emailData = extractEmailFromGmail();
    sendResponse(emailData || null);
  }
  return true; // keep channel open for async response
});

// ─── Extract email content from Gmail DOM ───
function extractEmailFromGmail() {
  const subjectEl = document.querySelector('h2[data-thread-perm-id]');
  const bodyEl    = document.querySelector('div.a3s.aiL');
  const senderEl  = document.querySelector('span.gD');
  const urlEls    = document.querySelectorAll('div.a3s a[href]');

  if (!bodyEl) return null;

  return {
    subject: subjectEl?.innerText || '',
    body:    bodyEl.innerText,
    sender:  senderEl?.getAttribute('email') || '',
    urls:    [...urlEls].map(a => a.href)
  };
}

// ─── Show result banner inside Gmail ───
function showBanner(result) {
  document.getElementById('phishing-banner')?.remove();

  const banner = document.createElement('div');
  banner.id = 'phishing-banner';

  const isPhishing = result.label === 'PHISHING';

  banner.innerHTML = `
    <div class="ph-banner ${isPhishing ? 'ph-danger' : 'ph-safe'}">
      <span class="ph-icon">${isPhishing ? '🚨' : '✅'}</span>
      <div class="ph-content">
        <strong>${isPhishing ? 'Phishing Detected!' : 'Email looks safe'}</strong>
        <span>Confidence: ${(result.confidence * 100).toFixed(1)}%</span>
        ${isPhishing && result.reasons.length ? 
          `<ul>${result.reasons.map(r => `<li>${r}</li>`).join('')}</ul>` : ''}
      </div>
      <button onclick="this.parentElement.parentElement.remove()" 
              style="background:none;border:none;cursor:pointer;font-size:16px;margin-left:auto;">✕</button>
    </div>
  `;

  const emailContainer = document.querySelector('div.nH.hx');
  if (emailContainer) emailContainer.prepend(banner);
}
