// Watches Gmail for when an email is opened
const observer = new MutationObserver(() => {
    const emailData = extractEmailFromGmail();
    if (emailData) analyzeEmail(emailData);
});

observer.observe(document.body, { childList: true, subtree: true });

// ─── Extract email content from Gmail DOM ───
function extractEmailFromGmail() {
    // Gmail-specific DOM selectors
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

// ─── Send to your Python backend ───
async function analyzeEmail(emailData) {
    // Remove any existing banner
    document.getElementById('phishing-banner')?.remove();

    try {
        const response = await fetch('http://localhost:8000/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(emailData)
        });

        const result = await response.json();
        showBanner(result);

    } catch (err) {
        console.error('Phishing detector backend not reachable:', err);
    }
}

// ─── Show result banner inside Gmail ───
function showBanner(result) {
    const banner = document.createElement('div');
    banner.id = 'phishing-banner';

    const isPhishing = result.label === 'PHISHING';

    banner.innerHTML = `
        <div class="ph-banner ${isPhishing ? 'ph-danger' : 'ph-safe'}">
            <span class="ph-icon">${isPhishing ? '🚨' : '✅'}</span>
            <div class="ph-content">
                <strong>${isPhishing ? 'Phishing Detected!' : 'Email looks safe'}</strong>
                <span>Confidence: ${(result.confidence * 100).toFixed(1)}%</span>
                ${isPhishing ? `<ul>${result.reasons.map(r => `<li>${r}</li>`).join('')}</ul>` : ''}
            </div>
            <button onclick="this.parentElement.parentElement.remove()">✕</button>
        </div>
    `;

    // Insert banner at top of email
    const emailContainer = document.querySelector('div.nH.hx');
    emailContainer?.prepend(banner);
}