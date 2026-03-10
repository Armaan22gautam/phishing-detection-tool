/* ====================================
   PhishGuard — Analysis Engine & UI
   ==================================== */

// ===== Background Particles =====
(function initParticles() {
    const container = document.getElementById('bg-particles');
    const colors = ['rgba(0,240,255,0.15)', 'rgba(139,92,246,0.12)', 'rgba(236,72,153,0.08)'];
    for (let i = 0; i < 30; i++) {
        const p = document.createElement('div');
        p.className = 'particle';
        const size = Math.random() * 4 + 2;
        p.style.width = size + 'px';
        p.style.height = size + 'px';
        p.style.left = Math.random() * 100 + '%';
        p.style.background = colors[Math.floor(Math.random() * colors.length)];
        p.style.animationDuration = (Math.random() * 15 + 10) + 's';
        p.style.animationDelay = (Math.random() * 10) + 's';
        container.appendChild(p);
    }
})();

// ===== DOM References =====
const tabUrl = document.getElementById('tab-url');
const tabEmail = document.getElementById('tab-email');
const tabIndicator = document.getElementById('tab-indicator');
const panelUrl = document.getElementById('panel-url');
const panelEmail = document.getElementById('panel-email');
const urlInput = document.getElementById('url-input');
const emailInput = document.getElementById('email-input');
const urlScanBtn = document.getElementById('url-scan-btn');
const emailScanBtn = document.getElementById('email-scan-btn');
const scanningOverlay = document.getElementById('scanning-overlay');
const resultsSection = document.getElementById('results-section');
const gaugeFill = document.getElementById('gauge-fill');
const gaugeScore = document.getElementById('gauge-score');
const riskBadge = document.getElementById('risk-badge');
const riskIcon = document.getElementById('risk-icon');
const riskText = document.getElementById('risk-text');
const resultsVerdict = document.getElementById('results-verdict');
const statIndicators = document.getElementById('stat-indicators');
const statCritical = document.getElementById('stat-critical');
const statWarnings = document.getElementById('stat-warnings');
const findingsList = document.getElementById('findings-list');
const historyList = document.getElementById('history-list');
const historyEmpty = document.getElementById('history-empty');
const clearHistoryBtn = document.getElementById('clear-history');
const loadSampleBtn = document.getElementById('load-sample-email');
const navScanner = document.getElementById('nav-scanner');
const navHistory = document.getElementById('nav-history');

// ===== Tab Switching =====
tabUrl.addEventListener('click', () => switchTab('url'));
tabEmail.addEventListener('click', () => switchTab('email'));

function switchTab(tab) {
    tabUrl.classList.toggle('active', tab === 'url');
    tabEmail.classList.toggle('active', tab === 'email');
    tabIndicator.classList.toggle('right', tab === 'email');
    panelUrl.classList.toggle('active', tab === 'url');
    panelEmail.classList.toggle('active', tab === 'email');
    resultsSection.classList.add('hidden');
    scanningOverlay.classList.add('hidden');
}

// ===== Quick Test Buttons =====
document.querySelectorAll('.quick-btn[data-url]').forEach(btn => {
    btn.addEventListener('click', () => {
        urlInput.value = btn.dataset.url;
        urlInput.focus();
    });
});

// ===== Sample Phishing Email =====
const samplePhishingEmail = `Subject: URGENT: Your Account Has Been Compromised!

Dear Valued Customer,

We have detected unauthorized access to your PayPal account from an unrecognized device. Your account has been temporarily limited and will be SUSPENDED within 24 hours unless you take immediate action.

CLICK HERE to verify your identity: http://paypa1-secure.tk/verify?user=you

You must provide the following to restore access:
- Full Name
- Social Security Number
- Credit Card Number
- Bank Account Details
- Password

WARNING: Failure to act NOW will result in permanent account closure and loss of funds!

This is your LAST CHANCE to secure your account. Act immediately!

Regards,
PayPal Security Team
paypal-support@secure-notifications.buzz`;

loadSampleBtn.addEventListener('click', () => {
    emailInput.value = samplePhishingEmail;
    emailInput.focus();
});

// ===== Scan Handlers =====
urlScanBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (!url) { urlInput.focus(); return; }
    runScan('url', url);
});

urlInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') urlScanBtn.click();
});

emailScanBtn.addEventListener('click', () => {
    const text = emailInput.value.trim();
    if (!text) { emailInput.focus(); return; }
    runScan('email', text);
});

async function runScan(type, input) {
    // Show scanning animation
    resultsSection.classList.add('hidden');
    scanningOverlay.classList.remove('hidden');

    // Simulate analysis delay for UX
    await sleep(1200 + Math.random() * 800);

    // Run analysis
    const findings = type === 'url' ? analyzeUrl(input) : analyzeEmail(input);
    const score = calculateScore(findings);
    const riskLevel = getRiskLevel(score);

    // Save to history
    saveToHistory(type, input, score, riskLevel, findings);

    // Hide scanning, show results
    scanningOverlay.classList.add('hidden');
    displayResults(score, riskLevel, findings);
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ===================================================================
//                       URL ANALYSIS ENGINE
// ===================================================================
function analyzeUrl(url) {
    const findings = [];
    let normalized = url.trim();

    // Ensure protocol for parsing
    if (!/^https?:\/\//i.test(normalized)) {
        normalized = 'http://' + normalized;
    }

    let parsed;
    try { parsed = new URL(normalized); } catch {
        findings.push({ severity: 'warning', label: 'Invalid URL Format', desc: 'The URL could not be parsed. This may indicate obfuscation or a malformed link.', weight: 10 });
        return findings;
    }

    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = normalized.toLowerCase();
    const path = parsed.pathname.toLowerCase();

    // 1. IP Address in URL
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        findings.push({ severity: 'critical', label: 'IP Address Instead of Domain', desc: `The URL uses a raw IP address (${hostname}) instead of a domain name. Legitimate services rarely do this.`, weight: 25 });
    }

    // 2. No HTTPS
    if (parsed.protocol === 'http:') {
        findings.push({ severity: 'warning', label: 'No HTTPS Encryption', desc: 'The URL uses HTTP instead of HTTPS. Sensitive data sent over this connection is not encrypted.', weight: 10 });
    }

    // 3. Suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.zip', '.top', '.xyz', '.club', '.work', '.click', '.link', '.info', '.icu', '.monster'];
    const tld = '.' + hostname.split('.').pop();
    if (suspiciousTLDs.includes(tld)) {
        findings.push({ severity: 'critical', label: 'Suspicious Top-Level Domain', desc: `The domain uses "${tld}" which is heavily associated with phishing and spam campaigns.`, weight: 20 });
    }

    // 4. Typosquatting detection
    const typosquatPatterns = [
        { pattern: /paypa[l1]/i, brand: 'PayPal' },
        { pattern: /g[o0]{2}gle/i, brand: 'Google' },
        { pattern: /micros[o0]ft/i, brand: 'Microsoft' },
        { pattern: /amaz[o0]n/i, brand: 'Amazon' },
        { pattern: /app[l1]e/i, brand: 'Apple' },
        { pattern: /netf[l1]ix/i, brand: 'Netflix' },
        { pattern: /faceb[o0]{2}k/i, brand: 'Facebook' },
        { pattern: /instag[r]?am/i, brand: 'Instagram' },
        { pattern: /dr[o0]pb[o0]x/i, brand: 'Dropbox' },
        { pattern: /[l1]inkedin/i, brand: 'LinkedIn' }
    ];

    // Check if it's NOT the actual domain
    const knownDomains = ['paypal.com', 'google.com', 'microsoft.com', 'amazon.com', 'apple.com', 'netflix.com', 'facebook.com', 'instagram.com', 'dropbox.com', 'linkedin.com'];
    const isRealDomain = knownDomains.some(d => hostname === d || hostname.endsWith('.' + d));

    if (!isRealDomain) {
        for (const { pattern, brand } of typosquatPatterns) {
            if (pattern.test(hostname)) {
                findings.push({ severity: 'critical', label: `Possible ${brand} Impersonation`, desc: `The domain "${hostname}" resembles ${brand} but is not an official ${brand} domain. This is a common typosquatting technique.`, weight: 25 });
                break;
            }
        }
    }

    // 5. URL Shorteners
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'bl.ink', 'short.io'];
    if (shorteners.some(s => hostname === s || hostname.endsWith('.' + s))) {
        findings.push({ severity: 'warning', label: 'URL Shortener Detected', desc: 'Shortened URLs hide the true destination and are often used to mask malicious links.', weight: 12 });
    }

    // 6. Excessive Subdomains
    const subdomainParts = hostname.split('.');
    if (subdomainParts.length > 4) {
        findings.push({ severity: 'warning', label: 'Excessive Subdomains', desc: `The URL has ${subdomainParts.length} domain levels ("${hostname}"). Attackers use deep subdomains to bury the real domain.`, weight: 12 });
    }

    // 7. @ symbol in URL
    if (fullUrl.includes('@')) {
        findings.push({ severity: 'critical', label: '@ Symbol in URL', desc: 'The "@" symbol in a URL can trick browsers into ignoring everything before it, redirecting to a different domain.', weight: 22 });
    }

    // 8. Punycode / Homograph Attack
    if (hostname.startsWith('xn--')) {
        findings.push({ severity: 'critical', label: 'Punycode / Homograph Attack', desc: 'The domain uses internationalized characters (punycode) that can visually mimic legitimate domains using look-alike characters.', weight: 25 });
    }

    // 9. Suspicious path keywords
    const suspiciousPathWords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'password', 'credential', 'authenticate', 'wallet', 'billing'];
    const foundPathWords = suspiciousPathWords.filter(w => path.includes(w));
    if (foundPathWords.length >= 2) {
        findings.push({ severity: 'warning', label: 'Suspicious Path Keywords', desc: `The URL path contains security-related words (${foundPathWords.join(', ')}), commonly used in phishing pages.`, weight: 10 });
    } else if (foundPathWords.length === 1) {
        findings.push({ severity: 'info', label: 'Security Keyword in Path', desc: `The URL path contains "${foundPathWords[0]}", which can be legitimate but is also common in phishing.`, weight: 5 });
    }

    // 10. Encoded/obfuscated characters
    const encodedCount = (fullUrl.match(/%[0-9a-f]{2}/gi) || []).length;
    if (encodedCount > 3) {
        findings.push({ severity: 'warning', label: 'URL Obfuscation Detected', desc: `The URL contains ${encodedCount} encoded characters, which may hide the true destination.`, weight: 12 });
    }

    // 11. Long URL
    if (fullUrl.length > 150) {
        findings.push({ severity: 'info', label: 'Unusually Long URL', desc: `The URL is ${fullUrl.length} characters long. Extra-long URLs are sometimes used to push the real domain out of view.`, weight: 5 });
    }

    // 12. Suspicious Query Parameters
    const sensitiveParams = ['password', 'passwd', 'ssn', 'creditcard', 'credit_card', 'cc_number', 'cardnumber', 'pin', 'secret'];
    const queryParams = parsed.search.toLowerCase();
    const foundParams = sensitiveParams.filter(p => queryParams.includes(p));
    if (foundParams.length > 0) {
        findings.push({ severity: 'critical', label: 'Sensitive Data in URL Parameters', desc: `The URL query contains sensitive parameter names (${foundParams.join(', ')}). Legitimate services never pass credentials via URL.`, weight: 22 });
    }

    // 13. Hyphen-heavy domain
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
        findings.push({ severity: 'warning', label: 'Hyphen-Heavy Domain', desc: `The domain contains ${hyphenCount} hyphens, which is unusual for legitimate domains and common in phishing.`, weight: 8 });
    }

    // 14. Number-heavy domain
    const digitCount = (hostname.replace(/\./g, '').match(/\d/g) || []).length;
    const letterCount = (hostname.replace(/\./g, '').match(/[a-z]/gi) || []).length;
    if (letterCount > 0 && digitCount / letterCount > 0.4) {
        findings.push({ severity: 'info', label: 'Number-Heavy Domain', desc: 'The domain contains a high ratio of numbers to letters, which is unusual for legitimate websites.', weight: 5 });
    }

    // If nothing found, mark as clean
    if (findings.length === 0) {
        findings.push({ severity: 'safe', label: 'No Threats Detected', desc: 'No known phishing indicators were found in this URL. However, always exercise caution with unfamiliar links.', weight: 0 });
    }

    return findings;
}

// ===================================================================
//                      EMAIL ANALYSIS ENGINE
// ===================================================================
function analyzeEmail(text) {
    const findings = [];
    const lower = text.toLowerCase();
    const words = lower.split(/\s+/);

    // 1. Urgency Indicators
    const urgencyPhrases = [
        'act now', 'immediately', 'urgent', 'right away', 'as soon as possible',
        'within 24 hours', 'within 48 hours', 'expire', 'expiring', 'time is running out',
        'don\'t delay', 'hurry', 'limited time', 'only today', 'last chance',
        'final warning', 'final notice', 'respond immediately', 'action required'
    ];
    const foundUrgency = urgencyPhrases.filter(p => lower.includes(p));
    if (foundUrgency.length >= 3) {
        findings.push({ severity: 'critical', label: 'Extreme Urgency Pressure', desc: `Multiple urgency phrases detected (${foundUrgency.slice(0, 4).join(', ')}). Phishing emails create panic to prevent rational thinking.`, weight: 22 });
    } else if (foundUrgency.length >= 1) {
        findings.push({ severity: 'warning', label: 'Urgency Language Detected', desc: `Found urgency phrase(s): "${foundUrgency.join('", "')}". Phishing often pushes victims to act without thinking.`, weight: 12 });
    }

    // 2. Threat / Fear Language
    const threatPhrases = [
        'unauthorized access', 'suspicious activity', 'compromised', 'locked',
        'suspended', 'terminated', 'disabled', 'restricted', 'permanently closed',
        'legal action', 'law enforcement', 'arrest', 'penalty', 'violation',
        'loss of funds', 'account closure', 'will be deleted'
    ];
    const foundThreats = threatPhrases.filter(p => lower.includes(p));
    if (foundThreats.length >= 2) {
        findings.push({ severity: 'critical', label: 'Threatening Language', desc: `Multiple threat phrases found (${foundThreats.slice(0, 3).join(', ')}). Phishing emails use fear to manipulate victims.`, weight: 20 });
    } else if (foundThreats.length === 1) {
        findings.push({ severity: 'warning', label: 'Threat / Fear Tactic', desc: `Detected threatening language: "${foundThreats[0]}". This is a common social engineering technique.`, weight: 10 });
    }

    // 3. Request for Sensitive Information
    const sensitiveRequests = [
        'password', 'credit card', 'social security', 'ssn', 'bank account',
        'pin number', 'routing number', 'card number', 'cvv', 'security code',
        'date of birth', 'mother\'s maiden', 'full name', 'account number',
        'tax id', 'national id', 'passport number', 'driver\'s license'
    ];
    const foundSensitive = sensitiveRequests.filter(p => lower.includes(p));
    if (foundSensitive.length >= 2) {
        findings.push({ severity: 'critical', label: 'Requests Sensitive Information', desc: `The email asks for sensitive data (${foundSensitive.slice(0, 4).join(', ')}). Legitimate organizations NEVER request this via email.`, weight: 25 });
    } else if (foundSensitive.length === 1) {
        findings.push({ severity: 'critical', label: 'Sensitive Data Request', desc: `The email mentions "${foundSensitive[0]}". Be extremely cautious — legitimate services do not ask for this information via email.`, weight: 18 });
    }

    // 4. Generic Greetings
    const genericGreetings = ['dear customer', 'dear user', 'dear valued customer', 'dear account holder', 'dear sir', 'dear madam', 'dear member', 'valued member'];
    const foundGeneric = genericGreetings.filter(g => lower.includes(g));
    if (foundGeneric.length > 0) {
        findings.push({ severity: 'warning', label: 'Generic Greeting', desc: `The email uses "${foundGeneric[0]}" instead of your name. Legitimate services usually address you by name.`, weight: 8 });
    }

    // 5. Brand Impersonation
    const brands = [
        { name: 'PayPal', pattern: /paypal/i },
        { name: 'Apple', pattern: /\bapple\b/i },
        { name: 'Microsoft', pattern: /microsoft/i },
        { name: 'Amazon', pattern: /amazon/i },
        { name: 'Netflix', pattern: /netflix/i },
        { name: 'Google', pattern: /google/i },
        { name: 'Bank of America', pattern: /bank of america/i },
        { name: 'Chase', pattern: /\bchase\b/i },
        { name: 'Wells Fargo', pattern: /wells fargo/i },
        { name: 'IRS', pattern: /\birs\b/i },
        { name: 'Meta / Facebook', pattern: /\b(facebook|meta)\b/i }
    ];
    const impersonated = brands.filter(b => b.pattern.test(text));
    if (impersonated.length > 0 && (foundUrgency.length > 0 || foundThreats.length > 0 || foundSensitive.length > 0)) {
        findings.push({ severity: 'critical', label: `Possible ${impersonated[0].name} Impersonation`, desc: `The email references ${impersonated.map(b => b.name).join(', ')} alongside suspicious patterns. This is a strong phishing indicator.`, weight: 20 });
    } else if (impersonated.length > 0) {
        findings.push({ severity: 'info', label: `References ${impersonated[0].name}`, desc: `The email mentions ${impersonated.map(b => b.name).join(', ')}. Verify the sender is legitimate before taking any action.`, weight: 3 });
    }

    // 6. Suspicious Links in Email
    const urlPattern = /https?:\/\/[^\s<>"]+/gi;
    const foundUrls = text.match(urlPattern) || [];
    let suspiciousLinkCount = 0;
    for (const u of foundUrls) {
        const urlFindings = analyzeUrl(u);
        const hasThreat = urlFindings.some(f => f.severity === 'critical' || f.severity === 'warning');
        if (hasThreat) suspiciousLinkCount++;
    }
    if (suspiciousLinkCount > 0) {
        findings.push({ severity: 'critical', label: 'Suspicious Links in Email', desc: `Found ${suspiciousLinkCount} suspicious link(s) embedded in the email. These links show phishing indicators.`, weight: 20 });
    }

    // 7. "Click Here" patterns
    const clickPatterns = ['click here', 'click below', 'click the link', 'click this link', 'follow this link', 'click immediately', 'tap here'];
    const foundClicks = clickPatterns.filter(c => lower.includes(c));
    if (foundClicks.length > 0) {
        findings.push({ severity: 'warning', label: '"Click Here" Call-to-Action', desc: 'The email uses generic "click here" language instead of describing where the link leads, which is common in phishing.', weight: 8 });
    }

    // 8. Excessive Capitalization / Exclamation
    const capsWords = words.filter(w => w.length > 3 && w === w.toUpperCase() && /[A-Z]/.test(w));
    const exclamationCount = (text.match(/!/g) || []).length;
    if (capsWords.length >= 5 || exclamationCount >= 5) {
        findings.push({ severity: 'warning', label: 'Excessive Emphasis', desc: `The email uses ${capsWords.length} ALL-CAPS words and ${exclamationCount} exclamation marks. This aggressive formatting is typical of phishing.`, weight: 8 });
    }

    // 9. Suspicious Sender Patterns
    const senderPatterns = [
        /support@.*\.(tk|ml|ga|cf|buzz|zip|top)$/i,
        /noreply.*security/i,
        /secure.*notification/i,
        /account.*verify/i
    ];
    for (const sp of senderPatterns) {
        if (sp.test(text)) {
            findings.push({ severity: 'warning', label: 'Suspicious Sender Pattern', desc: 'The email contains sender address patterns commonly used in phishing campaigns (e.g., suspicious domain or keyword combinations).', weight: 10 });
            break;
        }
    }

    // 10. Spelling / Grammar Red Flags
    const grammarFlags = ['kindly', 'do the needful', 'revert back', 'kindly check', 'dear sir/madam', 'yours faithfully'];
    const foundGrammar = grammarFlags.filter(g => lower.includes(g));
    if (foundGrammar.length >= 2) {
        findings.push({ severity: 'info', label: 'Unusual Phrasing', desc: `Detected unusual phrases (${foundGrammar.join(', ')}), which may indicate a non-native or auto-generated phishing email.`, weight: 5 });
    }

    // 11. Reward / Prize Bait
    const rewardPhrases = ['you have won', 'congratulations', 'you\'ve been selected', 'lottery', 'prize', 'inheritance', 'million dollars', 'claim your'];
    const foundRewards = rewardPhrases.filter(r => lower.includes(r));
    if (foundRewards.length > 0) {
        findings.push({ severity: 'critical', label: 'Prize / Reward Bait', desc: `The email contains prize/reward language ("${foundRewards.join('", "')}"). This is an extremely common scam tactic.`, weight: 20 });
    }

    // If nothing found
    if (findings.length === 0) {
        findings.push({ severity: 'safe', label: 'No Phishing Indicators Detected', desc: 'No known phishing patterns were found in this email. Always verify the sender before acting on any requests.', weight: 0 });
    }

    return findings;
}

// ===================================================================
//                       SCORING & DISPLAY
// ===================================================================
function calculateScore(findings) {
    const totalWeight = findings.reduce((sum, f) => sum + f.weight, 0);
    return Math.min(100, totalWeight);
}

function getRiskLevel(score) {
    if (score <= 5) return { level: 'safe', label: 'Safe', icon: '🛡️', verdict: 'This appears to be safe. No significant phishing indicators were detected.' };
    if (score <= 20) return { level: 'low', label: 'Low Risk', icon: '✅', verdict: 'Minor indicators detected. Likely safe, but stay vigilant.' };
    if (score <= 45) return { level: 'medium', label: 'Medium Risk', icon: '⚠️', verdict: 'Several suspicious patterns found. Exercise caution and verify legitimacy before proceeding.' };
    if (score <= 70) return { level: 'high', label: 'High Risk', icon: '🚨', verdict: 'Multiple phishing indicators detected. This is very likely a phishing attempt — do not click links or provide any information!' };
    return { level: 'critical', label: 'Critical Threat', icon: '☠️', verdict: 'Extreme phishing indicators across multiple categories. This is almost certainly a phishing attack. Do NOT interact with this content!' };
}

function displayResults(score, risk, findings) {
    resultsSection.classList.remove('hidden');

    // Animate gauge
    const circumference = 2 * Math.PI * 70; // r=70
    const offset = circumference - (score / 100) * circumference;
    gaugeFill.style.strokeDasharray = circumference;
    gaugeFill.style.strokeDashoffset = circumference;

    // Color based on risk
    const colors = { safe: '#34d399', low: '#fbbf24', medium: '#fb923c', high: '#ef4444', critical: '#ec4899' };
    gaugeFill.style.stroke = colors[risk.level];

    requestAnimationFrame(() => {
        gaugeFill.style.strokeDashoffset = offset;
    });

    // Animate score counter
    animateCounter(gaugeScore, 0, score, 1200);

    // Risk badge
    riskBadge.className = 'risk-badge ' + risk.level;
    riskIcon.textContent = risk.icon;
    riskText.textContent = risk.label;
    resultsVerdict.textContent = risk.verdict;

    // Stats
    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const warningCount = findings.filter(f => f.severity === 'warning').length;
    statIndicators.textContent = findings.length;
    statCritical.textContent = criticalCount;
    statCritical.style.color = criticalCount > 0 ? colors.high : '';
    statWarnings.textContent = warningCount;
    statWarnings.style.color = warningCount > 0 ? colors.medium : '';

    // Render findings
    findingsList.innerHTML = '';
    findings.sort((a, b) => {
        const order = { critical: 0, warning: 1, info: 2, safe: 3 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });
    findings.forEach((f, i) => {
        const icons = { critical: '🔴', warning: '🟡', info: '🔵', safe: '🟢' };
        const severityLabels = { critical: 'Critical', warning: 'Warning', info: 'Info', safe: 'Safe' };
        const el = document.createElement('div');
        el.className = 'finding-item';
        el.style.animationDelay = `${i * 0.08}s`;
        el.innerHTML = `
            <div class="finding-icon ${f.severity}">${icons[f.severity] || '🔵'}</div>
            <div class="finding-content">
                <div class="finding-label">
                    ${f.label}
                    <span class="finding-severity ${f.severity}">${severityLabels[f.severity] || f.severity}</span>
                </div>
                <p class="finding-desc">${f.desc}</p>
            </div>
        `;
        findingsList.appendChild(el);
    });

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function animateCounter(el, start, end, duration) {
    const startTime = performance.now();
    function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(start + (end - start) * eased);
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

// ===================================================================
//                       HISTORY MANAGEMENT
// ===================================================================
function loadHistory() {
    const history = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
    renderHistory(history);
}

function saveToHistory(type, input, score, risk, findings) {
    const history = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
    history.unshift({
        type,
        input: type === 'url' ? input : input.substring(0, 100) + (input.length > 100 ? '...' : ''),
        score,
        level: risk.level,
        label: risk.label,
        findingsCount: findings.length,
        timestamp: new Date().toISOString()
    });
    // Keep max 20
    if (history.length > 20) history.length = 20;
    localStorage.setItem('phishguard_history', JSON.stringify(history));
    renderHistory(history);
}

function renderHistory(history) {
    // Clear existing items (keep empty state)
    historyList.querySelectorAll('.history-item').forEach(el => el.remove());

    if (history.length === 0) {
        historyEmpty.style.display = 'flex';
        return;
    }
    historyEmpty.style.display = 'none';

    history.forEach(item => {
        const el = document.createElement('div');
        el.className = 'history-item';
        const date = new Date(item.timestamp);
        const timeStr = date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' · ' + date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
        el.innerHTML = `
            <div class="history-type-icon ${item.type}">${item.type === 'url' ? '🔗' : '📧'}</div>
            <div class="history-info">
                <div class="history-target">${escapeHtml(item.input)}</div>
                <div class="history-meta">${item.type === 'url' ? 'URL Scan' : 'Email Analysis'} · ${timeStr} · ${item.findingsCount} indicator${item.findingsCount !== 1 ? 's' : ''}</div>
            </div>
            <div class="history-score ${item.level}">${item.score}</div>
        `;
        historyList.appendChild(el);
    });
}

clearHistoryBtn.addEventListener('click', () => {
    localStorage.removeItem('phishguard_history');
    renderHistory([]);
});

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ===== Nav Links =====
navScanner.addEventListener('click', e => {
    e.preventDefault();
    navScanner.classList.add('active');
    navHistory.classList.remove('active');
    document.getElementById('scanner').scrollIntoView({ behavior: 'smooth' });
});

navHistory.addEventListener('click', e => {
    e.preventDefault();
    navHistory.classList.add('active');
    navScanner.classList.remove('active');
    document.getElementById('history').scrollIntoView({ behavior: 'smooth' });
});

// ===== Init =====
loadHistory();
