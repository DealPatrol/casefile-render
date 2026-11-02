const input = document.querySelector('#messageInput');
const analyzeButton = document.querySelector('#analyzeButton');
const resultsPanel = document.querySelector('#resultsPanel');
const emptyState = document.querySelector('#emptyState');
const resultsContent = document.querySelector('#resultsContent');
let lastReport = null;

const rules = [
  { id: 'urgency', label: 'Urgency or threat', weight: 15, patterns: [/act now/i, /immediately/i, /urgent/i, /final warning/i, /within \d+ (?:minutes?|hours?)/i, /account (?:will be )?(?:closed|suspended|locked)/i, /arrest warrant/i] },
  { id: 'payment', label: 'Unusual payment request', weight: 24, patterns: [/gift cards?/i, /bitcoin|crypto(?:currency)?/i, /wire transfer/i, /western union/i, /cash app|venmo|zelle/i, /processing fee/i, /pay a fee/i] },
  { id: 'credentials', label: 'Credential or code request', weight: 27, patterns: [/password/i, /passcode/i, /one[- ]time (?:code|password)/i, /verification code/i, /login (?:here|now)/i, /social security/i, /bank account/i, /routing number/i, /seed phrase/i] },
  { id: 'impersonation', label: 'Impersonation language', weight: 16, patterns: [/this is (?:the )?(?:irs|police|sheriff|fbi|support)/i, /from (?:amazon|microsoft|apple|paypal|your bank)/i, /your (?:boss|manager|ceo)/i, /family emergency/i, /package (?:is )?(?:held|undeliverable)/i] },
  { id: 'secrecy', label: 'Secrecy or isolation', weight: 17, patterns: [/do not tell/i, /keep this (?:private|secret)/i, /don't contact/i, /stay on the (?:line|phone)/i, /only communicate/i] },
  { id: 'remote', label: 'Remote access request', weight: 24, patterns: [/anydesk/i, /teamviewer/i, /remote access/i, /screen share/i, /install (?:this|the) app/i] },
  { id: 'reward', label: 'Prize or easy-money promise', weight: 13, patterns: [/you (?:have )?won/i, /claim your (?:prize|reward)/i, /guaranteed return/i, /easy money/i, /inheritance/i, /lottery/i] }
];

const example = `URGENT: This is Microsoft Security. Your account will be suspended within 30 minutes because of suspicious activity. Verify your password and one-time code at http://microsoft-security-check.example/login. Do not contact support or tell anyone while we fix this.`;

function extractUrls(text) {
  return [...text.matchAll(/(?:https?:\/\/|www\.)[^\s<>"']+/gi)].map(match => match[0].replace(/[),.;]+$/, ''));
}

function inspectUrl(rawUrl) {
  const result = { url: rawUrl, reasons: [], points: 0 };
  try {
    const normalized = rawUrl.startsWith('www.') ? `https://${rawUrl}` : rawUrl;
    const url = new URL(normalized);
    const host = url.hostname.toLowerCase();
    if (url.protocol !== 'https:') { result.points += 10; result.reasons.push('not HTTPS'); }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) { result.points += 18; result.reasons.push('raw IP address'); }
    if (host.includes('xn--')) { result.points += 17; result.reasons.push('lookalike characters'); }
    if ((host.match(/-/g) || []).length >= 3) { result.points += 8; result.reasons.push('many hyphens'); }
    if (host.split('.').length > 4) { result.points += 8; result.reasons.push('many subdomains'); }
    if (/(login|verify|secure|account|wallet|support)/i.test(url.pathname + url.search) && !/(google\.com|microsoft\.com|apple\.com|amazon\.com|paypal\.com)$/i.test(host)) {
      result.points += 13; result.reasons.push('sensitive-action path');
    }
  } catch {
    result.points += 12; result.reasons.push('malformed URL');
  }
  return result;
}

function analyze(text) {
  const signals = [];
  let score = 0;
  for (const rule of rules) {
    const matches = rule.patterns.filter(pattern => pattern.test(text)).length;
    if (matches) {
      const points = Math.min(rule.weight + Math.max(0, matches - 1) * 3, rule.weight + 8);
      score += points;
      signals.push({ id: rule.id, label: rule.label, points });
    }
  }
  const urls = extractUrls(text).map(inspectUrl);
  const urlPoints = Math.min(27, urls.reduce((sum, item) => sum + item.points, 0));
  if (urls.length) {
    score += 5 + urlPoints;
    signals.push({ id: 'links', label: urls.some(url => url.points > 0) ? 'Potentially risky link' : 'Contains external link', points: 5 + urlPoints });
  }
  if (/\b(?:kindly|dear customer|valued customer)\b/i.test(text) && /(?:click|pay|verify|account)/i.test(text)) {
    score += 7;
    signals.push({ id: 'generic', label: 'Generic scripted wording', points: 7 });
  }
  score = Math.min(100, score);
  let level = 'low';
  if (score >= 70) level = 'critical';
  else if (score >= 45) level = 'high';
  else if (score >= 20) level = 'caution';
  return { createdAt: new Date().toISOString(), score, level, signals, urls, messageLength: text.length };
}

const levelInfo = {
  low: { badge: 'Low signal', title: 'Low detected risk', color: 'var(--green)', summary: 'Few common scam patterns were detected. Stay cautious if the request is unexpected.' },
  caution: { badge: 'Use caution', title: 'Caution recommended', color: 'var(--amber)', summary: 'The message contains pressure or request patterns worth independently verifying.' },
  high: { badge: 'High risk', title: 'Likely unsafe', color: '#ff966e', summary: 'Several strong scam signals appear together. Do not use its links or contact details.' },
  critical: { badge: 'Critical risk', title: 'Strong scam pattern', color: 'var(--red)', summary: 'This combines high-risk tactics commonly used for fraud or account takeover.' }
};

function nextStepsFor(report) {
  const steps = ['Do not click links or download attachments from the message.', 'Contact the person or organization through an independently verified channel.'];
  if (report.signals.some(signal => signal.id === 'credentials')) steps.push('Do not share passwords or one-time codes. Change credentials if you already did.');
  if (report.signals.some(signal => signal.id === 'payment')) steps.push('Stop any payment. Contact the payment provider immediately if money was sent.');
  if (report.signals.some(signal => signal.id === 'remote')) steps.push('Do not install remote-access software. Disconnect the device if access was granted.');
  if (report.score >= 45) steps.push('Save evidence, block the sender, and report the account on the service used.');
  return steps;
}

function verificationNote(report) {
  if (report.signals.some(signal => signal.id === 'impersonation')) return 'I received a message claiming to be from you. I will not use the contact information or links in that message. I am contacting you through this independently verified channel to confirm whether the request is genuine.';
  return 'I received an unexpected request and am verifying it separately. Please confirm the request through an official channel without asking me to share a password, verification code, payment, or personal information.';
}

function render(report) {
  lastReport = { ...report, nextSteps: nextStepsFor(report), verificationNote: verificationNote(report) };
  const info = levelInfo[report.level];
  emptyState.hidden = true;
  resultsContent.hidden = false;
  resultsPanel.classList.remove('empty');
  document.querySelector('#riskScore').textContent = report.score;
  document.querySelector('#riskTitle').textContent = info.title;
  document.querySelector('#riskSummary').textContent = info.summary;
  const badge = document.querySelector('#riskBadge');
  badge.textContent = info.badge;
  badge.style.color = info.color;
  badge.style.background = `color-mix(in srgb, ${info.color} 12%, transparent)`;
  badge.style.border = `1px solid color-mix(in srgb, ${info.color} 36%, transparent)`;
  const ring = document.querySelector('#scoreRing');
  ring.style.setProperty('--score', `${Math.max(report.score, 2)}%`);
  ring.style.setProperty('--score-color', info.color);

  const signals = document.querySelector('#signals');
  signals.innerHTML = report.signals.length
    ? report.signals.map(signal => `<span class="signal-chip">${escapeHtml(signal.label)} · +${signal.points}</span>`).join('')
    : '<span class="signal-chip">No common high-risk pattern detected</span>';

  document.querySelector('#nextSteps').innerHTML = lastReport.nextSteps.map(step => `<li>${escapeHtml(step)}</li>`).join('');
  document.querySelector('#verifyText').textContent = lastReport.verificationNote;
  const localAiCard = document.querySelector('#localAiCard');
  localAiCard.hidden = !('LanguageModel' in globalThis);
  resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function escapeHtml(value) {
  return value.replace(/[&<>'"]/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#039;', '"': '&quot;' })[character]);
}

function reportText() {
  if (!lastReport) return '';
  return `SignalShield private risk report\nRisk: ${lastReport.score}/100 (${lastReport.level})\nSignals: ${lastReport.signals.map(item => item.label).join(', ') || 'No common high-risk pattern detected'}\n\nSafer next steps:\n${lastReport.nextSteps.map(step => `- ${step}`).join('\n')}\n\nVerification note:\n${lastReport.verificationNote}\n\nThis is an automated second opinion, not a guarantee.`;
}

async function copy(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    const original = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = original; }, 1400);
  } catch { window.prompt('Copy this text:', value); }
}

input.addEventListener('input', () => {
  document.querySelector('#charCount').textContent = `${input.value.length.toLocaleString()} / 12,000`;
  analyzeButton.disabled = !input.value.trim();
});

document.querySelector('#exampleButton').addEventListener('click', () => {
  input.value = example;
  input.dispatchEvent(new Event('input'));
  input.focus();
});

analyzeButton.addEventListener('click', () => {
  const text = input.value.trim();
  if (text) render(analyze(text));
});

document.querySelector('#copyVerifyButton').addEventListener('click', event => copy(lastReport.verificationNote, event.currentTarget));
document.querySelector('#copyReportButton').addEventListener('click', event => copy(reportText(), event.currentTarget));
document.querySelector('#downloadButton').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(lastReport, null, 2)], { type: 'application/json' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `signalshield-report-${new Date().toISOString().slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

document.querySelector('#resetButton').addEventListener('click', () => {
  input.value = '';
  input.dispatchEvent(new Event('input'));
  resultsContent.hidden = true;
  emptyState.hidden = false;
  resultsPanel.classList.add('empty');
  lastReport = null;
  input.focus();
  window.scrollTo({ top: input.offsetTop - 100, behavior: 'smooth' });
});

document.querySelector('#explainButton').addEventListener('click', async event => {
  const output = document.querySelector('#aiExplanation');
  output.hidden = false;
  output.textContent = 'Preparing the on-device model…';
  event.currentTarget.disabled = true;
  try {
    const availability = await globalThis.LanguageModel.availability();
    if (availability === 'unavailable') throw new Error('The local model is unavailable.');
    const session = await globalThis.LanguageModel.create({
      systemPrompt: 'You explain scam warning signs cautiously. Never claim certainty. Do not recommend replying, clicking, paying, or sharing credentials.'
    });
    const prompt = `Explain this private risk report in 120 words or fewer. Score: ${lastReport.score}/100. Signals: ${lastReport.signals.map(item => item.label).join(', ') || 'none'}. Give the two safest next actions.`;
    output.textContent = await session.prompt(prompt);
    session.destroy?.();
  } catch (error) {
    output.textContent = `Local AI was not ready, so the transparent rule-based report remains active. ${error.message}`;
  } finally { event.currentTarget.disabled = false; }
});

analyzeButton.disabled = true;
