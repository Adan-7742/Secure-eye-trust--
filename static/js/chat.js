/**
 * chat.js — Secure Eye Trust+ v5
 * Chat opens as a normal full-page tab from sidebar.
 * No floating overlay, no API key panel in UI.
 *
 * FR05-05 UPDATE:
 *  - Added "🔐 Security policy recommendations" suggestion chip
 *  - Added "🛡 Improve Windows policies" chip
 *  - Added loadPolicyRecommendations() — calls GET /api/chat/policy and
 *    renders a structured, formatted policy panel in the chat area
 *  - Policy chips trigger loadPolicyRecommendations() directly (not a
 *    plain text send) so results are always structured and formatted
 */

let chatHistory  = [];
let chatBusy     = false;
let serverOnline = false;

const SUGGESTIONS = [
  '🏥 System health report',
  '🔴 Top errors summary',
  '🔒 Security events analysis',
  '💾 Any disk issues?',
  '⚡ Recent crashes?',
  '🔑 What is Event ID 4625?',
  '🛠 Service failures?',
  '📊 Anomaly breakdown',
  '🌐 Network security events',
  '⚠ Critical warnings today',
  // FR05-05: policy improvement suggestions
  '🔐 Security policy recommendations',
  '🛡 Improve Windows policies',
];

// FR05-05: policy-specific quick chips shown after policy panel loads
const POLICY_CHIPS = [
  { label: '🔒 Account lockout policy',     text: 'account lockout policy' },
  { label: '🔑 MFA policy',                 text: 'MFA policy' },
  { label: '📋 Audit logging policy',       text: 'audit policy' },
  { label: '🛡 Defender policy',            text: 'Defender policy' },
  { label: '⚡ PowerShell policy',          text: 'PowerShell policy' },
  { label: '🌐 Firewall policy',            text: 'firewall policy' },
  { label: '🔄 Windows Update policy',      text: 'Windows Update policy' },
  { label: '👤 Least privilege policy',     text: 'least privilege policy' },
];


function initChat() {
  buildSuggestions();
  checkChatStatus();
  updateContextStrip();
  const msgs = document.getElementById('chat-messages');
  if (msgs && msgs.children.length === 0) showWelcome();
}

function buildSuggestions() {
  const el = document.getElementById('chat-suggestions');
  if (!el) return;

  el.innerHTML = '';
  SUGGESTIONS.forEach(s => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'chat-suggestion';
    btn.textContent = s;
    btn.addEventListener('click', () => window.openChatAndSend(s));
    el.appendChild(btn);
  });
}

function showWelcome() {
  const c = document.getElementById('chat-messages');
  if (!c) return;
  const d = document.createElement('div');
  d.className = 'chat-welcome';
  d.innerHTML = `
    <div class="chat-welcome-icon">
      <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M16 1 L30 7 L30 19 C30 26 24 31 16 33 C8 31 2 26 2 19 L2 7 Z"
          fill="rgba(26,140,255,.15)" stroke="#4da6ff" stroke-width="1.5"/>
        <rect x="11" y="18" width="10" height="8" rx="2" fill="#1a8cff" opacity=".9"/>
        <path d="M12.5 18 L12.5 14.5 C12.5 12 15.5 12 15.5 14.5 L15.5 18"
          stroke="#7dd3fc" stroke-width="2" stroke-linecap="round" fill="none"/>
        <circle cx="16" cy="22" r="1.4" fill="rgba(10,20,40,.8)"/>
      </svg>
    </div>
    <h2>Secure Eye AI</h2>
    <p>Your intelligent Windows log analyst. Ask anything about security events, application errors, system anomalies, network activity, or <strong>Windows security policy improvements</strong>.</p>
    <p style="margin-top:12px;font-size:11px;color:var(--text-dim)">AI key auto-loaded from .env · Pick a question from the left panel or type below</p>`;
  c.appendChild(d);
}

async function sendMessage(textOverride) {
  if (chatBusy) return;
  const input = document.getElementById('chat-input');
  const text  = (textOverride || input?.value || '').trim();
  if (!text) return;
  if (input) { input.value = ''; autoResize(input); }

  const welcome = document.querySelector('.chat-welcome');
  if (welcome) welcome.remove();

  // FR05-05: route policy queries to the structured policy endpoint
  const isPolicyQuery = /\b(policy|policies|harden|hardening|improve.*security|security.*improve|lockout|mfa|multi.?factor|audit.?log|applocker|whitelist|credential.?guard)\b/i.test(text);
  if (isPolicyQuery) {
    appendBubble('user', esc(text));
    chatHistory.push({ role: 'user', content: text });
    await loadPolicyRecommendations(text);
    return;
  }

  appendBubble('user', esc(text));
  chatHistory.push({ role: 'user', content: text });

  chatBusy = true;
  const btn = document.getElementById('chat-send-btn');
  if (btn) btn.disabled = true;
  const typingEl = showTyping();

  try {
    const res  = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text, history: chatHistory.slice(-8), api_key: '' }),
    });
    const data = await res.json();
    removeTyping(typingEl);
    if (data.error) {
      appendBubble('bot', `❌ ${esc(data.error)}`);
    } else {
      appendBubble('bot', renderMd(data.reply || '(empty)'));
      chatHistory.push({ role: 'assistant', content: data.reply || '' });
      setPillMode(data.online);
      serverOnline = data.online;
      if (data.reply && /critical|breach|attack|malware|ransomware/i.test(data.reply)) {
        window.refreshAlerts?.();
      }
    }
  } catch (e) {
    removeTyping(typingEl);
    appendBubble('bot', '❌ Cannot reach backend. Is <code>python app.py</code> running?');
  } finally {
    chatBusy = false;
    if (btn) btn.disabled = false;
    document.getElementById('chat-input')?.focus();
    if (!document.getElementById('page-chat')?.classList.contains('active')) {
      document.getElementById('chat-unread-dot')?.classList.add('show');
    }
  }
}


// ── FR05-05: Policy recommendations panel ─────────────────────────────────────

/**
 * loadPolicyRecommendations(focusText?)
 *
 * Calls GET /api/chat/policy (or POST with focus area) and renders a
 * structured, colour-coded policy improvement panel directly in the
 * chat message area.
 *
 * This is a dedicated render path — not a plain chat bubble — so that
 * policy output is always consistently formatted regardless of AI availability.
 */
async function loadPolicyRecommendations(focusText = '') {
  if (chatBusy) return;

  const welcome = document.querySelector('.chat-welcome');
  if (welcome) welcome.remove();

  if (focusText && !/policy|policies|harden/i.test(focusText)) {
    appendBubble('user', esc(focusText));
  } else if (!focusText) {
    appendBubble('user', '🔐 Show me Windows security policy recommendations');
  }

  chatBusy = true;
  const btn = document.getElementById('chat-send-btn');
  if (btn) btn.disabled = true;
  const typingEl = showTyping();

  try {
    const body = focusText ? { focus: focusText } : {};
    const res  = await fetch('/api/chat/policy', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const data = await res.json();
    removeTyping(typingEl);

    const html = _renderPolicyPanel(data);
    const bubble = appendBubble('bot', html);

    // Push a summary to history so the AI knows what was shown
    const summaryText = `[Policy recommendations shown — ${(data.recommendations || []).length} recommendations, summary: ${data.summary || ''}]`;
    chatHistory.push({ role: 'assistant', content: summaryText });
    setPillMode(data.online);

  } catch (e) {
    removeTyping(typingEl);
    appendBubble('bot', '❌ Could not load policy recommendations. Is <code>python app.py</code> running?');
  } finally {
    chatBusy = false;
    if (btn) btn.disabled = false;
    document.getElementById('chat-input')?.focus();
  }
}


/**
 * _renderPolicyPanel(data)
 * Converts the /policy JSON response into styled HTML for the chat bubble.
 */
function _renderPolicyPanel(data) {
  const recs    = data.recommendations || [];
  const summary = data.summary || '';
  const online  = data.online;
  const signals = data.signals || {};

  const PRIORITY_COLORS = {
    CRITICAL: { bg: '#2d1a1a', border: '#e24b4a', text: '#f09595', badge: '#e24b4a' },
    HIGH:     { bg: '#2d2010', border: '#EF9F27', text: '#FAC775', badge: '#EF9F27' },
    MEDIUM:   { bg: '#1a2430', border: '#378ADD', text: '#85B7EB', badge: '#378ADD' },
    LOW:      { bg: '#1a2a1a', border: '#639922', text: '#C0DD97', badge: '#639922' },
  };

  const PRIORITY_ICONS = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🔵', LOW: '🟢' };

  let html = `<div style="font-family:var(--font-sans,sans-serif)">`;

  // Header
  html += `<div style="font-size:15px;font-weight:500;margin-bottom:8px">🔐 Windows Security Policy Recommendations</div>`;

  // Mode badge
  const modeBadge = online
    ? `<span style="font-size:11px;background:#1a3d1a;color:#9FE1CB;padding:2px 8px;border-radius:4px">🟢 AI-powered</span>`
    : `<span style="font-size:11px;background:#2a2a1a;color:#FAC775;padding:2px 8px;border-radius:4px">🟡 Offline rules</span>`;
  html += `<div style="margin-bottom:10px">${modeBadge}</div>`;

  // Summary
  if (summary) {
    html += `<div style="font-size:12px;color:var(--text-secondary,#aaa);margin-bottom:14px;padding:8px;background:rgba(255,255,255,.04);border-radius:6px;border-left:3px solid #378ADD">${esc(summary)}</div>`;
  }

  // Signal quick-stats
  const sigKeys = [
    ['failed_logons_total',      'Failed logons'],
    ['account_lockouts',         'Account lockouts'],
    ['defender_disabled_events', 'Defender disabled'],
    ['update_failures',          'Update failures'],
    ['ps_suspicious_commands',   'Suspicious PS cmds'],
  ];
  const nonZeroSigs = sigKeys.filter(([k]) => (signals[k] || 0) > 0);
  if (nonZeroSigs.length) {
    html += `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px">`;
    for (const [k, label] of nonZeroSigs) {
      html += `<div style="font-size:11px;background:#2d1a1a;color:#f09595;padding:3px 8px;border-radius:4px;border:0.5px solid #e24b4a">⚠ ${label}: ${signals[k]}</div>`;
    }
    html += `</div>`;
  }

  // Recommendation cards
  if (recs.length === 0) {
    html += `<div style="font-size:13px;color:var(--text-secondary,#aaa)">No policy gaps detected from current log data.</div>`;
  }

  for (const rec of recs) {
    const p      = rec.priority || 'MEDIUM';
    const colors = PRIORITY_COLORS[p] || PRIORITY_COLORS.MEDIUM;
    const icon   = PRIORITY_ICONS[p] || '●';

    html += `<div style="background:${colors.bg};border:0.5px solid ${colors.border};border-radius:8px;padding:10px 12px;margin-bottom:10px">`;

    // Title row
    html += `<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">`;
    html += `<span style="font-size:11px;font-weight:500;background:${colors.badge};color:#fff;padding:2px 8px;border-radius:4px">${icon} ${p}</span>`;
    html += `<span style="font-size:13px;font-weight:500;color:${colors.text}">${esc(rec.title || '')}</span>`;
    if (rec.effort) {
      html += `<span style="font-size:10px;color:var(--text-dim,#666);margin-left:auto">Effort: ${esc(rec.effort)}</span>`;
    }
    html += `</div>`;

    // Reason
    if (rec.reason) {
      html += `<div style="font-size:12px;color:var(--text-secondary,#aaa);margin-bottom:6px">${esc(rec.reason)}</div>`;
    }

    // Steps
    if (rec.steps && rec.steps.length) {
      html += `<div style="font-size:11px;font-weight:500;color:${colors.text};margin-bottom:4px">Steps:</div>`;
      html += `<ol style="margin:0 0 6px 16px;padding:0;font-size:12px;color:var(--text-secondary,#aaa)">`;
      for (const step of rec.steps) {
        html += `<li style="margin-bottom:3px">${esc(step)}</li>`;
      }
      html += `</ol>`;
    }

    // GPO path
    if (rec.gpo_path && rec.gpo_path !== 'N/A') {
      html += `<div style="font-size:11px;color:var(--text-dim,#666);margin-bottom:4px">📁 <code style="font-size:10px">${esc(rec.gpo_path)}</code></div>`;
    }

    // Command
    if (rec.command && rec.command !== 'N/A') {
      html += `<pre style="background:rgba(0,0,0,.4);padding:6px 8px;border-radius:6px;font-size:10px;overflow-x:auto;margin:4px 0 0;border:0.5px solid ${colors.border}"><code>${esc(rec.command)}</code></pre>`;
    }

    // MITRE
    if (rec.mitre && rec.mitre !== 'N/A') {
      html += `<div style="font-size:10px;color:var(--text-dim,#666);margin-top:4px">MITRE: <code>${esc(rec.mitre)}</code></div>`;
    }

    html += `</div>`;
  }

  // Follow-up policy chips
  html += `<div style="margin-top:10px;font-size:12px;color:var(--text-secondary,#aaa);margin-bottom:6px">Ask about a specific area:</div>`;
  html += `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px">`;
  for (const chip of POLICY_CHIPS) {
    html += `<button onclick="window.openChatAndSend(${JSON.stringify(chip.text)})" style="font-size:11px;padding:4px 10px;border-radius:4px;background:rgba(255,255,255,.06);border:0.5px solid rgba(255,255,255,.15);color:var(--text-secondary,#aaa);cursor:pointer">${chip.label}</button>`;
  }
  html += `</div>`;

  html += `</div>`;
  return html;
}


// ── Standard chat helpers (unchanged) ─────────────────────────────────────────

async function checkChatStatus() {
  try {
    const data = await api('/api/chat/status');
    serverOnline = (data.env_key_set && data.network) || false;
    setPillMode(serverOnline);
  } catch (e) { setPillMode(false); }
}

function setPillMode(online) {
  const pill = document.getElementById('chat-mode-pill');
  if (!pill) return;
  pill.className   = 'chat-mode-pill ' + (online ? 'online' : 'offline');
  pill.textContent = online ? '🟢 AI Online' : '🟡 Offline Mode';
}

async function updateContextStrip() {
  try {
    const ctx   = await api('/api/chat/context');
    const strip = document.getElementById('chat-ctx-strip');
    if (!strip || !ctx.stats) return;
    const chips = Object.entries(ctx.stats).map(([cat, s]) => {
      if (!s) return '';
      const label = cat === 'windows_update' ? 'Win Update'
                  : cat.charAt(0).toUpperCase() + cat.slice(1);
      return `<div class="ctx-chip">
        <span class="ctx-chip-label">${label}</span>
        <span class="ctx-chip-val">${fmt(s.total)}</span>
      </div>`;
    });
    strip.innerHTML = chips.join('') ||
      '<div class="ctx-chip"><span class="ctx-chip-label">No logs — fetch first</span></div>';
  } catch (e) {}
}

function appendBubble(role, html) {
  const c = document.getElementById('chat-messages');
  if (!c) return;
  const d = document.createElement('div');
  d.className = `chat-msg ${role}`;
  d.innerHTML = html;
  c.appendChild(d);
  c.scrollTop = c.scrollHeight;
  return d;
}

function showTyping() {
  const c = document.getElementById('chat-messages');
  if (!c) return;
  const d = document.createElement('div');
  d.className = 'chat-msg typing';
  d.innerHTML = '<div class="typing-dots"><span></span><span></span><span></span></div>';
  c.appendChild(d);
  c.scrollTop = c.scrollHeight;
  return d;
}
function removeTyping(el) { if (el) el.remove(); }

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function renderMd(text) {
  return esc(text)
    .replace(/```[\w]*\n?([\s\S]*?)```/g,
      '<pre style="background:rgba(0,0,0,.4);padding:10px;border-radius:8px;font-size:11px;overflow-x:auto;margin:8px 0;border:1px solid var(--border2)"><code>$1</code></pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^### (.+)$/gm, '<div style="font-size:13px;font-weight:700;color:var(--text-bright);margin:10px 0 4px">$1</div>')
    .replace(/^## (.+)$/gm, '<div style="font-size:14px;font-weight:800;color:var(--sky-bright);margin:12px 0 6px">$1</div>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--text-bright)">$1</strong>')
    .replace(/^---$/gm, '<hr style="border-color:var(--border);margin:10px 0">')
    .replace(/^[-•] (.+)$/gm, '<div style="padding-left:14px;margin:3px 0">• $1</div>')
    .replace(/\n\n/g, '<br><br>').replace(/\n/g, '<br>');
}

function autoResize(el) {
  if (!el) return;
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

// Stubs
function toggleKeyPanel() {}
function saveGroqKey() {}
function toggleChat() {
  const navChat = document.getElementById('nav-chat');
  showPage('chat', navChat);
}

// Expose to inline onclick handlers
window.loadPolicyRecommendations = loadPolicyRecommendations;
window.openChatAndSend = function(text) {
  const navChat = document.getElementById('nav-chat');
  if (typeof showPage === 'function') showPage('chat', navChat);
  setTimeout(function() {
    const input = document.getElementById('chat-input');
    if (input) {
      input.value = text;
      autoResize(input);
    }
    if (typeof sendMessage === 'function') sendMessage(text);
    document.getElementById('chat-input')?.focus();
  }, 200);
};
