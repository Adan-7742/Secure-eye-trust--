/**
 * intruder.js — Secure Eye Trust+
 * Intruder Watch dashboard: shows webcam captures from failed login attempts.
 * Includes password-protected delete (single + all captures).
 */

let _intruderData   = [];
let _intruderTimer  = null;
const _intruderDeleteAttempts = {};

/* Logon type lookup for Windows EID 4625 */
const WIN_LOGON_TYPES = {
  2: 'Console / Lock Screen',
  3: 'Network',
  7: 'Screen Unlock',
  10: 'RDP Remote',
  11: 'Cached Interactive',
};

/* ── Load all intruder data ─────────────────────────────────── */
async function loadIntruderData() {
  try {
    const [listRes, statsRes] = await Promise.all([
      fetch('/api/auth/intruder-list'),
      fetch('/api/auth/stats'),
    ]);
    const list  = await listRes.json();
    const stats = await statsRes.json();

    _intruderData = list.captures || [];

    _renderIntruderStats(stats);
    _renderTopAttackers(stats);
    _renderGallery(_intruderData);
    _updateIntruderBadge(stats.unreviewed || 0);
  } catch(e) {
    console.warn('Intruder load failed:', e.message);
  }
}

/* ── Stats row ──────────────────────────────────────────────── */
function _renderIntruderStats(stats) {
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.querySelector('.intruder-stat-val').textContent = val;
  };
  set('istat-failed',     stats.total_failed    ?? '—');
  set('istat-captures',   stats.total_captures  ?? '—');
  set('istat-unreviewed', stats.unreviewed       ?? '—');
  set('istat-success',    stats.total_success    ?? '—');
}

/* ── Top IPs and usernames ──────────────────────────────────── */
function _renderTopAttackers(stats) {
  const ipEl   = document.getElementById('intruder-top-ips');
  const userEl = document.getElementById('intruder-top-users');

  if (ipEl) {
    const ips = stats.top_ips || [];
    ipEl.innerHTML = ips.length
      ? ips.map(r => `
        <div class="intruder-top-row-item">
          <span style="font-family:var(--mono);color:var(--text-bright)">${r.ip}</span>
          <span class="intruder-top-count">${r.count} attempt${r.count>1?'s':''}</span>
        </div>`).join('')
      : '<div style="padding:14px;color:var(--text-dim);font-size:12px">No failed attempts recorded</div>';
  }

  if (userEl) {
    const users = stats.top_usernames || [];
    userEl.innerHTML = users.length
      ? users.map(r => `
        <div class="intruder-top-row-item">
          <span style="color:var(--text-bright)">👤 ${r.username}</span>
          <span class="intruder-top-count">${r.count} attempt${r.count>1?'s':''}</span>
        </div>`).join('')
      : '<div style="padding:14px;color:var(--text-dim);font-size:12px">No usernames recorded</div>';
  }
}

/* ── Gallery ────────────────────────────────────────────────── */
function _renderGallery(captures) {
  const gallery = document.getElementById('intruder-gallery');
  const count   = document.getElementById('intruder-capture-count');
  if (!gallery) return;

  if (count) count.textContent = captures.length + ' capture' + (captures.length !== 1 ? 's' : '');

  if (!captures.length) {
    gallery.innerHTML = `
      <div style="text-align:center;padding:40px;color:var(--text-dim)">
        <div style="font-size:48px;margin-bottom:12px">📷</div>
        <div style="font-size:14px;font-weight:700;color:var(--text-bright);margin-bottom:6px">No captures yet</div>
        <div style="font-size:12px;line-height:1.7">
          Webcam photos will appear here automatically<br>
          after 3 or more failed login attempts.
        </div>
      </div>`;
    return;
  }

  gallery.innerHTML = '<div class="intruder-gallery-grid">' +
    captures.map(c => _captureCardHTML(c)).join('') +
  '</div>';
}

function _captureCardHTML(c) {
  const hasPhoto  = !!(c.photo_b64 && c.photo_b64.length > 100);
  const dismissed = c.dismissed ? 'dismissed' : '';
  const ts        = c.timestamp ? c.timestamp.slice(0,19).replace('T',' ') : '—';
  const logonType = WIN_LOGON_TYPES[c.attempt_no] || (c.attempt_no > 1 ? 'Attempt #' + c.attempt_no : 'Web Login');
  const username  = c.username && c.username !== '—' ? c.username : 'unknown';
  const location  = c.ip && c.ip !== '—' ? c.ip : 'Local machine';

  const photoHTML = hasPhoto
    ? `<img src="data:image/jpeg;base64,${c.photo_b64}" alt="Intruder capture" loading="lazy">`
    : `<div class="intruder-no-photo">
        <div class="no-photo-icon">🔒</div>
        <div class="no-photo-title">Windows Login Screen</div>
        <div class="no-photo-sub">Screenshot not available —<br>Windows isolates the login session<br>for security reasons.</div>
        <div class="no-photo-event">
          <div class="no-photo-row"><span class="no-photo-key">Event</span><span class="no-photo-val">EID 4625 Failed Logon</span></div>
          <div class="no-photo-row"><span class="no-photo-key">User</span><span class="no-photo-val">${username}</span></div>
          <div class="no-photo-row"><span class="no-photo-key">Type</span><span class="no-photo-val">${logonType}</span></div>
          <div class="no-photo-row"><span class="no-photo-key">Source</span><span class="no-photo-val">${location}</span></div>
          <div class="no-photo-row"><span class="no-photo-key">Time</span><span class="no-photo-val">${ts}</span></div>
        </div>
      </div>`;

  return `
  <div class="intruder-capture-card ${dismissed}" id="icap-${c.id}">
    <div class="capture-threat-bar"></div>
    <div class="intruder-photo ${hasPhoto ? 'has-photo' : 'no-photo-area'}" ${hasPhoto ? `onclick="openPhotoLightbox('${c.photo_b64}')"` : ''}>
      ${photoHTML}
      <div class="attempt-badge">${logonType}</div>
    </div>
    <div class="intruder-card-info">
      <div class="intruder-card-user">
        🚨 <span>${username}</span>
        ${!c.dismissed
          ? '<span style="margin-left:auto;font-size:9px;padding:2px 6px;border-radius:4px;background:rgba(239,68,68,.15);color:#f87171">UNREVIEWED</span>'
          : '<span style="margin-left:auto;font-size:9px;color:var(--emerald)">✓ Reviewed</span>'}
      </div>
      <div class="intruder-card-meta">
        🌐 ${location}<br>
        🔑 ${logonType}<br>
        🕐 ${ts}
      </div>
    </div>
    <div class="intruder-card-actions">
      ${hasPhoto ? `<button class="intruder-view-btn" onclick="openPhotoLightbox('${c.photo_b64}')">🔍 View Photo</button>` : ''}
      ${!c.dismissed
        ? `<button class="intruder-dismiss-btn" onclick="dismissCapture(${c.id})">✓ Mark Reviewed</button>`
        : `<button class="intruder-dismiss-btn" style="opacity:.5;cursor:not-allowed" disabled>✓ Reviewed</button>`}
      <button class="intruder-delete-btn" onclick="promptDeleteCapture(${c.id}, '${username}')">🗑 Delete</button>
    </div>
  </div>`;
}

/* ── Dismiss capture ────────────────────────────────────────── */
async function dismissCapture(id) {
  try {
    await fetch(`/api/auth/dismiss/${id}`, { method: 'POST' });
    const idx = _intruderData.findIndex(c => c.id === id);
    if (idx > -1) _intruderData[idx].dismissed = 1;
    _renderGallery(_intruderData);
    _updateIntruderBadge(_intruderData.filter(c => !c.dismissed).length);
    toast('✓ Marked as reviewed');
  } catch(e) {
    toast('❌ Could not dismiss: ' + e.message);
  }
}

/* ═══════════════════════════════════════════════════════════════
   PASSWORD-PROTECTED DELETE
═══════════════════════════════════════════════════════════════ */

/* ── Show delete modal for single capture ───────────────────── */
function promptDeleteCapture(id, username) {
  _showDeleteModal({
    title:    'Delete Capture',
    message:  `Permanently delete the capture from <strong>${username}</strong>?<br>
               <span style="color:#f87171;font-size:11px">This cannot be undone.</span>`,
    btnLabel: '🗑 Delete Capture',
    btnColor: '#ef4444',
    failKey:  'intruder-delete-' + id,
    captureReason: `Failed delete capture: ${username}`,
    onConfirm: async (password) => {
      const r = await fetch(`/api/auth/delete-capture/${id}`, {
        method:  'POST',
        headers: {'Content-Type':'application/json'},
        body:    JSON.stringify({ password }),
      });
      const d = await r.json();
      if (d.ok) {
        _intruderData = _intruderData.filter(c => c.id !== id);
        _renderGallery(_intruderData);
        _updateIntruderBadge(_intruderData.filter(c => !c.dismissed).length);
        toast('🗑 Capture deleted');
      } else {
        throw new Error(d.error || 'Delete failed');
      }
    }
  });
}

/* ── Show delete-all modal ──────────────────────────────────── */
function promptDeleteAllCaptures() {
  const count = _intruderData.length;
  if (!count) { toast('No captures to delete'); return; }

  _showDeleteModal({
    title:    'Delete All Captures',
    message:  `Permanently delete <strong>all ${count} capture${count!==1?'s':''}</strong>?<br>
               <span style="color:#f87171;font-size:11px">This cannot be undone.</span>`,
    btnLabel: `🗑 Delete All ${count} Captures`,
    btnColor: '#b91c1c',
    failKey: 'intruder-delete-all',
    captureReason: 'Failed bulk delete captures',
    onConfirm: async (password) => {
      const r = await fetch('/api/auth/delete-all-captures', {
        method:  'POST',
        headers: {'Content-Type':'application/json'},
        body:    JSON.stringify({ password }),
      });
      const d = await r.json();
      if (d.ok) {
        _intruderData = [];
        _renderGallery(_intruderData);
        _updateIntruderBadge(0);
        toast(`🗑 Deleted ${d.deleted} capture${d.deleted!==1?'s':''}`);
      } else {
        throw new Error(d.error || 'Delete failed');
      }
    }
  });
}

/* ── Generic password-confirm modal ────────────────────────── */
function _showDeleteModal({ title, message, btnLabel, btnColor, failKey, captureReason, onConfirm }) {
  // Remove any existing modal
  const existing = document.getElementById('intruder-del-modal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'intruder-del-modal';
  modal.style.cssText = [
    'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999',
    'display:flex;align-items:center;justify-content:center',
    'animation:idm-fade .15s ease'
  ].join(';');

  modal.innerHTML = `
    <div id="idm-card" style="
      background:#0f1a2e;border:1px solid rgba(255,255,255,.1);border-radius:16px;
      padding:28px 28px 24px;width:min(400px,92vw);
      box-shadow:0 24px 60px rgba(0,0,0,.6);
      animation:idm-in .18s ease
    ">
      <!-- Header -->
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px">
        <div style="width:38px;height:38px;background:rgba(239,68,68,.12);border-radius:10px;
          display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0">🗑</div>
        <div style="font-size:16px;font-weight:800;color:#e8f4ff">${title}</div>
      </div>

      <!-- Message -->
      <div style="font-size:13px;color:#8faac8;line-height:1.6;margin-bottom:20px">${message}</div>

      <!-- Password field -->
      <div style="margin-bottom:18px">
        <label style="display:block;font-size:11px;font-weight:700;color:#4a6a8a;
          text-transform:uppercase;letter-spacing:.1em;margin-bottom:7px">
          Enter Dashboard Password to Confirm
        </label>
        <div style="position:relative">
          <input id="idm-pass" type="password" placeholder="Your dashboard password"
            autocomplete="current-password"
            style="width:100%;padding:11px 42px 11px 14px;border-radius:9px;
              background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
              color:#e8f4ff;font-size:13px;outline:none;transition:border .2s;
              font-family:inherit"
            onfocus="this.style.borderColor='#ef4444';this.style.boxShadow='0 0 0 3px rgba(239,68,68,.12)'"
            onblur="this.style.borderColor='rgba(255,255,255,.1)';this.style.boxShadow='none'"
            onkeydown="if(event.key==='Enter')document.getElementById('idm-confirm').click()">
          <button onclick="var i=document.getElementById('idm-pass');i.type=i.type==='password'?'text':'password';this.textContent=i.type==='password'?'👁':'🙈'"
            style="position:absolute;right:10px;top:50%;transform:translateY(-50%);
              background:none;border:none;color:#4a6a8a;cursor:pointer;font-size:14px;padding:4px">👁</button>
        </div>
        <div id="idm-err" style="display:none;margin-top:8px;padding:8px 12px;border-radius:7px;
          background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);
          color:#fca5a5;font-size:12px"></div>
      </div>

      <!-- Buttons -->
      <div style="display:flex;gap:10px">
        <button onclick="document.getElementById('intruder-del-modal').remove()"
          style="flex:1;padding:11px;border-radius:9px;background:rgba(255,255,255,.06);
            border:1px solid rgba(255,255,255,.1);color:#8faac8;cursor:pointer;
            font-size:13px;font-weight:600;font-family:inherit;transition:all .15s"
          onmouseenter="this.style.background='rgba(255,255,255,.1)'"
          onmouseleave="this.style.background='rgba(255,255,255,.06)'">
          Cancel
        </button>
        <button id="idm-confirm"
          style="flex:2;padding:11px;border-radius:9px;background:${btnColor};
            border:none;color:#fff;cursor:pointer;font-size:13px;font-weight:700;
            font-family:inherit;transition:all .15s"
          onmouseenter="this.style.opacity='.85'"
          onmouseleave="this.style.opacity='1'">
          ${btnLabel}
        </button>
      </div>
    </div>`;

  // CSS animations
  if (!document.getElementById('idm-style')) {
    const s = document.createElement('style');
    s.id = 'idm-style';
    s.textContent = `
      @keyframes idm-fade { from{opacity:0} to{opacity:1} }
      @keyframes idm-in   { from{opacity:0;transform:scale(.94) translateY(10px)} to{opacity:1;transform:scale(1) translateY(0)} }
      .intruder-delete-btn {
        background: rgba(239,68,68,.12);
        color: #f87171;
        border: 1px solid rgba(239,68,68,.25);
        padding: 7px 14px;
        border-radius: 8px;
        cursor: pointer;
        font-size: 12px;
        font-weight: 700;
        transition: all .15s;
      }
      .intruder-delete-btn:hover {
        background: rgba(239,68,68,.25);
        border-color: rgba(239,68,68,.5);
      }
    `;
    document.head.appendChild(s);
  }

  // Close on backdrop click
  modal.addEventListener('click', function(e) {
    if (e.target === modal) modal.remove();
  });

  document.body.appendChild(modal);
  setTimeout(() => document.getElementById('idm-pass')?.focus(), 100);

  // Confirm handler
  document.getElementById('idm-confirm').addEventListener('click', async function() {
    const password = document.getElementById('idm-pass').value;
    const errEl    = document.getElementById('idm-err');
    const btn      = this;

    if (!password) {
      errEl.textContent = 'Please enter your password.';
      errEl.style.display = 'block';
      return;
    }

    btn.disabled = true;
    btn.textContent = '⟳ Verifying…';
    errEl.style.display = 'none';

    try {
      await onConfirm(password);
      if (failKey) _intruderDeleteAttempts[failKey] = 0;
      modal.remove();
    } catch(e) {
      errEl.textContent = '❌ ' + e.message;
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = btnLabel;
      if (failKey && /password/i.test(e.message)) {
        _intruderDeleteAttempts[failKey] = (_intruderDeleteAttempts[failKey] || 0) + 1;
        if (_intruderDeleteAttempts[failKey] >= 2) {
          toast('⚠ 2 failed password attempts — recording intruder capture');
          _captureIntruderPhoto(captureReason || title);
        }
      }
      // Shake the card
      const card = document.getElementById('idm-card');
      if (card) {
        card.style.animation = 'none';
        card.style.transform = 'translateX(-8px)';
        setTimeout(() => { card.style.transform = 'translateX(8px)'; }, 80);
        setTimeout(() => { card.style.transform = 'translateX(-4px)'; }, 160);
        setTimeout(() => { card.style.transform = ''; }, 240);
      }
      document.getElementById('idm-pass').value = '';
      document.getElementById('idm-pass').focus();
    }
  });
}

/* ── Photo lightbox ─────────────────────────────────────────── */
function openPhotoLightbox(b64) {
  let lb = document.getElementById('photo-lightbox');
  if (!lb) {
    lb = document.createElement('div');
    lb.id = 'photo-lightbox';
    lb.className = 'photo-lightbox';
    lb.innerHTML = `
      <button class="photo-lightbox-close" onclick="closePhotoLightbox()">✕</button>
      <img id="photo-lb-img" src="" alt="Intruder capture">`;
    lb.addEventListener('click', function(e) {
      if (e.target === lb) closePhotoLightbox();
    });
    document.body.appendChild(lb);
  }
  document.getElementById('photo-lb-img').src = 'data:image/jpeg;base64,' + b64;
  lb.classList.add('open');
}

window.closePhotoLightbox = function() {
  const lb = document.getElementById('photo-lightbox');
  if (lb) lb.classList.remove('open');
};

/* ── Badge ──────────────────────────────────────────────────── */
function _updateIntruderBadge(count) {
  const b = document.getElementById('badge-intruder');
  if (!b) return;
  b.textContent   = count;
  b.style.display = count > 0 ? 'inline-flex' : 'none';
}

/* ── Auto-poll every 20s when page is visible ───────────────── */
function startIntruderPolling() {
  loadIntruderData();
  if (_intruderTimer) clearInterval(_intruderTimer);
  _intruderTimer = setInterval(loadIntruderData, 20000);
}
function stopIntruderPolling() {
  clearInterval(_intruderTimer);
  _intruderTimer = null;
}
