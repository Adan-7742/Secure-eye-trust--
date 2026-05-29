/**
 * locker.js — Secure Eye Trust+
 * Folder Lock only (app locking removed)
 */

let _lockerFolders  = [];
let _lockerCaptures = [];
let _lockerStats    = {};
let _lockerTab      = 'folders';
let _unlockTarget   = null;
let _unlockFails    = 0;
let _removeFolderFails = 0;
let _unlockCamStream = null;

/* ── Init ───────────────────────────────────────────────────── */
async function initLocker() {
  console.log('[locker] initLocker()');
  // Clean up old shortcut/vbs files from previous lock versions
  try { await fetch('/api/locker/folders/cleanup-desktop', {method:'POST'}); } catch(e) { console.warn('[locker] cleanup-desktop failed', e); }
  await Promise.all([_loadFolders(), _loadCaptures(), _loadStats()]);
  _renderTab(_lockerTab);
  _populateDeleteSelect();
}

/* ── Data ───────────────────────────────────────────────────── */
async function _loadFolders() {
  try {
    const r = await fetch('/api/locker/folders', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    _lockerFolders = (data && Array.isArray(data.folders)) ? data.folders : [];
    console.log('[locker] loaded folders', _lockerFolders.length, 'items');
  } catch(e) {
    console.error('[locker] failed to load folders', e);
    _lockerFolders = [];
  }
}
async function _loadCaptures() {
  try {
    const r = await fetch('/api/locker/captures', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const data = await r.json();
    _lockerCaptures = (data && Array.isArray(data.captures)) ? data.captures : [];
  } catch(e) {
    console.error('[locker] failed to load captures', e);
    _lockerCaptures = [];
  }
}
async function _loadStats() {
  try {
    const r = await fetch('/api/locker/stats', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    _lockerStats = await r.json();
    _renderStats();
  } catch(e) {
    console.error('[locker] failed to load stats', e);
    _lockerStats = {};
    _renderStats();
  }
}

/* ── Stats ──────────────────────────────────────────────────── */
function _renderStats() {
  const s = _lockerStats || {};
  const set = (id, v) => {
    const el = document.getElementById(id);
    if (el) el.textContent = (v === undefined || v === null) ? '0' : v;
  };
  set('lstat-folders',  s.locked_folders  ?? 0);
  set('lstat-failed',   s.failed_unlocks  ?? 0);
  set('lstat-captures', s.unreviewed_captures ?? 0);
  const b = document.getElementById('badge-locker');
  const u = s.unreviewed_captures || 0;
  if (b) { b.textContent = u; b.style.display = u > 0 ? 'inline-flex' : 'none'; }
  const folderCount = _lockerFolders.filter(f => !!f.is_locked).length;
  set('lstat-folders', folderCount);
  const tc = document.getElementById('ltab-cap-count');
  if (tc) tc.textContent = _lockerCaptures.length;
}

/* ── Tab switching ──────────────────────────────────────────── */
function switchLockerTab(tab, btn) {
  _lockerTab = tab;
  document.querySelectorAll('.locker-tab').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  _renderTab(tab);
}
function _renderTab(tab) {
  ['folders','captures','settings'].forEach(p => {
    const el = document.getElementById('locker-panel-' + p);
    if (el) el.style.display = p === tab ? '' : 'none';
  });
  if (tab === 'folders')  _renderFolders();
  if (tab === 'captures') _renderCaptures();
  if (tab === 'settings') _populateDeleteSelect();
}

/* ── Folders ────────────────────────────────────────────────── */
function _renderFolders() {
  const el = document.getElementById('locker-folders-list');
  if (!el) return;
  if (!_lockerFolders.length) {
    el.innerHTML = `<div style="padding:36px;text-align:center;color:var(--text-dim)">
      <div style="font-size:44px;margin-bottom:12px">📁</div>
      <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:6px">No folders locked yet</div>
      <div style="font-size:12px">Click <strong>+ Lock Folder</strong> to protect a folder with a password</div>
    </div>`;
    return;
  }
  el.innerHTML = _lockerFolders.map(f => {
    const locked = !!f.is_locked;
    return `<div class="locker-item-row" id="frow-${f.id}"
        data-id="${f.id}" data-path="${f.folder_path}" data-name="${f.name}">
      <div class="locker-item-icon" style="background:${locked?'rgba(239,68,68,.12)':'rgba(16,185,129,.1)'}">
        ${locked ? '🔒' : '📂'}
      </div>
      <div class="locker-item-info">
        <div class="locker-item-name">${f.name}
          <span style="margin-left:8px;font-size:10px;padding:2px 9px;border-radius:6px;font-weight:700;
            background:${locked?'rgba(239,68,68,.15)':'rgba(16,185,129,.12)'};
            color:${locked?'#f87171':'var(--emerald)'};
            border:1px solid ${locked?'rgba(239,68,68,.25)':'rgba(16,185,129,.25)'}">
            ${locked ? '🔒 LOCKED' : '🔓 UNLOCKED'}
          </span>
        </div>
        <div class="locker-item-path">${locked ? 'Hidden until unlocked' : f.folder_path}</div>
      </div>
      <div class="locker-item-meta">
      </div>
      <div class="locker-item-actions">
        <button class="${locked ? 'locker-unlock-btn' : 'locker-relock-btn'}"
          onclick="toggleFolderLock('frow-${f.id}')">
          ${locked ? '🔓 Unlock &amp; Open' : '🔒 Lock It'}
        </button>
        <button class="locker-remove-btn" onclick="removeFolderById('frow-${f.id}')">✕</button>
      </div>
    </div>`;
  }).join('');
}

/* ── Toggle lock/unlock ─────────────────────────────────────── */
async function toggleFolderLock(rowId) {
  const row = document.getElementById(rowId);
  if (!row) return;
  const fid    = parseInt(row.dataset.id);
  const path   = row.dataset.path;
  const name   = row.dataset.name;
  const folder = _lockerFolders.find(f => f.id === fid);
  if (!folder) return;

  if (folder.is_locked) {
    // Show password dialog to unlock
    openUnlockModal(fid, name, path);
  } else {
    // Lock it — no password needed
    const btn = row.querySelector('button');
    if (btn) { btn.disabled = true; btn.textContent = '⟳ Locking…'; }
    try {
      const r = await fetch('/api/locker/folders/lock-no-pw', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({id: fid, folder_path: path})
      });
      const d = await r.json();
      if (d.ok) {
        toast('🔒 "' + name + '" is now locked');
        // Reload fresh data from server so button flips correctly
        await _loadFolders();
        await _loadStats();
        _renderFolders();
      } else {
        toast('❌ ' + (d.error || 'Failed — run app as Administrator'));
        if (btn) { btn.disabled = false; btn.textContent = '🔒 Lock It'; }
      }
    } catch(e) {
      toast('❌ Connection error');
      if (btn) { btn.disabled = false; btn.textContent = '🔒 Lock It'; }
    }
  }
}

/* ── Remove folder ──────────────────────────────────────────── */
async function removeFolderById(rowId) {
  const row = document.getElementById(rowId);
  if (!row) return;
  const name = row.dataset.name;
  const pw = prompt('Enter password for "' + name + '" to remove lock and restore folder:');
  if (!pw) return;
  // Disable button while working
  const btn = row.querySelectorAll('button')[1];
  if (btn) { btn.disabled = true; btn.textContent = '⟳…'; }
  try {
    _unlockTarget = {id: parseInt(row.dataset.id), name, path};
    const r = await fetch('/api/locker/folders/remove', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({id: parseInt(row.dataset.id), password: pw})
    });
    const d = await r.json();
    if (d.ok) {
      _removeFolderFails = 0;
      toast('✅ "' + name + '" restored to its original location');
      await initLocker();
    } else {
      _removeFolderFails += 1;
      if (_removeFolderFails >= 2) {
        await _captureIntruder();
      }
      toast('❌ ' + (d.error || 'Wrong password'));
      if (btn) { btn.disabled = false; btn.textContent = '✕'; }
    }
  } catch(e) {
    toast('❌ Connection error');
    if (btn) { btn.disabled = false; btn.textContent = '✕'; }
  } finally {
    _unlockTarget = null;
  }
}

/* ── Add folder modal ───────────────────────────────────────── */
function showLockerModal() {
  ['lock-name','lock-path','lock-password','lock-password2'].forEach(id => {
    const el = document.getElementById(id); if(el) el.value = '';
  });
  const msg = document.getElementById('locker-modal-msg');
  if (msg) msg.style.display = 'none';
  const m = document.getElementById('locker-modal');
  if (m) m.style.display = 'flex';
  setTimeout(() => document.getElementById('lock-name')?.focus(), 100);
}
function closeLockerModal() {
  const m = document.getElementById('locker-modal');
  if (m) m.style.display = 'none';
}

async function submitLockModal() {
  const name  = document.getElementById('lock-name')?.value.trim();
  const path  = document.getElementById('lock-path')?.value.trim();
  const pw    = document.getElementById('lock-password')?.value;
  const pw2   = document.getElementById('lock-password2')?.value;
  const msg   = document.getElementById('locker-modal-msg');

  const showMsg = (text, ok) => {
    if (!msg) return;
    msg.textContent = text;
    msg.style.cssText = `display:block;padding:10px 12px;border-radius:8px;font-size:12px;margin-bottom:12px;
      background:${ok?'rgba(16,185,129,.2)':'rgba(239,68,68,.2)'};
      border:1px solid ${ok?'rgba(16,185,129,.3)':'rgba(239,68,68,.3)'};
      color:${ok?'#6ee7b7':'#fca5a5'}`;
  };

  if (!name || !path || !pw) return showMsg('All fields are required', false);
  if (pw.length < 4)          return showMsg('Password must be at least 4 characters', false);
  if (pw !== pw2)             return showMsg('Passwords do not match', false);

  const btn = document.querySelector('#locker-modal .btn-primary');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Locking…'; }

  try {
    const r = await fetch('/api/locker/folders/add', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({name, folder_path: path, password: pw})
    });
    const d = await r.json();
    if (d.ok) {
      closeLockerModal();
      toast('🔒 "' + name + '" is now locked!');
      await initLocker();
    } else {
      showMsg('❌ ' + (d.error || 'Failed'), false);
    }
  } catch(e) {
    showMsg('❌ Connection error', false);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '🔒 Lock It'; }
  }
}

/* ── Unlock modal ───────────────────────────────────────────── */
function openUnlockModal(fid, name, path) {
  _unlockTarget = {id: fid, name, path};
  _unlockFails  = 0;
  document.getElementById('unlock-modal-title').textContent = '🔓 Unlock Folder';
  document.getElementById('unlock-modal-icon').textContent  = '📁';
  document.getElementById('unlock-modal-name').textContent  = name;
  document.getElementById('unlock-modal-path').textContent  = path;
  document.getElementById('unlock-password').value = '';
  const msg = document.getElementById('unlock-modal-msg');
  if (msg) msg.style.display = 'none';
  const m = document.getElementById('unlock-modal');
  if (m) m.style.display = 'flex';
  setTimeout(() => document.getElementById('unlock-password')?.focus(), 100);
}
function closeUnlockModal() {
  if (_unlockCamStream) { _unlockCamStream.getTracks().forEach(t=>t.stop()); _unlockCamStream=null; }
  const m = document.getElementById('unlock-modal');
  if (m) m.style.display = 'none';
  _unlockTarget = null; _unlockFails = 0;
}

async function submitUnlock() {
  if (!_unlockTarget) return;
  const pw  = document.getElementById('unlock-password')?.value || '';
  const msg = document.getElementById('unlock-modal-msg');
  const btn = document.querySelector('#unlock-modal .btn-primary');

  const showMsg = (text, ok) => {
    if (!msg) return;
    msg.textContent = text;
    msg.style.cssText = `display:block;padding:10px 12px;border-radius:8px;font-size:12px;margin-bottom:12px;
      background:${ok?'rgba(16,185,129,.2)':'rgba(239,68,68,.2)'};
      border:1px solid ${ok?'rgba(16,185,129,.3)':'rgba(239,68,68,.3)'};
      color:${ok?'#6ee7b7':'#fca5a5'}`;
  };

  if (!pw) return showMsg('Enter your password', false);
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Checking…'; }

  try {
    const r = await fetch('/api/locker/folders/unlock', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        id: _unlockTarget.id,
        password: pw,
        name: _unlockTarget.name,
        folder_path: _unlockTarget.path
      })
    });
    const d = await r.json();

    if (d.ok) {
      showMsg('✅ Unlocked! Folder is now visible.', true);
      const f = _lockerFolders.find(x => x.id === _unlockTarget.id);
      if (f) f.is_locked = 0;
      setTimeout(() => { closeUnlockModal(); _renderFolders(); _loadStats(); }, 700);
    } else {
      _unlockFails = d.attempt_no || (_unlockFails + 1);
      showMsg('❌ Wrong password.', false);
      document.getElementById('unlock-password').value = '';
      document.getElementById('unlock-password')?.focus();
      if (d.capture_needed) _captureIntruder();
    }
  } catch(e) {
    showMsg('❌ Connection error', false);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '🔓 Unlock'; }
  }
}

async function _captureIntruder() {
  const video  = document.getElementById('unlock-cam-video');
  const canvas = document.getElementById('unlock-cam-canvas');
  if (!video || !canvas || !_unlockTarget) return;
  let photo = '';
  try {
    _unlockCamStream = await navigator.mediaDevices.getUserMedia({video:{width:320,height:240},audio:false});
    video.srcObject = _unlockCamStream;
    await new Promise(r => { video.onloadedmetadata = () => { video.play(); setTimeout(r,700); }; });
    canvas.getContext('2d').drawImage(video,0,0,320,240);
    photo = canvas.toDataURL('image/jpeg',0.7);
    _unlockCamStream.getTracks().forEach(t=>t.stop()); _unlockCamStream=null;
  } catch(e) { console.warn('Webcam:', e.message); }
  await fetch('/api/locker/intruder-photo', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target_type:'folder', target_name:_unlockTarget.name,
      target_path:_unlockTarget.path, photo, attempt_no:_unlockFails})
  });
  await _loadCaptures();
}

/* ── Captures gallery ───────────────────────────────────────── */
function _renderCaptures() {
  const el  = document.getElementById('locker-captures-gallery');
  const cnt = document.getElementById('locker-cap-count');
  if (!el) return;
  if (cnt) cnt.textContent = _lockerCaptures.length;
  if (!_lockerCaptures.length) {
    el.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text-dim)">
      <div style="font-size:48px;margin-bottom:12px">📷</div>
      <div style="font-size:13px;font-weight:700;color:var(--text-bright);margin-bottom:6px">No captures yet</div>
      <div style="font-size:12px">Photos appear here after 3 failed unlock attempts</div>
    </div>`;
    return;
  }
  el.innerHTML = '<div class="intruder-gallery-grid">' +
    _lockerCaptures.map(c => {
      const hasPhoto = !!(c.photo_b64 && c.photo_b64.length > 100);
      const ts = (c.timestamp||'').slice(0,19).replace('T',' ');
      const photo = hasPhoto
        ? `<img src="data:image/jpeg;base64,${c.photo_b64}" style="width:100%;height:100%;object-fit:cover" loading="lazy">`
        : `<div class="intruder-no-photo">
            <div class="no-photo-icon">📁</div>
            <div class="no-photo-title">${c.target_name}</div>
            <div class="no-photo-sub">Failed unlock — no webcam</div>
            <div class="no-photo-event">
              <div class="no-photo-row"><span class="no-photo-key">Folder</span><span class="no-photo-val">${c.target_name}</span></div>
              <div class="no-photo-row"><span class="no-photo-key">Attempt</span><span class="no-photo-val">#${c.attempt_no}</span></div>
              <div class="no-photo-row"><span class="no-photo-key">Time</span><span class="no-photo-val">${ts}</span></div>
            </div>
          </div>`;
      return `<div class="intruder-capture-card ${c.dismissed?'dismissed':''}" id="lcap-${c.id}">
        <div class="capture-threat-bar" style="background:linear-gradient(90deg,var(--amber),rgba(245,158,11,.3))"></div>
        <div class="intruder-photo ${hasPhoto?'has-photo':'no-photo-area'}" ${hasPhoto?`onclick="openPhotoLightbox('${c.photo_b64}')"`:''}>${photo}
          <div class="attempt-badge" style="background:rgba(245,158,11,.8)">Attempt #${c.attempt_no}</div>
        </div>
        <div class="intruder-card-info">
          <div class="intruder-card-user">📁 <span>${c.target_name}</span>
            ${!c.dismissed
              ? '<span style="margin-left:auto;font-size:9px;padding:2px 6px;border-radius:4px;background:rgba(245,158,11,.15);color:var(--amber)">UNREVIEWED</span>'
              : '<span style="margin-left:auto;font-size:9px;color:var(--emerald)">✓ Reviewed</span>'}
          </div>
          <div class="intruder-card-meta">🕐 ${ts}</div>
        </div>
        <div class="intruder-card-actions">
          ${hasPhoto ? `<button class="intruder-view-btn" onclick="openPhotoLightbox('${c.photo_b64}')">🔍 View</button>` : ''}
          ${!c.dismissed
            ? `<button class="intruder-dismiss-btn" onclick="dismissLockerCap(${c.id})">✓ Reviewed</button>`
            : `<button class="intruder-dismiss-btn" style="opacity:.5" disabled>✓ Done</button>`}
          <button class="intruder-dismiss-btn" style="color:#f87171;border-color:rgba(239,68,68,.3)" onclick="deleteLockerCap(${c.id})">🗑</button>
        </div>
      </div>`;
    }).join('') + '</div>';
}

async function dismissLockerCap(id) {
  await fetch(`/api/locker/captures/dismiss/${id}`, {method:'POST'});
  const c = _lockerCaptures.find(x=>x.id===id);
  if (c) c.dismissed=1;
  _renderCaptures(); _loadStats();
  toast('✓ Marked reviewed');
}
let _lockerDeleteAttempts = 0;

function _showLockerPasswordModal({ title, message, btnLabel, onConfirm }) {
  const existing = document.getElementById('locker-del-modal');
  if (existing) existing.remove();

  const modal = document.createElement('div');
  modal.id = 'locker-del-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="background:#0f1a2e;border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:28px 26px;width:min(420px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.6);">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;">
        <div style="width:38px;height:38px;background:rgba(239,68,68,.12);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0">🔐</div>
        <div style="font-size:16px;font-weight:800;color:#e8f4ff">${title}</div>
      </div>
      <div style="font-size:13px;color:#8faac8;line-height:1.6;margin-bottom:20px;">${message}</div>
      <div style="margin-bottom:18px;">
        <label style="display:block;font-size:11px;font-weight:700;color:#4a6a8a;text-transform:uppercase;letter-spacing:.1em;margin-bottom:7px;">Enter Password to Confirm</label>
        <div style="position:relative;">
          <input id="ldm-pass" type="password" placeholder="Dashboard password" autocomplete="current-password"
            style="width:100%;padding:12px 44px 12px 14px;border-radius:10px;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);color:#e8f4ff;font-size:13px;outline:none;font-family:inherit;">
          <button id="ldm-toggle" type="button" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;color:#4a6a8a;cursor:pointer;font-size:14px;padding:4px;">👁</button>
        </div>
        <div id="ldm-err" style="display:none;margin-top:10px;padding:10px 12px;border-radius:8px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.25);color:#fca5a5;font-size:12px;"></div>
      </div>
      <div style="display:flex;gap:10px;">
        <button type="button" id="ldm-cancel" style="flex:1;padding:12px;border-radius:10px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.1);color:#8faac8;cursor:pointer;font-size:13px;font-weight:600;font-family:inherit;">Cancel</button>
        <button type="button" id="ldm-confirm" style="flex:2;padding:12px;border-radius:10px;background:#ef4444;border:none;color:#fff;cursor:pointer;font-size:13px;font-weight:700;font-family:inherit;">${btnLabel}</button>
      </div>
    </div>`;
  modal.addEventListener('click', function(e) { if (e.target === modal) modal.remove(); });
  document.body.appendChild(modal);
  const passInput = document.getElementById('ldm-pass');
  const errEl = document.getElementById('ldm-err');
  const confirmBtn = document.getElementById('ldm-confirm');
  const toggleBtn = document.getElementById('ldm-toggle');
  const cancelBtn = document.getElementById('ldm-cancel');
  passInput.focus();
  passInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') confirmBtn.click(); });
  toggleBtn.addEventListener('click', function() { passInput.type = passInput.type === 'password' ? 'text' : 'password'; toggleBtn.textContent = passInput.type === 'password' ? '👁' : '🙈'; });
  cancelBtn.addEventListener('click', () => modal.remove());
  confirmBtn.addEventListener('click', async function() {
    const password = passInput.value.trim();
    if (!password) { errEl.textContent = 'Please enter the dashboard password.'; errEl.style.display = 'block'; return; }
    confirmBtn.disabled = true;
    confirmBtn.textContent = '⟳ Verifying…';
    errEl.style.display = 'none';
    try {
      await onConfirm(password);
      _lockerDeleteAttempts = 0;
      modal.remove();
    } catch (err) {
      const msg = err?.message || 'Wrong password';
      errEl.textContent = '❌ ' + msg;
      errEl.style.display = 'block';
      confirmBtn.disabled = false;
      confirmBtn.textContent = btnLabel;
      if (/password/i.test(msg)) {
        _lockerDeleteAttempts += 1;
        if (_lockerDeleteAttempts >= 2) {
          toast('⚠ 2 failed password attempts — recording intruder photo');
          await _captureIntruder();
        }
      }
      passInput.value = '';
      passInput.focus();
    }
  });
}

async function deleteLockerCap(id) {
  _showLockerPasswordModal({
    title: 'Delete Capture',
    message: 'This will permanently delete the selected capture. Enter dashboard password to confirm.',
    btnLabel: '🗑 Delete',
    onConfirm: async function(password) {
      const r = await fetch(`/api/locker/captures/delete/${id}`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({password: password})
      });
      const d = await r.json();
      if (d.ok) {
        _lockerCaptures = _lockerCaptures.filter(c => c.id !== id);
        _renderCaptures(); _loadStats(); toast('🗑 Deleted');
      } else {
        throw new Error(d.error || 'Wrong password');
      }
    }
  });
}

/* ── Settings ───────────────────────────────────────────────── */
function _populateDeleteSelect() {
  const sel = document.getElementById('del-cap-select');
  if (!sel) return;
  sel.innerHTML = '<option value="">— Select capture —</option>' +
    _lockerCaptures.map(c => {
      const ts = (c.timestamp||'').slice(0,16).replace('T',' ');
      return `<option value="${c.id}">#${c.id} | ${c.target_name} | ${ts}</option>`;
    }).join('');
}
async function deleteSelectedCapture() {
  const sel = document.getElementById('del-cap-select');
  const pw  = document.getElementById('del-cap-password')?.value || '';
  if (!sel?.value) return toast('❌ Select a capture first');
  if (!pw)         return toast('❌ Enter your password');
  await deleteLockerCap(parseInt(sel.value));
  document.getElementById('del-cap-password').value = '';
}
async function dismissAllCaptures() {
  const pw = document.getElementById('bulk-password')?.value || '';
  if (!pw) return toast('❌ Enter your password');
  for (const c of _lockerCaptures.filter(x=>!x.dismissed)) {
    await fetch(`/api/locker/captures/dismiss/${c.id}`, {method:'POST'});
    c.dismissed = 1;
  }
  _renderCaptures(); _loadStats(); toast('✅ All marked reviewed');
}
async function deleteAllCaptures() {
  _showLockerPasswordModal({
    title: 'Delete All Locker Captures',
    message: 'This will permanently delete all capture images. Enter the dashboard password to confirm.',
    btnLabel: '🗑 Delete All',
    btnColor: '#ef4444',
    failKey: 'locker-delete-all',
    onConfirm: async function(password) {
      let count = 0;
      for (const c of [..._lockerCaptures]) {
        const r = await fetch(`/api/locker/captures/delete/${c.id}`, {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({password})
        });
        const d = await r.json();
        if (d.ok) count++;
        else throw new Error(d.error || 'Wrong password');
      }
      _lockerCaptures = [];
      _renderCaptures();
      _populateDeleteSelect();
      _loadStats();
      toast(`🗑 Deleted ${count} captures`);
    }
  });
}

/* ── Emergency restore all hidden folders ───────────────────── */
async function restoreAllFolders() {
  const btn = event.target;
  btn.disabled = true; btn.textContent = '⟳ Restoring…';
  try {
    const r = await fetch('/api/locker/folders/restore-all', {method:'POST'});
    const d = await r.json();
    if (d.ok) {
      toast('✅ ' + (d.message || 'Folders restored'));
      await initLocker();
    } else {
      toast('❌ ' + (d.error || 'Restore failed'));
    }
  } catch(e) {
    toast('❌ Connection error');
  } finally {
    btn.disabled = false; btn.textContent = '🔄 Restore All Hidden Folders';
  }
}
