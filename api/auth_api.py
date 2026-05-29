"""
api/auth_api.py — Secure Eye Trust+
Firebase authentication. Silent webcam capture after 2 wrong attempts.
No dots shown to user. No hints about capture.
"""
import os, hashlib, secrets
from datetime import datetime
from flask import Blueprint, request, jsonify, session, send_from_directory
from database.db import (
    log_login_attempt, save_intruder_capture,
    get_intruder_captures, dismiss_intruder, init_auth_db, get_conn,
)

# Embedded login page — used as fallback if login.html is old/missing
_EMBEDDED_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Eye Trust+</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#060c1a; --panel:#0f1a2e; --panel2:#0a1222;
  --border:rgba(255,255,255,.07); --border2:rgba(26,140,255,.25);
  --sky:#1a8cff; --sky-b:#4da6ff;
  --red:#ef4444; --green:#10b981; --amber:#f59e0b;
  --text:#b8cce0; --text-b:#e8f4ff; --text-d:#4a6a8a;
  --sans:'Segoe UI',system-ui,sans-serif;
}
body{font-family:var(--sans);background:var(--bg);color:var(--text);
  min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden}

/* — Background — */
.bg-grid{position:fixed;inset:0;
  background-image:linear-gradient(rgba(26,140,255,.035) 1px,transparent 1px),
    linear-gradient(90deg,rgba(26,140,255,.035) 1px,transparent 1px);
  background-size:48px 48px;animation:grid-move 24s linear infinite;pointer-events:none}
@keyframes grid-move{to{background-position:48px 48px}}
.bg-glow{position:fixed;top:25%;left:50%;transform:translate(-50%,-50%);
  width:700px;height:700px;border-radius:50%;
  background:radial-gradient(circle,rgba(26,140,255,.05) 0%,transparent 65%);pointer-events:none}
.bg-glow2{position:fixed;bottom:10%;right:10%;width:400px;height:400px;border-radius:50%;
  background:radial-gradient(circle,rgba(139,92,246,.04) 0%,transparent 65%);pointer-events:none}

/* — Card — */
.wrap{position:relative;z-index:10;width:min(430px,94vw)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:22px;
  padding:38px 36px 32px;
  box-shadow:0 32px 80px rgba(0,0,0,.7), 0 0 0 1px rgba(26,140,255,.05),
             inset 0 1px 0 rgba(255,255,255,.04)}

/* — Brand — */
.brand{text-align:center;margin-bottom:30px}
.shield-wrap{position:relative;width:76px;margin:0 auto 16px}
.shield{width:76px;height:76px;background:linear-gradient(145deg,#0d2a6e,#1a8cff);
  border-radius:18px;display:flex;align-items:center;justify-content:center;
  font-size:34px;box-shadow:0 0 0 1px rgba(26,140,255,.3), 0 0 32px rgba(26,140,255,.4);
  animation:shield-pulse 3.5s ease-in-out infinite}
@keyframes shield-pulse{
  0%,100%{box-shadow:0 0 0 1px rgba(26,140,255,.3),0 0 32px rgba(26,140,255,.4)}
  50%    {box-shadow:0 0 0 1px rgba(26,140,255,.6),0 0 52px rgba(26,140,255,.65)}}
.brand-title{font-size:22px;font-weight:900;color:var(--text-b);letter-spacing:-.02em}
.brand-title em{color:var(--sky-b);font-style:normal}
.brand-sub{font-size:10px;color:var(--text-d);margin-top:5px;
  text-transform:uppercase;letter-spacing:.18em}

/* — Firebase status badge — */
.fb-status{display:flex;align-items:center;gap:8px;padding:8px 12px;
  border-radius:8px;margin-bottom:22px;font-size:11px;font-weight:600;
  transition:all .3s}
.fb-status.checking{background:rgba(255,255,255,.03);border:1px solid var(--border);color:var(--text-d)}
.fb-status.ok      {background:rgba(16,185,129,.07);border:1px solid rgba(16,185,129,.2);color:#34d399}
.fb-status.err     {background:rgba(239,68,68,.07);border:1px solid rgba(239,68,68,.2);color:#fca5a5}
.fb-dot{width:6px;height:6px;border-radius:50%;background:currentColor;flex-shrink:0}

/* — Tabs — */
.tabs{display:flex;background:rgba(255,255,255,.03);border:1px solid var(--border);
  border-radius:10px;padding:3px;gap:3px;margin-bottom:22px}
.tab{flex:1;padding:9px 6px;border-radius:8px;border:none;background:transparent;
  color:var(--text-d);font-size:11px;font-weight:700;cursor:pointer;
  font-family:var(--sans);letter-spacing:.07em;text-transform:uppercase;transition:all .2s}
.tab.active{background:var(--sky);color:#fff;box-shadow:0 2px 14px rgba(26,140,255,.45)}
.tab:not(.active):hover{color:var(--text);background:rgba(255,255,255,.05)}

/* — Form — */
.pane{display:none}.pane.active{display:block}
.fg{margin-bottom:16px}
.flabel{display:block;font-size:10px;font-weight:700;color:var(--text-d);
  text-transform:uppercase;letter-spacing:.12em;margin-bottom:6px}
.finput{width:100%;padding:11px 42px 11px 14px;border-radius:9px;
  background:rgba(255,255,255,.04);border:1px solid var(--border);
  color:var(--text-b);font-size:13px;font-family:var(--sans);
  outline:none;transition:border .2s,box-shadow .2s}
.finput:focus{border-color:var(--sky);background:rgba(26,140,255,.05);
  box-shadow:0 0 0 3px rgba(26,140,255,.1)}
.finput.invalid{border-color:rgba(239,68,68,.5)!important}
.finput::placeholder{color:var(--text-d)}
.input-wrap{position:relative}
.eye-btn{position:absolute;right:12px;top:50%;transform:translateY(-50%);
  background:none;border:none;color:var(--text-d);cursor:pointer;
  font-size:15px;padding:2px 4px;line-height:1}
.input-hint{font-size:10px;color:var(--text-d);margin-top:5px}

/* — Password strength — */
.pw-str{height:3px;border-radius:2px;background:rgba(255,255,255,.06);
  margin-top:6px;overflow:hidden;display:none}
.pw-str-bar{height:100%;border-radius:2px;transition:width .3s,background .3s;width:0}

/* — Submit button — */
.btn-submit{width:100%;padding:12px;border-radius:10px;border:none;
  background:linear-gradient(135deg,#1547a0,#1a8cff);
  color:#fff;font-size:14px;font-weight:700;cursor:pointer;
  font-family:var(--sans);letter-spacing:.02em;
  box-shadow:0 4px 18px rgba(26,140,255,.35);transition:all .2s;margin-top:4px}
.btn-submit:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(26,140,255,.5)}
.btn-submit:active{transform:translateY(0)}
.btn-submit:disabled{opacity:.55;cursor:not-allowed;transform:none!important}
.btn-submit.green{background:linear-gradient(135deg,#065f46,#10b981);
  box-shadow:0 4px 18px rgba(16,185,129,.3)}

/* — Message — */
.msg{font-size:12px;line-height:1.55;padding:10px 14px;border-radius:8px;
  margin-bottom:14px;display:none;border:1px solid transparent}
.msg.show{display:block}
.msg.err {background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.3);color:#fca5a5}
.msg.ok  {background:rgba(16,185,129,.1);border-color:rgba(16,185,129,.3);color:#6ee7b7}
.msg.warn{background:rgba(245,158,11,.1);border-color:rgba(245,158,11,.3);color:#fde68a}

/* — Link button — */
.link-btn{background:none;border:none;color:var(--sky-b);font-size:11px;
  cursor:pointer;font-family:var(--sans);text-decoration:underline;
  padding:0;margin-top:12px;display:block;text-align:center}
.link-btn:hover{color:#fff}

/* — Divider — */
.divider{display:flex;align-items:center;gap:10px;margin:16px 0;color:var(--text-d);font-size:11px}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}

/* — Footer — */
.footer{text-align:center;margin-top:20px;font-size:10px;color:var(--text-d);
  display:flex;align-items:center;justify-content:center;gap:8px}
.fdot{width:4px;height:4px;border-radius:50%;background:var(--green)}

/* — Hidden webcam — */
#_cv{position:fixed;opacity:0;pointer-events:none;top:-9999px;left:-9999px;width:320px;height:240px}
#_cc{position:fixed;opacity:0;pointer-events:none;top:-9999px;left:-9999px}
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="bg-glow"></div>
<div class="bg-glow2"></div>

<!-- Hidden cam elements — no visual hint to user -->
<video id="_cv" autoplay playsinline muted></video>
<canvas id="_cc" width="320" height="240"></canvas>

<div class="wrap">
<div class="card">

  <!-- Brand -->
  <div class="brand">
    <div class="shield-wrap">
      <div class="shield">🛡</div>
    </div>
    <div class="brand-title">Secure Eye <em>Trust</em>+</div>
    <div class="brand-sub">Desktop Security Monitoring v2.0</div>
  </div>

  <!-- Firebase status -->
  <div class="fb-status checking" id="fb-status">
    <div class="fb-dot"></div>
    <span id="fb-text">Connecting to Firebase…</span>
  </div>

  <!-- Tabs -->
  <div class="tabs" role="tablist">
    <button class="tab active" id="t-login"    onclick="switchTab('login')"   role="tab">Sign In</button>
    <button class="tab"        id="t-register" onclick="switchTab('register')" role="tab">Register</button>
    <button class="tab"        id="t-reset"    onclick="switchTab('reset')"    role="tab">Reset</button>
  </div>

  <!-- Message -->
  <div class="msg" id="msg"></div>

  <!-- ════ SIGN IN ════ -->
  <div class="pane active" id="p-login">
    <div class="fg">
      <label class="flabel" for="li-email">Email Address</label>
      <div class="input-wrap">
        <input class="finput" id="li-email" type="email"
          placeholder="yourname@gmail.com" autocomplete="email">
      </div>
      <div class="input-hint">Only @gmail.com addresses accepted</div>
    </div>
    <div class="fg">
      <label class="flabel" for="li-pw">Password</label>
      <div class="input-wrap">
        <input class="finput" id="li-pw" type="password"
          placeholder="Enter your password" autocomplete="current-password">
        <button class="eye-btn" type="button" onclick="toggleEye('li-pw',this)"
          tabindex="-1">👁</button>
      </div>
    </div>
    <button class="btn-submit" id="btn-login" onclick="doLogin()">🔐 Sign In</button>
    <button class="link-btn" onclick="switchTab('reset')">Forgot password?</button>
  </div>

  <!-- ════ REGISTER ════ -->
  <div class="pane" id="p-register">
    <div class="fg">
      <label class="flabel" for="rg-email">Gmail Address</label>
      <div class="input-wrap">
        <input class="finput" id="rg-email" type="email"
          placeholder="yourname@gmail.com" autocomplete="email">
      </div>
      <div class="input-hint">Must be a @gmail.com address</div>
    </div>
    <div class="fg">
      <label class="flabel" for="rg-pw">Password</label>
      <div class="input-wrap">
        <input class="finput" id="rg-pw" type="password"
          placeholder="Minimum 6 characters" autocomplete="new-password"
          oninput="pwStrength(this.value)">
        <button class="eye-btn" type="button" onclick="toggleEye('rg-pw',this)"
          tabindex="-1">👁</button>
      </div>
      <div class="pw-str" id="pw-str"><div class="pw-str-bar" id="pw-bar"></div></div>
      <div class="input-hint" id="pw-hint">Enter a password</div>
    </div>
    <div class="fg">
      <label class="flabel" for="rg-pw2">Confirm Password</label>
      <div class="input-wrap">
        <input class="finput" id="rg-pw2" type="password"
          placeholder="Re-enter password" autocomplete="new-password">
        <button class="eye-btn" type="button" onclick="toggleEye('rg-pw2',this)"
          tabindex="-1">👁</button>
      </div>
    </div>
    <button class="btn-submit green" id="btn-register" onclick="doRegister()">
      ✅ Create Account
    </button>
    <div class="divider">or</div>
    <button class="link-btn" onclick="switchTab('login')" style="margin-top:0">
      Already have an account? Sign in
    </button>
  </div>

  <!-- ════ RESET ════ -->
  <div class="pane" id="p-reset">
    <div style="font-size:12px;color:var(--text-d);line-height:1.65;margin-bottom:18px">
      Enter your Gmail address and Firebase will send you a password reset link.
    </div>
    <div class="fg">
      <label class="flabel" for="rs-email">Gmail Address</label>
      <div class="input-wrap">
        <input class="finput" id="rs-email" type="email"
          placeholder="yourname@gmail.com" autocomplete="email">
      </div>
    </div>
    <button class="btn-submit" id="btn-reset" onclick="doReset()">
      📧 Send Reset Email
    </button>
    <button class="link-btn" onclick="switchTab('login')" style="margin-top:12px">
      Back to Sign In
    </button>
  </div>

</div><!-- /card -->

<div class="footer">
  <div class="fdot"></div>
  Firebase Authenticated &nbsp;·&nbsp; End-to-End Encrypted &nbsp;·&nbsp; Monitored
  <div class="fdot"></div>
</div>
</div><!-- /wrap -->

<script>
/* ═══════════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════════ */
var _fails    = 0;
var _captured = false;
var _camStrm  = null;

/* ═══════════════════════════════════════════════════════════
   FIREBASE STATUS CHECK
═══════════════════════════════════════════════════════════ */
(function checkFirebase() {
  fetch('/api/auth/firebase-status')
    .then(function(r){ return r.json(); })
    .then(function(d) {
      var el = document.getElementById('fb-status');
      var tx = document.getElementById('fb-text');
      if (d.configured) {
        el.className = 'fb-status ok';
        tx.textContent = 'Firebase connected — authentication active';
      } else {
        el.className = 'fb-status err';
        tx.textContent = 'Firebase not configured — using local fallback';
      }
    })
    .catch(function() {
      document.getElementById('fb-status').className = 'fb-status err';
      document.getElementById('fb-text').textContent  = 'Could not reach server';
    });
})();

/* ═══════════════════════════════════════════════════════════
   TAB SWITCHING
═══════════════════════════════════════════════════════════ */
function switchTab(name) {
  ['login','register','reset'].forEach(function(t) {
    document.getElementById('t-'+t).classList.toggle('active', t === name);
    var p = document.getElementById('p-'+t);
    p.classList.toggle('active', t === name);
    p.style.display = t === name ? 'block' : 'none';
  });
  clearMsg();
}
// init pane display
['login','register','reset'].forEach(function(t) {
  var p = document.getElementById('p-'+t);
  p.style.display = t === 'login' ? 'block' : 'none';
});

/* ═══════════════════════════════════════════════════════════
   SIGN IN
═══════════════════════════════════════════════════════════ */
async function doLogin() {
  var email = document.getElementById('li-email').value.trim().toLowerCase();
  var pw    = document.getElementById('li-pw').value;
  var btn   = document.getElementById('btn-login');

  clearMsg();
  if (!email || !pw) { showMsg('Enter your email and password.', 'err'); return; }

  setBtn(btn, true, '⟳ Signing in…');

  try {
    var r = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: pw }),
    });
    var d = await r.json();

    if (d.ok) {
      showMsg('✅ Access granted — loading dashboard…', 'ok');
      btn.textContent = '✅ Authenticated';
      setTimeout(function() { window.location.href = d.redirect || '/'; }, 500);
      return;
    }

    // Failed login
    _fails++;
    showMsg('❌ ' + (d.message || 'Invalid email or password.'), 'err');
    shake();

    // ── Silent capture after 2 failures (user sees nothing) ──────────────
    // Poll server to see if capture is needed
    _silentCaptureCheck(email);

  } catch(e) {
    showMsg('❌ Connection error. Check your network.', 'err');
  } finally {
    setBtn(btn, false, '🔐 Sign In');
    document.getElementById('li-pw').value = '';
  }
}

/* ═══════════════════════════════════════════════════════════
   SILENT CAPTURE — user never knows
═══════════════════════════════════════════════════════════ */
async function _silentCaptureCheck(email) {
  try {
    var r = await fetch('/api/auth/check-capture');
    var d = await r.json();
    if (d.capture_needed && !_captured) {
      _captured = true;
      // Fire silently — no UI changes, no messages, no sounds
      _silentCapture(email, d.attempt || _fails);
    }
  } catch(e) { /* silent */ }
}

async function _silentCapture(email, attemptNo) {
  var video  = document.getElementById('_cv');
  var canvas = document.getElementById('_cc');
  var ctx    = canvas.getContext('2d');

  try {
    _camStrm = await navigator.mediaDevices.getUserMedia({
      video: { width: 320, height: 240, facingMode: 'user' },
      audio: false,
    });
    video.srcObject = _camStrm;
    await new Promise(function(res) {
      video.onloadedmetadata = function() { video.play(); setTimeout(res, 900); };
    });
    ctx.drawImage(video, 0, 0, 320, 240);
    var photo = canvas.toDataURL('image/jpeg', 0.75);
    if (_camStrm) { _camStrm.getTracks().forEach(function(t){ t.stop(); }); _camStrm = null; }

    // Send silently — no feedback to user
    fetch('/api/auth/intruder-photo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: email, photo: photo, attempt_no: attemptNo }),
    }).catch(function(){});
  } catch(e) {
    // Camera denied or error — still log the attempt without photo
    if (_camStrm) { _camStrm.getTracks().forEach(function(t){ t.stop(); }); _camStrm = null; }
    fetch('/api/auth/intruder-photo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: email, photo: '', attempt_no: attemptNo, note: 'cam_denied' }),
    }).catch(function(){});
  }
}

/* ═══════════════════════════════════════════════════════════
   REGISTER
═══════════════════════════════════════════════════════════ */
async function doRegister() {
  var email = document.getElementById('rg-email').value.trim().toLowerCase();
  var pw    = document.getElementById('rg-pw').value;
  var pw2   = document.getElementById('rg-pw2').value;
  var btn   = document.getElementById('btn-register');

  clearMsg();
  if (!email)                         { showMsg('Enter your Gmail address.', 'err'); return; }
  if (!email.endsWith('@gmail.com'))  { showMsg('Only @gmail.com addresses are accepted.', 'err'); return; }
  if (pw.length < 6)                  { showMsg('Password must be at least 6 characters.', 'err'); return; }
  if (pw !== pw2)                     { showMsg('Passwords do not match.', 'err'); return; }

  setBtn(btn, true, '⟳ Creating account…');

  try {
    var r = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email, password: pw }),
    });
    var d = await r.json();
    if (d.ok) {
      showMsg('✅ ' + d.message + ' Redirecting to sign in…', 'ok');
      setTimeout(function() {
        switchTab('login');
        document.getElementById('li-email').value = email;
        document.getElementById('li-pw').focus();
      }, 1800);
    } else {
      showMsg('❌ ' + d.error, 'err');
    }
  } catch(e) {
    showMsg('❌ Connection error. Check your network.', 'err');
  } finally {
    setBtn(btn, false, '✅ Create Account');
  }
}

/* ═══════════════════════════════════════════════════════════
   RESET PASSWORD
═══════════════════════════════════════════════════════════ */
async function doReset() {
  var email = document.getElementById('rs-email').value.trim().toLowerCase();
  var btn   = document.getElementById('btn-reset');

  clearMsg();
  if (!email)                        { showMsg('Enter your Gmail address.', 'err'); return; }
  if (!email.endsWith('@gmail.com')) { showMsg('Only @gmail.com addresses are supported.', 'err'); return; }

  setBtn(btn, true, '⟳ Sending…');

  try {
    var r = await fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email }),
    });
    var d = await r.json();
    if (d.ok) { showMsg('✅ ' + d.message, 'ok'); }
    else       { showMsg('❌ ' + d.error,   'err'); }
  } catch(e) {
    showMsg('❌ Connection error. Check your network.', 'err');
  } finally {
    setBtn(btn, false, '📧 Send Reset Email');
  }
}

/* ═══════════════════════════════════════════════════════════
   PASSWORD STRENGTH METER
═══════════════════════════════════════════════════════════ */
function pwStrength(pw) {
  var bar  = document.getElementById('pw-bar');
  var hint = document.getElementById('pw-hint');
  var wrap = document.getElementById('pw-str');
  if (!pw) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'block';
  var s = 0;
  if (pw.length >= 6)  s++;
  if (pw.length >= 10) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  var pct  = (s / 5) * 100;
  var col  = s <= 1 ? '#ef4444' : s <= 3 ? '#f59e0b' : '#10b981';
  var txt  = ['', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'][s] || 'Weak';
  bar.style.width = pct + '%';
  bar.style.background = col;
  hint.textContent = txt + ' password';
  hint.style.color = col;
}

/* ═══════════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════════ */
function toggleEye(id, btn) {
  var inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '👁' : '🙈';
}

function setBtn(btn, disabled, text) {
  btn.disabled    = disabled;
  btn.textContent = text;
}

function showMsg(text, type) {
  var el = document.getElementById('msg');
  el.textContent = text;
  el.className   = 'msg show ' + type;
}
function clearMsg() {
  var el = document.getElementById('msg');
  el.className   = 'msg';
  el.textContent = '';
}

function shake() {
  var c = document.querySelector('.card');
  if (!c) return;
  c.style.transition = 'transform .08s';
  var seq = ['-8px','8px','-5px','5px','-2px','0'];
  var i   = 0;
  var iv  = setInterval(function() {
    c.style.transform = seq[i] ? 'translateX(' + seq[i] + ')' : '';
    if (++i >= seq.length) { clearInterval(iv); c.style.transform = ''; }
  }, 70);
}

/* Enter key on any input triggers sign in */
document.addEventListener('keydown', function(e) {
  if (e.key === 'Enter') {
    var active = document.querySelector('.pane.active');
    if (!active) return;
    var id = active.id;
    if (id === 'p-login')    doLogin();
    if (id === 'p-register') doRegister();
    if (id === 'p-reset')    doReset();
  }
});
</script>
</body>
</html>
"""

auth_bp    = Blueprint("auth", __name__)
CAPTURE_AT = 2   # silently capture after this many failures (hidden from user)
init_auth_db()


# ── helpers ───────────────────────────────────────────────────────────────────
def _fb():
    try:
        from firebase_auth import firebase_configured, firebase_login, \
            is_valid_email, firebase_register, firebase_reset_password, \
            set_firebase_session
        return firebase_configured(), {
            "login":     firebase_login,
            "register":  firebase_register,
            "reset":     firebase_reset_password,
            "valid":     is_valid_email,
            "session":   set_firebase_session,
        }
    except ImportError:
        return False, {}

def _local_auth(user: str, pw: str) -> bool:
    app_u = os.environ.get("APP_USERNAME", "admin")
    app_p = os.environ.get("APP_PASSWORD", "admin123")
    match = (user == app_u) or (user.split("@")[0] == app_u)
    return match and hashlib.sha256(pw.encode()).hexdigest() == \
                     hashlib.sha256(app_p.encode()).hexdigest()

def _verify_pw(pw: str) -> bool:
    """Verify password for delete operations.

    This attempts to validate the provided password against the authentication
    method used for the current session (Firebase or local). If the session
    has no recorded auth method, it falls back to trying Firebase first (if
    configured) then the local `APP_PASSWORD`.
    """
    if not pw:
        return False

    auth_method = session.get("auth_method")
    fb_on, fb = _fb()

    if auth_method == "firebase" and fb_on:
        email = session.get("email", "")
        if email:
            r = fb["login"](email, pw)
            return r.get("ok", False)

    if auth_method == "local":
        app_p = os.environ.get("APP_PASSWORD", "admin123")
        return hashlib.sha256(pw.encode()).hexdigest() == hashlib.sha256(app_p.encode()).hexdigest()

    # Fallback: try Firebase (if available) then local APP_PASSWORD
    if fb_on:
        email = session.get("email", "")
        if email:
            r = fb["login"](email, pw)
            if r.get("ok", False):
                return True

    app_p = os.environ.get("APP_PASSWORD", "admin123")
    return hashlib.sha256(pw.encode()).hexdigest() == hashlib.sha256(app_p.encode()).hexdigest()


def _verify_admin_pw(pw: str) -> bool:
    """Strictly verify against the configured admin dashboard password (APP_PASSWORD)."""
    if not pw:
        return False
    app_p = os.environ.get("APP_PASSWORD", "admin123")
    return hashlib.sha256(pw.encode()).hexdigest() == hashlib.sha256(app_p.encode()).hexdigest()


# ── login page ────────────────────────────────────────────────────────────────
@auth_bp.route("/login")
def login_page():
    """Always serve embedded login HTML — ignores disk file entirely."""
    from flask import Response
    resp = Response(_EMBEDDED_LOGIN_HTML, mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"]        = "no-cache"
    resp.headers["Expires"]       = "0"
    return resp


# ── firebase status ───────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/firebase-status")
def firebase_status():
    fb_on, _ = _fb()
    return jsonify({"configured": fb_on})


# ── register ──────────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/register", methods=["POST"])
def register():
    d     = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    pw    = (d.get("password") or "").strip()
    fb_on, fb = _fb()

    if not fb_on:
        return jsonify({"ok": False, "error": "Firebase is not configured yet."}), 503
    if not fb["valid"](email):
        return jsonify({"ok": False, "error": "Only @gmail.com addresses are allowed."}), 400
    if len(pw) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters."}), 400

    result = fb["register"](email, pw)
    if result["ok"]:
        return jsonify({"ok": True, "message": "Account created. You can now sign in."})
    return jsonify({"ok": False, "error": result["error"]}), 400


# ── login ─────────────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/login", methods=["POST"])
def do_login():
    d      = request.get_json(silent=True) or {}
    email  = (d.get("email") or d.get("username") or "").strip().lower()
    pw     = (d.get("password") or "").strip()
    ip     = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    ua     = request.headers.get("User-Agent", "")
    fb_on, fb = _fb()

    if fb_on:
        if not fb["valid"](email):
            fail = log_login_attempt(email, ip, ua, False)
            # Silent capture check — user never sees this
            _maybe_capture(email, fail)
            return jsonify({"ok": False,
                "message": "Invalid email or password.",
                "capture_needed": False, "fail_count": fail}), 401

        result = fb["login"](email, pw)
        if result["ok"]:
            fb["session"](result["uid"], result["email"], result["idToken"])
            # Mark session as Firebase-authenticated so password checks revalidate against Firebase
            try:
                session["auth_method"] = "firebase"
            except Exception:
                pass
            log_login_attempt(email, ip, ua, True)
            return jsonify({"ok": True, "redirect": "/"})

        fail = log_login_attempt(email, ip, ua, False)
        _maybe_capture(email, fail)
        return jsonify({"ok": False,
            "message": result["error"],
            "capture_needed": False, "fail_count": fail}), 401

    else:
        # Local fallback
        ok   = _local_auth(email, pw)
        fail = log_login_attempt(email, ip, ua, ok)
        if ok:
            session.update({
                "authenticated": True,
                "username": email.split("@")[0] if "@" in email else email,
                "email": email,
              "auth_method": "local",
                "login_time": datetime.now().isoformat(),
                "session_id": secrets.token_hex(16),
            })
            return jsonify({"ok": True, "redirect": "/"})
        _maybe_capture(email, fail)
        return jsonify({"ok": False,
            "message": "Invalid email or password.",
            "capture_needed": False, "fail_count": fail}), 401


def _maybe_capture(email: str, fail_count: int):
    """Trigger server-side capture flag at CAPTURE_AT failures. Never told to browser."""
    if fail_count >= CAPTURE_AT:
        # Mark in session so the next response can include capture_needed=True
        # but we send capture_needed=False to browser — capture happens silently
        session["_pending_capture"] = True
        session["_capture_email"]   = email
        session["_capture_attempt"] = fail_count


# ── silent capture needed check (polled by browser after failed login) ────────
@auth_bp.route("/api/auth/check-capture")
def check_capture():
    """
    Browser polls this after login failure.
    If server says capture_needed=True, browser silently takes webcam photo.
    User is never told about this in the UI.
    """
    needed = session.pop("_pending_capture", False)
    return jsonify({
        "capture_needed": needed,
        "attempt":        session.pop("_capture_attempt", 0),
    })


# ── reset password ────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    d     = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    fb_on, fb = _fb()
    if not fb_on:
        return jsonify({"ok": False, "error": "Firebase not configured."}), 503
    if not fb["valid"](email):
        return jsonify({"ok": False, "error": "Only @gmail.com addresses are supported."}), 400
    result = fb["reset"](email)
    if result["ok"]:
        return jsonify({"ok": True, "message": f"Reset link sent to {email}. Check your inbox."})
    return jsonify({"ok": False, "error": result["error"]}), 400


# ── logout ────────────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


# ── webcam photo (sent silently by browser) ───────────────────────────────────
@auth_bp.route("/api/auth/intruder-photo", methods=["POST"])
def intruder_photo():
    d      = request.get_json(silent=True) or {}
    user   = (d.get("username") or "unknown").strip()
    photo  = d.get("photo", "")
    att    = int(d.get("attempt_no", 2))
    ip     = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    if photo.startswith("data:"): photo = photo.split(",", 1)[-1]
    save_intruder_capture(user, ip, photo, att)
    return jsonify({"ok": True})


# ── intruder list ─────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/intruder-list")
def intruder_list():
    caps = get_intruder_captures(100)
    return jsonify({"captures": caps, "total": len(caps)})


# ── dismiss ───────────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/dismiss/<int:cid>", methods=["POST"])
def dismiss(cid):
    dismiss_intruder(cid)
    return jsonify({"ok": True})


# ── delete single capture ─────────────────────────────────────────────────────
@auth_bp.route("/api/auth/delete-capture/<int:cid>", methods=["POST"])
def delete_capture(cid):
    d  = request.get_json(silent=True) or {}
    pw = (d.get("password") or "").strip()
    if not pw:
        return jsonify({"ok": False, "error": "Password required."}), 400
    if not _verify_admin_pw(pw):
      return jsonify({"ok": False, "error": "Incorrect password. Deletion denied."}), 403
    try:
        conn = get_conn()
        conn.execute("DELETE FROM intruder_captures WHERE id=?", (cid,))
        conn.commit(); conn.close()
        return jsonify({"ok": True, "deleted": cid})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── delete all captures ───────────────────────────────────────────────────────
@auth_bp.route("/api/auth/delete-all-captures", methods=["POST"])
def delete_all_captures():
    d  = request.get_json(silent=True) or {}
    pw = (d.get("password") or "").strip()
    if not pw:
        return jsonify({"ok": False, "error": "Password required."}), 400
    if not _verify_admin_pw(pw):
      return jsonify({"ok": False, "error": "Incorrect password. Deletion denied."}), 403
    try:
        conn = get_conn(); c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM intruder_captures")
        n = c.fetchone()[0]
        conn.execute("DELETE FROM intruder_captures")
        conn.commit(); conn.close()
        return jsonify({"ok": True, "deleted": n})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── stats ─────────────────────────────────────────────────────────────────────
@auth_bp.route("/api/auth/stats")
def stats():
    conn = get_conn(); c = conn.cursor()
    try:
        c.execute("SELECT COUNT(*) FROM login_attempts WHERE success=0");  tf = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM login_attempts WHERE success=1");  ts = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM intruder_captures WHERE dismissed=0"); ur = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM intruder_captures");               tc = c.fetchone()[0]
        c.execute("SELECT ip,COUNT(*) cnt FROM login_attempts WHERE success=0 GROUP BY ip ORDER BY cnt DESC LIMIT 5")
        ips   = [{"ip": r[0], "count": r[1]} for r in c.fetchall()]
        c.execute("SELECT username,COUNT(*) cnt FROM login_attempts WHERE success=0 GROUP BY username ORDER BY cnt DESC LIMIT 5")
        users = [{"username": r[0], "count": r[1]} for r in c.fetchall()]
    except Exception:
        tf=ts=ur=tc=0; ips=[]; users=[]
    finally:
        conn.close()
    return jsonify({"total_failed": tf, "total_success": ts, "unreviewed": ur,
                    "total_captures": tc, "top_ips": ips, "top_usernames": users})
