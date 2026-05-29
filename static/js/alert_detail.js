/**
 * static/js/alert_detail.js  — v4
 * ================================
 * Clickable alert notifications with:
 *   ✅ Full detail popup when clicking any alert card or toast
 *   ✅ Per-alert-type knowledge base with REAL fixes (not just diagnostics)
 *   ✅ ⚡ Apply Fix button — runs the fix on the server (no copy-paste)
 *   ✅ Source Application panel (source process / user / IP / file / Sysmon details)
 *   ✅ "Mark as Resolved" button — writes to DB, removes from panel
 *   ✅ Resolved alerts never reappear (stored in DB permanently)
 *   ✅ Smart KB routing — privilege escalation no longer mismatched as logon
 */

'use strict';

// ── Alert knowledge base — fix steps per alert type ─────────────────────────
//
// Each entry's `fix_command` (when present) maps to a backend handler in
// /api/action/auto-fix-threat. The Apply Fix button POSTs that command and
// shows the result inline. Commands without a fix_command degrade to a
// purely diagnostic / educational view.
const _ALERT_KB = {

  // ── MEMORY ──────────────────────────────────────────────────────────────────
  ram: {
    icon: '💾',
    what: 'RAM (Random Access Memory) is running low. When RAM fills up, Windows uses the hard drive as virtual memory (paging), which is 100x slower — causing freezes and crashes.',
    causes: [
      'Too many programs open at the same time',
      'A process has a memory leak (keeps consuming more RAM over time)',
      'Browser tabs or electron apps consuming excessive memory',
    ],
    fix_steps: [
      'Open Task Manager (Ctrl+Shift+Esc) → click "Memory" column to sort',
      'Find the process using the most RAM — right-click → End Task if it\'s not essential',
      'In browser: close unused tabs or restart the browser',
      'If recurring: increase virtual memory — Search "Adjust the appearance of Windows" → Advanced → Virtual Memory → Change',
    ],
    ps_script: `# Find top 10 RAM-consuming processes
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name, @{N='RAM_MB';E={[Math]::Round($_.WorkingSet64/1MB,1)}}`,
    fix_command:       'find_top_ram',
    fix_button_label:  '⚡ Run RAM Audit',
    fix_description:   'Lists the 10 processes using the most RAM so you can pick what to close.',
    prevent: 'Close apps you are not using. Restart the machine daily. Consider upgrading RAM if consistently above 85%.',
  },

  // ── CPU ──────────────────────────────────────────────────────────────────────
  cpu: {
    icon: '🖥️',
    what: 'CPU usage is very high. This means the processor is working near its maximum capacity, which slows everything down. Sustained high CPU can cause system instability.',
    causes: [
      'A specific process is consuming excessive CPU (bug, loop, or malware)',
      'Antivirus full scan or Windows Update running in background',
      'Too many browser tabs with JavaScript running',
    ],
    fix_steps: [
      'Open Task Manager (Ctrl+Shift+Esc) → CPU tab → identify the top process',
      'If it is "python.exe" (your app): this is normal during log analysis — wait for it to finish',
      'If it is an unknown process: right-click → Open File Location to verify it is legitimate',
      'If a browser: go to browser Task Manager (Shift+Esc in Chrome) and close heavy tabs',
      'Restart the offending process if safe to do so',
    ],
    ps_script: `# List top CPU-consuming processes
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, CPU, Id`,
    fix_command:      'find_top_cpu',
    fix_button_label: '⚡ Run CPU Audit',
    fix_description:  'Lists the 10 processes using the most CPU so you can identify the culprit.',
    prevent: 'Schedule Windows Update and antivirus scans for off-hours (e.g., 2 AM). Close unused applications.',
  },

  // ── DISK ──────────────────────────────────────────────────────────────────────
  disk: {
    icon: '💿',
    what: 'Disk storage is running low or reporting errors. When disk is full or failing, Windows cannot create temp files, log files, or swap files — causing crashes and data loss.',
    causes: [
      'Log files or temp files accumulating over time',
      'Windows Update files not cleaned up',
      'Recycle Bin not emptied',
      'Bad sectors or failing SSD/HDD',
    ],
    fix_steps: [
      'Run Disk Cleanup: Search "Disk Cleanup" → select C: → check all boxes',
      'Empty the Recycle Bin',
      'Open Settings → System → Storage → Cleanup recommendations',
      'For hardware errors: schedule chkdsk on next boot (use Apply Fix below)',
    ],
    ps_script: `# Clear temp files + show disk space
Remove-Item "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue
Get-PSDrive C | Select-Object Used, Free`,
    fix_command:      'clear_temp_files',
    fix_button_label: '⚡ Clear Temp Files',
    fix_description:  'Removes user + system temp files and shows remaining free space.',
    prevent: 'Enable Storage Sense in Windows Settings to auto-clean temp files. Keep at least 15% of disk free.',
  },

  // ── NETWORK ──────────────────────────────────────────────────────────────────
  network: {
    icon: '🌐',
    what: 'An unusually high number of network connections are open. This could indicate malware, a port scanner, or a legitimate app making many simultaneous connections.',
    causes: [
      'Malware or botnet making outbound connections',
      'A legitimate app (backup software, browser sync) making many connections',
      'Port scan or DDoS attack targeting this machine',
    ],
    fix_steps: [
      'Run a network audit (Apply Fix) to see all active connections + the owning process',
      'Look for connections to unknown IP addresses (especially overseas)',
      'If suspicious: identify the process and use Active Response → Kill Process + Block Network',
      'Run a full Windows Defender scan: Settings → Privacy & Security → Virus protection → Quick scan',
    ],
    ps_script: `# Show established connections with owning process
Get-NetTCPConnection -State Established |
  Group-Object OwningProcess | Sort-Object Count -Descending`,
    fix_command:      'audit_network_connections',
    fix_button_label: '⚡ Audit Connections',
    fix_description:  'Lists all established TCP connections grouped by process so you can spot anomalies.',
    prevent: 'Enable Windows Firewall. Block unused inbound ports. Run regular antivirus scans.',
  },

  // ── PRIVILEGE ESCALATION (EID 4672/4673) — was previously misrouted ─────────
  privilege: {
    icon: '🔑',
    what: 'A user (or process running as that user) was assigned privileged Windows tokens at logon — for example SeDebugPrivilege, SeBackupPrivilege, SeImpersonatePrivilege. These tokens let the holder bypass normal security checks. Event ID 4672 fires once per high-privilege logon; EID 4673 fires when a privileged operation is actually invoked.',
    causes: [
      'A user with admin rights signed in normally — this is the COMMON case',
      'A service or scheduled task started as SYSTEM / LocalService — routine',
      'Privilege escalation: a malicious process is using stolen admin credentials',
      'Tooling like PsExec, Mimikatz, or remote-management agents elevating to admin context',
    ],
    fix_steps: [
      'Click Apply Fix below to list every 4672 event with user / source / time',
      'For each entry: is the user expected? Is the time of day expected?',
      'For unexpected entries — review the source workstation in EID 4624 right before the 4672',
      'If a service account is escalating without good reason: rotate its credentials',
      'For human admins: enable Just-In-Time (JIT) admin via Local Admin Password Solution (LAPS) instead of standing admin',
    ],
    ps_script: `# List recent privileged-logon events (EID 4672) with the user account
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -MaxEvents 50 -ErrorAction SilentlyContinue |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time = $_.TimeCreated
      User = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
      Sid  = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserSid'}).'#text'
    }
  } | Format-Table -AutoSize`,
    fix_command:      'audit_privileged_logons',
    fix_button_label: '⚡ Audit Privileged Logons',
    fix_description:  'Lists the 50 most recent 4672 events with username + SID so you can spot unexpected privilege use.',
    prevent: 'Adopt LAPS for standing admin accounts. Enable Credential Guard. Audit admin group membership monthly.',
  },

  // ── FAILED LOGON (EID 4625) ─────────────────────────────────────────────────
  logon: {
    icon: '🚪',
    what: 'Multiple failed login attempts have been detected (Event ID 4625). This may indicate someone is trying to guess a password (brute-force attack), a user with stale credentials, or a misconfigured service.',
    causes: [
      'Attacker attempting to guess username/password',
      'User changed their password but it\'s cached somewhere (phone, mapped drive)',
      'Scheduled task or service running with old credentials',
    ],
    fix_steps: [
      'Click Apply Fix below to apply Windows account lockout policy (5 attempts / 15-min lockout)',
      'Check Event Viewer Security log for EID 4625 — note the username and source IP',
      'If IP is external: add a Windows Firewall block rule via Active Response → Block Network',
      'If IP is internal and a known user: ask them to check cached credentials on their devices',
      'Consider blocking RDP (port 3389) from the public internet',
    ],
    ps_script: `# Show recent failed logons with source IP / workstation
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 -ErrorAction SilentlyContinue |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time   = $_.TimeCreated
      User   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
      IP     = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'
      Reason = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'FailureReason'}).'#text'
    }
  } | Format-Table -AutoSize`,
    fix_command:      'apply_lockout_policy',
    fix_button_label: '⚡ Apply Lockout Policy',
    fix_description:  'Sets the Windows account lockout policy to 5 failed attempts → 15-min lockout. Reversible via "net accounts /lockoutthreshold:0".',
    prevent: 'Enable MFA. Block RDP (port 3389) from the internet. Use a VPN for remote access.',
  },

  // ── ACCOUNT LOCKED OUT (EID 4740) ───────────────────────────────────────────
  lockout: {
    icon: '🔒',
    what: 'A user account was locked out (Event ID 4740) — this happens after the configured number of failed logon attempts is reached. It is the LOCKOUT POLICY doing its job, but the underlying cause needs investigation.',
    causes: [
      'Brute-force attack against this account',
      'A user typed the wrong password too many times (legitimate)',
      'A cached/stale credential on a device repeatedly retrying',
      'A service account whose password was rotated but a server is still using the old one',
    ],
    fix_steps: [
      'Click Apply Fix to list the calling computer of recent 4740 events',
      'For each entry: trace where the bad credential is coming from (a forgotten mapped drive, a phone email config, a Windows service)',
      'Unlock the account: Local Users → right-click the user → uncheck "Account is locked out"',
      'For service accounts: update the password everywhere the account is used',
    ],
    ps_script: `# Show recent account lockouts with the source workstation
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740} -MaxEvents 20 -ErrorAction SilentlyContinue |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time          = $_.TimeCreated
      LockedUser    = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'
      CallerComputer= ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetDomainName'}).'#text'
    }
  } | Format-Table -AutoSize`,
    fix_command:      'audit_account_lockouts',
    fix_button_label: '⚡ Audit Lockouts',
    fix_description:  'Lists the last 20 lockout events with the calling computer so you can find the bad credential source.',
    prevent: 'Use a password manager. Rotate service-account passwords through a vault, not by hand.',
  },

  // ── AUDIT POLICY TAMPER (EID 4719/4739/4713) ────────────────────────────────
  policy: {
    icon: '📜',
    what: 'Security audit policy was modified (Event ID 4719/4739/4713). Attackers tamper with audit policy to hide their tracks. Legitimate changes usually only happen during initial server setup or GPO refresh.',
    causes: [
      'A domain administrator made a policy change (legitimate)',
      'GPO refresh from a Domain Controller (legitimate)',
      'An attacker disabling audit categories to evade detection',
    ],
    fix_steps: [
      'Identify WHO made the change — Event Viewer → Security → EID 4719 → SubjectUserName field',
      'Confirm with the admin that the change was authorized',
      'If unauthorized: revert audit policy to baseline (Apply Fix below)',
      'Investigate further: did the same user trigger other recent events? (logons, file access)',
    ],
    ps_script: `# Show last 10 audit policy changes (4719) with user
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4719} -MaxEvents 10 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Message | Format-List`,
    fix_command:      'restore_audit_policy_baseline',
    fix_button_label: '⚡ Restore Audit Baseline',
    fix_description:  'Re-enables Success+Failure auditing for Logon, Account Management, and Privilege Use categories.',
    prevent: 'Pin a baseline audit policy via GPO. Alert on any 4719 from a non-administrator user.',
  },

  // ── SCHEDULED TASK (EID 4698) ───────────────────────────────────────────────
  task: {
    icon: '⏰',
    what: 'A new scheduled task was registered (Event ID 4698). Scheduled tasks are a top-tier persistence mechanism — once registered, they re-launch the attacker\'s code on every boot/logon/timer.',
    causes: [
      'You (or an admin) installed software that registered a maintenance task — legitimate',
      'Windows Update or another Microsoft component created a task — legitimate',
      'Malware persistence: an attacker created a task to re-run their payload',
    ],
    fix_steps: [
      'Open Task Scheduler (Apply Fix below) to inspect all tasks',
      'Look at the most recently created tasks — check the Action tab for the executable / script they run',
      'If the executable path looks suspicious (Temp / AppData / Downloads / no signature): right-click → Disable, then investigate the file',
      'Once confirmed malicious: Active Response → Remove Persistence (kind=task)',
    ],
    ps_script: `# List the 20 most recently created scheduled tasks
Get-ScheduledTask | Get-ScheduledTaskInfo |
  Sort-Object LastRunTime -Descending |
  Select-Object -First 20 TaskName, LastRunTime, NextRunTime`,
    fix_command:      'open_taskschd_msc',
    fix_button_label: '⚡ Open Task Scheduler',
    fix_description:  'Opens Windows Task Scheduler so you can review tasks directly.',
    prevent: 'Audit /Microsoft/Windows/Defrag, /Microsoft/Windows/UpdateOrchestrator, and the task root for unexpected entries quarterly.',
  },

  // ── NEW SERVICE (EID 7045) ──────────────────────────────────────────────────
  service: {
    icon: '⚙️',
    what: 'A new Windows service was installed (Event ID 7045). Services run silently in the background and survive reboots — this is a common malware-persistence technique.',
    causes: [
      'You installed legitimate software that registers a service — common',
      'A driver was installed — common',
      'Malware installed a service to maintain access',
    ],
    fix_steps: [
      'Open Services console (Apply Fix below)',
      'Sort by Description / Path — look for entries with random names or a path under Temp/AppData/Downloads',
      'If you find a suspicious service: right-click → Stop, then Disable, then investigate the binary',
      'Once confirmed malicious: Active Response → Remove Persistence (kind=service)',
    ],
    ps_script: `# List the 20 most recently created services
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 20 -ErrorAction SilentlyContinue |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
      Time      = $_.TimeCreated
      Service   = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ServiceName'}).'#text'
      ImagePath = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'ImagePath'}).'#text'
    }
  } | Format-Table -AutoSize`,
    fix_command:      'open_services_msc',
    fix_button_label: '⚡ Open Services Console',
    fix_description:  'Opens the Windows Services console so you can review and disable suspicious services.',
    prevent: 'Application allow-listing (AppLocker / WDAC) prevents unknown services from being installed in the first place.',
  },

  // ── NEW ADMIN / GROUP CHANGE (EID 4720/4728/4732) ───────────────────────────
  account: {
    icon: '👤',
    what: 'A user account was created, or someone was added to the Administrators group (Event ID 4720 / 4728 / 4732). Creating an admin account is the most common post-compromise persistence move.',
    causes: [
      'You (or IT) created a legitimate new user — verify',
      'A new admin was added intentionally — verify',
      'An attacker added themselves to Administrators to maintain persistence',
    ],
    fix_steps: [
      'Open Local Users console (Apply Fix below)',
      'Inspect the Administrators group — does every member belong there?',
      'For an unexpected account: right-click → Disable account (do not delete yet — preserve evidence)',
      'Run the apply-fix script to also dump the recent 4720/4728 events for your incident report',
    ],
    ps_script: `# Show local Administrators group + recent 4720/4728 events
Get-LocalGroupMember -Group Administrators | Format-Table -AutoSize
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4728,4732} -MaxEvents 10 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message | Format-List`,
    fix_command:      'open_lusrmgr_msc',
    fix_button_label: '⚡ Open Local Users',
    fix_description:  'Opens the Local Users and Groups console so you can review membership directly.',
    prevent: 'Limit Administrators group to 1-2 named accounts. Use UAC at maximum. Audit group membership quarterly.',
  },

  // ── GENERIC LOGS ────────────────────────────────────────────────────────────
  logs: {
    icon: '📋',
    what: 'Multiple ERROR or CRITICAL entries have been found in the Windows Event Log. These indicate application crashes, service failures, or system errors that need attention.',
    causes: [
      'An application or service crashed or failed to start',
      'A Windows component encountered an unexpected error',
      'Hardware issue causing software errors (disk, RAM, or driver problem)',
    ],
    fix_steps: [
      'Click Apply Fix below to run System File Checker — repairs corrupted Windows files',
      'Go to Log Categories in the sidebar to see the specific error messages',
      'Click the 🤖 Explain button on any red error row for AI-powered analysis',
      'For driver issues: Settings → Windows Update → Check for updates',
    ],
    ps_script: `# Run System File Checker (fixes corrupted Windows files)
sfc /scannow

# View recent Application errors
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 10 |
  Select-Object TimeCreated, ProviderName, Message | Format-List`,
    fix_command:      'run_sfc_scannow',
    fix_button_label: '⚡ Run sfc /scannow',
    fix_description:  'Scans and repairs corrupted Windows system files. Takes 3-5 minutes; output appears in the popup.',
    prevent: 'Keep Windows and all applications updated. Run sfc /scannow monthly. Keep disk usage below 80%.',
  },

  // ── WINDOWS UPDATE ──────────────────────────────────────────────────────────
  update: {
    icon: '🔄',
    what: 'Windows Update encountered errors. Missing security updates leave your system vulnerable to known attacks and exploits.',
    causes: [
      'Windows Update service stopped or disabled',
      'Corrupted Windows Update cache',
      'Insufficient disk space for update files',
      'Group Policy blocking updates',
    ],
    fix_steps: [
      'Click Apply Fix below to reset the Windows Update components automatically',
      'Check disk space — need at least 10 GB free for large updates',
      'After fix runs: Settings → Windows Update → Check for updates',
    ],
    ps_script: `# Reset Windows Update (run as Administrator)
Stop-Service wuauserv, cryptSvc, bits, msiserver -Force
Rename-Item "C:\\Windows\\SoftwareDistribution" "SoftwareDistribution.old" -ErrorAction SilentlyContinue
Start-Service wuauserv, cryptSvc, bits, msiserver
Write-Host "Windows Update reset complete — try updating again"`,
    fix_command:      'wu_reset',
    fix_button_label: '⚡ Reset Windows Update',
    fix_description:  'Stops update services, renames the cache, restarts the services. Resolves most update failures.',
    prevent: 'Enable automatic updates. Ensure Windows Update service is set to Automatic startup.',
  },
};

// Map alert category/type/title keywords → KB key
//
// IMPORTANT: order matters here — the *more specific* condition must come
// first. Previously the rule `t.includes('logon')` matched the title
// "Privilege escalation: 63 special logon events" and routed it to the
// failed-logon KB (wrong content). The privilege check now wins.
function _getKBKey(alert) {
  const t   = (alert.title || alert.label || alert.name || '').toLowerCase();
  const c   = (alert.category || '').toLowerCase();
  const eid = parseInt(alert.event_id || 0, 10);

  // Exact event-ID matches first (highest precedence)
  if ([4672, 4673].includes(eid))                          return 'privilege';
  if ([4740].includes(eid))                                return 'lockout';
  if ([4625, 4771, 4776].includes(eid))                    return 'logon';
  if ([4719, 4739, 4713, 4902, 4904, 4905].includes(eid))  return 'policy';
  if ([4698, 4699, 4700, 4701, 4702].includes(eid))        return 'task';
  if ([7045, 7036, 7040].includes(eid))                    return 'service';
  if ([4720, 4728, 4732, 4756].includes(eid))              return 'account';

  // Category-based routing
  if (c === 'privilege_escalation')                        return 'privilege';
  if (c === 'persistence' && t.includes('task'))           return 'task';
  if (c === 'persistence' && t.includes('service'))        return 'service';
  if (c === 'policy_tamper')                               return 'policy';
  if (c === 'brute_force')                                 return 'logon';
  if (c === 'patching')                                    return 'update';

  // Title-keyword routing — specific terms BEFORE generic ones
  if (t.includes('privilege') || t.includes('elevation') || t.includes('escalation')) return 'privilege';
  if (t.includes('lockout') || t.includes('locked out')) return 'lockout';
  if (t.includes('audit policy') || t.includes('policy change') || t.includes('policy disabled')) return 'policy';
  if (t.includes('scheduled task') || t.includes('schtasks')) return 'task';
  if (t.includes('new service') || t.includes('service installed')) return 'service';
  if (t.includes('admin group') || t.includes('user created') || t.includes('account created')) return 'account';
  if (t.includes('failed log') || t.includes('4625') || t.includes('brute')) return 'logon';
  if (t.includes('memory') || t.includes('ram')) return 'ram';
  if (t.includes('cpu')) return 'cpu';
  if (t.includes('disk') || t.includes('storage') || t.includes('hardware error')) return 'disk';
  if (t.includes('connection') || c === 'network') return 'network';
  if (t.includes('update')) return 'update';

  // Fallback
  return 'logs';
}

// ── Resolved alert IDs set (loaded from server on init) ─────────────────────
window._resolvedAlertIds = new Set();

async function _loadResolvedIds() {
  try {
    const r = await fetch('/api/alerts/resolved-ids');
    const d = await r.json();
    if (d.ids) d.ids.forEach(id => window._resolvedAlertIds.add(String(id)));
  } catch(e) { /* offline — not critical */ }
}

// ── Main: open detail popup for an alert object ──────────────────────────────

window.openAlertDetail = function(alert) {
  if (!alert) return;

  const kb    = _ALERT_KB[_getKBKey(alert)] || _ALERT_KB.logs;
  const isRes = window._resolvedAlertIds.has(String(alert.id));
  const sev   = (alert.type || 'warning').toLowerCase();

  const COLS = {
    critical: { text:'#ef4444', bg:'rgba(239,68,68,.12)', border:'rgba(239,68,68,.3)', glow:'rgba(239,68,68,.15)' },
    warning:  { text:'#f59e0b', bg:'rgba(245,158,11,.1)',  border:'rgba(245,158,11,.25)',glow:'rgba(245,158,11,.1)' },
    info:     { text:'#3b82f6', bg:'rgba(59,130,246,.1)',  border:'rgba(59,130,246,.25)',glow:'rgba(59,130,246,.1)' },
  };
  const c  = COLS[sev] || COLS.warning;
  const e  = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const steps = (arr) => (arr||[]).map((item,i) =>
    `<div style="display:flex;gap:10px;margin-bottom:10px;align-items:flex-start">
      <span style="width:20px;height:20px;border-radius:50%;background:rgba(59,130,246,.15);
        color:#60a5fa;font-size:9px;font-weight:800;display:flex;align-items:center;
        justify-content:center;flex-shrink:0;border:1px solid rgba(59,130,246,.2)">${i+1}</span>
      <span style="font-size:12px;color:#cbd5e1;line-height:1.65;padding-top:1px">${e(item)}</span>
    </div>`
  ).join('');

  const bullets = (arr, col) => (arr||[]).map(item =>
    `<div style="display:flex;gap:8px;margin-bottom:8px;align-items:flex-start">
      <span style="width:5px;height:5px;border-radius:50%;background:${col};
        margin-top:6px;flex-shrink:0"></span>
      <span style="font-size:12px;color:#94a3b8;line-height:1.6">${e(item)}</span>
    </div>`
  ).join('');

  const secHdr = (icon, label, col) =>
    `<div style="display:flex;align-items:center;gap:7px;margin-bottom:10px;
      padding-bottom:8px;border-bottom:1px solid rgba(255,255,255,.06)">
      <span style="font-size:11px">${icon}</span>
      <span style="font-size:9px;font-weight:800;color:${col};text-transform:uppercase;
        letter-spacing:.1em;font-family:monospace">${label}</span>
    </div>`;

  // ── Build or reuse overlay ────────────────────────────────────────────────
  let overlay = document.getElementById('alert-detail-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'alert-detail-overlay';
    overlay.style.cssText = `
      position:fixed;inset:0;background:rgba(0,0,0,.75);backdrop-filter:blur(8px);
      z-index:10500;display:flex;align-items:center;justify-content:center;padding:16px;
    `;
    overlay.addEventListener('click', (ev) => {
      if (ev.target === overlay) closeAlertDetail();
    });
    document.body.appendChild(overlay);
  }
  overlay.style.display = 'flex';

  overlay.innerHTML = `
    <div id="alert-detail-box" style="
      background:#0a1018;border:1px solid rgba(255,255,255,.1);border-radius:14px;
      width:100%;max-width:780px;max-height:90vh;overflow-y:auto;
      box-shadow:0 32px 100px rgba(0,0,0,.85),0 0 0 1px rgba(255,255,255,.04);
      animation:adSlideIn .22s cubic-bezier(.16,1,.3,1)
    ">
      <style>
        @keyframes adSlideIn{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
        @keyframes adSpin{to{transform:rotate(360deg)}}
        .ad-copy-flash{animation:adCopyFlash .4s ease}
        @keyframes adCopyFlash{0%,100%{background:rgba(59,130,246,.15)}50%{background:rgba(59,130,246,.35)}}
      </style>

      <!-- ═══ HEADER ═══ -->
      <div style="
        padding:18px 22px 14px;
        background:linear-gradient(135deg,#0d1626,#0f1a30);
        border-radius:14px 14px 0 0;border-bottom:1px solid rgba(255,255,255,.07);
        position:relative;overflow:hidden;
      ">
        <!-- Top accent bar -->
        <div style="position:absolute;top:0;left:0;right:0;height:2px;
          background:linear-gradient(90deg,${c.text},#8b5cf6 50%,${c.text})"></div>

        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">
              <span style="font-size:18px">${kb.icon}</span>
              <span style="font-size:15px;font-weight:800;color:#fff;letter-spacing:-.01em">
                ${e(alert.title || 'Alert Detail')}
              </span>
              <span style="font-size:9px;padding:2px 8px;border-radius:4px;font-weight:800;
                background:${c.bg};color:${c.text};border:1px solid ${c.border};
                font-family:monospace;text-transform:uppercase;letter-spacing:.07em">
                ${sev.toUpperCase()}
              </span>
              ${isRes ? `<span style="font-size:9px;padding:2px 8px;border-radius:4px;font-weight:800;
                background:rgba(34,197,94,.12);color:#4ade80;border:1px solid rgba(34,197,94,.25);
                font-family:monospace">✅ RESOLVED</span>` : ''}
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:5px">
              <span style="font-size:9px;padding:2px 7px;border-radius:4px;
                background:rgba(255,255,255,.05);color:#64748b;font-family:monospace">
                📡 ${e(alert.source || 'System')}
              </span>
              <span style="font-size:9px;padding:2px 7px;border-radius:4px;
                background:rgba(255,255,255,.05);color:#64748b;font-family:monospace">
                🗂 ${e((alert.category||'system').toUpperCase())}
              </span>
              <span style="font-size:9px;padding:2px 7px;border-radius:4px;
                background:rgba(255,255,255,.05);color:#64748b;font-family:monospace">
                🕐 ${e(alert.detail || '')}
              </span>
            </div>
          </div>
          <button onclick="closeAlertDetail()" style="
            background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);
            color:#94a3b8;width:30px;height:30px;border-radius:8px;cursor:pointer;
            font-size:14px;display:flex;align-items:center;justify-content:center;flex-shrink:0
          ">✕</button>
        </div>
      </div>

      <!-- ═══ BODY ═══ -->
      <div style="padding:14px 20px 20px;display:flex;flex-direction:column;gap:12px">

        <!-- What is this? -->
        <div style="background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);
          border-radius:10px;padding:14px 16px">
          ${secHdr('💬','What is this?','#94a3b8')}
          <p style="font-size:13px;color:#cbd5e1;line-height:1.75;margin:0">${e(kb.what)}</p>
        </div>

        <!-- Source Application — concrete details about what triggered this -->
        ${_adRenderSourceSection(alert)}

        <!-- Causes + Fix Steps -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div style="background:rgba(239,68,68,.04);border:1px solid rgba(239,68,68,.12);
            border-radius:10px;padding:14px 16px">
            ${secHdr('⚠️','Likely causes','#ef4444')}
            ${bullets(kb.causes, '#ef4444')}
          </div>
          <div style="background:rgba(34,197,94,.04);border:1px solid rgba(34,197,94,.12);
            border-radius:10px;padding:14px 16px">
            ${secHdr('🔧','How to fix — step by step','#22c55e')}
            ${steps(kb.fix_steps)}
          </div>
        </div>

        <!-- PowerShell Fix Script -->
        ${kb.ps_script ? `
        <div style="background:rgba(0,0,0,.3);border-radius:10px;
          border:1px solid rgba(255,255,255,.07);overflow:hidden">
          <div style="padding:8px 14px;background:rgba(0,0,0,.3);
            border-bottom:1px solid rgba(255,255,255,.06);
            display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px">
            <span style="font-size:9px;font-weight:800;color:#475569;font-family:monospace;
              text-transform:uppercase;letter-spacing:.07em">💻 PowerShell Fix Script</span>
            <div style="display:flex;gap:6px;flex-wrap:wrap">
              ${kb.fix_command ? `
              <button id="ad-applyfix-btn"
                onclick="_adApplyFix('${e(kb.fix_command)}','${e(String(alert.id||''))}','${e(_getKBKey(alert))}')"
                title="${e(kb.fix_description || 'Runs the fix on this machine via the SecureEyeTrust+ backend.')}"
                style="padding:5px 14px;border-radius:5px;font-size:10px;font-weight:800;
                background:linear-gradient(135deg,#10b981,#059669);
                border:1px solid #059669;color:#fff;cursor:pointer;font-family:monospace;
                box-shadow:0 2px 8px rgba(16,185,129,.4);letter-spacing:.02em">
                ${e(kb.fix_button_label || '⚡ Apply Fix')}
              </button>` : ''}
              <button id="ad-copy-btn" onclick="_adCopyScript()" style="
                padding:5px 12px;border-radius:5px;font-size:10px;font-weight:700;
                background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);
                color:#60a5fa;cursor:pointer;font-family:monospace">📋 Copy</button>
              <button onclick="_adShowRunHelp()" style="
                padding:5px 12px;border-radius:5px;font-size:10px;font-weight:700;
                background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
                color:#94a3b8;cursor:pointer;font-family:monospace">💻 How to run</button>
            </div>
          </div>
          ${kb.fix_command && kb.fix_description ? `
          <div style="padding:8px 14px;background:rgba(16,185,129,.04);
            border-bottom:1px solid rgba(255,255,255,.04);font-size:11px;color:#86efac;line-height:1.55">
            <span style="opacity:.75">What "Apply Fix" does:</span> ${e(kb.fix_description)}
          </div>` : ''}
          <pre id="ad-script-code" style="margin:0;padding:10px 14px;font-family:monospace;
            font-size:10px;color:#7dd3fc;line-height:1.7;white-space:pre-wrap;
            word-break:break-all;background:transparent">${e(kb.ps_script)}</pre>
          <!-- Result panel — populated by _adApplyFix() -->
          <div id="ad-applyfix-result" style="display:none;border-top:1px solid rgba(255,255,255,.06);
            padding:10px 14px;font-family:monospace;font-size:11px;line-height:1.6"></div>
        </div>` : ''}

        <!-- Prevention -->
        <div style="background:rgba(167,139,250,.04);border:1px solid rgba(167,139,250,.15);
          border-radius:10px;padding:14px 16px">
          ${secHdr('🛡️','Prevention','#a78bfa')}
          <p style="font-size:12px;color:#c4b5fd;line-height:1.7;margin:0">${e(kb.prevent||'')}</p>
        </div>

        <!-- ═══ RESOLVE BUTTON ═══ -->
        <div style="background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.2);
          border-radius:10px;padding:14px 16px">
          <div style="font-size:9px;font-weight:800;color:#22c55e;text-transform:uppercase;
            letter-spacing:.1em;font-family:monospace;margin-bottom:10px">
            ✅ Mark as Resolved
          </div>
          <p style="font-size:12px;color:#94a3b8;line-height:1.65;margin:0 0 12px">
            Once you have applied the fix, mark this alert as resolved.
            It will be removed from the notification panel and <strong style="color:#4ade80">saved to the database</strong>
            so it will not reappear — even after a restart.
          </p>
          ${isRes
            ? `<div style="padding:8px 16px;border-radius:7px;background:rgba(34,197,94,.1);
                border:1px solid rgba(34,197,94,.2);color:#4ade80;font-size:12px;font-weight:700;
                text-align:center">✅ This alert is already marked as resolved</div>`
            : `<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
                <textarea id="ad-resolve-note" placeholder="Optional: write what you did to fix this (e.g. 'Ended python.exe process, freed 2GB RAM')"
                  style="flex:1;min-width:200px;height:52px;padding:8px 10px;border-radius:7px;
                    background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.1);
                    color:#cbd5e1;font-size:11px;font-family:sans-serif;resize:none;
                    outline:none;line-height:1.5"></textarea>
                <button id="ad-resolve-btn" onclick="_adMarkResolved('${e(String(alert.id))}')" style="
                  padding:10px 20px;border-radius:8px;font-size:12px;font-weight:800;
                  background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.3);
                  color:#4ade80;cursor:pointer;font-family:monospace;white-space:nowrap;
                  transition:all .15s;letter-spacing:.02em
                " onmouseover="this.style.background='rgba(34,197,94,.3)'"
                   onmouseout="this.style.background='rgba(34,197,94,.15)'">
                  ✅ Mark Resolved
                </button>
              </div>`
          }
        </div>

      </div>

      <!-- ═══ FOOTER ═══ -->
      <div style="padding:10px 20px;border-top:1px solid rgba(255,255,255,.06);
        display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;
        background:rgba(0,0,0,.2);border-radius:0 0 14px 14px">
        <span style="font-size:9px;color:#1e3050;font-family:monospace">
          Secure Eye Trust+ — Alert Analysis Engine
        </span>
        <button onclick="closeAlertDetail()" style="
          background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.1);
          color:#94a3b8;padding:6px 18px;border-radius:6px;cursor:pointer;font-size:11px">
          Close
        </button>
      </div>
    </div>
  `;

  // Store current script for copy
  window._adCurrentScript = kb.ps_script || '';
  window._adCurrentAlertId = String(alert.id);

  // Close on Escape
  document.addEventListener('keydown', _adEscHandler);
};

// ── Helper functions ─────────────────────────────────────────────────────────

function closeAlertDetail() {
  const overlay = document.getElementById('alert-detail-overlay');
  if (overlay) overlay.style.display = 'none';
  document.removeEventListener('keydown', _adEscHandler);
}

function _adEscHandler(e) { if (e.key === 'Escape') closeAlertDetail(); }

/* ── Source Application section ────────────────────────────────────────────
 *
 * Renders WHAT triggered this alert — the concrete entity (event id,
 * source process, user, IP, file, sysmon image+parent+command+PID, YARA
 * rule). Previously the modal only showed the generic "what is this?"
 * text from the KB; the operator had to dig through Event Viewer to find
 * out which application was responsible. Now every concrete detail the
 * alert carries is shown right here.
 */
function _adRenderSourceSection(alert) {
  if (!alert) return '';
  const safe = v => (v === undefined || v === null || v === '') ? null : String(v);
  const E = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // Collect every concrete field the alert carries
  const rows = [];
  const push = (label, val) => { if (safe(val)) rows.push({label, val: safe(val)}); };
  push('Event ID',         alert.event_id);
  push('Event label',      alert.label);
  push('Log source',       alert.source);
  push('Category',         alert.category);
  push('User account',     alert.user || alert.target_user);
  push('Source IP',        alert.ip || alert.source_ip);
  push('Source host',      alert.source_host || alert.workstation);
  // Sysmon specifics
  push('Process image',    alert.image || alert.process_name);
  push('Parent process',   alert.parent || alert.parent_image);
  push('PID',              alert.pid || alert.process_id);
  push('Command line',     (alert.command || alert.command_line || '').slice(0, 200));
  push('Signed',           alert.signed !== undefined ? (alert.signed ? 'yes' : 'no') : null);
  // YARA / file specifics
  push('YARA rule',        alert.yara_rule || alert.rule);
  push('File path',        alert.file_path || alert.path);
  push('SHA-256',          alert.sha256 ? String(alert.sha256).slice(0, 16) + '…' : null);
  // Registry / persistence
  push('Target object',    alert.target_object || alert.target);
  push('Target file',      alert.target_file);
  // Risk + timing
  push('Risk score',       alert.risk_score);
  push('Time',             (alert.timestamp || '').slice(0, 19));
  push('Repeated',         (alert.count && alert.count > 1) ? `${alert.count}× within dedup window` : null);

  // Truncated raw message (only if it adds info)
  const msg = (alert.message || alert.description || '').slice(0, 400);

  if (rows.length === 0 && !msg) return '';

  // Pick a heading icon based on what kind of evidence we have
  let icon = '🎯';
  if (alert.yara_rule || alert.file_path) icon = '📁';
  else if (alert.image || alert.pid)      icon = '⚙️';
  else if (alert.user || alert.ip)        icon = '👤';

  return `
    <div style="background:rgba(59,130,246,.04);border:1px solid rgba(59,130,246,.18);
      border-radius:10px;padding:14px 16px">
      <div style="font-size:9px;font-weight:800;color:#60a5fa;text-transform:uppercase;
        letter-spacing:.1em;font-family:monospace;margin-bottom:10px">
        ${icon} Source Application — what triggered this alert
      </div>
      ${rows.length ? `
      <div style="display:grid;grid-template-columns:140px 1fr;gap:6px 12px;font-size:11.5px;line-height:1.55">
        ${rows.map(r => `
          <div style="color:#64748b">${E(r.label)}</div>
          <div style="color:#cbd5e1;font-family:monospace;word-break:break-all">${E(r.val)}</div>
        `).join('')}
      </div>` : ''}
      ${msg ? `
      <details style="margin-top:${rows.length ? '10px' : '0'};font-size:11px">
        <summary style="cursor:pointer;color:#64748b;font-family:monospace">▸ raw message</summary>
        <pre style="margin:6px 0 0;padding:8px 10px;background:rgba(0,0,0,.25);border-radius:6px;
          color:#94a3b8;font-size:10.5px;line-height:1.55;white-space:pre-wrap;word-break:break-word">${E(msg)}</pre>
      </details>` : ''}
    </div>
  `;
}


/* ── Apply Fix button — runs the predefined safe command on the server ────
 *
 * Posts to /api/action/auto-fix-threat with the kb.fix_command. The
 * backend has a fixed dispatch table (see _THREAT_EXPLAIN +
 * auto_fix_threat in api/response_actions_api.py) so there's no
 * arbitrary script execution from the UI — only the pre-vetted command
 * names are accepted.
 */
async function _adApplyFix(command, alertId, kbKey) {
  if (!command) return;
  const btn   = document.getElementById('ad-applyfix-btn');
  const panel = document.getElementById('ad-applyfix-result');
  if (!panel) return;

  // ── Themed confirmation modal (replaces native confirm() so the
  //    dialog matches the dark UI instead of showing "localhost:5000")
  const confirmed = await _adConfirmFixModal(command, kbKey || alertId);
  if (!confirmed) return;

  const origText = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled = true;
    btn.style.opacity = '0.6';
    btn.textContent = '⏳ Working…';
  }
  panel.style.display = 'block';
  panel.style.background    = 'rgba(59,130,246,.06)';
  panel.style.borderColor   = 'rgba(59,130,246,.2)';
  panel.style.color         = '#93c5fd';
  // ── Live progress: shows the command + elapsed time so the user
  //    knows why sfc / DISM is taking minutes instead of seconds.
  const progressStart = Date.now();
  const _adEsc = function (s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
    });
  };
  const _adRenderProgress = function () {
    const sec = Math.floor((Date.now() - progressStart) / 1000);
    const mm  = Math.floor(sec / 60);
    const ss  = String(sec % 60).padStart(2, '0');
    // Friendly hint about what the command is doing (and why it takes
    // time for the slow ones).
    let hint = 'Sending the command to the server…';
    if (/sfc|run_sfc/i.test(command))                 hint = 'Scanning Windows system files (sfc /scannow). This takes 3–5 minutes — Windows is verifying every protected file against its catalogue.';
    else if (/DISM|RestoreHealth/i.test(command))     hint = 'Running DISM /RestoreHealth — repairing the component store from Windows Update.';
    else if (/chkdsk/i.test(command))                 hint = 'Running chkdsk on the system volume.';
    else if (/logs|Get-WinEvent/i.test(command))      hint = 'Querying recent event log entries on the server.';
    else if (/restart|reset|service/i.test(command))  hint = 'Restarting / resetting the affected service.';

    panel.innerHTML =
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">' +
        '<span style="font-weight:800;color:#fbbf24">' +
          '<span style="display:inline-block;animation:adspin 1.2s linear infinite">⏳</span> ' +
          'Running fix on the system…' +
        '</span>' +
        '<span style="font-family:JetBrains Mono,monospace;color:#fde68a;font-weight:700">' +
          mm + ':' + ss +
        '</span>' +
      '</div>' +
      '<div style="font-size:11.5px;color:#cbd5e1;line-height:1.65;margin-bottom:8px">' +
        _adEsc(hint) +
      '</div>' +
      '<div style="background:rgba(0,0,0,.3);border-radius:6px;padding:8px 12px;' +
                  'font-family:JetBrains Mono,monospace;font-size:10.5px;color:#7dd3fc;line-height:1.7">' +
        '$ ' + _adEsc(command) +
      '</div>';
  };
  // First paint then refresh once per second while waiting
  _adRenderProgress();
  if (!document.getElementById('ad-spin-css')) {
    const css = document.createElement('style');
    css.id = 'ad-spin-css';
    css.textContent = '@keyframes adspin{from{transform:rotate(0)}to{transform:rotate(360deg)}}';
    document.head.appendChild(css);
  }
  const progressTimer = setInterval(_adRenderProgress, 1000);

  try {
    const r = await fetch('/api/action/auto-fix-threat', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ command, rule_id: kbKey || '', alert_id: alertId || '' }),
    });
    const d = await r.json();
    clearInterval(progressTimer);
    const ok = d.ok || d.success;
    panel.style.background  = ok ? 'rgba(16,185,129,.06)' : 'rgba(239,68,68,.06)';
    panel.style.color       = ok ? '#86efac' : '#fca5a5';

    // Build a multi-line result panel — show the detail line AND any
    // captured stdout so the operator sees evidence of what happened.
    const E2 = (s) => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const stdout = d.stdout || (Array.isArray(d.details) ? d.details.join('\n') : '');
    let html = `<div style="font-weight:800;margin-bottom:6px">${ok ? '✅' : '✗'} ${E2(d.detail || (ok ? 'Fix applied' : 'Fix failed'))}</div>`;
    if (stdout) {
      html += `<pre style="margin:6px 0 0;padding:8px 10px;background:rgba(0,0,0,.3);border-radius:6px;
        color:#cbd5e1;font-size:10.5px;line-height:1.55;white-space:pre-wrap;word-break:break-word;
        max-height:240px;overflow:auto">${E2(stdout)}</pre>`;
    }
    panel.innerHTML = html;

    if (btn) {
      btn.textContent = ok ? '✓ Applied' : '✗ Failed';
      btn.style.background = ok ? 'rgba(16,185,129,.5)' : 'rgba(239,68,68,.4)';
      if (!ok) {
        // Allow retry after 3s if it failed
        setTimeout(() => {
          if (btn) {
            btn.disabled = false;
            btn.style.opacity = '';
            btn.textContent = origText;
            btn.style.background = 'linear-gradient(135deg,#10b981,#059669)';
          }
        }, 3000);
      }
    }
  } catch (err) {
    clearInterval(progressTimer);
    panel.style.background = 'rgba(239,68,68,.08)';
    panel.style.color      = '#fca5a5';
    panel.innerHTML        = `<div style="font-weight:800">✗ Network error</div><div style="margin-top:4px">${err.message}</div>`;
    if (btn) {
      btn.disabled = false;
      btn.style.opacity = '';
      btn.textContent = origText;
    }
  }
}


/* ──────────────────────────────────────────────────────────────────────────
 * _adConfirmFixModal — themed replacement for the native confirm() popup.
 *
 * Returns a Promise that resolves to `true` (Run) or `false` (Cancel).
 * Matches the rest of the dark UI — no more browser "localhost:5000" popup.
 * ────────────────────────────────────────────────────────────────────────── */
function _adConfirmFixModal(command, alertLabel) {
  return new Promise(function (resolve) {
    const esc = function (s) {
      return String(s).replace(/[&<>"']/g, function (c) {
        return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
      });
    };
    const overlay = document.createElement('div');
    overlay.className = 'ad-confirm-overlay';
    overlay.innerHTML =
      '<div class="ad-confirm-modal" role="dialog" aria-modal="true">' +
        '<div class="ad-confirm-title">🛠 Apply Fix on this Machine?</div>' +
        '<div class="ad-confirm-sub">' +
          'The action below will run on the host where Secure Eye Trust+ is ' +
          'installed. Every run is logged in the audit history.' +
        '</div>' +
        '<div class="ad-confirm-block">' +
          '<div class="ad-confirm-block-row"><span class="ad-confirm-key">Command</span>' +
            '<span class="ad-confirm-val"><code>' + esc(command) + '</code></span></div>' +
          '<div class="ad-confirm-block-row"><span class="ad-confirm-key">Alert</span>' +
            '<span class="ad-confirm-val">' + esc(alertLabel || '—') + '</span></div>' +
        '</div>' +
        '<div class="ad-confirm-hint">' +
          '⚠ Some commands need <strong>Administrator</strong> rights. If you see ' +
          '<em>"permission denied"</em>, restart SecureEyeTrust+ as Administrator and try again.' +
        '</div>' +
        '<div class="ad-confirm-row">' +
          '<button class="ad-confirm-btn ad-confirm-btn--cancel" data-act="cancel" type="button">Cancel</button>' +
          '<button class="ad-confirm-btn ad-confirm-btn--ok"     data-act="ok"     type="button">▶ Run Fix</button>' +
        '</div>' +
      '</div>';

    // One-time CSS
    if (!document.getElementById('ad-confirm-css')) {
      const css = document.createElement('style');
      css.id = 'ad-confirm-css';
      css.textContent = [
        '.ad-confirm-overlay{position:fixed;inset:0;z-index:10002;',
        '  background:rgba(0,0,0,.7);backdrop-filter:blur(6px);',
        '  display:flex;align-items:center;justify-content:center;',
        '  animation:ad-confirm-fadein .15s ease both}',
        '@keyframes ad-confirm-fadein{from{opacity:0}to{opacity:1}}',
        '.ad-confirm-modal{background:#0d1626;border:1px solid rgba(255,255,255,.1);',
        '  border-radius:14px;max-width:560px;width:92%;padding:24px 26px;',
        '  box-shadow:0 24px 64px rgba(0,0,0,.6);color:#cbd5e1;font-family:inherit}',
        '.ad-confirm-title{font-size:17px;font-weight:800;color:#fff;margin-bottom:8px}',
        '.ad-confirm-sub{font-size:13px;color:#94a3b8;line-height:1.6;margin-bottom:14px}',
        '.ad-confirm-block{background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.06);',
        '  border-radius:8px;padding:12px 14px;margin-bottom:14px}',
        '.ad-confirm-block-row{display:flex;gap:10px;padding:4px 0;font-size:12.5px;line-height:1.6}',
        '.ad-confirm-key{min-width:78px;color:#64748b;font-weight:700;font-size:11px;',
        '  text-transform:uppercase;letter-spacing:.08em;font-family:JetBrains Mono,monospace}',
        '.ad-confirm-val{color:#cbd5e1;word-break:break-word;flex:1}',
        '.ad-confirm-val code{background:rgba(251,191,36,.1);color:#fbbf24;padding:2px 7px;',
        '  border-radius:5px;font-family:JetBrains Mono,monospace;font-size:11.5px}',
        '.ad-confirm-hint{font-size:12px;color:#94a3b8;line-height:1.6;margin-bottom:18px;',
        '  background:rgba(245,158,11,.05);border-left:3px solid rgba(245,158,11,.45);',
        '  padding:10px 14px;border-radius:6px}',
        '.ad-confirm-hint strong{color:#fbbf24}',
        '.ad-confirm-hint em{color:#fca5a5;font-style:normal}',
        '.ad-confirm-row{display:flex;gap:10px;justify-content:flex-end}',
        '.ad-confirm-btn{padding:10px 20px;border-radius:9px;font-size:13px;font-weight:700;',
        '  cursor:pointer;border:1px solid transparent;letter-spacing:.02em;',
        '  transition:background .12s ease, transform .12s ease}',
        '.ad-confirm-btn--cancel{background:rgba(255,255,255,.04);color:#cbd5e1;',
        '  border-color:rgba(255,255,255,.08)}',
        '.ad-confirm-btn--cancel:hover{background:rgba(255,255,255,.09)}',
        '.ad-confirm-btn--ok{background:linear-gradient(135deg,#10b981 0%,#059669 100%);',
        '  color:#fff;border-color:#059669;box-shadow:0 4px 14px rgba(16,185,129,.35)}',
        '.ad-confirm-btn--ok:hover{transform:translateY(-1px);box-shadow:0 8px 22px rgba(16,185,129,.5)}',
      ].join('');
      document.head.appendChild(css);
    }
    document.body.appendChild(overlay);

    function finish(value) { overlay.remove(); resolve(value); }
    overlay.querySelector('[data-act="cancel"]').addEventListener('click', function () { finish(false); });
    overlay.querySelector('[data-act="ok"]').addEventListener('click',     function () { finish(true);  });
    overlay.addEventListener('click', function (e) { if (e.target === overlay) finish(false); });
    document.addEventListener('keydown', function escListener(e) {
      if (e.key === 'Escape') { finish(false); document.removeEventListener('keydown', escListener); }
    });
  });
}

function _adCopyScript() {
  const script = window._adCurrentScript || '';
  if (!script) return;
  navigator.clipboard.writeText(script).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = script; ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove();
  });
  const btn = document.getElementById('ad-copy-btn');
  if (btn) {
    btn.textContent = '✅ Copied!';
    btn.classList.add('ad-copy-flash');
    setTimeout(() => { btn.textContent = '📋 Copy'; btn.classList.remove('ad-copy-flash'); }, 2000);
  }
}

function _adShowRunHelp() {
  // Inline tooltip
  const existing = document.getElementById('ad-run-tip');
  if (existing) { existing.remove(); return; }
  const box = document.getElementById('alert-detail-box');
  if (!box) return;

  const tip = document.createElement('div');
  tip.id = 'ad-run-tip';
  tip.style.cssText = `
    position:sticky;bottom:0;background:#1e2d40;border:1px solid rgba(59,130,246,.3);
    border-radius:10px;padding:14px 16px;margin:0 20px 16px;font-size:12px;color:#cbd5e1;
    line-height:1.7;z-index:10;
  `;
  tip.innerHTML = `
    <div style="font-weight:700;color:#60a5fa;margin-bottom:6px;font-size:13px">💻 How to run the fix script</div>
    <ol style="margin:0;padding-left:18px;color:#94a3b8">
      <li>Click <strong style="color:#e2e8f0">📋 Copy</strong> above to copy the script</li>
      <li>Press <strong style="color:#e2e8f0">Win + X</strong> → choose <strong style="color:#e2e8f0">Windows Terminal (Admin)</strong> or <strong style="color:#e2e8f0">PowerShell (Admin)</strong></li>
      <li>Paste with <strong style="color:#e2e8f0">Ctrl+V</strong> and press <strong style="color:#e2e8f0">Enter</strong></li>
      <li>Read the output — it will tell you what it did</li>
    </ol>
    <div style="margin-top:8px;font-size:11px;color:#475569">
      ⚠️ Always review a script before running it. These scripts only read system info or perform safe cleanup operations.
    </div>
    <button onclick="document.getElementById('ad-run-tip').remove()" style="
      margin-top:10px;padding:4px 14px;border-radius:5px;background:rgba(59,130,246,.15);
      border:1px solid rgba(59,130,246,.3);color:#60a5fa;cursor:pointer;font-size:10px;width:100%">
      Got it ✓
    </button>
  `;
  box.appendChild(tip);
}

async function _adMarkResolved(alertId) {
  const btn  = document.getElementById('ad-resolve-btn');
  const note = (document.getElementById('ad-resolve-note')?.value || '').trim();

  if (btn) { btn.textContent = '⏳ Saving…'; btn.disabled = true; }

  try {
    const res = await fetch('/api/alerts/resolve', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ id: alertId, note }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error || 'Server error');

    // Mark locally
    window._resolvedAlertIds.add(String(alertId));

    // Remove from alerts panel
    const card = document.querySelector(`[data-alert-id="${alertId}"]`) ||
                 document.getElementById(`acard-${alertId}`);
    if (card) {
      card.style.transition = 'all .3s ease';
      card.style.opacity    = '0';
      card.style.transform  = 'translateX(30px)';
      setTimeout(() => { card.remove(); window._renderAlerts?.(); window._updateBell?.(); }, 300);
    } else {
      window._alertsData = (window._alertsData||[]).filter(a => String(a.id) !== String(alertId));
      window._renderAlerts?.();
      window._updateBell?.();
    }

    // Update the popup to show "resolved"
    if (btn) {
      btn.textContent          = '✅ Resolved! Alert removed.';
      btn.style.background     = 'rgba(34,197,94,.25)';
      btn.style.color          = '#4ade80';
      btn.style.borderColor    = 'rgba(34,197,94,.5)';
    }

    // Auto-close popup after 1.5s
    setTimeout(() => closeAlertDetail(), 1500);

  } catch(err) {
    if (btn) {
      btn.textContent  = '❌ Failed — retry';
      btn.disabled     = false;
      btn.style.background = 'rgba(239,68,68,.15)';
      btn.style.color      = '#ef4444';
    }
    console.error('Resolve failed:', err);
  }
}

// ── Patch _renderAlerts to make cards clickable ──────────────────────────────
// This runs after the original _renderAlerts to add click handlers

function _patchAlertCards() {
  const list = document.getElementById('alert-list');
  if (!list) return;
  // Add click on each card (skip dismiss button)
  list.querySelectorAll('.alert-card').forEach(card => {
    if (card._detailPatched) return;
    card._detailPatched = true;
    card.style.cursor = 'pointer';
    card.addEventListener('click', (e) => {
      if (e.target.classList.contains('alert-card-dismiss')) return;
      // Find alert data by id
      const id = card.id.replace('acard-', '');
      const alert = (window._alertsData||[]).find(a => String(a.id) === String(id));
      if (alert) window.openAlertDetail(alert);
    });
  });
}

// Override _renderAlerts to patch cards after render
const _origRenderAlerts = window._renderAlerts;
if (_origRenderAlerts) {
  window._renderAlerts = function() {
    _origRenderAlerts.call(this);
    setTimeout(_patchAlertCards, 50);
  };
}

// Also patch after every refresh
const _origRefreshAlerts = window.refreshAlerts;
if (_origRefreshAlerts) {
  window.refreshAlerts = async function() {
    await _origRefreshAlerts.call(this);
    setTimeout(_patchAlertCards, 100);
  };
}

// Init: load resolved IDs on page load
document.addEventListener('DOMContentLoaded', () => {
  _loadResolvedIds();
  // Patch cards that may already be rendered
  setTimeout(_patchAlertCards, 500);
});

// Expose
window.openAlertDetail  = window.openAlertDetail;
window.closeAlertDetail = closeAlertDetail;
