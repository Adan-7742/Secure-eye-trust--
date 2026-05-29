/**
 * rag_intelligence.js — Secure Eye Trust+
 * ==========================================
 * Full RAG Intelligence Panel for Perform Analysis.
 * Shows per-threat: Severity · MITRE · Possible Attack · Recommended Actions
 * Sources: MITRE ATT&CK · NIST CSF · CVE Program · Incident Playbooks · Previous Resolutions
 */

/* ═══════════════════════════════════════════════════════════════════════
   KNOWLEDGE BASE — embedded reference data (no network needed for lookup)
═══════════════════════════════════════════════════════════════════════ */

var RIG_MITRE = {
  'Brute Force Login': {
    id: 'T1110', tactic: 'Credential Access', technique: 'Brute Force',
    subtechnique: 'T1110.001 — Password Guessing',
    kill_chain: 'Reconnaissance → Initial Access → Lateral Movement',
    nist: 'AC-7 · IA-5 · SI-3',
    cve_refs: ['CVE-2024-21762 (FortiOS auth bypass)', 'CVE-2023-27997 (SSL-VPN brute force)'],
    playbook: [
      'Block source IP at perimeter firewall immediately',
      'Force password reset on targeted accounts',
      'Enable MFA on all internet-facing services',
      'Review EID 4624 for successful logins from same source',
      'Run: Get-EventLog Security -InstanceId 4625 -Newest 200 | Group Message'
    ],
    attack_chain: 'Attacker discovered valid usernames via OSINT → automated password spray using EID 4625 → looking for EID 4624 success to confirm access',
    nist_guideline: 'NIST SP 800-63B §5.2.2 — Implement rate-limiting and account lockout after 5 failed attempts within 30 minutes.',
  },
  'Account Lockout': {
    id: 'T1110.001', tactic: 'Credential Access', technique: 'Password Guessing / Lockout DoS',
    subtechnique: 'T1531 — Account Access Removal (secondary effect)',
    kill_chain: 'Initial Access → Impact (Availability)',
    nist: 'AC-7 · IA-11',
    cve_refs: ['CVE-2023-23397 (Outlook NTLM hash steal)'],
    playbook: [
      'Run: Search-ADAccount –LockedOut | FT Name,LockedOut,LastLogonDate',
      'Identify lockout source: Get-WinEvent -FilterHashtable @{LogName="Security";Id=4740}',
      'Check for automated spray pattern: same source, multiple accounts, <60s apart',
      'Temporarily increase lockout threshold if service account affected',
      'Enable Azure AD Identity Protection or on-prem equivalent'
    ],
    attack_chain: 'Automated credential stuffing tool cycling usernames → triggers EID 4740 lockouts → may be deliberate DoS against admin accounts',
    nist_guideline: 'NIST SP 800-53 AC-7 — Enforce a limit of no more than 5 consecutive invalid logon attempts.',
  },
  'Privilege Escalation': {
    id: 'T1548', tactic: 'Privilege Escalation', technique: 'Abuse Elevation Control',
    subtechnique: 'T1548.002 — Bypass UAC · T1134 — Access Token Manipulation',
    kill_chain: 'Initial Access → Privilege Escalation → Defense Evasion',
    nist: 'AC-6 · AU-9 · CM-7',
    cve_refs: ['CVE-2024-26169 (Windows Error Reporting LPE)', 'CVE-2023-36874 (WER LPE)', 'CVE-2024-21338 (Kernel LPE)'],
    playbook: [
      'Audit: who triggered EID 4672 — is it expected admin or unknown account?',
      'Check EID 4673 for privileged service calls immediately following 4672',
      'Review: Get-LocalGroupMember -Group Administrators',
      'Enable Credential Guard and Windows Defender Credential Guard',
      'Audit LSASS protection: reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL'
    ],
    attack_chain: 'Attacker with low-priv access exploits UAC bypass or kernel vuln → gains SYSTEM/Admin token (EID 4672) → pivots to credential dumping or lateral movement',
    nist_guideline: 'NIST SP 800-53 AC-6 — Apply least privilege across all accounts and services.',
  },
  'Windows Defender Alert': {
    id: 'T1059', tactic: 'Execution · Defense Evasion', technique: 'Command and Scripting Interpreter / Malware Detected',
    subtechnique: 'T1059.001 — PowerShell · T1027 — Obfuscated Files',
    kill_chain: 'Delivery → Installation → Command & Control',
    nist: 'SI-3 · SI-7 · IR-4',
    cve_refs: ['CVE-2024-21412 (SmartScreen bypass)', 'CVE-2023-36025 (Windows SmartScreen bypass)', 'CVE-2024-29988 (MoTW bypass)'],
    playbook: [
      'DO NOT dismiss Defender alerts — quarantine and investigate immediately',
      'Check: Get-MpThreatDetection | Sort-Object ActionSuccess',
      'Preserve: wevtutil epl System defender_events.evtx',
      'Isolate system from network if ransomware/RAT indicators present',
      'Submit suspicious file to VirusTotal and Microsoft MSTIC',
      'Review PowerShell history: Get-Content (Get-PSReadlineOption).HistorySavePath'
    ],
    attack_chain: 'Malicious payload delivered (phishing/drive-by) → Defender detects execution → if not blocked, attacker achieves persistence via startup/registry/scheduled task',
    nist_guideline: 'NIST SP 800-61 §3.2 — Treat any AV/EDR detection as a confirmed incident requiring triage within 1 hour.',
  },
  'Scheduled Task Created': {
    id: 'T1053.005', tactic: 'Persistence · Execution', technique: 'Scheduled Task',
    subtechnique: 'T1053.005 — Windows Scheduled Task',
    kill_chain: 'Installation → Persistence → Execution',
    nist: 'CM-7 · AU-12 · IA-2',
    cve_refs: ['CVE-2022-21999 (Task Scheduler LPE)', 'CVE-2021-1675 (PrintNightmare via tasks)'],
    playbook: [
      'Review: schtasks /query /fo LIST /v | findstr "Task Name\\|Run As\\|Task To Run"',
      'Check EID 4698 details: who created it, what command, what account',
      'Look for base64-encoded or obfuscated task actions (-EncodedCommand)',
      'Review: Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\\Microsoft*"}',
      'Disable suspicious task: schtasks /change /tn "TaskName" /disable'
    ],
    attack_chain: 'Attacker with user/admin access creates scheduled task (EID 4698) running malicious script at startup or on schedule → ensures persistence across reboots',
    nist_guideline: 'NIST SP 800-167 — Only approved, documented tasks should exist on production systems. All EID 4698 events require review.',
  },
  'New Admin Account': {
    id: 'T1136', tactic: 'Persistence', technique: 'Create Account',
    subtechnique: 'T1136.001 — Local Account · T1098 — Account Manipulation',
    kill_chain: 'Installation → Persistence → Privilege Escalation',
    nist: 'AC-2 · AC-3 · AU-12',
    cve_refs: ['No specific CVE — TTP-based persistence technique'],
    playbook: [
      'Verify: Get-LocalUser | Where-Object {$_.Enabled -eq $True}',
      'Check EID 4720 (created) + EID 4728 (added to admins group) — same timestamp = backdoor',
      'Run: net localgroup administrators',
      'If unauthorized: Disable-LocalUser -Name "SuspiciousUser" immediately',
      'Check for AD changes: Get-ADUser -Filter * -Properties WhenCreated | Sort WhenCreated -Desc | Select -First 10'
    ],
    attack_chain: 'Attacker with admin rights creates new account (EID 4720) → immediately adds to Administrators group (EID 4728) → provides persistent backdoor even if original access is revoked',
    nist_guideline: 'NIST SP 800-53 AC-2(4) — Require approval for account creation. All EID 4720 events must be reviewed.',
  },
  'Audit Policy Change': {
    id: 'T1562.002', tactic: 'Defense Evasion', technique: 'Disable Windows Event Logging',
    subtechnique: 'T1562.001 — Disable or Modify Tools',
    kill_chain: 'Defense Evasion → Lateral Movement (invisible)',
    nist: 'AU-2 · AU-9 · AU-12',
    cve_refs: ['No specific CVE — standard anti-forensics TTP'],
    playbook: [
      'CRITICAL: Audit policy changes almost always precede malicious activity',
      'Restore audit policy: auditpol /restore /file:C:\\baseline_audit.csv',
      'Check what was disabled: Get-WinEvent -FilterHashtable @{LogName="Security";Id=4719}',
      'Enable log forwarding to SIEM immediately if not already active',
      'Ensure Security log max size: wevtutil sl Security /ms:1073741824'
    ],
    attack_chain: 'Attacker disables specific audit subcategories (EID 4719) → subsequent malicious actions leave no log trail → escalates or exfiltrates undetected',
    nist_guideline: 'NIST SP 800-92 — Audit policy changes must be alerted on and never permitted without a change request ticket.',
  },
  'Registry Tampering': {
    id: 'T1112', tactic: 'Defense Evasion · Persistence', technique: 'Modify Registry',
    subtechnique: 'T1547.001 — Registry Run Keys / Startup Folder',
    kill_chain: 'Installation → Persistence → Defense Evasion',
    nist: 'CM-2 · CM-6 · SI-7',
    cve_refs: ['CVE-2024-26198 (Registry manipulation RCE)'],
    playbook: [
      'Identify: EID 4657 details — which key, old/new value, which process',
      'Check autorun keys: reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'Also: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (user-level)',
      'Use Autoruns (SysInternals) to enumerate all persistence points',
      'Enable registry auditing on sensitive keys via GPO'
    ],
    attack_chain: 'Malware or attacker modifies Run/RunOnce keys or LSA settings (EID 4657) → payload executes at every startup or login → persists across patches and reboots',
    nist_guideline: 'NIST SP 800-53 CM-6 — Critical registry keys must be integrity-monitored and changes alerted.',
  },
  'Service Failure': {
    id: 'T1543', tactic: 'Persistence', technique: 'Create or Modify System Process',
    subtechnique: 'T1543.003 — Windows Service',
    kill_chain: 'Installation → Persistence → Execution',
    nist: 'CM-7 · SI-2 · AU-12',
    cve_refs: ['CVE-2024-21447 (Windows Service tampering)'],
    playbook: [
      'Identify failing service: Get-Service | Where-Object {$_.Status -ne "Running"}',
      'Check EID 7045 for newly installed services — malware often installs as a service',
      'Review service binary path: sc qc ServiceName',
      'Verify binary hash: Get-FileHash -Path "C:\\path\\to\\service.exe"',
      'Check service recovery actions: sc failure ServiceName'
    ],
    attack_chain: 'Attacker installs malicious service (EID 7045) or tampers existing one → service runs as SYSTEM → provides persistent elevated execution',
    nist_guideline: 'NIST SP 800-53 CM-7(1) — Prohibit or restrict use of unauthorized services.',
  },
  'Disk Hardware Error': {
    id: 'SYS-001', tactic: 'System Health / Impact', technique: 'Storage Failure',
    subtechnique: 'Hardware failure or T1485 — Data Destruction',
    kill_chain: 'Hardware degradation → Data loss risk',
    nist: 'CP-9 · CP-10 · MP-6',
    cve_refs: ['Not applicable — hardware event'],
    playbook: [
      'Run SMART test: Get-Disk | Get-StorageReliabilityCounter',
      'Check: wmic diskdrive get status',
      'Back up all data immediately before further investigation',
      'Run: chkdsk /f /r on affected volume (schedule for next reboot)',
      'Monitor EID 11 frequency — increasing rate = imminent failure'
    ],
    attack_chain: 'Disk I/O errors (EID 11/7) indicate physical degradation or possible ransomware/wiper attacking storage layer → data loss risk escalates rapidly without intervention',
    nist_guideline: 'NIST SP 800-53 CP-9 — Conduct backups of user-level, system-level, and application data at defined frequencies.',
  },
  'Unexpected Shutdown': {
    id: 'T1499', tactic: 'Impact', technique: 'Endpoint Denial of Service',
    subtechnique: 'T1529 — System Shutdown/Reboot',
    kill_chain: 'Impact → Availability disruption',
    nist: 'CP-10 · IR-4 · SI-7',
    cve_refs: ['CVE-2024-21305 (Hypervisor crash)', 'CVE-2023-28229 (BSOD via driver)'],
    playbook: [
      'Check: Get-WinEvent -FilterHashtable @{LogName="System";Id=41,6008} | Select -First 20',
      'Review minidump: C:\\Windows\\Minidump\\ — analyze with WinDbg',
      'Check for kernel exploits: driver signatures, third-party drivers',
      'Run: sfc /scannow and DISM /Online /Cleanup-Image /RestoreHealth',
      'Monitor temperature and hardware health via HWiNFO64'
    ],
    attack_chain: 'Repeated unexpected shutdowns (EID 41/6008) may indicate kernel exploit crashing system, ransomware forcing reboot, or hardware destruction attack',
    nist_guideline: 'NIST SP 800-53 SI-7 — System availability events require root-cause analysis and must be documented.',
  },
  'Memory Corruption': {
    id: 'T1499.001', tactic: 'Impact · Exploitation', technique: 'OS Exhaustion Flood / Memory Exploit',
    subtechnique: 'T1190 — Exploit Public-Facing Application',
    kill_chain: 'Exploitation → Privilege Escalation → Impact',
    nist: 'SI-7 · SC-39 · IR-4',
    cve_refs: ['CVE-2024-21338 (Windows Kernel pool corruption)', 'CVE-2023-35385 (Windows MSMQ RCE)'],
    playbook: [
      'Analyze BSOD dump: WinDbg > !analyze -v',
      'Check pool corruption source: look for non-Microsoft drivers in dump',
      'Run: verifier /standard /all (driver verifier — test environment only)',
      'Test RAM: mdsched.exe (Windows Memory Diagnostic)',
      'If kernel exploit suspected: deploy signed driver enforcement, enable HVCI'
    ],
    attack_chain: 'Kernel pool/heap corruption may indicate active exploit chain targeting privilege escalation — attacker intentionally corrupts memory to gain kernel execution',
    nist_guideline: 'NIST SP 800-53 SC-39 — Enable process isolation and exploit protection (Windows Defender Exploit Guard).',
  },
  'Application Crash': {
    id: 'T1190', tactic: 'Initial Access', technique: 'Exploit Public-Facing Application',
    subtechnique: 'T1211 — Exploitation for Defense Evasion',
    kill_chain: 'Reconnaissance → Weaponization → Exploitation',
    nist: 'SI-2 · SI-10 · RA-5',
    cve_refs: ['CVE-2024-1086 (Linux kernel use-after-free)', 'CVE-2024-21413 (Outlook RCE)'],
    playbook: [
      'Check faulting module in EID 1000: is it a third-party DLL?',
      'Review: C:\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue\\',
      'Run: Get-WinEvent -FilterHashtable @{LogName="Application";Id=1000} | Select -First 20',
      'Check for injection: unusual DLL in crash report ≠ application DLL',
      'Patch application to latest version — check vendor advisory'
    ],
    attack_chain: 'Attacker sends malformed input to crash public-facing application (EID 1000) → if exploited: shellcode execution → RCE → initial foothold',
    nist_guideline: 'NIST SP 800-40 — Maintain patching within 30 days of critical CVE disclosure for internet-facing applications.',
  },
  'TLS/SSL Error': {
    id: 'T1557', tactic: 'Collection', technique: 'Adversary-in-the-Middle',
    subtechnique: 'T1557.001 — LLMNR/NBT-NS Poisoning · SSL Stripping',
    kill_chain: 'Collection → Credential Access',
    nist: 'SC-8 · SC-23 · IA-5',
    cve_refs: ['CVE-2024-20656 (Schannel vulnerability)', 'CVE-2023-38408 (OpenSSH agent forwarding)'],
    playbook: [
      'Check: SChannel errors in System log — which certificates are failing?',
      'Verify certificate validity: certutil -verify certname.cer',
      'Check for expired/self-signed certs in use: Get-ChildItem Cert:\\LocalMachine\\My',
      'Disable weak protocols: TLS 1.0, TLS 1.1, SSL 3.0 via registry',
      'Monitor for unexpected cert changes — may indicate MITM positioning'
    ],
    attack_chain: 'TLS errors may indicate MITM attack intercepting traffic, expired certificates enabling downgrade attacks, or attacker-controlled certificate substitution',
    nist_guideline: 'NIST SP 800-52 Rev 2 — Only TLS 1.2 and TLS 1.3 with approved cipher suites shall be used.',
  },
  'Network Error': {
    id: 'T1499.002', tactic: 'Impact', technique: 'Network Denial of Service',
    subtechnique: 'T1071 — Application Layer Protocol',
    kill_chain: 'Command & Control → Exfiltration or DoS',
    nist: 'SC-5 · SC-7 · IR-4',
    cve_refs: ['CVE-2024-2961 (glibc network stack)', 'CVE-2023-44487 (HTTP/2 Rapid Reset DoS)'],
    playbook: [
      'Check network connectivity: Test-NetConnection -ComputerName 8.8.8.8 -Port 443',
      'Review: netstat -ano | findstr "ESTABLISHED\\|TIME_WAIT\\|CLOSE_WAIT"',
      'Check for unusual outbound connections — possible C2 beaconing',
      'Monitor bandwidth: Get-NetAdapterStatistics',
      'Block suspicious IP ranges at firewall if C2 suspected'
    ],
    attack_chain: 'Network errors may indicate C2 beacon failing to reach attacker infrastructure, or DDoS traffic overwhelming network stack — investigate outbound connection patterns',
    nist_guideline: 'NIST SP 800-41 — All outbound network connections from servers should be explicitly permitted and monitored.',
  },
};

/* ═══════════════════════════════════════════════════════════════════════
   PREVIOUS RESOLUTIONS STORE — tracks what user has done before
═══════════════════════════════════════════════════════════════════════ */

var _rigResolutions = (function() {
  try {
    var raw = sessionStorage.getItem('rig_resolutions');
    return raw ? JSON.parse(raw) : {};
  } catch(e) { return {}; }
})();

function _rigSaveResolution(threatName, action) {
  _rigResolutions[threatName] = _rigResolutions[threatName] || [];
  var entry = { action: action, ts: new Date().toISOString().slice(0,16).replace('T',' ') };
  _rigResolutions[threatName].unshift(entry);
  _rigResolutions[threatName] = _rigResolutions[threatName].slice(0, 5);
  try { sessionStorage.setItem('rig_resolutions', JSON.stringify(_rigResolutions)); } catch(e) {}
}

function _rigGetResolutions(threatName) {
  return _rigResolutions[threatName] || [];
}

/* ═══════════════════════════════════════════════════════════════════════
   MAIN PANEL INJECTION
═══════════════════════════════════════════════════════════════════════ */

var _rigInjected = false;

function rigInjectPanel(report) {
  // Remove old panel if re-running
  var old = document.getElementById('rig-panel');
  if (old) old.remove();
  _rigInjected = false;

  var threats = (report.threat_hits || []);
  if (!threats.length) return;

  _rigInjectStyles();

  // Find insertion point — after the threat panel
  var anchor = document.getElementById('pa-threats-table');
  if (!anchor) return;
  var panel = anchor.closest('.panel') || anchor.parentElement;
  if (!panel) return;

  var wrapper = document.createElement('div');
  wrapper.id = 'rig-panel';

  // Section divider
  wrapper.innerHTML = [
    '<div class="rig-divider">',
      '<div class="rig-divider-pill">',
        '<span class="rig-divider-dot"></span>',
        'RAG Intelligence Analysis',
        '<span class="rig-divider-dot"></span>',
      '</div>',
      '<div class="rig-divider-line"></div>',
    '</div>',

    // Header bar
    '<div class="rig-header">',
      '<div class="rig-header-left">',
        '<div class="rig-header-icon">🧠</div>',
        '<div>',
          '<div class="rig-header-title">Threat Intelligence Report</div>',
          '<div class="rig-header-sub">',
            'Sources: MITRE ATT&amp;CK · NIST SP 800-53 · CVE Program · Incident Playbooks · Previous Resolutions',
          '</div>',
        '</div>',
      '</div>',
      '<div class="rig-header-right">',
        '<div class="rig-source-pill" title="MITRE ATT&CK">ATT&amp;CK</div>',
        '<div class="rig-source-pill" title="NIST CSF">NIST</div>',
        '<div class="rig-source-pill" title="CVE Program">CVE</div>',
        '<div class="rig-source-pill" title="Incident Playbooks">Playbooks</div>',
        '<button class="rig-run-btn" id="rig-groq-btn" onclick="rigRunGroqAnalysis()">',
          '✦ Enrich with AI',
        '</button>',
      '</div>',
    '</div>',

    // Threat cards container
    '<div class="rig-cards" id="rig-cards"></div>',

    // Groq AI enrichment result
    '<div class="rig-ai-result" id="rig-ai-result" style="display:none"></div>',

  ].join('');

  panel.parentNode.insertBefore(wrapper, panel.nextSibling);

  // Render all threat cards
  _rigRenderCards(threats, report);
  _rigInjected = true;
}

/* ═══════════════════════════════════════════════════════════════════════
   CARD RENDERING
═══════════════════════════════════════════════════════════════════════ */

function _rigRenderCards(threats, report) {
  var container = document.getElementById('rig-cards');
  if (!container) return;

  var SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  var sorted = threats.slice().sort(function(a, b) {
    return (SEV_ORDER[a.severity] || 3) - (SEV_ORDER[b.severity] || 3);
  });

  container.innerHTML = sorted.map(function(threat, idx) {
    return _rigBuildCard(threat, idx, report);
  }).join('');

  // Stagger animation
  container.querySelectorAll('.rig-card').forEach(function(card, i) {
    card.style.animationDelay = (i * 0.07) + 's';
  });
}

function _rigBuildCard(threat, idx, report) {
  var kb = RIG_MITRE[threat.name] || _rigFallbackKB(threat);
  var sev = threat.severity || 'MEDIUM';
  var resolutions = _rigGetResolutions(threat.name);

  var SEV_META = {
    CRITICAL: { col: '#f87171', bg: 'rgba(248,113,113,.08)', border: 'rgba(248,113,113,.25)', glow: '0 0 24px rgba(248,113,113,.12)', label: 'CRITICAL', bar: '#f87171' },
    HIGH:     { col: '#fb923c', bg: 'rgba(251,146,60,.07)',  border: 'rgba(251,146,60,.22)',  glow: '0 0 20px rgba(251,146,60,.10)', label: 'HIGH',     bar: '#fb923c' },
    MEDIUM:   { col: '#fbbf24', bg: 'rgba(251,191,36,.06)',  border: 'rgba(251,191,36,.2)',   glow: 'none',                           label: 'MEDIUM',   bar: '#fbbf24' },
    LOW:      { col: '#4ade80', bg: 'rgba(74,222,128,.05)',  border: 'rgba(74,222,128,.18)',  glow: 'none',                           label: 'LOW',      bar: '#4ade80' },
  };
  var sm = SEV_META[sev] || SEV_META.MEDIUM;
  var cardId = 'rig-card-' + idx;

  // Count section
  var maxCount = 1000;
  var barW = Math.min(100, Math.round((threat.count || 1) / maxCount * 100));

  // MITRE badges
  var mitreBadges = [
    '<span class="rig-badge rig-badge-mitre" title="MITRE Technique ID">' + kb.id + '</span>',
    '<span class="rig-badge rig-badge-tactic" title="MITRE Tactic">' + kb.tactic + '</span>',
  ].join('');

  // CVE pills
  var cvePills = (kb.cve_refs || []).map(function(cve) {
    return '<span class="rig-badge rig-badge-cve">' + cve.split(' ')[0] + '</span>';
  }).join('');

  // Playbook steps
  var playbookHtml = (kb.playbook || []).map(function(step, i) {
    var isCritical = step.startsWith('DO NOT') || step.startsWith('CRITICAL') || step.startsWith('Isolate');
    return '<div class="rig-step ' + (isCritical ? 'rig-step-urgent' : '') + '">' +
      '<span class="rig-step-num">' + (i + 1) + '</span>' +
      '<span class="rig-step-text">' + _rigEsc(step) + '</span>' +
      '<button class="rig-step-done" onclick="rigMarkDone(this, \'' + _rigEsc(threat.name) + '\', \'' + _rigEsc(step.substring(0,40)) + '\')" title="Mark done">✓</button>' +
    '</div>';
  }).join('');

  // Previous resolutions
  var prevHtml = '';
  if (resolutions.length) {
    prevHtml = '<div class="rig-prev-wrap">' +
      '<div class="rig-prev-title">📋 Previous Resolutions</div>' +
      resolutions.map(function(r) {
        return '<div class="rig-prev-item"><span class="rig-prev-ts">' + r.ts + '</span><span class="rig-prev-action">' + _rigEsc(r.action) + '</span></div>';
      }).join('') +
    '</div>';
  }

  // NIST reference
  var nistHtml = kb.nist_guideline
    ? '<div class="rig-nist"><span class="rig-nist-label">NIST</span>' + _rigEsc(kb.nist_guideline) + '</div>'
    : '';

  return [
    '<div class="rig-card rig-card-' + sev.toLowerCase() + '" id="' + cardId + '" style="--sev-col:' + sm.col + ';--sev-bg:' + sm.bg + ';--sev-border:' + sm.border + ';--sev-glow:' + sm.glow + '">',

      // ── Card Header ──────────────────────────────────────────────────
      '<div class="rig-card-header">',
        '<div class="rig-card-header-left">',
          '<div class="rig-sev-pill" style="background:' + sm.col + '1a;color:' + sm.col + ';border-color:' + sm.col + '44">',
            '<span class="rig-sev-dot" style="background:' + sm.col + '"></span>',
            sm.label,
          '</div>',
          '<div class="rig-card-title">' + _rigEsc(threat.name) + '</div>',
        '</div>',
        '<div class="rig-card-header-right">',
          '<div class="rig-event-count" style="color:' + sm.col + '">' + (threat.count || 0).toLocaleString() + '<span class="rig-ev-label">events</span></div>',
          '<button class="rig-toggle-btn" id="' + cardId + '-tog" onclick="rigToggleCard(\'' + cardId + '\')">▼</button>',
        '</div>',
      '</div>',

      // Count bar
      '<div class="rig-count-bar-wrap">',
        '<div class="rig-count-bar" style="width:' + barW + '%;background:' + sm.bar + '"></div>',
      '</div>',

      // ── Card Body (collapsible) ──────────────────────────────────────
      '<div class="rig-card-body" id="' + cardId + '-body">',

        // 4-pillar grid
        '<div class="rig-pillars">',

          // 1. Threat Severity
          '<div class="rig-pillar">',
            '<div class="rig-pillar-header">',
              '<span class="rig-pillar-num">1</span>',
              '<span class="rig-pillar-title">Threat Severity</span>',
            '</div>',
            '<div class="rig-pillar-body">',
              '<div class="rig-sev-gauge">',
                '<div class="rig-gauge-fill" style="width:' + _rigSevPct(sev) + '%;background:' + sm.col + '"></div>',
              '</div>',
              '<div class="rig-sev-meta">',
                '<span class="rig-sev-score" style="color:' + sm.col + '">' + _rigSevPct(sev) + '/100</span>',
                '<span class="rig-sev-desc">' + _rigSevDesc(sev) + '</span>',
              '</div>',
              '<div class="rig-sev-detail">',
                'Count: <b style="color:' + sm.col + '">' + (threat.count||0).toLocaleString() + '</b> events &nbsp;·&nbsp; ',
                'Last: <b>' + ((threat.latest||'').substring(0,16)||'—') + '</b>',
              '</div>',
              (threat.confidence_pct ? '<div class="rig-conf-bar-wrap"><span class="rig-conf-label">Detection confidence</span><div class="rig-conf-bar"><div style="width:' + threat.confidence_pct + '%;background:' + sm.col + '"></div></div><span class="rig-conf-pct">' + threat.confidence_pct + '%</span></div>' : ''),
            '</div>',
          '</div>',

          // 2. MITRE Mapping
          '<div class="rig-pillar">',
            '<div class="rig-pillar-header">',
              '<span class="rig-pillar-num">2</span>',
              '<span class="rig-pillar-title">MITRE ATT&amp;CK</span>',
            '</div>',
            '<div class="rig-pillar-body">',
              '<div class="rig-mitre-block">',
                '<div class="rig-mitre-id" style="color:' + sm.col + '">' + kb.id + '</div>',
                '<div class="rig-mitre-name">' + _rigEsc(kb.technique) + '</div>',
                '<div class="rig-mitre-sub">' + _rigEsc(kb.subtechnique || '') + '</div>',
              '</div>',
              '<div class="rig-badges-row">' + mitreBadges + '</div>',
              '<div class="rig-kill-chain">',
                '<div class="rig-kc-label">Kill Chain</div>',
                '<div class="rig-kc-steps">' + _rigKillChainHtml(kb.kill_chain) + '</div>',
              '</div>',
              '<div class="rig-nist-ref">NIST Controls: <b>' + (kb.nist || 'N/A') + '</b></div>',
              (cvePills ? '<div class="rig-cve-row"><span class="rig-cve-label">Related CVEs</span>' + cvePills + '</div>' : ''),
            '</div>',
          '</div>',

          // 3. Possible Attack
          '<div class="rig-pillar">',
            '<div class="rig-pillar-header">',
              '<span class="rig-pillar-num">3</span>',
              '<span class="rig-pillar-title">Possible Attack</span>',
            '</div>',
            '<div class="rig-pillar-body">',
              '<div class="rig-attack-chain">',
                '<div class="rig-attack-label">Attack Chain Reconstruction</div>',
                '<div class="rig-attack-text">' + _rigEsc(kb.attack_chain || 'Analysis pending.') + '</div>',
              '</div>',
              nistHtml,
            '</div>',
          '</div>',

          // 4. Recommended Actions
          '<div class="rig-pillar">',
            '<div class="rig-pillar-header">',
              '<span class="rig-pillar-num">4</span>',
              '<span class="rig-pillar-title">Recommended Actions</span>',
            '</div>',
            '<div class="rig-pillar-body rig-playbook">',
              playbookHtml,
              prevHtml,
            '</div>',
          '</div>',

        '</div>', // /rig-pillars

        // AI enrichment slot for this threat
        '<div class="rig-ai-slot" id="' + cardId + '-ai" style="display:none"></div>',

      '</div>', // /rig-card-body

    '</div>', // /rig-card
  ].join('');
}

/* ═══════════════════════════════════════════════════════════════════════
   GROQ AI ENRICHMENT
═══════════════════════════════════════════════════════════════════════ */

async function rigRunGroqAnalysis() {
  var report = window._ragCurrentReport || window._paLastReport;
  if (!report) { _rigToast('No report loaded — run analysis first'); return; }

  var btn = document.getElementById('rig-groq-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⟳ Analyzing…'; btn.classList.add('rig-btn-loading'); }

  var threats = report.threat_hits || [];
  if (!threats.length) {
    if (btn) { btn.disabled = false; btn.textContent = '✦ Enrich with AI'; btn.classList.remove('rig-btn-loading'); }
    return;
  }

  // Show loading state on all AI slots
  threats.forEach(function(_, idx) {
    var slot = document.getElementById('rig-card-' + idx + '-ai');
    if (slot) {
      slot.style.display = 'block';
      slot.innerHTML = '<div class="rig-ai-loading"><span class="rig-spin">⟳</span> Querying Groq LLaMA 3.3 · MITRE · CVE databases…</div>';
    }
  });

  try {
    var logs = threats.map(function(h) {
      var kb = RIG_MITRE[h.name] || {};
      return [
        '[' + h.severity + '] ' + h.name,
        'Count: ' + h.count + ' events',
        'EventIDs: ' + (h.event_ids || []).join(','),
        'Last: ' + (h.latest || '').substring(0, 16),
        'MITRE: ' + (kb.id || 'unknown') + ' — ' + (kb.technique || ''),
        (h.evidence || []).join(' | '),
      ].join(' — ');
    });

    var resp = await fetch('/api/rag-analysis/bulk', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logs: logs, k: 4 }),
    });

    if (!resp.ok) throw new Error('API ' + resp.status);
    var data = await resp.json();
    if (!data.ok) throw new Error(data.error || 'Unknown error');

    // Render AI results into each card's AI slot
    (data.results || []).forEach(function(result, idx) {
      var slot = document.getElementById('rig-card-' + idx + '-ai');
      if (!slot) return;
      var threat = threats[idx] || {};
      slot.innerHTML = _rigAiResultHtml(result, threat);
      slot.style.display = 'block';
    });

    if (btn) { btn.textContent = '✦ Re-analyze'; btn.disabled = false; btn.classList.remove('rig-btn-loading'); }
    _rigToast('✅ AI enrichment complete');

  } catch(err) {
    threats.forEach(function(_, idx) {
      var slot = document.getElementById('rig-card-' + idx + '-ai');
      if (slot) { slot.innerHTML = '<div class="rig-ai-err">⚠ AI error: ' + _rigEsc(err.message) + '</div>'; }
    });
    if (btn) { btn.disabled = false; btn.textContent = '✦ Retry AI'; btn.classList.remove('rig-btn-loading'); }
  }
}

function _rigAiResultHtml(result, threat) {
  var sev = result.severity || threat.severity || 'MEDIUM';
  var SEV_COL = { CRITICAL:'#f87171', HIGH:'#fb923c', MEDIUM:'#fbbf24', LOW:'#4ade80', INFO:'#38bdf8' };
  var col = SEV_COL[sev] || '#94a3b8';

  var mitreBadges = (result.mitre || []).slice(0, 4).map(function(m) {
    return '<span class="rig-badge rig-badge-ai-mitre" title="' + _rigEsc(m.tactic || '') + '">' + m.id + ' · ' + _rigEsc(m.technique || '') + '</span>';
  }).join('');

  var actions = (result.recommended_actions || []).map(function(a) {
    return '<div class="rig-ai-action"><span class="rig-ai-action-arrow">→</span>' + _rigEsc(a) + '</div>';
  }).join('');

  return [
    '<div class="rig-ai-enrichment">',
      '<div class="rig-ai-enrichment-header">',
        '<span class="rig-ai-icon">✦</span>',
        '<span class="rig-ai-title">Groq AI Analysis</span>',
        '<span class="rig-ai-sev" style="color:' + col + ';border-color:' + col + '44">' + sev + '</span>',
        '<span class="rig-ai-elapsed">' + (result.elapsed_s || 0) + 's</span>',
      '</div>',
      (mitreBadges ? '<div class="rig-ai-mitre-row">' + mitreBadges + '</div>' : ''),
      '<div class="rig-ai-desc">' + _rigEsc(result.attack_description || '') + '</div>',
      (actions ? '<div class="rig-ai-actions-title">AI-Recommended Actions</div>' + actions : ''),
    '</div>',
  ].join('');
}

/* ═══════════════════════════════════════════════════════════════════════
   CARD INTERACTIONS
═══════════════════════════════════════════════════════════════════════ */

function rigToggleCard(cardId) {
  var body = document.getElementById(cardId + '-body');
  var tog  = document.getElementById(cardId + '-tog');
  if (!body) return;
  var open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  if (tog) { tog.textContent = open ? '▼' : '▲'; tog.style.color = open ? '' : 'var(--sev-col)'; }
}

function rigMarkDone(btn, threatName, actionShort) {
  btn.classList.add('rig-step-done-active');
  btn.textContent = '✓';
  btn.disabled = true;
  btn.closest('.rig-step').classList.add('rig-step-completed');
  _rigSaveResolution(threatName, actionShort);
  _rigToast('✅ Marked as done — saved to resolutions');
}

/* ═══════════════════════════════════════════════════════════════════════
   HELPERS
═══════════════════════════════════════════════════════════════════════ */

function _rigSevPct(sev) { return { CRITICAL: 95, HIGH: 75, MEDIUM: 45, LOW: 20 }[sev] || 40; }

function _rigSevDesc(sev) {
  return {
    CRITICAL: 'Active or imminent threat — respond immediately',
    HIGH: 'Elevated risk — investigate within 2 hours',
    MEDIUM: 'Moderate concern — review at next window',
    LOW: 'Low-risk — monitor for changes',
  }[sev] || 'Unknown severity';
}

function _rigKillChainHtml(chain) {
  if (!chain) return '';
  return chain.split(' → ').map(function(step) {
    return '<span class="rig-kc-step">' + _rigEsc(step) + '</span>';
  }).join('<span class="rig-kc-arrow">→</span>');
}

function _rigFallbackKB(threat) {
  return {
    id: 'T???', tactic: threat.mitre_tactic || 'Unknown Tactic',
    technique: threat.name, subtechnique: '',
    kill_chain: 'Initial Access → Execution → Impact',
    nist: 'SI-3 · AU-12',
    cve_refs: [],
    playbook: [
      'Review all matching log entries for this pattern',
      'Correlate with other threat detections in the same timeframe',
      'Check MITRE ATT&CK Navigator for similar techniques',
      'Engage incident response team if pattern persists',
    ],
    attack_chain: 'Pattern detected in logs — manual investigation required to determine exact attack chain for this threat type.',
    nist_guideline: 'NIST SP 800-61 — All detected security events require triage and documentation.',
  };
}

function _rigEsc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _rigToast(msg) {
  if (typeof toast === 'function') { toast(msg); return; }
  var t = document.createElement('div');
  t.textContent = msg;
  t.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#1e293b;color:#e2e8f0;padding:10px 18px;border-radius:8px;font-size:13px;z-index:9999;box-shadow:0 4px 20px rgba(0,0,0,.4);border:1px solid rgba(255,255,255,.1)';
  document.body.appendChild(t);
  setTimeout(function(){ t.remove(); }, 3000);
}

/* ═══════════════════════════════════════════════════════════════════════
   STYLES
═══════════════════════════════════════════════════════════════════════ */

function _rigInjectStyles() {
  if (document.getElementById('rig-styles')) return;
  var s = document.createElement('style');
  s.id = 'rig-styles';
  s.textContent = `
  /* ── Divider ──────────────────────────────────────── */
  .rig-divider { display:flex; align-items:center; gap:14px; margin:28px 0 18px; }
  .rig-divider-pill {
    display:flex; align-items:center; gap:8px; white-space:nowrap;
    font-size:10px; font-weight:800; letter-spacing:.12em; text-transform:uppercase;
    font-family:monospace; color:#a78bfa;
    background:rgba(167,139,250,.1); border:1px solid rgba(167,139,250,.25);
    padding:5px 14px; border-radius:20px;
  }
  .rig-divider-dot { width:5px; height:5px; border-radius:50%; background:#a78bfa; opacity:.7; }
  .rig-divider-line { flex:1; height:1px; background:linear-gradient(90deg,rgba(167,139,250,.3),transparent); }

  /* ── Header ───────────────────────────────────────── */
  #rig-panel { margin-bottom:24px; }
  .rig-header {
    display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;
    background:rgba(167,139,250,.06); border:1px solid rgba(167,139,250,.18);
    border-radius:14px; padding:16px 20px; margin-bottom:16px;
  }
  .rig-header-left  { display:flex; align-items:center; gap:14px; }
  .rig-header-right { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .rig-header-icon  { font-size:28px; }
  .rig-header-title { font-size:15px; font-weight:900; color:#e2e8f0; letter-spacing:.01em; }
  .rig-header-sub   { font-size:11px; color:#64748b; margin-top:3px; }
  .rig-source-pill  {
    font-size:9px; font-weight:800; padding:3px 9px; border-radius:20px;
    background:rgba(148,163,184,.08); color:#64748b; border:1px solid rgba(148,163,184,.2);
    text-transform:uppercase; letter-spacing:.06em;
  }
  .rig-run-btn {
    font-size:12px; font-weight:800; padding:8px 18px; border-radius:8px;
    background:rgba(167,139,250,.15); color:#c4b5fd;
    border:1px solid rgba(167,139,250,.35); cursor:pointer;
    transition:all .18s; letter-spacing:.03em;
  }
  .rig-run-btn:hover:not(:disabled) { background:rgba(167,139,250,.28); transform:translateY(-1px); }
  .rig-run-btn:disabled { opacity:.5; cursor:not-allowed; }
  .rig-btn-loading { animation:rig-pulse 1.2s ease-in-out infinite; }
  @keyframes rig-pulse { 0%,100%{opacity:.5} 50%{opacity:1} }

  /* ── Cards container ──────────────────────────────── */
  .rig-cards { display:flex; flex-direction:column; gap:14px; }

  /* ── Card ─────────────────────────────────────────── */
  .rig-card {
    border:1px solid var(--sev-border); border-radius:14px;
    background:var(--sev-bg); box-shadow:var(--sev-glow);
    animation:rig-fadein .4s ease both;
    overflow:hidden;
  }
  @keyframes rig-fadein { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }

  /* Card Header */
  .rig-card-header {
    display:flex; align-items:center; justify-content:space-between;
    padding:14px 18px; gap:12px; cursor:pointer;
  }
  .rig-card-header-left  { display:flex; align-items:center; gap:12px; flex:1; min-width:0; }
  .rig-card-header-right { display:flex; align-items:center; gap:14px; flex-shrink:0; }
  .rig-sev-pill {
    display:inline-flex; align-items:center; gap:6px;
    font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:.08em;
    padding:4px 12px; border-radius:20px; border:1px solid; white-space:nowrap; flex-shrink:0;
  }
  .rig-sev-dot { width:6px; height:6px; border-radius:50%; flex-shrink:0; }
  .rig-card-title { font-size:14px; font-weight:800; color:#e2e8f0; line-height:1.3; }
  .rig-event-count { font-size:22px; font-weight:900; line-height:1; text-align:right; }
  .rig-ev-label { display:block; font-size:9px; color:#64748b; font-weight:400; text-transform:uppercase; letter-spacing:.06em; }
  .rig-toggle-btn {
    background:none; border:1px solid rgba(255,255,255,.1); color:#64748b;
    width:28px; height:28px; border-radius:6px; cursor:pointer; font-size:11px;
    display:flex; align-items:center; justify-content:center;
    transition:all .15s; flex-shrink:0;
  }
  .rig-toggle-btn:hover { border-color:var(--sev-col); color:var(--sev-col); }

  /* Count bar */
  .rig-count-bar-wrap { height:3px; background:rgba(255,255,255,.05); }
  .rig-count-bar { height:100%; border-radius:0; transition:width .7s ease; opacity:.7; }

  /* ── Card Body ─────────────────────────────────────── */
  .rig-card-body { border-top:1px solid rgba(255,255,255,.06); }

  /* 4-pillar grid */
  .rig-pillars {
    display:grid; grid-template-columns:repeat(4,1fr);
    gap:0; border-bottom:1px solid rgba(255,255,255,.05);
  }
  @media(max-width:1100px) { .rig-pillars { grid-template-columns:repeat(2,1fr); } }
  @media(max-width:700px)  { .rig-pillars { grid-template-columns:1fr; } }

  .rig-pillar { padding:16px 18px; border-right:1px solid rgba(255,255,255,.05); }
  .rig-pillar:last-child { border-right:none; }

  .rig-pillar-header {
    display:flex; align-items:center; gap:8px; margin-bottom:12px;
    padding-bottom:8px; border-bottom:1px solid rgba(255,255,255,.05);
  }
  .rig-pillar-num {
    width:20px; height:20px; border-radius:50%; background:var(--sev-col);
    color:#000; font-size:10px; font-weight:900;
    display:flex; align-items:center; justify-content:center; flex-shrink:0;
  }
  .rig-pillar-title { font-size:11px; font-weight:800; color:#94a3b8; text-transform:uppercase; letter-spacing:.08em; }

  /* Pillar 1 — Severity */
  .rig-sev-gauge { height:6px; background:rgba(255,255,255,.07); border-radius:3px; overflow:hidden; margin-bottom:8px; }
  .rig-gauge-fill { height:100%; border-radius:3px; transition:width .8s ease; }
  .rig-sev-meta { display:flex; align-items:baseline; gap:8px; margin-bottom:6px; }
  .rig-sev-score { font-size:20px; font-weight:900; line-height:1; }
  .rig-sev-desc  { font-size:11px; color:#64748b; line-height:1.4; }
  .rig-sev-detail { font-size:11px; color:#64748b; line-height:1.6; }
  .rig-conf-bar-wrap { display:flex; align-items:center; gap:6px; margin-top:8px; }
  .rig-conf-label { font-size:9px; color:#475569; white-space:nowrap; text-transform:uppercase; letter-spacing:.05em; }
  .rig-conf-bar { flex:1; height:4px; background:rgba(255,255,255,.07); border-radius:2px; overflow:hidden; }
  .rig-conf-bar div { height:100%; border-radius:2px; transition:width .8s; }
  .rig-conf-pct { font-size:10px; color:#64748b; white-space:nowrap; }

  /* Pillar 2 — MITRE */
  .rig-mitre-block { margin-bottom:10px; }
  .rig-mitre-id   { font-size:22px; font-weight:900; font-family:monospace; line-height:1; margin-bottom:3px; }
  .rig-mitre-name { font-size:13px; font-weight:700; color:#e2e8f0; margin-bottom:2px; }
  .rig-mitre-sub  { font-size:10px; color:#64748b; }
  .rig-badges-row { display:flex; flex-wrap:wrap; gap:5px; margin-bottom:10px; }
  .rig-badge {
    font-size:9px; font-weight:700; padding:2px 8px; border-radius:20px;
    border:1px solid; white-space:nowrap;
  }
  .rig-badge-mitre  { color:#a78bfa; border-color:rgba(167,139,250,.35); background:rgba(167,139,250,.1); }
  .rig-badge-tactic { color:#38bdf8; border-color:rgba(56,189,248,.3);   background:rgba(56,189,248,.08); }
  .rig-badge-cve    { color:#fb923c; border-color:rgba(251,146,60,.3);   background:rgba(251,146,60,.08); }
  .rig-kill-chain { margin-bottom:8px; }
  .rig-kc-label { font-size:9px; color:#475569; text-transform:uppercase; letter-spacing:.07em; margin-bottom:5px; }
  .rig-kc-steps { display:flex; flex-wrap:wrap; align-items:center; gap:3px; }
  .rig-kc-step  { font-size:9px; color:#94a3b8; background:rgba(255,255,255,.05); padding:2px 7px; border-radius:4px; }
  .rig-kc-arrow { font-size:9px; color:#475569; }
  .rig-nist-ref { font-size:10px; color:#475569; }
  .rig-nist-ref b { color:#64748b; }
  .rig-cve-row  { margin-top:8px; display:flex; flex-wrap:wrap; gap:4px; align-items:center; }
  .rig-cve-label { font-size:9px; color:#475569; text-transform:uppercase; letter-spacing:.05em; margin-right:4px; }
  .rig-badge-ai-mitre { color:#c4b5fd; border-color:rgba(196,181,253,.3); background:rgba(196,181,253,.08); }

  /* Pillar 3 — Possible Attack */
  .rig-attack-chain { margin-bottom:12px; }
  .rig-attack-label { font-size:9px; color:#475569; text-transform:uppercase; letter-spacing:.07em; margin-bottom:6px; font-weight:700; }
  .rig-attack-text  { font-size:12px; color:#94a3b8; line-height:1.65; }
  .rig-nist { font-size:11px; color:#64748b; line-height:1.6; background:rgba(59,130,246,.05); border-left:2px solid rgba(59,130,246,.3); padding:8px 10px; border-radius:0 6px 6px 0; }
  .rig-nist-label { font-size:9px; font-weight:800; color:#3b82f6; text-transform:uppercase; letter-spacing:.07em; display:block; margin-bottom:3px; }

  /* Pillar 4 — Playbook */
  .rig-playbook { display:flex; flex-direction:column; gap:0; }
  .rig-step {
    display:flex; align-items:flex-start; gap:8px;
    padding:7px 0; border-bottom:1px solid rgba(255,255,255,.04);
    transition:background .15s;
  }
  .rig-step:last-child { border-bottom:none; }
  .rig-step-urgent .rig-step-text { color:#fbbf24; }
  .rig-step-num {
    width:18px; height:18px; border-radius:50%; flex-shrink:0; margin-top:1px;
    background:rgba(255,255,255,.07); color:#64748b;
    font-size:9px; font-weight:800; display:flex; align-items:center; justify-content:center;
  }
  .rig-step-text { font-size:11px; color:#94a3b8; line-height:1.55; flex:1; }
  .rig-step-done {
    flex-shrink:0; width:20px; height:20px; border-radius:5px;
    background:rgba(74,222,128,.1); color:#4ade80; border:1px solid rgba(74,222,128,.25);
    font-size:10px; cursor:pointer; display:flex; align-items:center; justify-content:center;
    transition:all .15s; margin-top:1px;
  }
  .rig-step-done:hover:not(:disabled) { background:rgba(74,222,128,.25); }
  .rig-step-done-active { background:rgba(74,222,128,.3) !important; }
  .rig-step-completed .rig-step-text { text-decoration:line-through; opacity:.5; }
  .rig-step-completed .rig-step-num { background:rgba(74,222,128,.2); color:#4ade80; }

  /* Previous Resolutions */
  .rig-prev-wrap { margin-top:12px; padding-top:10px; border-top:1px solid rgba(255,255,255,.05); }
  .rig-prev-title { font-size:9px; color:#475569; text-transform:uppercase; letter-spacing:.07em; margin-bottom:6px; font-weight:700; }
  .rig-prev-item  { display:flex; gap:8px; align-items:flex-start; padding:4px 0; font-size:10px; }
  .rig-prev-ts    { color:#334155; white-space:nowrap; }
  .rig-prev-action{ color:#4ade80; flex:1; }

  /* ── AI Enrichment slot ─────────────────────────────── */
  .rig-ai-slot { padding:0; }
  .rig-ai-loading {
    display:flex; align-items:center; gap:10px;
    padding:14px 18px; color:#64748b; font-size:12px;
  }
  .rig-spin { display:inline-block; animation:rig-spin .7s linear infinite; }
  @keyframes rig-spin { to{transform:rotate(360deg)} }
  .rig-ai-err { padding:12px 18px; color:#fb923c; font-size:12px; }

  .rig-ai-enrichment {
    padding:16px 18px; border-top:1px solid rgba(167,139,250,.15);
    background:rgba(167,139,250,.04);
  }
  .rig-ai-enrichment-header {
    display:flex; align-items:center; gap:10px; margin-bottom:10px;
  }
  .rig-ai-icon  { color:#a78bfa; font-size:14px; }
  .rig-ai-title { font-size:12px; font-weight:800; color:#c4b5fd; }
  .rig-ai-sev   { font-size:10px; font-weight:800; padding:2px 8px; border-radius:20px; border:1px solid; }
  .rig-ai-elapsed { font-size:10px; color:#475569; margin-left:auto; }
  .rig-ai-mitre-row { display:flex; flex-wrap:wrap; gap:5px; margin-bottom:10px; }
  .rig-ai-desc  { font-size:12px; color:#94a3b8; line-height:1.65; margin-bottom:10px; }
  .rig-ai-actions-title { font-size:9px; color:#475569; text-transform:uppercase; letter-spacing:.07em; margin-bottom:6px; font-weight:700; }
  .rig-ai-action { display:flex; gap:8px; font-size:11px; color:#94a3b8; padding:4px 0; border-bottom:1px solid rgba(255,255,255,.03); line-height:1.5; }
  .rig-ai-action:last-child { border-bottom:none; }
  .rig-ai-action-arrow { color:var(--sev-col,#64748b); flex-shrink:0; }
  `;
  document.head.appendChild(s);
}
