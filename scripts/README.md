# Secure Eye Trust+ — Test Payload Harness

Two scripts that exercise EVERY detection layer of the app so you can verify the dashboard actually finds and reports things.

| File | Drop into |
|---|---|
| `test_payloads.py` | `scripts/test_payloads.py` (or anywhere in the project root) |
| `test_anomaly_traffic.py` | **same folder** as `test_payloads.py` |

Both must sit side-by-side because `test_payloads.py deploy --traffic` spawns the traffic generator by name.

---

## What it does

```
python test_payloads.py deploy
```

Triggers all six "No X detected" panels at once:

| Panel that was empty | What gets injected | Detection that now fires |
|---|---|---|
| Malware Detections | EID 1 macro chain row | `SIGMA_OFFICE_SPAWN_SHELL` (CRITICAL) |
| Suspicious Processes (Sysmon) | Office → PowerShell parent/child row | Sysmon EID 1, Office→Shell |
| File Drops | EID 11 row for `SET_TEST_payload.exe` in Downloads | Sysmon EID 11 — Suspicious Files Created |
| Sigma Rule Detections | 9 specifically-crafted rows | 8 Sigma rules fire (Office→Shell, EncodedPowerShell, RegistryRunPersist, FileDrop, NetShellExternal, CertutilDownload, SchtasksPersist, UnsignedTempExe) |
| YARA / Behavioural Matches | 5 dropped script files (`.ps1`, `.bat`, `.vbs`) in Downloads / Desktop / Temp / AppData | YARA scanner finds: PowerShell_Download_Cradle, PowerShell_Encoded_Command, PowerShell_AMSI_Bypass, Suspicious_VBScript_Dropper, Suspicious_Batch_LOLbin |
| Correlated Attack Sequences | EID 11 followed by EID 13 (Run-key) | `SYSMON_DROPPER_PERSIST` (CRITICAL multi-stage chain) |
| Anomaly Detection (Network Analyzer) | background daemon opens 80+ sockets in SYN_SENT | suspicious_port, port_scan, syn_flood, beaconing |

**End-to-end verified** against the project's actual `core/analysis_engine/sigma_engine.py`, `correlator.py`, and `api/network_api.py` — every layer fires, and `remove` cleans it all back to zero.

---

## Commands

```
python test_payloads.py deploy             # everything: files + sysmon + traffic
python test_payloads.py deploy --files     # YARA scanner only
python test_payloads.py deploy --sysmon    # Sigma / chain / processes / file-drops only
python test_payloads.py deploy --traffic   # network anomaly traffic only

python test_payloads.py status             # what's currently deployed

python test_payloads.py remove             # tear everything down
python test_payloads.py remove --traffic   # just stop the traffic
```

---

## How removal works

Every artifact is tagged with a recognisable marker so cleanup can't touch anything else:

- **Files**: every dropped file is named `SET_TEST_*.{ps1,bat,vbs}`. `remove` does a `glob("SET_TEST_*")` per monitored directory and `unlink()` only those.
- **Sysmon rows**: every injected row has `source = 'Sysmon_SET_TEST'`. `remove` runs `DELETE FROM logs_sysmon WHERE source = 'Sysmon_SET_TEST'`.
- **Anomaly traffic**: the background script writes its PID to `~/.set_test_anomaly.pid`. `remove` reads it and sends SIGTERM (or `taskkill /F /PID` on Windows). The script catches SIGTERM, closes every socket, and exits — so the OS instantly stops reporting SYN_SENT connections.

Real malware on the same machine would not be tagged with these markers and is therefore safe.

---

## Two ways to "clean up" after detection

**Path A — use the app's own Active Response buttons.** This is the realistic flow:

1. `python test_payloads.py deploy`
2. UI → Perform Analysis → Re-run Analysis
3. Click **Delete File** on the dropped `.ps1` / `.bat` artifacts
4. Click **Remove Persistence** on the Registry Run-key row
5. Click **Kill Process** on the suspicious PowerShell row
6. Re-run analysis — fewer hits each time
7. When done, `python test_payloads.py remove` just to be sure nothing leftover

**Path B — fast wipe via the harness:**

```
python test_payloads.py remove
```

Everything gone in one command. Useful when you just wanted to see the detection screens light up.

---

## What `test_anomaly_traffic.py` does on its own

It can be run standalone too:

```
python test_anomaly_traffic.py            # interactive — Ctrl+C to stop
python test_anomaly_traffic.py --short    # one wave, hold 60s, exit
python test_anomaly_traffic.py --quiet    # silent (daemon mode)
```

It opens 80+ TCP sockets to deliberately suspicious targets — 9 known threat ports (4444 Metasploit, 1337 backdoor, 31337 BO, 6667 IRC, 12345 Netbus, 27374 Sub7, 5555 ADB, 23 Telnet, 9001 Tor), 12 port-scan-pattern ports on `192.168.0.50`, 30 half-open SYN_SENT connections, and 15 to a public RFC-5737 reserved IP for the beaconing pattern. Nothing routes to a real host.

When `test_payloads.py deploy --traffic` runs, it spawns this script in detached background mode (writing PID to `~/.set_test_anomaly.pid`); `remove --traffic` finds that PID and stops it.

---

## Verified output

After `deploy`, running the actual detectors against the live DB:

```
SIGMA RULE ENGINE
  Sigma rules fired: 9
    [CRITICAL] SIGMA_OFFICE_SPAWN_SHELL       Office Application Spawning Shell Interpreter
    [HIGH    ] SIGMA_ENCODED_POWERSHELL       Suspicious Encoded PowerShell Command
    [HIGH    ] SIGMA_CERTUTIL_DOWNLOAD        CertUtil Used for Download (LOLBin Abuse)
    [HIGH    ] SIGMA_SUSPICIOUS_FILE_DROP     Executable Dropped in User-Writable Directory
    [HIGH    ] SIGMA_REGISTRY_RUN_PERSIST     Registry Run Key Persistence
    [HIGH    ] SIGMA_UNSIGNED_TEMP_EXE        Unsigned Executable Running from Temp Location
    [HIGH    ] SIGMA_NET_SHELL_EXTERNAL       Shell Process Connecting to External IP
    [HIGH    ] SIGMA_REGISTRY_RUN_PERSIST     Registry Run Key Persistence
    [MEDIUM  ] SIGMA_SCHTASKS_PERSIST         Scheduled Task Created via Schtasks

ATTACK-CHAIN CORRELATOR
  Attack chains found: 1
    [CRITICAL] SYSMON_DROPPER_PERSIST   Downloaded Executable → Registry Persistence (Sysmon)
       Evidence: File dropped: SET_TEST_payload.exe at 2026-05-18T21:31:39

NETWORK ANOMALY DETECTOR
  Anomaly alerts: 4
    [MEDIUM ] 🚨 Connection to suspicious port 9001
    [HIGH   ] 🔍 Possible port scan from 192.168.0.50
    [HIGH   ] 🔍 Possible port scan from 198.51.100.5
    [CRITICAL] 🌊 Possible SYN flood: 78 half-open connections
```

After `remove`:

```
SET_TEST sigma hits = 0
SET_TEST attack chains = 0
Files dropped = 0
Sysmon test rows = 0
Traffic generator = not running
```

---

## One-time database migration

The Sigma engine and the SYSMON_DROPPER_PERSIST correlator query columns named `sysmon_image`, `sysmon_command_line`, `sysmon_target_file`, etc. — but the live `logs_sysmon` table in your database was created with unprefixed column names (`command_line`, `parent_image`, `target_filename`).  
The detectors were therefore silently producing nothing.

The first time `test_payloads.py deploy --sysmon` runs, it auto-`ALTER TABLE`s the missing `sysmon_*` columns into your existing table. This is non-destructive and persists — after that, **Sigma + Attack-Chain detection now works against real Sysmon data too**, not just test data.

You'll see this message once:

```
✓ added missing sysmon_* columns: sysmon_image, sysmon_command_line, …
```

After that, subsequent deploys don't re-print it.
