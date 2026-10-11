

# 1. FRONT MATTER AND DOCUMENT CONTROL

| | |
|---|---|
| Report title | Meridian Healthcare Portal Incident Report |
| Incident reference | PW-2026-0206 |
| Author | Ashik Arif |
| Version | 1.0 |
| Date issued (UTC) | 2026-10-02 |
| Classification / handling | TLP Amber |
| Distribution | CISO, SOC Lead, IR on call |

**Revision history**

| Version | Date (UTC) | Author | Change |
|---|---|---|---|
| 1.0 | 2026-10-02 | Ashik Arif | Initial report |

---

# 2. EXECUTIVE SUMMARY

An external attacker compromised the patient portal by exploiting an authenticated file-read vulnerability and reused credentials found on the server to establish persistent access. The attacker reached a privileged context, planted a disguised backdoor, and attempted to export patient data to an external server. Patient data was exposed to unauthorised read access; outbound exfiltration was blocked at the network layer. The IR team captured memory for forensics and identified the backdoor, which remains running. The file-read vulnerability must be patched and service credentials must be removed from web-readable paths, or the same chain remains available to the next attacker.

---

# 3. INCIDENT OVERVIEW

| | |
|---|---|
| Incident reference | PW-2026-0206 |
| Severity / priority | High |
| Status | Open — persistence not eradicated |
| Detected (UTC) | 2026-02-06 03:47:26 |
| Detected by | Retrospective threat hunt; no real-time detection fired during the attack window |
| Contained (UTC) | Not achieved — network block only |
| Closed (UTC) | — |
| Incident type | Authenticated LFI → credential theft → SSH access → privilege escalation → persistence → C2 |
| Systems affected | `ip-10-1-15-67` (internal `10.1.15.67`) — web server, web application, database, and SSH service on a single host |
| Identities affected | See identities table below |

**Identities affected**

| Hostname | User | Type | How compromised |
|---|---|---|---|
| ip-10-1-15-67 | svc_backup | Linux service account | Credentials believed read from `database.conf` via LFI; reused for SSH login from `10.1.134.57` at 2026-02-06 04:09:31 UTC (inference — High confidence) |
| ip-10-1-15-67 | root | Local privileged context | Obtained via SUID shell `/tmp/rootbash -p` executed by `svc_backup` at 2026-02-06 04:40:15 UTC; no root credential compromise observed |

---

# 4. SCOPE AND DATA SOURCES

| Data source | Platform | Period available | Confidence in coverage |
|---|---|---|---|
| MeridianAccess_CL | Azure Log Analytics | 2026-02-06 02:42:56–05:30 UTC | High |
| MeridianAuth_CL | Azure Log Analytics | 2026-02-06 02:42:56–05:30 UTC | High |
| MeridianDefender_CL | Azure Log Analytics | 2026-02-06 02:42:56–05:30 UTC | High |
| MeridianAudit_CL | Azure Log Analytics | 2026-02-06 02:42:56–05:30 UTC | High |
| MeridianSnapshot_CL | Azure Log Analytics | 2026-02-06 02:42:56–05:30 UTC | High |

**Gaps.**

- **Timestamp field mismatch.** The workspace `TimeGenerated` field reflects ingestion time (2026-08-30), not real event time. All analysis relies on `EventTime_t`. *Effect on conclusions:* any analysis that inadvertently used `TimeGenerated` would produce a timeline off by approximately six months.
- **Sysmon removed at 03:08:19.** An automated remediation sweep removed `sysmon.service` as a non-baseline systemd service approximately 40 minutes before the real intrusion began. *Effect on conclusions:* process-level telemetry coverage for the entire attacker window is absent. Process trees, parent-child relationships, and command-line arguments cannot be reconstructed for activity after 03:08:19. This is the single largest evidence gap in the investigation.
- **No real-time detection during the attack window.** No detection fired between 03:47 and 05:30. The activity was surfaced only through retrospective threat hunting. *Effect on conclusions:* dwell time and time-to-containment cannot be measured as response metrics — they reflect a complete detection gap, not a delayed response.
- **Contents of `database.conf` are not visible in available telemetry.** The inference that it contained the SSH credential used at 04:09:31 is based on temporal proximity (57 seconds) and the absence of an alternative credential source. *Effect on conclusions:* the specific credential-reuse mechanism is unconfirmed. The timing-based inference is High confidence; the mechanism itself is Medium confidence.
- **Authentication method for the initial web-app login is not visible.** The LFI is authenticated, meaning the attacker held a valid web-app session before exploiting `config_viewer.php`. The method by which that session was obtained is not established from available telemetry. *Effect on conclusions:* the true initial access vector may precede the earliest observed activity.
- **No endpoint detection telemetry post-Sysmon removal.** Host-level process execution evidence derives only from `MeridianAudit_CL` and `MeridianSnapshot_CL`, which have narrower field coverage than Sysmon.

---

# 5. UTC TIMELINE

| Time (UTC) | Event | Source | Evidence ref |
|---|---|---|---|
| 2026-02-06 02:53:31 | Detection burst: SSH key changes, crontab changes, new systemd service — all auto-reverted within 1 second | MeridianDefender_CL (DETECTION) | §6 F13 |
| 2026-02-06 02:58:00 | DB: Full patient table query logged (49 min before first confirmed attacker activity) | MeridianDefender_CL (WEB/DB) | §6 F11 |
| 2026-02-06 03:08:19 | `sysmon.service` removed by first automated sweep as "new/non-baseline systemd service" | MeridianDefender_CL (SWEEP) | §6 F14 |
| 2026-02-06 03:47:26 | First confirmed attacker activity — Nmap NSE HTTP enumeration from 10.1.134.57 | MeridianAccess_CL | §6 F1 |
| 2026-02-06 03:52:00 | curl/8.18.0 manual page probing | MeridianAccess_CL | §6 F1 |
| 2026-02-06 03:52:29 | Direct request to `config_viewer.php` (pre-scan, deliberate) | MeridianAccess_CL | §6 F2 |
| 2026-02-06 03:54:00 | WhatWeb/0.6.3 technology fingerprinting | MeridianAccess_CL | §6 F1 |
| 2026-02-06 03:55:05 | gobuster/3.8.2 directory brute-force begins (18,454 requests) | MeridianAccess_CL | §6 F1 |
| 2026-02-06 04:07:59 | `../../../etc/passwd` read via LFI (3077 bytes) | MeridianAccess_CL | §6 F3 |
| 2026-02-06 04:08:34 | `database.conf` read via LFI (1231 bytes) | MeridianAccess_CL | §6 F3 |
| 2026-02-06 04:09:31 | SSH login as `svc_backup` from 10.1.134.57 (57 seconds after config read) | MeridianAuth_CL | §6 F4 |
| 2026-02-06 04:15:07 | `svc_backup` runs `sudo` — "command not allowed" | MeridianDefender_CL (AUTH) | §6 F5 |
| 2026-02-06 04:40:15 | `/tmp/rootbash -p` executed by `svc_backup`, euid=0 (SUID root shell) | MeridianAudit_CL (EXECVE) | §6 F6 |
| 2026-02-06 04:44–04:46 | Four failed SSH root login attempts (2 from localhost, 2 from attacker IP) | MeridianDefender_CL (SSH) | §6 F5 |
| 2026-02-06 04:48–05:02 | 73 blocked outbound connection attempts to `10.1.134.57:43212` | MeridianDefender_CL (NETWORK) | §6 F9 |
| 2026-02-06 04:51 | `/opt/meridian/scripts/health_check` planted (real UID 1001, effective UID 0, PPid 1) | MeridianSnapshot_CL | §6 F7 |
| 2026-02-06 05:05:01 | Automated sweep terminates the first backdoor (`/tmp/rootbash`) | MeridianDefender_CL (SWEEP) | §6 F8 |
| 2026-02-06 05:05:02 | `backup.conf` tampered — reverted by final sweep | MeridianDefender_CL (SWEEP) | §6 F12 |
| 2026-02-06 05:05:06 | Sweep logs `health_check` as non-baseline but does not remediate it | MeridianDefender_CL (SWEEP) | §6 F8 |
| 2026-02-06 05:27:48 | AVML memory capture #1 → `/tmp/evidence/memory.lime` | MeridianAudit_CL (EXECVE) | §6 F15 |
| 2026-02-06 05:28:24 | AVML memory capture #2 → `/tmp/evidence/memory.lime` | MeridianAudit_CL (EXECVE) | §6 F15 |
| 2026-02-06 05:30:00 | End of observation window — `health_check` (PID 267155) still running | MeridianSnapshot_CL | §6 F16 |

**Gaps > 5 minutes during active attacker window (03:47–05:30):**

| Gap | Between | Duration | Assessment |
|---|---|---|---|
| 1 | 03:55:05 → 04:07:59 | ~12 min 54 sec | Wordlist scan duration; 18,454 requests explain the gap |
| 2 | 04:15:07 → 04:40:15 | ~25 min 8 sec | Process-level activity invisible (Sysmon removed at 03:08). Unknown whether other escalation attempts occurred |
| 3 | 05:05:06 → 05:27:48 | ~22 min 46 sec | Response gap between sweep completion and forensic capture |

---

# 6. FINDINGS BY ATTACK PHASE

## Phase: Reconnaissance

### F1 — Four-tool recon chain

**State it:** The attacker used four distinct tools to map the web server before touching sensitive endpoints.

**Show it:** `MeridianAccess_CL`; `ClientIp_s == "10.1.134.57"`; summarize by `UserAgent_s`, order by `min(EventTime_t)`. Nmap NSE at 03:47, curl/8.18.0 at 03:52, WhatWeb/0.6.3 at 03:54, gobuster/3.8.2 at 03:55 (18,454 requests).

**Interpret it:** Methodical progression: port discovery, manual probing, tech fingerprinting, exhaustive directory enumeration. WhatWeb between curl and gobuster indicates the attacker was fingerprinting the stack to select the appropriate wordlist. *(Fact.)*

---

## Phase: Initial Access

### F2 — Deliberate pre-scan request to `config_viewer.php`

**State it:** Before mass wordlist scanning began, the attacker deliberately touched one endpoint on its own — the entry point.

**Show it:** `MeridianAccess_CL`; `ClientIp_s == "10.1.134.57"`, `EventTime_t < 2026-02-06 03:55:00`, `RequestUri_s has "config"`. Request at 03:52:29, before gobuster at 03:55:05.

**Interpret it:** A deliberate pre-scan request to a specific vulnerable endpoint indicates prior reconnaissance or leaked intelligence. The attacker already knew this endpoint existed. ATT&CK **T1190**. *(Fact.)*

### F3 — Two-file LFI: `/etc/passwd` then `database.conf`

**State it:** The attacker leveraged an improperly scoped `file=` parameter in `config_viewer.php` to read two files in sequence.

**Show it:** `MeridianAccess_CL`; `ClientIp_s == "10.1.134.57"`, `RequestUri_s has "config_viewer" and RequestUri_s has "file="`, `StatusCode_s == "200"`. `../../../etc/passwd` at 04:07:59 (3077 bytes), `database.conf` at 04:08:34 (1231 bytes).

**Interpret it:** Classic LFI two-step: enumerate users, then obtain connection credentials. The 35-second gap shows deliberate, sequential exploitation, not automated scanning. `/etc/passwd` is world-readable by design and yields usernames only. `database.conf` is the material exposure — it was readable by the web process and held service-account credentials. ATT&CK **T1552.001**. *(Fact.)*

---

## Phase: Credential Access

### F4 — SSH login as `svc_backup` via credentials likely reused from `database.conf`

**State it:** 57 seconds after reading `database.conf`, the attacker authenticated over SSH as `svc_backup`.

**Show it:** `MeridianAuth_CL`; `RawMessage_s has "Accepted password"`; 04:09:31. `Accepted password for svc_backup from 10.1.134.57`.

**Interpret it:** The sub-minute gap between reading the config and successful SSH login supports the inference that the credential came from `database.conf`. *(Inference — High confidence.)* The specific mechanism (password field, key material, or other credential in the file) is not established from available telemetry. *(Inference — Medium confidence.)* ATT&CK **T1078**.

---

## Phase: Privilege Escalation

### F5 — Two failed privilege escalation attempts

**State it:** Besides the SUID shell, the attacker tried two other methods to get root — both failed.

**Show it:** `MeridianDefender_CL` — `EventCategory_s == "AUTH"` and `EventCategory_s == "SSH"` with `RawMessage_s has "Failed"`. Results: `sudo` at 04:15:07 — "command not allowed"; SSH as root at 04:44–04:46 — four failed attempts (2 from localhost, 2 from attacker IP).

**Interpret it:** The failed paths show where defence held. The sudo failure preceded the SUID shell; the SSH root attempts followed it. ATT&CK **T1078**, **T1548.003**. *(Fact.)*

### F6 — SUID root shell: `/tmp/rootbash -p`

**State it:** `svc_backup` obtained root through a SUID-root binary already present on disk.

**Show it:** `MeridianAudit_CL`; `Types_s has "EXECVE"`, `Argv_s has "rootbash"`. `/tmp/rootbash -p` executed at 04:40:15 by `svc_backup` (auid), euid=0.

**Interpret it:** The `-p` flag preserves SUID privileges on a bash copy — the standard invocation for a pre-staged SUID backdoor. How the binary was staged is not captured because process-level telemetry ended at 03:08:19. ATT&CK **T1548.001**. *(Fact.)*

---

## Phase: Persistence

### F7 — Second foothold: `/opt/meridian/scripts/health_check`

**State it:** The attacker planted a durable persistence mechanism disguised as an application maintenance process.

**Show it:** `MeridianSnapshot_CL`; `isnotempty(ProcBeaconExeLink_s)`. Result: `/opt/meridian/scripts/health_check`, real UID 1001 (`svc_backup`), effective UID 0, PPid 1 (orphaned).

**Interpret it:** Hidden in the application's own scripts folder under a routine-sounding name. This is the persistence mechanism that survived every automated remediation action. ATT&CK **T1036.005**. *(Fact.)*

### F8 — Why it survived the sweep

**State it:** The automated sweep flagged `health_check` as non-baseline in every cycle but never remediated it.

**Show it:** `MeridianDefender_CL`; `EventCategory_s == "SWEEP"`, `RawMessage_s has "health_check"`. Flagged in every sweep, never acted on.

**Interpret it:** The sweep's remediation logic covers five categories: SSH keys, crontabs, temp directories, SUID files in watched paths, and systemd services. `health_check` is a plain script under an application directory — none of those categories. Detected but never remediated. ATT&CK **T1564.001**. *(Fact.)*

---

## Phase: Command and Control

### F9 — C2 destination: `10.1.134.57:43212`, not neutralised

**State it:** The backdoor attempted outbound C2 communication on a recurring schedule.

**Show it:** `MeridianDefender_CL`; `EventCategory_s == "NETWORK"`, `DestIp_s == "10.1.134.57"`. 73 blocked connection attempts between 04:48 and 05:02. PID 267155 still running at 05:30 (`MeridianSnapshot_CL`).

**Interpret it:** The network block stopped the callback but did not kill the process. ATT&CK **T1071**. *(Fact.)*

### F10 — What the block proves and what it does not

**State it:** The network block proves exfiltration was prevented. It does not prove eradication.

**Show it:** `MeridianDefender_CL` (NETWORK) — 73 dropped connections; `MeridianSnapshot_CL` — backdoor PID 267155 still running at 05:30.

**Interpret it:** Outbound TCP to `10.1.134.57:43212` was intercepted and dropped. The process is not stopped, the code is not removed, the host is not contained. The backdoor will resume C2 the moment the block is lifted. *(Fact + inference: process resumes C2 if block lifted — High confidence.)*

---

## Phase: Collection

### F11 — Patient data export attempt

**State it:** The defence stack logged an attempted export of patient data from the attacker IP.

**Show it:** `MeridianDefender_CL`; `EventCategory_s == "WEB"`, `RawMessage_s has "export"`. "WEB: Patient data export from 10.1.134.57."

**Interpret it:** Healthcare portal; the patient table is the highest-value target. A separate "DB: Full patient table query" entry at 02:58 is a red herring — 49 minutes before first confirmed attacker activity. ATT&CK **T1213**. *(Fact.)*

### F12 — Tampered file: `backup.conf`

**State it:** The final sweep catches and reverts a tampered backup configuration file.

**Show it:** `MeridianDefender_CL`; `EventCategory_s == "SWEEP"`, `EventTime_t > 2026-02-06 05:04:00`, `RawMessage_s has "tampered"`. "SWEEP: backup.conf tampered -- reverting" at 05:05:02.

**Interpret it:** Tampering with backup configuration is an attempt to maintain access through the estate's own backup infrastructure. ATT&CK **T1565.001**. *(Fact.)*

---

## Phase: Defense Evasion

### F13 — Setup noise misclassified as tampering

**State it:** The defence log fires a burst of detections before any real intrusion — all auto-reverted within a second.

**Show it:** `MeridianDefender_CL`; `EventCategory_s == "DETECTION"`, `EventTime_t < 2026-02-06 03:00:00`. Burst at 02:53:31.

**Interpret it:** Defence stack's own installation misread as tampering, over 50 minutes before first confirmed attacker activity. Treating installation artefacts as attack indicators is a common triage error. ATT&CK **T1036**. *(Fact + inference: these are installation artefacts — High confidence.)*

### F14 — Collateral damage: `sysmon.service` removed

**State it:** The first automated sweep removed a "new systemd service" that was not attacker-planted.

**Show it:** `MeridianDefender_CL`; `EventCategory_s == "SWEEP"`, `RawMessage_s has "Removed service: sysmon"`, `EventTime_t < 2026-02-06 03:10:00`. `sysmon.service` removed at 03:08:19.

**Interpret it:** Linux Sysmon removed as non-baseline, blinding process-level telemetry ~40 minutes before the real intrusion. This is the largest detection gap in the incident. ATT&CK **T1562.001**. *(Fact.)*

---

## Phase: Incident Response

### F15 — Forensic capture: `avml` → `/tmp/evidence/memory.lime`

**State it:** The returning admin captured volatile state before remediation.

**Show it:** `MeridianAudit_CL`; `Types_s has "EXECVE"`, `EventTime_t > 2026-02-06 05:25:00`, `Argv_s has "avml" or comm_s has "avml"`. Run at 05:27:48 and 05:28:24 → `/tmp/evidence/memory.lime`.

**Interpret it:** AVML is Microsoft's Linux memory-acquisition tool. Proper volatile-state capture before remediation is the correct forensic response to a live backdoor. ATT&CK **T1005**. *(Fact.)*

### F16 — Persistence not yet remediated

**State it:** The sweep ran, the admin captured memory, and the incident still is not closed.

**Show it:** `MeridianDefender_CL`; `RawMessage_s has "health_check"`. Flagged in every sweep, never remediated. `MeridianSnapshot_CL` confirms PID 267155 still running at 05:30.

**Interpret it:** The sweep terminated the first backdoor, reverted `backup.conf`, and the admin captured memory — but `health_check` was only flagged, never remediated. The incident remains open until manual termination and binary removal are completed. ATT&CK **T1036.005**. *(Fact.)*

---

# 7. MITRE ATT&CK MAPPING

| Tactic | Technique | ID | Evidence ref |
|---|---|---|---|
| Reconnaissance | Active Scanning | T1595 | F1 |
| Initial Access | Exploit Public-Facing Application | T1190 | F2, F3 |
| Credential Access | Credentials In Files | T1552.001 | F3 |
| Credential Access | Valid Accounts | T1078 | F4, F5 |
| Privilege Escalation | Setuid and Setgid | T1548.001 | F6 |
| Privilege Escalation | Sudo and Sudo Caching | T1548.003 | F5 |
| Persistence | Match Legitimate Name or Location | T1036.005 | F7, F16 |
| Persistence | Hidden Files and Directories | T1564.001 | F8 |
| Command and Control | Application Layer Protocol | T1071 | F9, F10 |
| Collection | Data from Information Repositories | T1213 | F11 |
| Collection | Stored Data Manipulation | T1565.001 | F12 |
| Defense Evasion | Masquerading | T1036 | F13 |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | F14 |
| Collection | Data from Local System | T1005 | F15 |

---

# 8. IMPACT AND DWELL TIME

| | |
|---|---|
| First malicious activity (UTC) | 2026-02-06 03:47:26 |
| First detection (UTC) | None during the attack window; surfaced retrospectively by threat hunt on 2026-09-26 |
| **Dwell time to detection** | Not measurable — no real-time detection fired. Retrospective only. |
| **Time to containment** | Not achieved — network block only; backdoor process still live at 05:30 |
| Data confirmed accessed | `../../../etc/passwd` (3077 bytes); `database.conf` (1231 bytes); patient table query logged |
| Data confirmed exfiltrated | Not confirmed — C2 exfiltration blocked (73 attempts, all dropped) |
| Business impact | Patient data exposed to unauthorised read access; backup configuration tampered; host remains compromised; regulatory exposure (see §16) |

*Accessed and exfiltrated are separated deliberately. Access = LFI reads and patient table query. Exfiltration = network block prevented outbound transfer, but the process remains live.*

---

# 9. ROOT CAUSE

Two conditions combined to enable the breach:

1. **An authenticated local file inclusion vulnerability** in `config_viewer.php` allowed any logged-in user to read arbitrary files as the web server process.
2. **A service-account credentials file (`database.conf`) was stored in a location readable by the web process** and contained credentials that could be reused for SSH access.

Either condition alone would have been survivable. Together they allowed the attacker to obtain reusable credentials and pivot from file-read to command execution. Compounding conditions:

1. `svc_backup` had interactive SSH login enabled, allowing credential reuse to grant shell access.
2. A SUID-root copy of bash (`/tmp/rootbash`) was already present on disk, providing an immediate privilege escalation path once shell access was obtained.
3. The automated remediation sweep's rule set was too narrow to cover scripts in application directories, allowing `health_check` to persist indefinitely after detection.
4. The same sweep removed `sysmon.service` as a false positive, blinding process-level telemetry before the intrusion began.
5. No real-time detection coverage existed for authenticated LFI, SUID execution outside watched paths, or backdoors in application directories.

Root cause is the combination of an unpatched public service, credentials exposed in a web-readable path, and an overzealous automated sweep that removed more telemetry than it protected.

---

# 10. INDICATORS OF COMPROMISE

*Ordered by Pyramid of Pain — TTPs first, then tools, then network, then host.*

| Type | Indicator | Context | Confidence |
|---|---|---|---|
| TTP | 4-tool recon chain (Nmap → curl → WhatWeb → gobuster) | Pre-exploitation enumeration | High |
| TTP | Direct pre-scan request to `config_viewer.php` | Deliberate targeting of vulnerable endpoint | High |
| TTP | LFI two-step: `/etc/passwd` → `database.conf` | Credential harvesting tradecraft | High |
| TTP | Credential reuse from config file for SSH (57-second gap) | Read-to-login timing | High (inference) |
| TTP | SUID shell exploitation: `/tmp/rootbash -p` | Standard SUID backdoor invocation | High |
| TTP | Masquerading persistence: `/opt/meridian/scripts/health_check` | Hidden in app scripts folder, PPid 1 | High |
| TTP | Scheduled C2 beaconing (73 attempts, 04:48–05:02) | Beacon-on-a-schedule with backoff | High |
| TTP | Backup config tampering (`backup.conf`) | Persistence via backup infrastructure | High |
| Tool | Nmap NSE, curl/8.18.0, WhatWeb/0.6.3, gobuster/3.8.2 | Attacker recon toolkit | High |
| Tool | `avml` | Defensive forensic tool | High |
| Network | `10.1.134.57` | Attacker source IP | High |
| Network | `10.1.134.57:43212` | C2 destination | High |
| Host | `config_viewer.php` | Vulnerable endpoint | High |
| Host | `../../../etc/passwd` | LFI target | High |
| Host | `database.conf` | Credential file | High |
| Host | `svc_backup` | Compromised service account | High |
| Host | `/tmp/rootbash -p` | SUID root shell | High |
| Host | `/opt/meridian/scripts/health_check` | Persistent backdoor (PID 267155) | High |
| Host | `backup.conf` | Tampered file | High |
| Host | `/tmp/evidence/memory.lime` | Forensic memory capture | High |

---

# 11. CONTAINMENT

| # | Action | Rationale | Time (UTC) | Owner |
|---|---|---|---|---|
| 1 | Block outbound traffic to `10.1.134.57:43212` | Sever C2 channel at the network layer | 2026-02-06 04:48 | Network |
| 2 | Flag `health_check` as non-baseline in sweep logs | Detection only — no remediation | 2026-02-06 05:05:06 | Automated sweep |
| 3 | Capture volatile memory via AVML | Preserve live evidence before remediation | 2026-02-06 05:27–05:28 | Returning admin |

**The naive move and why it fails.**

**Naive move:** Block the C2 destination at the firewall and consider the host contained.

**Why it fails:** The network block stopped 73 outbound connections, but the backdoor process (`health_check`, PID 267155) remains running. The moment the block is lifted, or the attacker changes C2 destination, the backdoor resumes communication. Blocking network traffic addresses the symptom (outbound traffic) but not the cause (persistent process). The host is not contained.

**Correct move:** Manually terminate the `health_check` process, remove the binary, and verify no other persistence mechanisms exist. Network blocking is a temporary measure, not a containment action.

---

# 12. ERADICATION

| # | Action | Rationale | Time (UTC) | Owner |
|---|---|---|---|---|
| 1 | Kill PID 267155 (`health_check`) | Terminate live backdoor process | Pending | IR |
| 2 | Remove `/opt/meridian/scripts/health_check` | Eliminate binary | Pending | IR |
| 3 | Remove `/tmp/rootbash` | Remove SUID escalation vector | Removed by automatic sweep
| 4 | Patch LFI vulnerability in `config_viewer.php` | Close initial access vector | Pending | Platform |
| 5 | Rotate `svc_backup` credentials; remove interactive SSH | Revoke compromised identity and access path | Pending | Platform |
| 6 | Relocate `database.conf` credentials to a secrets manager | Remove web-readable credential source | Pending | Platform |
| 7 | Verify no other persistence (crontabs, SSH keys, systemd services, app scripts) | Comprehensive sweep | Pending | IR |

**Persistence that survives the obvious fix.**

Killing PID 267155 and removing the binary is not sufficient if the process is restarted by a parent or if a copy exists elsewhere. The sweep already removed `/tmp/rootbash` and reverted `backup.conf`, but `health_check` was only flagged, never remediated. A password reset for `svc_backup` does not remove the running backdoor process. A certificate revocation does not remove the running backdoor process. The persistence outlives credential rotation, password resets, and network blocks. Only manual process termination and binary removal close this persistence.

---

# 13. RECOVERY

| # | Action | Verification | Time (UTC) | Owner |
|---|---|---|---|---|
| 1 | Confirm no `health_check` process running | `ps aux \| grep health_check` returns nothing | Pending | IR |
| 2 | Confirm no `rootbash` binary on disk | `find / -name "*rootbash*"` returns nothing | Pending | IR |
| 3 | Confirm `config_viewer.php` patched | Code review + penetration test | Pending | Platform |
| 4 | Confirm `svc_backup` credentials rotated | Old credentials fail, new credentials work | Pending | Platform |
| 5 | Confirm `database.conf` credentials relocated to a secrets manager | File no longer exists in web-readable path | Pending | Platform |
| 6 | Re-enable Sysmon service | Process-level telemetry restored | Pending | Platform |
| 7 | 14-day clean monitoring | No recurrence of IOCs | Pending | SOC |

**Return-to-trust criteria.**

- No `health_check` process or binary on disk.
- No `rootbash` binary on disk.
- `config_viewer.php` LFI patched and verified.
- `svc_backup` credentials rotated; old credentials invalid.
- `database.conf` no longer contains reusable credentials; secrets moved to a secrets manager.
- Sysmon service restored and collecting process-level telemetry.
- 14 days of clean monitoring with no recurrence of attacker IP or IOCs.
- Automated sweep rules updated to remediate scripts in application directories and to exclude legitimate telemetry agents from baseline remediation.

---

# 14. CHAIN OF CUSTODY

| Evidence item | Collected (UTC) | Collected by | Hash | Storage | Handled by |
|---|---|---|---|---|---|
| `/tmp/evidence/memory.lime` (capture 1) | 2026-02-06 05:27:48 | Returning admin | Not provided | `/tmp/evidence/` | IR |
| `/tmp/evidence/memory.lime` (capture 2) | 2026-02-06 05:28:24 | Returning admin | Not provided | `/tmp/evidence/` | IR |

*Note: Hash values were not available from available telemetry. Recommended to compute SHA-256 of memory captures before transfer to evidence storage.*

---

# 15. RECOMMENDATIONS

| # | Recommendation | Addresses | Priority | Owner | Effort |
|---|---|---|---|---|---|
| 1 | Manually terminate `health_check` and remove binary | Persistence | Critical | IR | Low |
| 2 | Patch `config_viewer.php` LFI vulnerability | Root cause | Critical | Platform | Medium |
| 3 | Move `database.conf` credentials to a secrets manager | Root cause | Critical | Platform | Medium |
| 4 | Rotate `svc_backup` credentials and remove interactive SSH | Credential access | Critical | Platform | Low |
| 5 | Expand sweep remediation rules to cover app directory scripts | Detection gap | High | Detection Eng | Medium |
| 6 | Restore `sysmon.service` and exclude from sweep baseline | Telemetry gap | High | Platform | Low |
| 7 | Remove SUID binaries from `/tmp` and monitor SUID creation | Privilege escalation | High | Platform | Medium |
| 8 | Implement egress allow-listing for the estate | C2/exfiltration | High | Network | High |
| 9 | Build detection coverage for authenticated LFI and app-directory script execution | Detection gap | High | Detection Eng | Medium |
| 10 | Add `config_viewer.php` to secure code review checklist | Root cause | Medium | App Sec | Low |
| 11 | Validate sweep baseline before production deployment | Collateral damage | Medium | Detection Eng | Medium |

*Ranked by leverage, not cost.*

---

# 16. REGULATORY NOTIFICATION

| | |
|---|---|
| Personal data involved | Yes — patient data accessed (healthcare portal) |
| Regulation(s) engaged | HIPAA / HITECH (confirm with counsel); applicable state breach notification laws |
| Notification required | Under assessment |
| Deadline (UTC) | 60 days from discovery (HIPAA) — confirm with counsel |
| Notified (UTC) | (pending) |
| Notified by | (pending) |

---

# 17. APPENDICES

### A. Full queries

#### Flag 1 — Recon toolchain

```kql
MeridianAccess_CL
| where EventTime_t between (datetime(2026-02-06) .. datetime(2026-02-07))
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| summarize FirstSeen = min(EventTime_t) by UserAgent_s
| order by FirstSeen asc
```

#### Flag 2 — Deliberate pre-scan request to `config_viewer.php`

```kql
MeridianAccess_CL
| where EventTime_t between (datetime(2026-02-06 02:42) .. datetime(2026-02-06 05:30))
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| where UserAgent_s startswith "curl"
| order by EventTime_t asc
| project EventTime_t, HttpMethod_s, RequestUri_s, StatusCode_s
```

#### Flag 3 — LFI file reads

```kql
MeridianAccess_CL
| where EventTime_t between (datetime(2026-02-06 02:42) .. datetime(2026-02-06 05:30))
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| where UserAgent_s startswith "curl"
| where StatusCode_s == "200"
| where RequestUri_s contains "file"
| order by EventTime_t asc
| project EventTime_t, HttpMethod_s, RequestUri_s, StatusCode_s
```

#### Flag 4 — SSH login as `svc_backup`

```kql
MeridianAuth_CL
| where EventTime_t between (datetime(2026-02-06 04:08) .. datetime(2026-02-06 05:30))
| where isnotempty(EventTime_t)
| where SourceIP == "10.1.134.57"
```

#### Flag 5 — Failed privilege escalation attempts

```kql
MeridianDefender_CL
| where EventTime_t between (datetime(2026-02-06 04:08) .. datetime(2026-02-06 04:50))
| where isnotempty(EventTime_t)
| where EventCategory_s == "AUTH"
| project EventTime_t, RawMessage_s

MeridianDefender_CL
| where EventTime_t between (datetime(2026-02-06 04:08) .. datetime(2026-02-06 04:50))
| where isnotempty(EventTime_t)
| where EventCategory_s == "SSH"
| where RawMessage_s has "Failed"
| project EventTime_t, RawMessage_s
```

#### Flag 6 — SUID shell execution

```kql
MeridianAudit_CL
| where EventTime_t between (datetime(2026-02-06 04:08) .. datetime(2026-02-07))
| where isnotempty(EventTime_t)
| where cwd_s == "/home/svc_backup"
| where Argv_s contains "root"
```

#### Flag 7 — Persistence process

```kql
MeridianSnapshot_CL
| where EventTime_t between (datetime(2026-02-06) .. datetime(2026-02-07))
| where isnotempty(ProcBeaconExeLink_s)
| project ProcBeaconName_s, ProcBeaconExeLink_s, ProcBeaconUid_s, ProcBeaconPPid_s
```

#### Flag 8 — Sweep flags `health_check`

```kql
MeridianDefender_CL
| where EventCategory_s == "SWEEP"
| where RawMessage_s has "health_check"
| project EventTime_t, RawMessage_s
```

#### Flag 9 & 10 — C2 destination

```kql
MeridianDefender_CL
| where EventTime_t between (datetime(2026-02-06) .. datetime(2026-02-07))
| where EventCategory_s == "NETWORK"
| where DestIp_s == "10.1.134.57"
| summarize count() by DestPort_s
| project DestPort_s, count_
```

#### Flag 11 — Patient data export

```kql
MeridianDefender_CL
| where EventTime_t between (datetime(2026-02-06) .. datetime(2026-02-07))
| where EventCategory_s == "WEB"
| where RawMessage_s has "export"
| project EventTime_t, RawMessage_s
```

#### Flag 12 — Tampered file `backup.conf`

```kql
MeridianDefender_CL
| where EventTime_t between (datetime(2026-02-06) .. datetime(2026-02-07))
| where EventCategory_s == "SWEEP"
| where EventTime_t > datetime(2026-02-06 05:04:00)
| where RawMessage_s has "tampered"
| project EventTime_t, RawMessage_s
```

#### Flag 13 — Setup noise / false positive

```kql
MeridianDefender_CL
| where EventTime_t between (datetime(2026-02-06) .. datetime(2026-02-07))
| where EventCategory_s == "DETECTION"
| where EventTime_t < datetime(2026-02-06 03:00:00)
| project EventTime_t, RawMessage_s
```

#### Flag 14 — Sysmon removal (collateral damage)

```kql
MeridianDefender_CL
| where EventTime_t between (datetime(2026-02-06) .. datetime(2026-02-07))
| where isnotempty(EventTime_t)
| where EventCategory_s == "SWEEP"
| where RawMessage_s has "Removed service: sysmon"
```

#### Flag 15 — Forensic memory capture (`avml`)

```kql
MeridianAudit_CL
| where Types_s has "EXECVE"
| where EventTime_t > datetime(2026-02-06 05:25:00)
| where Argv_s has "avml" or comm_s has "avml"
| project EventTime_t, Argv_s, exe_s
```

### B. Raw evidence extracts

- `Accepted password for svc_backup from 10.1.134.57` — MeridianAuth_CL, 2026-02-06 04:09:31
- `sudo: svc_backup : command not allowed` — MeridianDefender_CL (AUTH), 2026-02-06 04:15:07
- `/tmp/rootbash -p` executed by `svc_backup`, euid=0 — MeridianAudit_CL (EXECVE), 2026-02-06 04:40:15
- `health_check` PPid 1, real UID 1001, effective UID 0 — MeridianSnapshot_CL
- `SWEEP: backup.conf tampered -- reverting` — MeridianDefender_CL (SWEEP), 2026-02-06 05:05:02
- `SWEEP: Removed service sysmon.service` — MeridianDefender_CL (SWEEP), 2026-02-06 03:08:19
- `WEB: Patient data export from 10.1.134.57` — MeridianDefender_CL (WEB)
- `avml /tmp/evidence/memory.lime` — MeridianAudit_CL (EXECVE), 2026-02-06 05:27:48 and 05:28:24

### C. Reference list

- MITRE ATT&CK (14 techniques, §7)
- NIST SP 800-61r3 — Incident Handling Guide
- SANS PICERL — Incident Response Framework
- Pacific Cyber Range — Hunt 25 Meridian case brief
- Microsoft AVML — Linux memory acquisition tool

---

*End of report. Prepared by Ashik Arif. All times UTC.*
