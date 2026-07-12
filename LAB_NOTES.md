# Home SIEM Lab — Build & Investigation Log

## Environment
- **Host:** Windows PC, i7-9750H, 32 GB RAM, VMware Workstation Pro (free personal use license)
- **VMs:**
  - Security Onion (Standalone install) — 16 GB RAM, 4 CPU, 200 GB disk
    - Management NIC: `ens160` (NAT, DHCP)
    - Monitor NIC: `ens192` (VMnet2, host-only, promiscuous mode enabled via `.vmx` edit)
  - Windows 10/11 target — VMnet2 only (post-setup)
  - Kali Linux (prebuilt VMware image) — VMnet2 only (post-setup)
- **Network:** VMnet2 = isolated host-only network, subnet `192.168.50.0/24`
- **Web UI access:** IP-based, `0.0.0.0/0` allowed range (lab-only, justified since network is isolated)

## Config decisions worth remembering
- Security Onion Standalone install requires **2 NICs minimum** (management + monitor) or setup exits to shell
- Standalone install requires **16 GB RAM minimum**
- VMware doesn't expose promiscuous mode in the GUI — required manual `.vmx` edit: `ethernet1.noPromisc = "false"`
- Security Onion uses a **bonded interface** (`bond0`) wrapping the physical monitor NIC(s) — config lives in `/opt/so/conf/zeek/node.cfg`
- VM files should NOT live under a OneDrive-synced folder (`Documents\Virtual Machines`) — causes file-access errors on suspend/resume and wastes cloud storage on multi-GB disposable files. Moved VM storage to `C:\VMs`.

## Problems hit, root cause, and fix (troubleshooting log)

| # | Problem | Root Cause | Fix |
|---|---|---|---|
| 1 | Setup exited to command line after selecting install type | Standalone mode requires 2 NICs; VM only had 1 | Added second network adapter in VMware settings before re-running setup |
| 2 | "Install will fail without 16GB memory" | Standalone mode's RAM minimum | Increased VM memory allocation to 16 GB |
| 3 | Setup failed: "no space left on device" during Elastic Agent extraction | Root (`/`) LVM volume only had 33 GB, 93% full — most disk space had gone to `/nsm` instead | (First attempt) Diagnosed via `df -h`, `vgs`, `lvs` — found `VFree: 0`, no room to extend without adding a disk. (Final fix) Rebuilt VM from scratch with a full 200 GB disk allocated up front |
| 4 | VMware error: "Virtualized Intel VT-x/EPT is not supported on this platform" | Windows **Core Isolation / Memory Integrity** was silently using virtualization-based security, blocking VMware's access to VT-x — even though Hyper-V and BIOS VT-x settings were already correctly configured | Disabled Memory Integrity in Windows Security → Device Security → Core Isolation, then restarted |
| 5 | PowerShell: "running scripts is disabled on this system" | Default execution policy blocks unsigned/downloaded scripts | `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process` (session-scoped, not a permanent security change) |
| 6 | Ran default `Invoke-AtomicTest T1046`, no alerts in Security Onion | Default atomic for T1046 may run local-only discovery commands (no real network traffic) | Used `-ShowDetailsBrief` to list all available sub-tests; selected **T1046-10** (PowerShell /24 subnet scan) since it generates genuine cross-network traffic |
| 7 | No alerts/Hunt results even after real scan traffic (T1046-10) confirmed via `tcpdump` on `ens192` | **Still under investigation** — traffic capture confirmed working at the packet level; `bond0`/`ens192` binding confirmed healthy via `/proc/net/bonding/bond0`; all Security Onion containers (Suricata, Zeek, Elasticsearch, etc.) show "running/healthy" via `so-status`. Next step: check Zeek's raw `conn.log` directly to isolate whether this is a Zeek processing issue vs. an Elasticsearch/Kibana ingestion or time-filter issue | *(pending)* |
| 8 | VMware failed to resume Windows VM: "Could not create anonymous paging file... insufficient system resources" | Host RAM contention (other VMs likely still running) + VM files stored under OneDrive-synced folder, causing file access conflicts during suspend/resume | Discarded suspended state (cold boot instead of resume); relocated all VM storage from `OneDrive\Documents\Virtual Machines` to local `C:\VMs` and changed VMware's default Workspace location |

## Investigation Findings

### Technique: T1046-10 — Port-Scanning /24 Subnet with PowerShell (MITRE T1046, Network Service Scanning)
- **Executed from:** Windows VM (192.168.50.129), via Invoke-AtomicRedTeam
- **Command:** `Invoke-AtomicTest T1046-10`
- **Observed behavior:** PowerShell swept the `192.168.50.0/24` range, checking port 445 (SMB) on each host; confirmed port 445 open on `192.168.50.129` (itself)
- **Packet capture (tcpdump on ens192):** Confirmed — SYN packets visible to multiple destination IPs (.1, .130, .254, etc.) on port 445/microsoft-ds
- **Zeek conn.log:** Confirmed (Day 3) — multiple entries showing `192.168.50.129` → various destination IPs, port 445/tcp, `conn_state: S0` (connection attempts, no response — expected for a scan against mostly-closed ports)
- **Security Onion Alerts/Hunt:** No Suricata alert fired specifically for the scan. **Conclusion:** traffic was correctly captured and logged by Zeek, but not flagged by Suricata — most likely because horizontal port-scan detection signatures are disabled by default in the ruleset (a conservative default to avoid noise in production). Pipeline itself confirmed fully functional via a separate real alert (see Milestone below).
- **Status:** RESOLVED as a finding — this is a legitimate, valid outcome: "traffic generated, captured, and logged correctly, but not flagged by default detection rules." Good basis for a write-up and a natural next lab step (enabling/tuning a scan-detection rule).

### Milestone — Pipeline Confirmed End-to-End (Day 3)
After extensive troubleshooting (problems #7, #9-11 below), confirmed the full detection pipeline works: traffic capture (tcpdump) → Zeek processing → Elasticsearch ingestion → Kibana/Alerts UI. First real alert observed: **"ET INFO Possible Kali Linux hostname in DHCP Request Packet"** (Suricata, high severity) — triggered by Kali's DHCP request revealing its hostname. Confirms the alerting pipeline is fully functional end-to-end.

## Current Blocker (as of end of Day 2 — pick up here tomorrow)

**Web UI (port 443) became unreachable** after enabling "Show advanced settings" in SOC's firewall configuration (Administration → Configuration → firewall). All containers still show `running`/`healthy` via `so-status`, and the box's IP is unchanged (`192.168.128.130`), so this is a firewall-state issue, not a service crash.

**Attempted fix (not yet confirmed):**
```
sudo so-firewall includehost analyst 0.0.0.0/0
sudo so-firewall apply
```

**RESOLVED (Day 3):** Reboot alone did not fix it. Running `sudo so-firewall includehost analyst 0.0.0.0/0` + `sudo so-firewall apply` from the console restored web UI access immediately. Likely cause: enabling "Show advanced settings" in SOC triggered a Salt state sync that dropped the `0.0.0.0/0` rule on the `analyst` hostgroup, and the CLI command restored it. No container/service was ever actually broken — this was purely a firewall rule issue. **Lesson: avoid the "Show advanced settings" firewall path unless intentionally editing role/chain/portgroup config; stick to basic hostgroup pages for routine changes.**

## Additional troubleshooting log entries (Day 2)

| # | Problem | Root Cause | Fix |
|---|---|---|---|
| 9 | SSH (port 22) connection failed with "Unknown error" from Windows | Security Onion's host-based firewall blocks all ports by default except explicitly allowed ones; only web UI (443) had been opened during setup | Confirmed via `ping` + `Test-NetConnection` that TCP 22 specifically was unreachable, not a DNS/routing issue |
| 10 | Added Windows host IP to `analyst` hostgroup via both SOC UI and `so-firewall includehost` CLI — SSH still didn't connect | In current Security Onion 2.4, the `analyst` hostgroup only opens ports 80/443 (web UI) by default — it does **not** include SSH (22) like older Security Onion versions did | Root cause identified but not yet fully resolved — would require attaching the `analyst` hostgroup (or a new one) to the `ssh` portgroup under the box's role (`standalone`) → chain (`INPUT`), via SOC's advanced settings view |
| 11 | Enabling "Show advanced settings" in SOC's firewall config coincided with the web UI (port 443) becoming unreachable | Likely a Salt state sync issue triggered by the settings change — under investigation | Planned: reboot + CLI-based `so-firewall includehost`/`apply` fix (see Current Blocker above) |

**Write-up angle worth keeping:** the SSH/firewall investigation is itself a good demonstration of Security Onion's security posture working as intended (default-deny host firewall), even though it turned into an unplanned troubleshooting detour. Worth noting in a write-up as "confirmed the appliance defaults to deny-all and requires explicit allow-listing per service — a good practice to point out even when it slows down my own management workflow."

## Day 3 (continued) — Kibana/Hunt Search Lessons + Resource Management

### Lesson: searching Elasticsearch/Kibana-style tools by guessing field names is unreliable
Spent significant time trying to search `destination.port:445` and `id.resp_p:445` directly — both returned 0 results even for values we could see existed in the raw JSON (confirmed via `id.resp_p:53` also returning 0 despite being visibly present in a record). **Root cause:** typing field names manually requires knowing the exact underlying field mapping, which varies by data source/schema and is easy to get wrong (dotted field names, text vs. keyword field types, etc.).

**Better approach discovered:** click directly on a real data value in the UI (e.g., a destination port shown in a results column) to auto-generate a correctly-mapped filter, rather than typing field names from memory. This is a generally useful skill for any new/unfamiliar Elasticsearch or Kibana-based data source — explore via the UI first, don't assume field names.

### Lesson: aggregation panels can have their own separate sampling limits
The "Group Metrics" panel (grouped by destination port) initially appeared to show only 5 distinct ports with no port 445 present, suggesting the scan data was missing. **Root cause:** the panel had its own "Fetch Limit" (set to 10) separate from the main search's total match count (4,055) — it was only aggregating a small sample, not the full result set. Lesson: always check for hidden sub-scoped limits on aggregation/summary widgets, separate from the main query's fetch settings, before concluding data is missing.

### Resource management: VM memory sizing on a 32GB host
Running Security Onion (16GB) + Windows (originally 4GB) + Kali (originally 2-4GB) simultaneously left very little headroom — Task Manager showed 97% memory usage with committed memory (34.4GB) exceeding physical RAM (31.8GB), meaning the host was already relying on page file/swap. This directly explains earlier VM resume/allocation failures.

**Mitigations applied:**
- Trimmed Windows VM to 3GB RAM, Kali to 2GB RAM
- Closed unnecessary host background processes
- Adopted a deliberate boot sequencing practice: Security Onion first (let it fully settle) → Windows → Kali, and shut down Windows/Kali promptly after each test rather than leaving all three idle simultaneously, since Security Onion alone plus host overhead consumes the large majority of available RAM

**Write-up angle:** this is a legitimate, relatable resource-planning finding — many real-world SOC/lab environments face similar constraints, and documenting the actual math (16+3+2GB VMs + host overhead ≈ full 32GB capacity) demonstrates capacity-planning awareness, not just "it broke and I fixed it."


1. **"Building a Home SIEM Lab: What Actually Broke"** — the build + troubleshooting log above, framed as a real analyst-adjacent problem-solving narrative rather than a clean tutorial
2. **"When a Scan Doesn't Alert: Investigating a Detection Gap"** — once the T1046-10 mystery is resolved, write up the diagnostic process (tcpdump → bond status → so-status → conn.log) as a mini investigation, regardless of whether the root cause turns out to be a config issue or a genuine detection gap

## Day 4 — T1003-7 Investigation (Credential Dumping via NTLM)

### Technique: T1003-7 — Send NTLM Hash with RPC Test Connection (MITRE T1003, OS Credential Dumping)
- **Command:** `Invoke-AtomicTest T1003-7 -InputArgs @{ "server_ip" = "<target>"; "custom_port" = "445" }`
- **Attempt 1 — target: 192.168.50.1 (gateway, no real service):** Zeek logged 3x `zeek.conn` entries (TCP SYN attempts, port 445) — connection never completed (no service listening). No Suricata alert — makes sense, no app-layer content to inspect.
- **Attempt 2 — target: 192.168.50.129 (Windows' own IP, i.e. self):** **Zero results anywhere in Hunt**, even within a tight 15-minute window. Root cause: Windows almost certainly routed the "connection" to itself via loopback internally, never actually putting packets on the network wire — so the monitor NIC had nothing to capture. Good conceptual finding: network sensors can only see traffic that actually crosses the network; self-directed connections may bypass this entirely.
- **Attempt 3 — target: 192.168.50.130 (Kali, real peer with an active listener via `nc -lvp 445`):** Kali's listener confirmed the connection was received (real cross-network traffic). **Result: 2 Suricata alerts fired** — "ET INFO NTLM Session Setup Request - Negotiate" (low severity) and a repeat of the earlier "ET INFO Possible Kali Linux hostname in DHCP Request Packet" (high severity, unrelated to this specific test but same Kali VM).
- **Conclusion:** Confirms Suricata's signature relies on inspecting actual protocol content (the NTLM negotiation itself), not just a connection attempt — explaining why attempts 1 and 2 produced no alert despite the underlying command running successfully (exit code 0) each time. Strong demonstration of the difference between "traffic was attempted" vs. "traffic completed with inspectable content" for detection purposes.

**Troubleshooting note:** Mid-test, `Invoke-AtomicTest` unexpectedly prompted to kill `dwm.exe`/`fontdrvhost.exe` (repeatedly, ignoring "No to All"). Cause suspected to be leftover job state from a broader technique invocation earlier in the session pulling in unrelated cleanup/rollback logic from a different atomic. Confirmed no processes were actually terminated (`Get-Process` showed both alive/healthy) after breaking out via Ctrl+C. **Lesson: always invoke specific test IDs (e.g. `T1003-7`) rather than bare technique IDs, and treat unexpected destructive-sounding confirmation prompts with caution even in a lab context — verify via `Get-Job`/`Get-Process` before assuming everything is fine.**

## Write-up ideas (draft angles, expand once resolved)
1. **"Building a Home SIEM Lab: What Actually Broke"** — the build + troubleshooting log above, framed as a real analyst-adjacent problem-solving narrative rather than a clean tutorial
2. **"When a Scan Doesn't Alert: Investigating a Detection Gap"** — T1046-10 diagnostic process (tcpdump → bond status → so-status → conn.log), showing traffic captured but not flagged due to disabled default scan-detection rules
3. **"Same Command, Three Outcomes: How Target Selection Changes What a Sensor Sees"** — T1003-7 run against three different targets (dead host, self/loopback, real peer), showing progressively how network visibility depends on where traffic actually goes — a genuinely interesting narrative for a portfolio piece

### Alert Detail — "ET INFO NTLM Session Setup Request - Negotiate" (sid 2067085)
- **Rule:** `alert tcp-pkt $HOME_NET any -> any 445 (msg:"ET INFO NTLM Session Setup Request - Negotiate"; flow:established,to_server; content:"NTLMSSP|00 01 00 00 00|"; ...)`
- **Source → Destination:** 192.168.50.129 (Windows) → 192.168.50.130 (Kali), TCP/445
- **Payload evidence:** `network.data.decoded` field shows the raw NTLM negotiation bytes, including the literal string `NTLMSSP` and the Windows VM's actual hostname/workgroup (`DESKTOP-H63K059WORKGROUP`) transmitted in the negotiation — direct proof of what the signature matched against.
- **Classification:** confidence Medium, severity Informational, rule.action "allowed" (observational alert, not a block) — this signature is a visibility/hunting tool flagging NTLM negotiation traffic in general, not a definitive malicious-activity verdict. Worth noting in write-up: not every alert = confirmed attack; some (like this one) are designed to surface activity worth a human review.
- **Analyst takeaway:** demonstrates full alert-to-payload traceability — from Suricata's signature match, back to the actual bytes on the wire that caused it, including recognizing protocol-identifying strings (NTLMSSP) and incidentally-leaked host info (computer name/workgroup) — a realistic example of what "investigating an alert" looks like in practice.
