**SYSTEM SECURITY PLAN (SSP)**

**Home SIEM Detection Lab**

*Prepared under the NIST Risk Management Framework (SP 800-37 Rev. 2)*

**Control Baseline:** NIST SP 800-53 Rev. 5 — LOW

**System Owner / ISSO:** Jearld P. Palmer

**Version:** 1.0 **Date:** 2026-10-15

*Training / portfolio artifact — RMF documentation practices applied to
a self-built home lab.*

**1. Introduction and RMF Context**

This System Security Plan (SSP) documents the security categorization,
architecture, and control implementation for the Home SIEM Detection
Lab, a self-built environment used to develop hands-on security
monitoring and detection-engineering skills. It is written to mirror how
a federal system is documented under the NIST Risk Management Framework
(RMF, SP 800-37 Rev. 2) and the SP 800-53 Rev. 5 control catalog.

The RMF has seven steps: **Prepare, Categorize, Select, Implement,
Assess, Authorize, and Monitor**. An SSP is the central artifact
produced across the Categorize, Select, and Implement steps: it records
what the system is, how sensitive it is, which controls apply, and how
each control is satisfied. This document covers those three steps; the
Assess, Authorize, and Monitor steps are summarized at the end as next
actions.

**Scope:** the four virtual machines of the lab and the virtual networks
that connect them, hosted on a single workstation. The host operating
system, the home network, and the public internet are outside the
authorization boundary and are addressed only where they affect the lab.

**2. System Identification**

| **Attribute**                       | **Value**                                                                                |
|-------------------------------------|------------------------------------------------------------------------------------------|
| System Name                         | Home SIEM Detection Lab                                                                  |
| System Owner / ISSO / Administrator | Jearld P. Palmer (single operator; see Section 5)                                        |
| System Type                         | Standalone, non-production training and research environment                             |
| Operational Status                  | Operational                                                                              |
| Purpose                             | Detection engineering, MITRE ATT&CK threat emulation, and SOC analysis skill development |
| Hosting                             | VMware Workstation Pro on a single Windows 11 host (Intel i7-9750H, 32 GB RAM)           |

**3. Security Categorization (FIPS 199 / SP 800-60)**

The system processes only synthetic security telemetry, emulated attack
artifacts, and lab configuration data. It contains no PII, no Controlled
Unclassified Information (CUI), and no production or mission data. Each
security objective is rated below; the overall categorization is the
high-water mark of the three.

| **Security Objective** | **Impact** | **Rationale**                                                                               |
|------------------------|------------|---------------------------------------------------------------------------------------------|
| Confidentiality        | LOW        | No sensitive, CUI, or personal data is stored or processed; only synthetic lab telemetry.   |
| Integrity              | LOW        | Loss or alteration of lab data affects only personal training, not any operational mission. |
| Availability           | LOW        | Downtime affects only self-study; no external users or services depend on the system.       |

**Overall System Categorization: LOW** (C = Low, I = Low, A = Low).

***Note:** a production SOC handling real network telemetry, PII, or CUI
would categorize at MODERATE or higher and inherit the larger MODERATE
control baseline. The LOW baseline is selected here because it
accurately reflects this lab’s data and mission impact.*

**4. System Environment and Architecture**

**4.1 Components**

- **Security Onion 2.4 (Standalone) —** the monitoring platform: Zeek
  (network metadata), Suricata (IDS), and the Elastic Stack
  (Elasticsearch/Kibana, SOC interface) for alerting, hunting, and case
  management.

- **Windows 11 Target VM —** the victim host for technique emulation,
  instrumented with Sysmon (SwiftOnSecurity config) and enrolled as an
  Elastic Agent endpoint via Fleet.

- **Kali Linux VM —** the attacker host for cross-network techniques
  requiring a real network peer.

- **Atomic Red Team —** the emulation framework used on the target to
  execute specific MITRE ATT&CK techniques.

**4.2 Network and Data Flow**

Lab attack/target traffic runs on an isolated host-only network (VMnet2,
192.168.50.0/24) that the Security Onion sensor monitors in promiscuous
mode. A separate NAT segment provides outbound access for updates only.
Network activity is captured by Zeek/Suricata on the sensor interface
and shipped to Elasticsearch; Windows endpoint activity is collected by
Sysmon, forwarded by the Elastic Agent through Fleet into the same
Elastic Stack, giving layered network-plus-endpoint visibility.

**4.3 Authorization Boundary**

**In boundary:** the Security Onion, Windows target, and Kali VMs, plus
the VMnet2 host-only network and the NAT segment, all on the single
VMware host. **Out of boundary:** the host operating system, the home
network, and the public internet (reached only via NAT for updates). The
host-only design keeps all emulated attack traffic contained within the
boundary.

**5. Roles and Responsibilities**

As a single-operator lab, all roles are performed by one person; they
are mapped to their federal equivalents for learning and to make the
separation-of-duties gap explicit.

| **Role**             | **Responsibility (all performed by J. Palmer)**                                             |
|----------------------|---------------------------------------------------------------------------------------------|
| System Owner         | Accountable for the system, its risk posture, and this SSP.                                 |
| ISSO                 | Day-to-day security operations: monitoring, alert triage, investigation, and documentation. |
| System Administrator | Builds and maintains the VMs, sensors, network, and tooling.                                |

***Limitation:** no separation of duties is possible with a single
operator (see POA&M P-5). In production these roles are held by
different people, and AC-5 (Separation of Duties) would be enforced.*

**6. Security Control Implementation (SP 800-53 Rev. 5, LOW baseline)**

Twenty representative controls are documented below, drawn from the
families most relevant to a monitoring lab. Status is one of
**Implemented**, **Partial**, or **Planned**. A realistic mix (not all
"Implemented") is expected and is itself a sign of an honest assessment.

| **Control** | **Title**                                | **Implementation Statement**                                                                                                                                                     | **Status**  |
|-------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| AC-2        | Account Management                       | Individual accounts exist for each OS and for the Security Onion SOC web interface; created and managed manually by the operator.                                                | Implemented |
| AC-3        | Access Enforcement                       | OS permissions and SOC role-based access enforce authorized actions on each component.                                                                                           | Implemented |
| AC-7        | Unsuccessful Logon Attempts              | Default OS account-lockout policies apply; SOC UI requires authentication. Not centrally tuned.                                                                                  | Partial     |
| AC-17       | Remote Access                            | SOC UI (HTTPS/443) and SSH (22) to Security Onion are restricted to the host via the appliance host-based firewall hostgroups.                                                   | Implemented |
| AU-2        | Event Logging                            | Logged events are defined across Zeek (network metadata), Suricata (IDS alerts), Sysmon (process/network/registry), and Windows event logs.                                      | Implemented |
| AU-6        | Audit Review, Analysis & Reporting       | Alerts are reviewed in the SOC Alerts/Hunt interfaces; investigations are documented in lab notes (e.g., the T1046 detection write-up).                                          | Implemented |
| AU-12       | Audit Record Generation                  | Sensors generate time-stamped records with source identity and ship them to Elasticsearch for correlation.                                                                       | Implemented |
| CM-2        | Baseline Configuration                   | VM specifications, network settings, and sensor configs are documented; VM snapshots serve as recoverable baselines.                                                             | Partial     |
| CM-6        | Configuration Settings                   | Hardened settings are applied: SwiftOnSecurity Sysmon config, curated Suricata ruleset, and firewall hostgroup/portgroup rules.                                                  | Implemented |
| CM-7        | Least Functionality                      | Security Onion enforces a default-deny host firewall; only required ports (443, 22) are explicitly allowed.                                                                      | Implemented |
| IA-2        | Identification & Authentication (Users)  | Each OS and the SOC interface require a unique authenticated login before access.                                                                                                | Implemented |
| IA-5        | Authenticator Management                 | Passwords protect all accounts; Fleet uses a self-signed certificate (accepted for lab use). No MFA.                                                                             | Partial     |
| SC-7        | Boundary Protection                      | Host-only VMnet2 segmentation isolates lab traffic from the home network; the appliance firewall and monitored sensor interface enforce the boundary.                            | Implemented |
| SC-8        | Transmission Confidentiality & Integrity | HTTPS protects the SOC UI and TLS protects agent traffic; certificates are self-signed in the lab.                                                                               | Partial     |
| SI-2        | Flaw Remediation                         | OS and tool updates are applied via the NAT segment on an ad-hoc basis; no formal cadence yet (see POA&M P-4).                                                                   | Partial     |
| SI-3        | Malicious Code Protection                | Windows Defender runs on the target and has demonstrably blocked live-off-the-land activity (T1105 certutil) before execution.                                                   | Implemented |
| SI-4        | System Monitoring                        | Core capability: layered detection via Zeek/Suricata (network) and Sysmon/Elastic Agent (endpoint), using ET Open and custom rules, continuously validated with Atomic Red Team. | Implemented |
| RA-5        | Vulnerability Monitoring & Scanning      | No authenticated vulnerability scanning yet; planned via OpenVAS/Nessus with a defined cadence (see POA&M P-1).                                                                  | Planned     |
| CP-9        | System Backup                            | VM snapshots are taken before major configuration changes, enabling rollback.                                                                                                    | Partial     |
| AU-11       | Audit Record Retention                   | Elasticsearch retention is governed by available disk capacity; no formal retention period is defined.                                                                           | Partial     |

**7. Risk Assessment (SP 800-30)**

Key risks to the lab are assessed below. Likelihood and Impact are rated
Low/Moderate/High; the Risk Rating is their combination. Because the
system is categorized LOW, even realized risks have limited consequence
beyond personal training time.

| **ID** | **Risk / Threat Scenario**                                                   | **Likelihood** | **Impact** | **Rating** | **Mitigation / Response**                                                                                                 |
|--------|------------------------------------------------------------------------------|----------------|------------|------------|---------------------------------------------------------------------------------------------------------------------------|
| R-1    | Emulated malware or attack tooling escapes the lab to the home network.      | Low            | Moderate   | Low        | Host-only VMnet2 isolation (no bridged adapter); Defender on target; snapshots for recovery.                              |
| R-2    | Host resource exhaustion causes sensor/telemetry loss (blinding).            | Moderate       | Low        | Low        | Deliberate VM RAM sizing and boot sequencing; monitor host utilization; shut down idle VMs.                               |
| R-3    | Lab account credentials are weak, default, or exposed.                       | Low            | Low        | Low        | Unique passwords on all accounts; access limited to the host; MFA planned (POA&M P-2).                                    |
| R-4    | Unpatched lab components are exploitable via known CVEs.                     | Moderate       | Low        | Low        | Periodic manual updates; formal cadence and vulnerability scanning planned (P-1, P-4).                                    |
| R-5    | Detection gaps or misconfigured monitoring miss malicious activity.          | Moderate       | Low        | Low        | Layered network + endpoint telemetry; rule tuning (e.g., the Day 7 threshold tuning); ongoing Atomic Red Team validation. |
| R-6    | Self-signed certificates / insecure agent enrollment weaken transport trust. | Low            | Low        | Low        | Accepted in the isolated lab; a production analog would use CA-signed certificates (SC-8, P-3).                           |

**8. Plan of Action and Milestones (POA&M)**

Known gaps and planned improvements. Several map directly to upcoming
self-study projects, making the POA&M a live roadmap rather than a
static list.

| **ID** | **Weakness / Gap**                        | **Control**    | **Planned Remediation**                                                      | **Target**         |
|--------|-------------------------------------------|----------------|------------------------------------------------------------------------------|--------------------|
| P-1    | No vulnerability scanning in place        | RA-5           | Deploy OpenVAS/Nessus; establish a scan cadence and triage workflow.         | Next lab (Phase 3) |
| P-2    | Single-factor authentication only         | IA-2(1) / IA-5 | Evaluate and enable MFA for the SOC interface where supported.               | Future             |
| P-3    | Self-signed TLS certificates              | SC-8           | Document; use a CA-signed chain in any production analog.                    | Future             |
| P-4    | Ad-hoc patching                           | SI-2           | Define an update cadence and a patch checklist across components.            | Near-term          |
| P-5    | No separation of duties (single operator) | AC-5           | Accepted as an inherent single-user limitation; documented for transparency. | Accepted           |
| P-6    | No formal audit retention period          | AU-11          | Define a retention window and index lifecycle policy in Elasticsearch.       | Near-term          |

**9. DoD Relevance — Mapping Toward 800-171 / CMMC**

NIST SP 800-171 (the basis for CMMC assessment of Controlled
Unclassified Information) draws its requirements from the SP 800-53
MODERATE baseline, and it is organized around the same control families
used in this plan. The lab’s controls therefore map cleanly onto the
800-171 requirement families a defense contractor would be assessed
against:

| **This SSP (800-53)** | **800-171 Family**                      | **Lab control that maps**                                                   |
|-----------------------|-----------------------------------------|-----------------------------------------------------------------------------|
| AC-2, AC-3, AC-17     | 3.1 Access Control                      | Account management, access enforcement, restricted remote access.           |
| AU-2, AU-6, AU-12     | 3.3 Audit & Accountability              | Event logging, audit review, record generation across Zeek/Suricata/Sysmon. |
| CM-2, CM-6, CM-7      | 3.4 Configuration Management            | Baselines, hardened settings, least functionality (default-deny firewall).  |
| IA-2, IA-5            | 3.5 Identification & Authentication     | Unique logins and authenticator management.                                 |
| SC-7, SC-8            | 3.13 System & Communications Protection | Boundary protection via segmentation; encrypted transport.                  |
| SI-2, SI-3, SI-4      | 3.14 System & Information Integrity     | Flaw remediation, malicious code protection, continuous monitoring.         |

*For reference, CMMC Level 2 corresponds to implementing all 110
requirements of NIST 800-171. This lab is not a CUI environment and is
not in scope for CMMC, but the mapping demonstrates that the same
control thinking applies directly to a cleared-contractor setting.*

**10. Summary and Next RMF Steps**

This SSP completes the documentation produced in the Categorize, Select,
and Implement steps of the RMF. The remaining steps are:

- **Assess —** test whether the documented controls work as intended
  (e.g., the Day 7 exercise assessing SI-4 by confirming a custom
  detection fired against an emulated scan).

- **Authorize —** make and record a risk-based decision to operate,
  accepting the residual risks in the POA&M. For this lab, the operator
  accepts them as documented.

- **Monitor —** continuously watch the system and reassess as it
  changes. The lab performs this literally: the SIEM is itself a
  continuous-monitoring capability, and new techniques are regularly
  validated.

*Maintained by J. Palmer. This is a living document; it is updated as
controls, risks, and the environment change.*
