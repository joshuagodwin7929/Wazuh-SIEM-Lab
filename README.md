# Wazuh-SIEM-Lab

A hands-on Wazuh SIEM build, hardening, and detection-engineering project.
Starting from a bare Wazuh install, this project deploys agents across a
small Active Directory lab, builds File Integrity Monitoring and custom
correlation rules for four Kerberos/AD attack techniques, wires up Active
Response, hardens both endpoints against the CIS benchmark, and finally
validates the whole stack with a real [MITRE Caldera](https://github.com/mitre/caldera)
attack chain, which surfaced (and then closed) a genuine detection gap.

## Repo structure

```
Wazuh-SIEM-Lab/
├── rules/
│   └── local_rules.xml                     All custom rules (100100-100105), documented
├── validation/
│   ├── detection-results.md                Per-technique results + evidence, all 7 milestones
│   ├── kerberos-password-spray-gap.md       The gap Milestone 7 found, root cause, and the fix
│   └── evidence/                           Curated screenshots, one folder per milestone
│       ├── 01-installation-first-login/
│       ├── 02-agent-deployment-sysmon/
│       ├── 03-file-integrity-monitoring/
│       ├── 04-custom-correlation-rules/
│       ├── 05-active-response-password-spray/
│       ├── 06-cis-hardening-vuln-detection/
│       └── 07-caldera-purple-team-chain/
├── wazuh-project-report.md                 Full write-up: scope, methodology, results, gap analysis
├── wazuh-vs-elk-comparison.md               Hands-on comparison against an earlier ELK/Elastic lab
├── LICENSE
└── README.md                               This file
```

## Lab topology

| Host | Role | IP |
|---|---|---|
| wazuh-server | Wazuh manager, indexer, dashboard (v4.14.10) | 192.168.18.210 |
| Joshua-Server2022 | Windows Server 2022 domain controller, Wazuh agent 002 | 192.168.18.50 |
| MY-LAB-PC | Windows 10 Pro domain member, Wazuh agent 001 | 192.168.18.51 |
| Kali | Red-team attack box (Impacket, Kerbrute, netexec) | 192.168.18.70 |
| caldera-server | MITRE Caldera C2, Sandcat agent on Kali | 192.168.18.205 |

## What was built

### Milestone 1: Installation and first login
Installed Wazuh 4.14.10 single-node (manager, indexer, dashboard) on an
Ubuntu VM. Hit an LVM issue where the logical volume was only using half
the disk's allocated space during install; fixed with `lvextend` +
`resize2fs` before continuing. Confirmed first login and an empty
Overview dashboard with zero agents, then generated the first 245
baseline events from the manager's own host activity in Threat Hunting.

### Milestone 2: Agent deployment and Sysmon
Deployed the Wazuh agent to both Joshua-Server2022 and MY-LAB-PC,
installed Sysmon on each with a process-creation and logon-focused
config, and confirmed both showed as active in Endpoints. Event volume
jumped from 245 to 936 hits in Threat Hunting within minutes of the
agents reporting in, and the first real Windows security event (4625,
logon failure) showed up in Document Details.

### Milestone 3: File Integrity Monitoring
Configured `syscheck` with `whodata` (not realtime) on a watched
directory so file events carry the real actor's identity, not just
"SYSTEM". Validated the SACL audit flags were actually applied with
`Get-Acl`, then ran a PowerShell script to create, modify, rename, and
delete a test file. All four operations showed up as separate FIM
events (rules 553/550/554), and a follow-up access attempt was
cross-checked against the raw event 4663 (object access) to confirm the
actor field matched.

### Milestone 4: Custom correlation rules for Kerberos/AD attacks
Stock Wazuh ruleset has no purpose-built rules for AS-REP Roasting,
Kerberoasting, or DCSync; a real GetNPUsers.py roast against a
`DONT_REQUIRE_PREAUTH` account only landed in a generic audit-failure
catch-all (rule 60104) with a near-useless description, "the miss" that
motivated this milestone. Wrote three new rules (100100-100102)
matching on the specific Windows event IDs and field values each
technique actually produces (4768 + `preAuthType=0`; 4769 +
`ticketEncryptionType=0x17`; 4662 + the DS-Replication-Get-Changes-All
GUID), validated with `wazuh-analysisd -t`, restarted the manager, and
confirmed a real AS-REP roast now produced a readable, correctly
attributed alert instead of a generic one.

### Milestone 5: Active Response for password spraying
Built rule 100103, a frequency/correlation rule that chains off the
stock NTLM logon-failure rule (60122) and fires on 5+ failures from the
same source IP within 60 seconds. First version used
`<same_source_ip/>`, which doesn't exist as a condition in this Wazuh
version; corrected to `<same_field>win.eventdata.ipAddress</same_field>`.
Wired up a custom PowerShell Active Response script that adds (and later
removes) Windows Firewall rules blocking the attacking IP in both
directions. Ran a real netexec/crackmapexec SMB password spray from
Kali against 16 accounts; the manager fired rule 100103 and the
firewall rule went live, confirmed by a follow-up ping from Kali
dropping to 100% packet loss. Also hit, and debugged, a case where the
default `win_route-null.exe` script aborted on the larger correlated
alert payload before the script was swapped for the custom one.

### Milestone 6: CIS hardening and Vulnerability Detection
Ran the CIS Microsoft Windows Server/10 benchmark via Configuration
Assessment on both endpoints. Joshua-Server2022 started at 27% (98
passed / 261 failed). Fixed the password-policy and guest-account
findings through Group Policy (`gpupdate /force` + a Wazuh service
restart to pick up the change), confirmed the Guest account was
actually disabled via `Get-CimInstance`, and re-scanned to 28% (104
passed / 255 failed); the remaining failures are largely
hardware/virtualization-dependent checks (Credential Guard, VBS) that a
VM can't pass. Vulnerability Detection separately flagged MY-LAB-PC
with 71 Critical and 1,755 High findings, almost all against its own
Windows 10 Pro build, 2,413 of them; that same endpoint's Windows
Update panel confirmed why: **its version of Windows has reached end of
support** and is no longer receiving security updates.

### Milestone 7: Purple-team validation with Caldera
**Infrastructure recovery.** The dedicated Caldera server VM was
unreachable at the start of this milestone: SSH connection timed out,
then came back but refused key and password auth, and the VM ultimately
had to be booted into GRUB rescue mode to reset the admin password
before Caldera itself was reachable again.

**Attack chain.** Built the `AD Credential Access Chain` adversary
profile chaining four abilities against the Kali Sandcat agent: DCSync
(`secretsdump.py`), AS-REP Roasting (`GetNPUsers.py`), Kerberoasting
(`GetUserSPNs.py`), and Password Spraying (Kerbrute). Early runs of
individual abilities timed out against the domain controller; root
cause turned out to be this lab's own Active Response: an earlier test
had left a Windows Firewall rule (`WazuhAR_Block_192.168.18.70`)
blocking the red-team Kali box itself, a self-inflicted block from the
project's own detection stack. Removed it and reran; all four abilities
completed successfully.

**Detection results and the gap.** Three of the four techniques fired
exactly as designed: rule 100101 (Kerberoasting) and rule 100102
(DCSync) both hit cleanly. Rule 100103 (password spray) did not fire at
all, despite Kerbrute running 16 login attempts against the domain
controller. Root cause: Kerbrute attacks over the Kerberos protocol
directly, generating Windows event 4771 (Kerberos pre-authentication
failed), never 4625/529 (NTLM logon failure). Rule 100103 depends on
stock rule 60122, which only ever matches 4625/529. A spray tool that
never touches NTLM is structurally invisible to that rule, confirmed
directly with `grep` against 60122's real definition.

**The fix.** Added rules 100104 (base: matches event 4771) and 100105
(correlation: 5+ failures from the same IP in 60 seconds), mirroring
60122/100103's NTLM-side logic on the Kerberos side. Validated,
restarted the manager, and reran the exact same Kerbrute attack: rule
100104 fired 15 times (once per failed login) and rule 100105 fired 3
times as the sliding window re-triggered, closing the gap. Full
root-cause writeup: [`validation/kerberos-password-spray-gap.md`](validation/kerberos-password-spray-gap.md).

## How to reproduce

> Run only against a lab you own and are authorised to test.

### Prerequisites
- A Windows Server domain controller + at least one Windows 10/11 domain member
- Sysmon installed on both, shipping Windows Event Log to a Wazuh agent
- Wazuh manager/indexer/dashboard (this project used v4.14.10)
- An attacker host with Impacket and Kerbrute installed
- Optional, for Milestone 7: a Caldera server (Docker Compose) with a
  Sandcat agent on the attacker host

### Steps
1. **Install Wazuh** and confirm the dashboard loads with zero agents.
2. **Deploy agents** to the domain controller and any domain members,
   with Sysmon configured for process creation and logon events.
3. **Configure FIM** with `whodata` on directories you want attributed
   file-level audit trails for, and confirm the SACL flags applied.
4. **Add the custom rules** in [`rules/local_rules.xml`](rules/local_rules.xml)
   to `/var/ossec/etc/rules/local_rules.xml`, validate with
   `sudo /var/ossec/bin/wazuh-analysisd -t`, then
   `sudo systemctl restart wazuh-manager`.
5. **Wire up Active Response** for rule 100103/100105 with a script
   that blocks the offending IP (inbound and outbound) in Windows
   Firewall, and remember to clean up any block before using that same
   attacker IP for later tests.
6. **Run the CIS benchmark** via Configuration Assessment, fix what
   Group Policy can fix, and re-scan.
7. **Validate end to end.** Run each technique for real (Impacket for
   Kerberoasting/AS-REP/DCSync, Kerbrute or netexec for spraying, or
   both via a Caldera adversary profile) and confirm each one in Threat
   Hunting against the matching rule ID.

## Results

| Technique | Rule(s) | Status |
|---|---|---|
| T1558.004 – AS-REP Roasting | 100100 | 🟢 Detected |
| T1558.003 – Kerberoasting | 100101 | 🟢 Detected |
| T1003.006 – DCSync | 100102 | 🟢 Detected |
| T1110.003 – Password Spray (NTLM) | 100103 | 🟢 Detected |
| T1110.003 – Password Spray (Kerberos pre-auth) | 100104 / 100105 | 🟢 Detected (gap found and fixed in Milestone 7) |
| CIS Benchmark hardening | Configuration Assessment | 🟡 Partial (27% → 28%, VM-hardware-dependent checks remain) |
| Vulnerability Detection / EOL | Vulnerability Detection | 🔴 Finding: MY-LAB-PC's Windows 10 build has reached end of support |

Full detail: [`validation/detection-results.md`](validation/detection-results.md)
Full write-up: [`wazuh-project-report.md`](wazuh-project-report.md)
Known gap and fix: [`validation/kerberos-password-spray-gap.md`](validation/kerberos-password-spray-gap.md)
Platform comparison: [`wazuh-vs-elk-comparison.md`](wazuh-vs-elk-comparison.md)

## Key Lessons

- A detection rule is only as good as the tool it was tested against.
  Validating with a second, protocol-different tool is what actually
  proves (or disproves) coverage of a technique, not just of one tool's
  signature, the whole reason Milestone 7's Kerbrute gap only showed up
  once the original netexec-based test was replaced with something
  different.
- Vulnerability scanning and configuration hardening are two different
  jobs. A fully patched host can still be badly configured, and a
  well-configured host can still be riddled with unpatched CVEs.
- Automated response can create its own side effects. An Active
  Response rule built to protect the environment can just as easily
  block your own testing later if it isn't tracked, which is exactly
  what happened to the Kali box in Milestone 7.
- End-of-support software is a different risk category from "overdue
  for patching." One can be fixed with an update; the other cannot be
  fixed at all without replacing the system.

## Tools Used

Wazuh 4.14.10, MITRE Caldera, Impacket (`GetNPUsers`, `GetUserSPNs`,
`secretsdump`), Kerbrute, netexec, PowerShell, Windows Server 2022,
Windows 10.

## Next steps

1. Upgrade MY-LAB-PC to a supported Windows 10/11 build to close the
   end-of-support finding from Milestone 6.
2. Work the remaining CIS benchmark failures that aren't
   hardware-dependent (Credential Guard and Virtualization Based
   Security need a physical host or nested virtualization to test
   properly).
3. Extend Active Response cleanup so a stale `WazuhAR_Block_*` firewall
   rule can't silently block a legitimate host again, the way it did to
   the Kali box in Milestone 7.
4. Add a Sigma-style rule for Kerberoasting/AS-REP/DCSync alongside the
   native Wazuh XML, to make the detection logic portable to other SIEMs.

## Author

Joshua Godwin · [LinkedIn](https://linkedin.com/in/okunnuwa-joshua-godwin) · [GitHub](https://github.com/joshuagodwin7929)
