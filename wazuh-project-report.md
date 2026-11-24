# Wazuh SIEM Lab: Build, Hardening, and Purple-Team Validation Report

## 1. Objective & Scope

This project builds a Wazuh SIEM deployment from a bare install through to
a validated detection stack, then proves it against real attack execution
rather than hand-run hunt queries alone.

**Scope:** 7 milestones spanning installation, agent/Sysmon deployment,
File Integrity Monitoring, four custom correlation rules for
Kerberos/Active-Directory credential-access techniques, Active Response,
CIS benchmark hardening, Vulnerability Detection, and a full purple-team
validation pass using MITRE Caldera.

**Environment:** A small Active Directory lab (one domain controller, one
domain-joined Windows 10 client), a single-node Wazuh 4.14.10 deployment,
a Kali Linux red-team host, and a dedicated Caldera C2 server for
Milestone 7.

| Host | Role | IP |
|---|---|---|
| wazuh-server | Wazuh manager, indexer, dashboard | 192.168.18.210 |
| Joshua-Server2022 | Domain controller, Wazuh agent 002 | 192.168.18.50 |
| MY-LAB-PC | Domain member (Windows 10 Pro), Wazuh agent 001 | 192.168.18.51 |
| Kali | Red-team attack box | 192.168.18.70 |
| caldera-server | MITRE Caldera C2 | 192.168.18.205 |

## 2. Methodology

| Milestone | Focus | Key artifact |
|---|---|---|
| 1 | Installation and first login | Baseline Overview dashboard, 245 events |
| 2 | Agent deployment + Sysmon | Both endpoints active, first 4625 alert |
| 3 | File Integrity Monitoring | `whodata`-backed FIM rules 553/550/554 |
| 4 | Custom correlation rules | Rules 100100-100102 (AS-REP, Kerberoasting, DCSync) |
| 5 | Active Response | Rule 100103 + firewall-block PowerShell script |
| 6 | CIS hardening + Vulnerability Detection | CIS score 27% → 28%, MY-LAB-PC EOL finding |
| 7 | Purple-team validation (Caldera) | Full 4-technique chain, gap found and fixed |

Milestones 1-6 were built and validated by hand: generate the real
Windows event with a PowerShell command or a manual tool run, confirm it
lands in Threat Hunting under the expected rule, then adjust the rule
where the stock ruleset's description was too generic to be useful.
Milestone 7 replaced hand-run validation with a scripted MITRE Caldera
adversary profile so all four Kerberos/AD techniques execute from one
operation, in a realistic attacker order, against the same lab.

### Adversary profile (Milestone 7)

**Caldera profile:** `AD Credential Access Chain`

| Order | Technique | Tool |
|---|---|---|
| 1 | DCSync (T1003.006) | Impacket `secretsdump.py` |
| 2 | AS-REP Roasting (T1558.004) | Impacket `GetNPUsers.py` |
| 3 | Kerberoasting (T1558.003) | Impacket `GetUserSPNs.py` |
| 4 | Password Spraying (T1110.003) | Kerbrute |

Stockpile, Caldera's stock ability pack, has no abilities for any of
these four techniques that run on a Linux Sandcat agent (its
Kerberos/AD content assumes Rubeus or WinPwn on a Windows agent), so all
four were built as custom abilities around Impacket and Kerbrute.

## 3. Execution Summary

| Technique | Target Account | Target Host | Result |
|---|---|---|---|
| DCSync | j.jenkins (non-DC account) | Joshua-Server2022 | Success |
| AS-REP Roasting | (UF_DONT_REQUIRE_PREAUTH account) | Joshua-Server2022 | Success |
| Kerberoasting | svc_sql | Joshua-Server2022 | Success |
| Password Spraying (Kerbrute, first run) | 16 accounts tested, 1 valid (j.jenkins) | Joshua-Server2022 | Success (attack); **no detection** |
| Password Spraying (Kerbrute, re-run after fix) | Same 16 accounts | Joshua-Server2022 | Success (attack); **detected** |

Before the first full chain could run cleanly, every individual ability
timed out against the domain controller. Root cause: an earlier
Active Response test had left a Windows Firewall rule
(`WazuhAR_Block_192.168.18.70`) blocking the Kali box's own IP, a
self-inflicted block from this project's own detection stack. Removing
that rule let the chain complete.

## 4. Detection Results

| Technique | Event ID | Rule(s) | Hits | Status |
|---|---|---|---|---|
| T1558.004 – AS-REP Roasting | 4768 | 100100 | 1 | 🟢 Detected |
| T1558.003 – Kerberoasting | 4769 | 100101 | 2 | 🟢 Detected |
| T1003.006 – DCSync | 4662 | 100102 | 1 | 🟢 Detected |
| T1110.003 – Password Spray (NTLM) | 4625/529 | 100103 | 3 | 🟢 Detected |
| T1110.003 – Password Spray (Kerberos pre-auth), before fix | 4771 | 100103 | 0 | 🔴 Not detected |
| T1110.003 – Password Spray (Kerberos pre-auth), after fix | 4771 | 100104 / 100105 | 15 / 3 | 🟢 Detected |

**Detail on each finding:**

- **AS-REP Roasting (4768):** `preAuthType: 0` confirmed on the target
  account, meaning pre-authentication was skipped entirely, the exact
  weakness `GetNPUsers.py` exploits on accounts with
  `UF_DONT_REQUIRE_PREAUTH` set.
- **Kerberoasting (4769):** `TicketEncryptionType: 0x17` on both hits,
  matching the RC4 downgrade signature `GetUserSPNs.py` produces when
  requesting a service ticket for `svc_sql`.
- **DCSync (4662):** one hit with the DS-Replication-Get-Changes-All GUID
  in `win.eventdata.properties`, attributed to `j.jenkins`, an account
  with no business holding directory-replication rights.
- **Password spray, NTLM (100103):** 3 hits during the Milestone 5
  netexec/crackmapexec run, confirmed by a follow-up ping from Kali
  dropping to 100% packet loss once the Active Response firewall rule
  applied.
- **Password spray, Kerberos pre-auth, before the fix:** Kerbrute tested
  16 logins and found 1 valid credential, but rule 100103 never fired.
  Root cause, confirmed by `grep`-ing rule 60122's real definition: it
  matches only Windows event IDs 529 and 4625 (NTLM), and Kerbrute never
  generates either, it only ever produces event 4771 (Kerberos
  pre-authentication failure). See Section 5 and
  [`validation/kerberos-password-spray-gap.md`](validation/kerberos-password-spray-gap.md).
- **Password spray, Kerberos pre-auth, after the fix:** rerunning the
  identical Kerbrute attack fired rule 100104 15 times, once per failed
  login, and rule 100105 3 times as its 60-second sliding window
  re-triggered, exactly mirroring how 60122/100103 behave on the NTLM
  side.

## 5. Hardening and Vulnerability Findings (Milestone 6)

| Area | Before | After | Notes |
|---|---|---|---|
| CIS Benchmark (Joshua-Server2022) | 27% (98 passed / 261 failed) | 28% (104 passed / 255 failed) | Password policy + guest account fixed via GPO; most remaining failures are VM-hardware-dependent (Credential Guard, VBS) |
| Vulnerability Detection (MY-LAB-PC) | N/A | 71 Critical, 1,755 High, 583 Medium | 2,413 findings against its own Windows 10 Pro build alone |
| End-of-support (MY-LAB-PC) | N/A | Confirmed | Windows Update reports this build has reached end of support and is no longer receiving security updates |

The CIS and Vulnerability Detection findings are related: a large share
of MY-LAB-PC's critical/high findings exist precisely because its
Windows 10 build is past end of support and no longer receiving
security patches, which is itself the single highest-value remediation
item from this milestone.

## 6. Gap Analysis

The Milestone 7 Kerbrute run is the clearest finding in this project:
**a rule that looks like it covers "password spraying" in general
actually only covers one of the two common transports an attacker can
use.** Rule 100103 depends entirely on stock rule 60122, which was
written for NTLM logon failures (event IDs 529/4625). Any tool that
sprays passwords over Kerberos directly, Kerbrute foremost among them,
produces event 4771 instead and was structurally invisible to this
detection stack until Milestone 7's fix.

This matters beyond this one rule: it is a reminder that a detection
rule's real coverage is defined by the specific event IDs and field
values it matches, not by the English description attached to it. A
rule titled "password spray detection" can still have a blind spot the
size of an entire protocol.

**Root cause:** `<if_matched_sid>60122</if_matched_sid>` in rule 100103,
combined with 60122 itself only ever matching `win.system.eventID`
529 or 4625.

## 7. Recommendations

1. **Close the Kerberos password-spray gap** by deploying rules 100104
   and 100105 (done; see [`rules/local_rules.xml`](rules/local_rules.xml)).
2. **Audit other correlation rules for the same single-transport blind
   spot.** Any rule built on top of a stock base rule should be checked
   for which specific event IDs that base rule actually matches, not
   just what its description claims to cover.
3. **Add Active Response cleanup.** The self-inflicted Kali block in
   Milestone 7 shows a stale `WazuhAR_Block_*` firewall rule can block
   a legitimate host indefinitely; add an expiry or a manual-review step
   before reusing an attacker IP for further testing.
4. **Upgrade MY-LAB-PC** off its end-of-support Windows 10 build, the
   single highest-leverage fix for its Vulnerability Detection findings.
5. **Re-run the full Caldera chain periodically** as new rules are
   added, the same way Milestone 7 caught this gap, to catch the next
   one before it ships to production.

---
*Companion files: [`validation/detection-results.md`](validation/detection-results.md) ·
[`validation/kerberos-password-spray-gap.md`](validation/kerberos-password-spray-gap.md) ·
[`rules/local_rules.xml`](rules/local_rules.xml)*
