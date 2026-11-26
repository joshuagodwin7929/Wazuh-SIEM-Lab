# Detection Results

Evidence for all 7 milestones, cross-checked directly in the Wazuh dashboard
(Threat Hunting / Document Details) and in the source Windows/Caldera/Kali
output where relevant. Images are in [`evidence/`](evidence/), one folder per
milestone.

## Milestone 1: Installation and first login

- Clean install completed on Ubuntu, after fixing an LVM volume that was
  only using half the VM's allocated disk.
- First login to the dashboard with zero agents enrolled, confirming a
  correct manager/indexer/dashboard install before anything else was added.
- 245 baseline events already visible in Threat Hunting from the
  manager's own host activity.

![Install complete](evidence/01-installation-first-login/01-install-complete.png)
![LVM disk fix](evidence/01-installation-first-login/02-lvm-disk-fix.png)
![Wazuh login page](evidence/01-installation-first-login/03-wazuh-login-page.png)
![Overview dashboard, no agents](evidence/01-installation-first-login/04-overview-dashboard-no-agents.png)
![Threat Hunting, 245 hits](evidence/01-installation-first-login/05-threat-hunting-245-hits.png)

## Milestone 2: Agent deployment and Sysmon

- Both Joshua-Server2022 and MY-LAB-PC enrolled and reporting as active.
- Sysmon configured on both for process creation and logon telemetry.
- Event volume jumped from 245 to 936 hits once both agents came online.
- First real Windows security alert (event 4625, logon failure) confirmed
  in Document Details.

![Agent install success](evidence/02-agent-deployment-sysmon/01-mylabpc-agent-install-success.png)
![Two active agents](evidence/02-agent-deployment-sysmon/02-endpoints-two-active-agents.png)
![Threat Hunting, 936 hits](evidence/02-agent-deployment-sysmon/03-threat-hunting-936-hits.png)
![First 4625 alert detail](evidence/02-agent-deployment-sysmon/04-first-4625-alert-details.png)
![ossec.conf Sysmon config](evidence/02-agent-deployment-sysmon/05-ossec-conf-sysmon-config.png)

## Milestone 3: File Integrity Monitoring

- `syscheck` configured with `whodata` (not plain `realtime`) so FIM
  events carry the real actor's identity rather than just `SYSTEM`.
- SACL audit flags confirmed actually applied with `Get-Acl` before
  testing, rather than assumed.
- A PowerShell script creating, modifying, renaming, and deleting a test
  file produced four separate FIM events (rules 553/550/554).
- A follow-up access attempt cross-checked against the raw event 4663
  (object access) to confirm the actor field matched what FIM reported.

![syscheck whodata config](evidence/03-file-integrity-monitoring/01-syscheck-whodata-config.png)
![PowerShell FIM test file ops](evidence/03-file-integrity-monitoring/02-powershell-fim-test-fileops.png)
![FIM Events, rules 553/550/554](evidence/03-file-integrity-monitoring/03-fim-events-rules-553-550-554.png)
![Get-Acl SACL audit flags](evidence/03-file-integrity-monitoring/04-get-acl-sacl-audit-flags.png)
![Event 4663 cross-check](evidence/03-file-integrity-monitoring/05-event-4663-cross-check.png)

## Milestone 4: Custom correlation rules (T1558.004, T1558.003, T1003.006)

| Technique | Event ID | Rule | Status |
|---|---|---|---|
| AS-REP Roasting | 4768 (`preAuthType=0`) | 100100 | 🟢 Detected |
| Kerberoasting | 4769 (`ticketEncryptionType=0x17`) | 100101 | 🟢 Detected |
| DCSync | 4662 (replication GUID) | 100102 | 🟢 Detected |

- A real AS-REP roast initially landed only in generic audit-failure
  rule 60104, with no useful description, "the miss" that motivated
  writing purpose-built rules.
- Rules 100100-100102 added in `nano`, validated with
  `wazuh-analysisd -t`, and the manager restarted.
- A re-run of the same AS-REP roast now produced a readable,
  correctly-attributed alert under rule 100100 instead of the generic one.

![Generic rule 60104, the miss](evidence/04-custom-correlation-rules/01-generic-rule-60104-the-miss.png)
![nano: rules 100101/100102 added](evidence/04-custom-correlation-rules/02-nano-rules-100101-100102-added.png)
![analysisd test + restart](evidence/04-custom-correlation-rules/03-analysisd-test-and-restart.png)
![AS-REP TGT log confirmed](evidence/04-custom-correlation-rules/04-asrep-tgt-log-confirmed.png)

## Milestone 5: Active Response for password spraying (T1110.003, NTLM)

- Rule 100103 built as a frequency/correlation rule on top of stock rule
  60122 (NTLM logon failure). First version used a `<same_source_ip/>`
  condition that doesn't exist in this Wazuh version; corrected to
  `<same_field>win.eventdata.ipAddress</same_field>`.
- A custom PowerShell Active Response script adds (and later removes)
  Windows Firewall rules blocking the attacking IP, inbound and outbound.
- A real netexec/crackmapexec SMB spray from Kali against 16 accounts
  triggered rule 100103 three times.
- The block was confirmed live: a follow-up ping from Kali to the
  domain controller dropped to 100% packet loss.
- Document Details confirms the final hit: `firedtimes: 3`,
  `rule.mitre.id: T1110.003`.

![nano: rule 100103, same_field fix](evidence/05-active-response-password-spray/01-nano-rule-100103-same-field-fix.png)
![Kali netexec/crackmapexec SMB spray attack](evidence/05-active-response-password-spray/02-kali-netexec-smb-spray-attack.png)
![Active Response firewall block/unblock](evidence/05-active-response-password-spray/03-active-response-firewall-block-unblock.png)
![Spray run, ping confirms block](evidence/05-active-response-password-spray/04-spray-run-ping-confirms-block.png)
![Rule 100103 hit confirmed](evidence/05-active-response-password-spray/05-rule-100103-hit-confirmed.png)

## Milestone 6: CIS hardening and Vulnerability Detection

| Area | Finding |
|---|---|
| CIS Benchmark, Joshua-Server2022 | 27% → 28% after GPO fixes (password policy, guest account) |
| Vulnerability Detection, MY-LAB-PC | 71 Critical, 1,755 High, 583 Medium findings |
| End-of-support, MY-LAB-PC | Windows Update confirms this build no longer receives security updates |

- Password-policy and guest-account CIS failures fixed through Group
  Policy, applied with `gpupdate /force` and a Wazuh service restart.
- Guest account confirmed actually disabled with `Get-CimInstance`
  rather than assumed from the GPO setting alone.
- Re-scan moved the score from 27% to 28%; remaining failures are
  largely hardware/virtualization-dependent checks (Credential Guard,
  Virtualization Based Security) that a VM cannot pass regardless of
  policy configuration.
- Vulnerability Detection's 2,413 findings against MY-LAB-PC's own
  Windows 10 Pro build line up directly with its Windows Update panel
  reporting that version has reached end of support.

![CIS baseline scan, 27%](evidence/06-cis-hardening-vuln-detection/01-cis-baseline-scan-27pct.png)
![GPO Password Policy configured](evidence/06-cis-hardening-vuln-detection/02-gpo-password-policy-configured.png)
![Guest account disabled, confirmed](evidence/06-cis-hardening-vuln-detection/03-guest-account-disabled-confirmed.png)
![CIS re-scan, 28%, improved](evidence/06-cis-hardening-vuln-detection/04-cis-rescan-28pct-improved.png)
![MY-LAB-PC Windows 10 end of support](evidence/06-cis-hardening-vuln-detection/05-mylabpc-windows10-end-of-support.png)
![MY-LAB-PC Vulnerability Detection](evidence/06-cis-hardening-vuln-detection/06-mylabpc-vulnerability-detection.png)

## Milestone 7: Purple-team validation with Caldera (T1003.006, T1558.004, T1558.003, T1110.003)

| Technique | Event ID | Rule(s) | Hits | Status |
|---|---|---|---|---|
| DCSync | 4662 | 100102 | 1 | 🟢 Detected |
| AS-REP Roasting | 4768 | 100100 | 1 | 🟢 Detected |
| Kerberoasting | 4769 | 100101 | 2 | 🟢 Detected |
| Password Spray (Kerbrute), before fix | 4771 | 100103 | 0 | 🔴 Gap found |
| Password Spray (Kerbrute), after fix | 4771 | 100104 / 100105 | 15 / 3 | 🟢 Detected |

- The full `AD Credential Access Chain` adversary profile completed all
  four abilities successfully against the Kali Sandcat agent.
- Before that, individual ability runs were timing out; root cause was a
  stale Active Response firewall rule (`WazuhAR_Block_192.168.18.70`)
  from a previous test, self-inflicted blocking of the red-team box by
  this project's own detection stack. Removed and reran.
- Rule 100101 (Kerberoasting) and 100102 (DCSync) both hit cleanly.
- Rule 100103 (password spray) did **not** fire despite Kerbrute testing
  16 logins and finding 1 valid credential. A direct `grep` of rule
  60122's real definition confirmed why: it only ever matches
  `win.system.eventID` 529 or 4625 (NTLM), and Kerbrute never generates
  either.
- Rules 100104/100105 added to close the gap, mirroring 60122/100103's
  logic for Kerberos event 4771. Re-running the identical Kerbrute
  attack fired rule 100104 15 times and rule 100105 3 times.
- Full root-cause writeup: [`kerberos-password-spray-gap.md`](kerberos-password-spray-gap.md).

![Caldera full chain success](evidence/07-caldera-purple-team-chain/01-caldera-full-chain-success.png)
![Kerbrute output before fix](evidence/07-caldera-purple-team-chain/02-kerbrute-output-before-fix.png)
![Rule 100101, Kerberoasting hit](evidence/07-caldera-purple-team-chain/03-rule-100101-kerberoasting-hit.png)
![Rule 100102, DCSync hit](evidence/07-caldera-purple-team-chain/04-rule-100102-dcsync-hit.png)
![Rule 100103, no results, the gap](evidence/07-caldera-purple-team-chain/05-rule-100103-no-results-the-gap.png)
![Rule 60122, root cause grep](evidence/07-caldera-purple-team-chain/06-rule-60122-root-cause-grep.png)
![Self-inflicted firewall block](evidence/07-caldera-purple-team-chain/07-self-inflicted-firewall-block.png)
![local_rules.xml before the fix](evidence/07-caldera-purple-team-chain/08-local-rules-before-fix.png)
![nano: rules 100104/100105 added](evidence/07-caldera-purple-team-chain/09-nano-rules-100104-100105-added.png)
![analysisd test, clean](evidence/07-caldera-purple-team-chain/10-analysisd-test-clean.png)
![Caldera rerun, Kerbrute](evidence/07-caldera-purple-team-chain/11-caldera-rerun-kerbrute.png)
![Rule 100105, 3 hits, fix confirmed](evidence/07-caldera-purple-team-chain/12-rule-100105-3-hits-fix-confirmed.png)
