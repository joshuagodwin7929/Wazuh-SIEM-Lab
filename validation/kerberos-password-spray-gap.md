# Known Gap (Found and Fixed): Kerberos Password Spraying (T1110.003)

## Why this wasn't covered

Rule 100103 was built in Milestone 5 to detect password spraying, and it
worked, against a real netexec/crackmapexec SMB spray. But it only
worked because it was built on top of stock Wazuh rule 60122, and that
rule's actual condition is narrower than its description suggests:

```
<rule id="60122" level="5">
  <if_sid>60105</if_sid>
  <field name="win.system.eventID">^529$|^4625$</field>
  <description>Logon Failure - Unknown user or bad password</description>
</rule>
```

Event IDs 529 and 4625 are both NTLM logon failures. Rule 100103
inherits that scope by chaining off 60122 with
`<if_matched_sid>60122</if_matched_sid>`. Any password-spraying tool
that never produces an NTLM logon failure is therefore invisible to it,
no matter how aggressively it sprays.

## What was found

During the Milestone 7 Caldera operation, the `AD Credential Access
Chain` adversary profile ran Kerbrute against the domain controller,
testing 16 accounts and finding 1 valid credential
(`j.jenkins@joshua.local:Password1!`). The attack itself worked exactly
as intended. Rule 100103 never fired.

Root cause: Kerbrute doesn't attempt an NTLM logon at all. It sends
Kerberos AS-REQ messages directly and reads the KDC's response, so a
wrong password produces Windows event **4771** (Kerberos
pre-authentication failed), not 529 or 4625. Confirmed directly:

```
$ grep -r 'id="60122"' /var/ossec/ruleset/rules/ -A 15
<rule id="60122" level="5">
  <if_sid>60105</if_sid>
  <field name="win.system.eventID">^529$|^4625$</field>
  ...
```

Threat Hunting for `rule.id: 100103` over the full attack window
returned zero hits, while `data.win.system.eventID: 4771` over the same
window showed all 16 pre-authentication failures, unmatched by any
custom rule.

## Why it matters

Kerberos-based spraying tools (Kerbrute, and others that speak the
Kerberos protocol directly) are common in real engagements specifically
*because* they're quieter and faster than NTLM-based spraying, and in
this lab they were also completely invisible to a rule whose name
promised general password-spray coverage. A detection rule's real scope
is set by the exact event IDs and field values it matches, not by its
description; this is the clearest example from the whole project of
that gap between what a rule says and what it actually does.

## Resolution

Two new rules were added, mirroring 60122/100103's structure on the
Kerberos side instead of the NTLM side:

```xml
<rule id="100104" level="5">
  <if_group>windows</if_group>
  <decoded_as>windows_eventchannel</decoded_as>
  <field name="win.system.eventID">^4771$</field>
  <description>Kerberos pre-authentication failed for $(win.eventdata.targetUserName)</description>
</rule>

<rule id="100105" level="12" frequency="5" timeframe="60">
  <if_matched_sid>100104</if_matched_sid>
  <same_field>win.eventdata.ipAddress</same_field>
  <description>Password spray detected (Kerberos pre-auth): 5+ failures from $(win.eventdata.ipAddress) in 60 seconds</description>
  <mitre><id>T1110.003</id></mitre>
</rule>
```

Validated with `sudo /var/ossec/bin/wazuh-analysisd -t` (clean), applied
with `sudo systemctl restart wazuh-manager`, and confirmed against the
identical Kerbrute attack re-run:

- Rule 100104 fired **15 times**, once per failed pre-authentication
  attempt.
- Rule 100105 fired **3 times**, as its 60-second sliding window
  re-triggered across the burst, exactly mirroring how 60122/100103
  behave on the NTLM side.

The gap is closed: a password-spray attempt over either NTLM (rule
100103) or Kerberos (rule 100105) now reaches an alert.

## Remaining follow-up

1. Audit any other correlation rule in this ruleset that chains off a
   single stock base rule, for the same single-transport blind spot.
2. Consider a third, protocol-agnostic correlation rule that fires on
   combined 100103 + 100105 activity from the same IP, to catch an
   attacker who splits a spray across both transports to stay under
   either rule's individual frequency threshold.
