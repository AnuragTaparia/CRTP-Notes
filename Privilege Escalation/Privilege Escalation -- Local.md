
- There are various ways of locally escalating privileges on Windows box:
	- Missing patches
	- Automated deployment and AutoLogon passwords in clear text
	- AlwaysInstallElevated (Any user can run MSI as SYSTEM)
	- Misconfigured Services
	- DLL Hijacking and more
	- Kerberos and NTLM Relaying

- We can use below tools for complete coverage
	- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
	```
	Invoke-AllChecks
	```
	- [Privesc](https://github.com/itm4n/PrivescCheck)
	```
	Invoke-PrivEscCheck
	```
	- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) -- very updated but very noisy 
	```
	winPEASx64.exe
	```

- Services Issues using PowerUp
	- Get services with unquoted paths and a space in their name.
	```
	Get-ServiceUnquoted -Verbose
	```
	- Get services where the current user can write to its binary path or change arguments to the binary
	```
	Get-ModifiableServiceFile -Verbose
	```
	- Get the services whose configuration current user can modify.
	```
	Get-ModifiableService -Verbose
	```
	- ACL (normal windows cmd)
	```
	sc.exe sdshow [service name]
	``` 

