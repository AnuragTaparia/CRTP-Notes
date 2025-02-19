- Do not use psexe since it is very noisy
- PSRemoting uses Windows Remote Management (WinRM) which is Microsoft's implementation of WS-Management.
- Enabled by default on Server 2012 onwards with a firewall exception.
- Uses WinRM and listens by default on 5985 (HTTP) and 5986 (HTTPS).
- It is the recommended way to manage Windows Core servers.
- The remoting process runs as a high integrity process. That is, you get an elevated shell.
- Need admin access to use this
#### One-to-One
- PSSession
	- Interactive
	- Runs in a new process (wsmprovhost)
	- Is Stateful
- Useful cmdlets
	- New-PSSession
	- Enter-PSSession
```
Enter-PSSession -ComputerName dcorp-adminsrv
```
#### One-to-Many
- Also known as Fan-out remoting.
- Non-interactive.
- Executes commands parallely.
- Useful cmdlets
	- Invoke-Command


- Use below to execute commands or scriptblocks:
```
Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)
```

- Use below to execute scripts from files (it run in memory on the machines)
```
Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```

- Use below to execute locally loaded function on the remote machines:
```
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)
```

- In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way:
```
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList
```

- Use below to execute "Stateful" commands using Invoke-Command:
```
$Sess = New-PSSession -Computername Server1

Enter-PSSession -Session $Sess

Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process}
Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}

Invoke-Command -Session $Sess -ScriptBlock {ls env:}
```

- PowerShell remoting supports the system-wide transcripts and deep script block logging.
- MDE is fine with winrs but MDI is not
- We can use winrs in place of PSRemoting to evade the logging (and still reap the benefit of 5985 allowed between hosts):
```
winrs -remote:server1 -u:server1\administrator -p:Pass@1234 hostname

winrs -r:dcorp-adminsrv cmd
```
- We can also use winrm.vbs and COM objects of WSMan object - [WSMan-WinRM](https://github.com/bohops/WSMan-WinRM)
