- For enumeration we can use the following tools
	- The ActiveDirectory PowerShell module (MS signed and works even in PowerShell CLM)
		- https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps
		- https://github.com/samratashok/ADModule
		```
		Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
		Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
		```
	- BloodHound (C# and PowerShell Collectors)
		- https://github.com/BloodHoundAD/BloodHound
	- PowerView (PowerShell)
		- https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1
		```
		. C:\AD\Tools\PowerView.ps1
		```
	- SharpView (C#) - Doesn't support filtering using Pipeline
		- https://github.com/tevora-threat/SharpView/

### Domain Enumeration
- Get current domain
```
#PowerView
Get-Domain 

#ActiveDirectory Module
Get-ADDomain 
```
- Get object of another domain
```
#Power View
Get-Domain -Domain moneycorp.local 

#ActiveDirectory Module
Get-ADDomain -Identity moneycorp.local
```
- Get domain SID for the current domain
```
#Power View
Get-DomainSID 

#ActiveDirectory Module
(Get-ADDomain).DomainSID 
```
- Get domain policy for the current domain
```
# PowerView
Get-DomainPolicy
Get-DomainPolicyData
(Get-DomainPolicyData).systemaccess
```
- Get domain policy for another domain
```
# Power View
(Get-DomainPolicyData -domain moneycorp.local).systemaccess
```
- Get domain controllers for the current domain
```
#Power View
Get-DomainController

#ActiveDirectory Module
Get-ADDomainController
```
- Get domain controllers for another domain
```
#Power View
Get-DomainController -Domain moneycorp.local

#ActiveDirectory Module
Get-ADDomainController -DomainName moneycorp.local -Discover
```

### Domain Enumeration -- Users
- Get a list of users in the current domain
```
# Power View
Get-DomainUser
Get-DomainUser -Identity student1

# ActiveDirectory Module
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties * 
```
- Get list of all properties for users in the current domain
```
#Power View
Get-DomainUser -Identity student1 -Properties *

#To spot decoy or dormant user (logon count less than 5 or 10)
# Do not target the account
Get-DomainUser -Properties samaccountname,logonCount

# ActiveDirectory module
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,logoncount,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```
- Search for a particular string in a user's attributes:
```
#Power View
Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description

# ActiveDirectory module
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

### Domain Enumeration -- Computers
- Get a list of computers in the current domain
```
#Power View
Get-DomainComputer | select Name
Get-DomainComputer -OperatingSystem "*Server 2022*"
Get-DomainComputer -Ping

# ActiveDirectory module
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2022*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
```

### Domain Enumeration -- Group & member
- For "Enterprise Admins" specify  Domain name before enum
#### Group
- Get all the groups in the current domain
```
#Power View
Get-DomainGroup | select Name
Get-DomainGroup -Domain <targetdomain>

# ActiveDirectory module
Get-ADGroup -Filter * | select Name
Get-ADGroup -Filter * -Properties *
```
- Get all groups containing the word "admin" in group name
```
#Power View
Get-DomainGroup *admin*

# ActiveDirectory module
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

#### Group Member
- Get all the members of the Domain Admins group
```
#Power View
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# ActiveDirectory module
Get-ADGroupMember -Identity "Domain Admins" -Recursive
```
- Get the group membership for a user:
```
#Power View
Get-DomainGroup -UserName "student1"

# ActiveDirectory module
Get-ADPrincipalGroupMembership -Identity student1
```

- List all the local groups on a machine (needs administrator privs on non-dc machines) :
```
#Power view
Get-NetLocalGroup -ComputerName dcorp-dc
```
- Get members of the local group "Administrators" on a machine (needs administrator privs on non-dc machines) 
```
#power view
Get-NetLocalGroupMember -ComputerName dcorp-dc -GroupName Administrators
```

### Domain Enumeration -- File $ shares
- Requires Admin rights
- Find shares on hosts in current domain.
```
#Power View
Invoke-ShareFinder -Verbose
```
- Find sensitive files on computers in the domain
```
#Power View
Invoke-FileFinder -Verbose
```
- Get all fileservers of the domain
```
#Power View
Get-NetFileServer
```

### Domain Enumeration -- GPO & OU
- GPO are always applied on OU
#### GPO
- Get list of GPO in current domain.
```
#Power View
Get-DomainGPO
Get-DomainGPO -ComputerIdentity dcorp-student1
```
- Get GPO(s) which use Restricted Groups or groups.xml for interesting users
```
#Power View
Get-DomainGPOLocalGroup
```
- Get users which are in a local group of a machine using GPO
```
#Power View
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-student1
```
- Get machines where the given user is member of a specific group
```
#Power view
Get-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose
```

#### OU
- Get OUs in a domain
```
#Power View
Get-DomainOU

# ActiveDirectory module
Get-ADOrganizationalUnit -Filter * -Properties *
```
- Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU
```
Get-DomainGPO -Identity "{0D1CC23D-1F20-4EEE-AF64-D99597AE2A6E}"
```
- List all the computers in Studentmachine OU
```
(Get-DomainOU -Identity StudentMachine).distinguishednmae | %{Get-DomainComputer -Searchbase $_} | Select name
```

### Domain Enumeration -- ACL
- Get the ACLs associated with the specified object
```
#Power View
Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
```
- Get the ACLs associated with the specified prefix to be used for search
```
#Power view
Get-DomainObjectAcl -SearchBase "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose

# ActiveDirectory Module
(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
```
- Search for interesting ACEs
```
#Power view
Find-InterestingDomainAcl -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityRefereceName -match "student1"}
```
- Get the ACLs associated with the specified path
```
#Power view
Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"
```

### Domain Enumeration -- Trusts
- In an AD environment, trust is a relationship between two domains or forests which allows users of one domain or forest to access resources in the other domain or forest.
- Trust can be automatic (parent-child, same forest etc.) or established (forest, external).
- Trusted Domain Objects (TDOs) represent the trust relationships in a domain.
#### Trust Direction
- **One-way trust** - Unidirectional. Users in the trusted domain can access resources in the trusting domain but the reverse is not true.
![[one way trust.png]]
- **Two-way trust** - Bi-directional. Users of both domains can access resources in the other domain.
![[two way trust.png]]

#### Trusts - Transitivity
- **Transitive** - Can be extended to establish trust relationships with other domains.
	- All the default intra-forest trust relationships (Tree-root, Parent-Child) between domains within a same forest are transitive two-way trusts.
- **Nontransitive** - Cannot be extended to other domains in the forest. Can be two-way or one-way.
	- This is the default trust (called external trust) between two domains in different forests when forests do not have a trust relationship.
![[Transitive Trust.png]]
#### Types of Trust
- **Default/Automatic Trusts**
	- **Parent-child trust**
		- It is created automatically between the new domain and the domain that precedes it in the namespace hierarchy, whenever a new domain is added in a tree. For example, dollarcorp.moneycorp.local is a child of moneycorp.local
		- This trust is always two-way transitive.
	- **Tree-root trust**
		- It is created automatically between whenever a new domain tree is added to a forest root.
		- This trust is always two-way transitive.

![[Default_Automatic Trusts.png]]

- **External Trusts**
	- Between two domains in different forests when forests do not have a trust relationship.
	- Can be one-way or two-way and is nontransitive

![[External Trust.png]]

- Forest Trusts
	- Between forest root domain.
	- Cannot be extended to a third forest (no implicit trust).
	- Can be one-way or two-way transitive
![[forest trust.png]]

#### Domain Trust mapping
- Get a list of all domain trusts for the current domain
```
#Power View
Get-DomainTrust
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local

# ActiveDirectory Module
Get-ADTrust
Get-ADTrust -Identity us.dollarcorp.moneycorp.local
```

#### Forest trust Mapping
- Get details about the current forest
```
#Power View
Get-Forest
Get-Forest -Forest eurocorp.local

#ActiveDirectory Module
Get-ADForest
Get-ADForest -Identity eurocorp.local
```
- Get all domains in the current forest
```
#Power View
Get-ForestDomain
Get-ForestDomain -Forest eurocorp.local

#ActiveDirectory Module
(Get-ADForest).Domains
```
- Get all global catalogs for the current forest
```
#Power View
Get-ForestGlobalCatalog
Get-ForestGlobalCatalog -Forest eurocorp.local

#ActiveDirectory Module
Get-ADForest | select -ExpandProperty GlobalCatalogs
```
- Map trusts of a forest (no Forest trusts in the lab)
```
#Power View
Get-ForestTrust
Get-ForestTrust -Forest eurocorp.local

#ActieDirectory Module
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```
- Map External trusts forest
```
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```

### Domain Enumeration -- User Hunting
- Find all machines on the current domain where the current user has local admin access
```
#Power view
Find-LocalAdminAccess -Verbose
```
- See Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1 (provide list of machine for less noise)
- Find computers where a domain admin (or specified user/group) has sessions
```
#Power view
Find-DomainUserLocation -Verbose
Find-DomainUserLocation -UserGroupIdentity "RDPUsers"
```

> [!note]
> Note that for Server 2019 and onwards, local administrator privileges are required to list sessions.

- Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess).
```
Find-DomainUserLocation -CheckAccess
```
- Find computers (File Servers and Distributed File servers) where a domain admin session is available
```
Find-DomainUserLocation -Stealth
```

- List sessions on remote machines (https://github.com/Leo4j/Invoke-SessionHunter)
```
Invoke-SessionHunter -FailSafe
```
- Above command doesn’t need admin access on remote machines. Uses Remote Registry and queries HKEY_USERS hive.
- An opsec friendly command would be (avoid connecting to all the target machines by specifying targets)
```
Invoke-SessionHunter -NoPortScan -Targets C:\AD\Tools\servers.txt
```

