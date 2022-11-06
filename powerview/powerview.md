# PowerView

## Users
```powershell
# current user's accessible shares (long & noisy)
Find-DomainShare -CheckShareAccess

# all enabled users
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE -Properties samaccountname,distinguishedname,description,memberof | fl

# all users
Get-NetUser | select samaccountname, description

# specific user
Get-NetUser -UserName username

# users with SPNs
Get-DomainUser -SPN -properties samaccountname,serviceprincipalname,description,memberof,distinguishedname | fl

# users without preauthentication
Get-DomainUser -PreauthNotRequired -properties samaccountname,serviceprincipalname,description,memberof,distinguishedname | fl

# users with constrained delegation
Get-DomainUser -TrustedToAuth
Get-Netuser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

# list all logon sessions
Find-DomainUserLocation

# list users in groups not in current domain or specify with -domain
Get-DomainForeignUser -domain domain.com

# find computers where current user has local admin in current domain or specify with -domain (noisy)
Find-LocalAdminAccess -domain domain.com

# check all computers for logged in domain admins, or -UserGroupIdentity for specific group (noisy)
Find-DomainUserLocation | select UserName, SessionFromName

# user sessions on specific computer, CName = source ip
Get-NetSession -ComputerName dc-2 | select CName, UserName

# find computers where user has admin
Get-DomainGPOUserLocalGroupMapping -Identity username | select ComputerName,GPODisplayName,GPOGuid

# users logged on to computers with unconstrained delegation
Find-DomainUserLocation -ComputerUnconstrained -ShowAll

# admin users logged on to computers with unconstrained delegation
Find-DomainUserLocation -ComputerUnconstrained -UserAdminCount -UserAllowDelegation

# show UAC values
Get-DomainUser username | ConvertFrom-UACValue -showall

# users with unusual properties (i.e. not shared with first result)
Get-DomainUser -FindOne | Find-DomainObjectPropertyOutlier | fl
Get-DomainUser username | Find-DomainObjectPropertyOutlier | fl
```

## Groups
```powershell
# user's group memberships
Get-DomainGroup -MemberIdentity username -properties distinguishedname
Get-NetGroup -UserName username
Get-NetGroup -UserName username -properties name,distinguishedname,member,memberof  | fl

# all groups
Get-DomainGroup -properties samaccountname,distinguishedname,member,description | fl
Get-NetGroup | select samaccountname,admincount,description

# specific group
Get-NetGroup 'Domain Admins'

# admin groups
Get-DomainGroup | where Name -like "*dmin*" | select SamAccountName
Get-NetGroup -AdminCount | select name,memberof,admincount,member | fl

# specific group SID
get-domaingroup -identity "domain admins" -domain domain.com -properties cn,objectsid

# members of a group
Get-DomainGroupMember -Identity "Domain Admins" -Recurse | select MemberName,MemberDistinguishedName,MemberObjectClass
Get-NetGroupMember -Identity "Administrators" -Recurse

# groups with foreign members (MemberName SID won't resolve for outbound)
Get-DomainForeignGroupMember -Domain domain.com

# AdminSDHolder protected groups
Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=domain,DC=com' | %{ $_.SecurityIdentifier } | Convert-SidToName

# find computers where group has admin
Get-DomainGPOUserLocalGroupMapping -Identity TestGroup

# find logged on users from group
Invoke-UserHunter -GroupName "TestGroup"

# groups with unusual properties (i.e. not shared with first result)
Get-DomainGroup -FindOne | Find-DomainObjectPropertyOutlier | fl
```

## Computers
```powershell
# computers with constrained delegation
Get-DomainComputer -TrustedToAuth -properties samaccountname,distinguishedname,msds-allowedtodelegateto,dnshostname | fl
Get-NetComputer -TrustedToAuth

# computers with unconstrained delegation
Get-DomainComputer -Unconstrained -properties samaccountname,distinguishedname,dnshostname | fl
Get-NetComputer -Unconstrained -properties samaccountname,distinguishedname,dnshostname | fl

# domain info
Get-WmiObject -Class Win32_NTDomain

# computers in an OU
Get-DomainComputer -SearchBase "ldap://OU=.." | select dnshostname,operatingsystem

# computers with unusual properties (i.e. not shared with first result)
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier | fl

# check if current user has admin access with OpenSCManagerW Win32API
Test-AdminAccess -ComputerName dc.domain.com
Get-DomainComputer | Test-AdminAccess

# computer ip address
Resolve-IPAddress -ComputerName dc

# share permissions
Get-PathAcl -Path "\\dc\software" | select FileSystemRights,IdentityReference,AccessControlType

# admin groups query dc or have local admin on computer
Get-NetLocalGroupMember -computername dc

# file servers
Get-NetFileServer

# interesting files on shares, default '*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'
Find-InterestingDomainShareFile
```

## GPOs
```powershell
# all available information from Group Policy Result tool
run gpresult /z

# list GPOs
Get-DomainGPO -properties displayname,name,gpcfilesyspath | fl
Get-NetGPO | select displayname

# list GPOs linked to domain and OUs
(([adsi]'LDAP://DC=domain,DC=com'),(([adsisearcher]'(objectcategory=organizationalunit)')).findall()).Path | %{if(([ADSI]"$_").gPlink){Write-Host "[+] OU Path:"([ADSI]"$_").Path;$a=((([ADSI]"$_").gplink) -replace "[[;]" -split "]");for($i=0;$i -lt $a.length;$i++){if($a[$i]){Write-Host "Policy Path[$i]:"([ADSI]($a[$i]).Substring(0,$a[$i].length-1)).Path;Write-Host "Policy Name[$i]:"([ADSI]($a[$i]).Substring(0,$a[$i].length-1)).DisplayName} };Write-Output "`n" }}

# look for AppLocker GPO
Get-DomainGPO -Domain domain.com | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath
Get-DomainGPO -Domain domain.com | ? { $_.DisplayName -like "*ocker*" } | select displayname, gpcfilesyspath

# look for LAPS GPO
powershell Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

# get SIDs of principals who can read LAPS password of OU
Get-DomainObjectAcl -SearchBase "LDAP://OU=Workstations,DC=domain,DC=com" -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -like "*ReadProperty*" } | select ObjectDN, SecurityIdentifier

# read LAPS password
Get-DomainObject -Identity [computer name] -Properties ms-Mcs-AdmPwd

# download GPO from gpcfilesyspath
download \\domain.com\SysVol\domain.com\Policies\{E4E6CCDB-1F0E-482D-B0BC-0E0EC5E6BDD5}\Machine\Registry.pol

# find OUs GPO is applied to with GUID from ObjectDN or name
Get-DomainOU -GPLink "{AD2F58B9-97A0-4DBC-A535-B4ED36D5DD2F}" | select distinguishedName

# list GPOs applied to computer
Get-DomainGPO -ComputerIdentity dc -properties displayname,name,gpcfilesyspath | fl
Get-NetGPO -ComputerName dc

# find computers where user/group is local admin
Get-DomainGPOUserLocalGroupMapping -Identity username | select ComputerName,GPODisplayName,ContainerName | fl

# list all local admin group mappings
Get-DomainGPOUserLocalGroupMapping | select ObjectName,GPODisplayName,ContainerName,ComputerName | fl

# permissions for GPOs where users with RIDs of > 1000 have some kind of modification/control rights
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')}
Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')} | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl

# get names from returned SIDs
ConvertFrom-SID S-1-5-..

# GPOs that modify local groups, specify name for specific GPO
Get-DomainGPOLocalGroup
Get-DomainGPOLocalGroup "Servicedesk Admins"
Get-DomainGPOLocalGroup | select GPODisplayName, GroupName, GPOType
Get-NetGPOGroup

# groups with local admin rights to specific computer
Get-DomainGPOComputerLocalGroupMapping -ComputerName dc
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl

# users that can create GPOs
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=domain,DC=com" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=domain,DC=com" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }

# users that can link GPOs
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl

# GPOs that can be modified by RID > 1000 users
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "^S-1-5-.*-[1-9]\d{3,}$" }

# get GPO name with ObjectDN
Get-DomainGPO -Identity "CN={AD7EE1ED-CDC8-4994-AE0F-50BA8B264829},CN=Policies,CN=System,DC=domain,DC=com" | select displayName, gpcFileSysPath

# get principal name with SecurityIdentifier
convertfrom-sid S-1-5-21-3263068140-2042698922-2891547269-1126

# GPO that can be modified by specific user, with SID
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner" -and $_.SecurityIdentifier -match "[userSID]" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl

# list WMI filters
Get-DomainObject -SearchBase "CN=SOM, CN=WmiPolicy, CN=System, DC=lab, DC=dev" -LDAPFilter "(objectclass=msWMI-Som)" -Properties name,mswmi-name,mswmi-parm2 | fl

# check filter name GUID against gpcwqlfilter to find the GPO they're linked to
Get-DomainObject -SearchBase "CN=Policies, CN=System, DC=lab, DC=dev" -LDAPFilter "(objectclass=groupPolicyContainer)" -Properties displayname,gpcwqlfilter | fl

# remove filter
Set-DomainObject -Identity "{249177CF-9AE9-4603-9246-2E246E50A66C}" -Clear gpcwqlfilter -Verbose
```

## OUs
```powershell
# all domain OUs
Get-DomainOU -properties name,gplink,distinguishedname | fl
Get-DomainOU -Properties Name | sort -Property Name
Get-NetOU

# specific OU
Get-NetOU "Workstations"| %{Get-NetComputer -ADSPath $_}

# get GPO of an OU
Get-DomainGPO -SearchBase "LDAP://cn={16927C64-CF83-4962-B0CF-6F90710F19C8},cn=policies,cn=system,DC=domain,DC=com" -properties displayname,name,gpcfilesyspath | fl
Get-NetGPO -GPOName '{16927C64-CF83-4962-B0CF-6F90710F19C8}'

# computers inside OU
Get-DomainOU "Workstations" | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties Name,dnshostname,operatingsystem,samaccountname,distinguishedname}
Get-NetOU Workstations | %{Get-NetComputer -ADSPath $_}
```

## Domain
```powershell
# domain info for current domain or specify with -domain
get-domain -domain domain.com
Get-NetDomain

# domain SID
get-domainsid

# domain controllers
Get-DomainController | select Forest, Domain, IPAddress, Name, OSVersion | fl
Get-NetDomainController -Domain domain.com

# trusts for current and resulting domains
Get-DomainTrustMapping

# trusts for current domain, or specify with -domain
Get-DomainTrust
Get-NetDomainTrust

# information on current forest, or specify with -Forest
Get-ForestDomain

# global catalog of current forest, or specify with -Forest
Get-ForestGlobalCatalog

# forest trusts
Get-NetForestTrust

# domain password policy
Get-DomainPolicyData | select -ExpandProperty SystemAccess
(Get-DomainPolicy)."SystemAccess"

# domain kerberos policy
(Get-DomainPolicy)."KerberosPolicy"
```

## References

https://powersploit.readthedocs.io/en/latest/
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
