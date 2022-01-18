#Disable AD user not logged in X number of days, move to separate OU.

#define Ou domain name here Where users Exits
$DomainDN = Get-ADDomain | Select-Object DistinguishedName -ExpandProperty DistinguishedName

#Description for disabled users adding date of disabled and ticket#
$date = Get-date -Format "MM.dd.yy"
$description = "Disabled by TIG on $Date"

#Create Log File for Objects Disabled
$worksfolder="C:\windows\LTSvc\Reports\AD Cleanup"
if ( !(test-path "$worksfolder")) {
    Write-Verbose "Folder [$($worksfolder)] does not exist, creating"
    new-item $worksFolder -type directory -Force 
}
$DisabledUsersFile = "$worksfolder\DisabledUsers.csv"
$DisabledComputersFile = "$worksfolder\DisabledComputers.csv"
#if ( !(test-path "$DisabledUsersFile")) {
#    Write-Verbose "Folder [$($DisabledUsersFile)] does not exist, creating"
#    new-item $DisabledUsersFile -type directory -Force 
#}
#if ( !(test-path "$DisabledComputersFile")) {
#    Write-Verbose "Folder [$($DisabledComputersFile)] does not exist, creating"
#    new-item $DisabledComputersFile -type directory -Force 
#}

#Define OU where you want disabled users to be moved.
$TIGDisabled="TIG MANAGE" # Type OU name and pass as variable 
$TIGDisabledUsersGroup="TIG-DisabledUsers"
$TIGDisabledComputersGroup="TIG-DisabledComputers"
$DomainDN = Get-ADDomain | Select-Object DistinguishedName -ExpandProperty DistinguishedName
    Write-Host -ForegroundColor Green "Checking if OU exist $DomainDN"
$oucheck = [adsi]::Exists("LDAP://OU=$TIGDisabled,$DomainDN")
$OUDN = "OU=$TIGDisabled,$DomainDN"
if($oucheck -eq $true) {
    $text = "The TIG MANAGE OU already exist in Active Directory"
    Write-Host -ForegroundColor red $text.ToUpper()
}
else {
    Write-Host "$TIGDisabled does not exist.  Creating now."
    New-ADOrganizationalUnit -Name "$TIGDisabled" -Path "$DomainDN"
}
$disabledou="OU=$TIGDisabled,$DomainDN"
Write-Host -ForegroundColor Green "Checking if $TIGDisabledUsersGroup exist $OUDN"
$usersgroupcheck= Get-ADGroup -LDAPFilter "(SAMAccountName=$TIGDisabledUsersGroup)"
if($null -eq $UsersGroupCheck) {
    New-ADGroup -Name "TIG-DisabledUsers" -SamAccountName TIG-DisabledUsers -GroupCategory Security -GroupScope Global -Description "Members of this group have been disabled by TIG MANAGE" -Path $OUDN
}
else {
    Write-Host "TIG-DisabledUsers already exists"
}
Write-Host -ForegroundColor Green "Checking if $TIGDisabledComputersGroup exist $OUDN"
$computersgroupcheck= Get-ADGroup -LDAPFilter "(SAMAccountName=$TIGDisabledComputersGroup)"
if($null -eq $ComputersGroupCheck) {
    New-ADGroup -Name "TIG-DisabledComputers" -SamAccountName TIG-DisabledComputers -GroupCategory Security -GroupScope Global -Description "Members of this group have been disabled by TIG MANAGE" -Path $OUDN
}
else {
    Write-Host "TIG-DisabledComputers already exists"
}
#Cleanup Actions
Import-Module activedirectory
Write-Host "Starting Inactive User Cleanup"
#Users Inactive in the last 90 days
$targetUsers = Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly | Where-Object{$_.enabled -eq $true} | Select-Object  samaccountname,name
Foreach($user in $targetUsers){  
     $UserDN  = (Get-ADUser -Identity $user.samaccountname).distinguishedName  
     Move-ADObject  -Identity $UserDN  -TargetPath $disabledou
     Set-ADUser $user.samaccountname -Description "$description"
     $UserGroups = (Get-ADPrincipalGroupMembership -Identity $user.SamAccountName | Select-Object Name -ExpandProperty name) -join ','
     get-aduser $user.SamAccountName -properties memberof,samaccountname,givenname,surname,description | Select-Object samaccountname,givenname,surname, @{name="Groups";expression={$UserGroups}},description | export-csv "$DisabledUsersFile" -Delimiter ";" -NoTypeInformation -Encoding UTF8 -Append
     #Get-ADGroup -Filter {name -notlike "$TIGDisabledUsersGroup"}  | Remove-ADGroupMember -Members $user.samaccountname -Confirm:$False
     Add-ADGroupMember -Identity $TIGDisabledUsersGroup -Members $user.samaccountname}
Foreach($user in $targetUsers){  
     Disable-ADAccount -Identity $user.samaccountname -Verbose
}

Write-Host "Starting Inactive Computers Cleanup"
#Computers Inactive in the last 90 days
$targetComputers = Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -ComputersOnly | Where-Object{$_.enabled -eq $true} | Select-Object  samaccountname,name
Foreach($computer in $targetComputers){  
         $ComputerDN  = (Get-ADComputer -Identity $computer.samaccountname).distinguishedName  
         Move-ADObject  -Identity $ComputerDN  -TargetPath $disabledou
         Set-ADComputer $computer.samaccountname -Description "$description"
         $ComputerGroups = (Get-ADPrincipalGroupMembership -Identity $computer.samaccountname | Select-Object Name -ExpandProperty name) -join ','
         get-adcomputer $computer.samaccountname -properties memberof,Name,DNSHostName,DistinguishedName,description | Select-Object Name,DNSHostName,DistinguishedName, @{name="Groups";expression={$ComputerGroups}},description | export-csv "$DisabledComputersFile" -Delimiter ";" -NoTypeInformation -Encoding UTF8 -Append
         #Get-ADGroup -Filter {name -notlike "$TIGDisabledGroup"}  | Remove-ADGroupMember -Members $user.samaccountname -Confirm:$False
         Add-ADGroupMember -Identity $TIGDisabledComputersGroup -Members $computer.samaccountname}
Foreach($computer in $targetComputers){   
         Disable-ADAccount -Identity $computer.samaccountname -Verbose
}