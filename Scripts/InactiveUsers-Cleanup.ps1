#Disable AD user not logged in X number of days, move to separate OU.


<#

Written By allenage.com


#>

#define Ou domain name here Where users Exits
$DomainDN = Get-ADDomain | Select-Object DistinguishedName -ExpandProperty DistinguishedName

#setting description for disabled users adding date of disabled, previous group membership

$Ticket =
$date = Get-date -Format "MM.dd.yy"
$description = "Disabled by TIG on $Date - Ticket #$Ticket"


$worksfolder="C:\windows\LTSvc\Reports\AD Cleanup"
if ( !(test-path "$worksfolder")) {
    Write-Verbose "Folder [$($worksfolder)] does not exist, creating"
    new-item $worksFolder -type directory -Force 
}

#define days days the period which users did not logged and you want to disable
$DaysInactive = 30
$today = Get-date -Format "MM_dd_yy"
$time = (Get-Date).Adddays(-($DaysInactive)) 

#you can change the path where users will be exported.
$exportedpath= "$worksfolder\inactiveusers.csv"

#Define OU where you want disabled users to be moved.
$TIGDisabled="TIG MANAGE" # Type OU name and pass as variable 
$DomainDN = Get-ADDomain | Select-Object DistinguishedName -ExpandProperty DistinguishedName
    Write-Host -ForegroundColor Green "Checking if OU exist $DomainDN"
$oucheck = [adsi]::Exists("LDAP://OU=$TIGDisabled,$DomainDN")
if($oucheck -eq $true) {
    $text = "The OU already exist in Active Directory"
    Write-Host -ForegroundColor red $text.ToUpper()
}
else {
    Write-Host "$TIGDisabled does not exist"
    New-ADOrganizationalUnit -Name "$TIGDisabled" -Path "$DomainDN"
}
$disabledou="OU=$TIGDisabled,$DomainDN"

# Do not modify anything below this
Import-Module activedirectory

$target = Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 <# -SearchBase $ou #>| Where-Object{$_.enabled -eq $true} | Select-Object  samaccountname,name
$target | export-csv $exportedpath -nti

Foreach($user in $target){
Disable-ADAccount -Identity $user.samaccountname -Verbose
}

## RESET A Random Password
$length = 25
$nonAlphaChars = 5
$pwd = [System.Web.Security.Membership]::GeneratePassword($length, $nonAlphaChars)
Foreach($user in $target){
Try{
Set-ADAccountPassword -identity $user.samaccountname -NewPassword (ConvertTo-SecureString -AsPlainText $pwd -force)
}
Catch{
write-warning "$_ "}
}

## move To disabled OU
Foreach($user in $target){  
     $UserDN  = (Get-ADUser -Identity $user.samaccountname).distinguishedName  
     Move-ADObject  -Identity $UserDN  -TargetPath $disabledou}

## Set Description
Foreach($user in $target){
    $grp=get-aduser $user.samaccountname -Properties memberof | Select-Object name, @{n=’MemberOf’; e= { ( $_.memberof | ForEach-Object { (Get-ADObject $_).Name }) -join “,” }}
    Set-ADUser $user.samaccountname -Description "$description" 
}

# Remove From all the Groups
Foreach($user in $target){
    Get-ADGroup -Filter {name -notlike "*domain users*"}  | Remove-ADGroupMember -Members $user.samaccountname -Confirm:$False 
}

New-ADGroup -Name "TIG-DisabledUsers" -SamAccountName TIGDisabledUsers -GroupCategory Security -GroupScope Global -Description "Members of this group have been disabled by TIG MANAGE"