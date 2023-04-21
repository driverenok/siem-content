$items =	'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
			'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
			'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx',
			'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
			'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
			'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesEx',
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesEx',
			'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
			'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
			'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx',						
			'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
			'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
			'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx',
			'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices',
			'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce',
			'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesEx',						
			'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices',
			'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce',
			'HKCU:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesEx',
			'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
			'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
			'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders',
			'HKCU:\Environment\',
			'HKCU:\Control Panel\Desktop',
			'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters'

#New-PSDrive HKU Registry HKEY_USERS | Out-Null

# Проверить наследование

$SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
$AuditUser = $SID.Translate([System.Security.Principal.NTAccount])

foreach ($item in $items) {
	if (-not (Test-Path -Path $item -PathType Container)) {
		New-Item -ItemType Directory -Path $item -Force | Out-Null
	}
	$RegKey_ACL = new-object System.Security.AccessControl.RegistrySecurity
	$AccessRule = new-object System.Security.AccessControl.RegistryAuditRule($AuditUser,"SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership","containerinherit","none","Success")
	$RegKey_ACL.SetAuditRule($AccessRule)
	$RegKey_ACL | Set-Acl $item 2>&1 | Out-Null
	
#	Get-Item -Path $item | Select-Object Name

}

<#

RightsToAudit can have the following values when using RegistryAuditRule.

Source: https://giuoco.org/security/configure-file-and-registry-auditing-with-powershell/

    FullControl
    QueryValues
    SetValue
    CreateSubKey
    EnumerateSubKeys
    Notify
    CreateLink
    Delete
    WriteKey
    ChangePermissions
    TakeOwnership
    ReadPermissions
	
	SetValue,CreateSubKey,Delete,ChangePermissions,TakeOwnership
#>