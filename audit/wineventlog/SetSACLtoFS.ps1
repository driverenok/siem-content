$relativeAuditDirs = '\Desktop\'

$SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")

$AuditUser = $SID.Translate([System.Security.Principal.NTAccount])
$AuditRules = "CreateFiles,AppendData,ChangePermissions,TakeOwnership"
$InheritType = "ContainerInherit,ObjectInherit"
$AuditType = "Success"

$userProfiles = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" | Where-Object {$_.Property -like 'ProfileImagePath'} | Get-ItemProperty -name 'ProfileImagePath'

function SetAuditToRootFSObject($absoluteRootPath)
{
	$FileSACL = Get-Acl $absoluteRootPath -audit

    # remove old SACL
	foreach ($FileACE in $FileSACL.Audit) {
		$FileSACL.RemoveAuditRule($FileACE)
	}

    # set net SACL
    $AccessRule = new-object System.Security.AccessControl.FileSystemAuditRule($AuditUser,$AuditRules,$InheritType,"none",$AuditType)
	$FileSACL.SetAuditRule($AccessRule)
	$FileSACL.SetAuditRuleProtection($True, $True)
    $FileSACL | Set-Acl $absoluteRootPath
	echo $("SACL for " + $absoluteRootPath + " directory successfull apply.")
}

function SetAuditToChildFSObject($absolutePath)
{
    $FileSACL = Get-Acl $absolutePath -audit

    # remove old SACL
	foreach ($FileACE in $FileSACL.Audit) {
		$FileSACL.RemoveAuditRule($FileACE)
	}
	# https://stackru.com/questions/46516055/powershell-c-setauditruleprotection-ne-rabotaet-na-nekotoryih-papkah?ysclid=lf9jnou13v762719928
	$AccessRule = new-object System.Security.AccessControl.FileSystemAuditRule($AuditUser, "Delete", "none", "none", $AuditType)
	$FileSACL.SetAuditRule($AccessRule)
	# включу наследование и заменю существующие разрешения родительскими (Устанавливаю наследование и перезапись прав)
    $FileSACL.SetAuditRuleProtection($False,$True)
	#$FileSACL.RemoveAuditRule($AccessRule)
    Set-Acl $absolutePath -ACLObject $FileSACL
	
	#$FileSACL.RemoveAuditRule($AccessRule)
	#$FileSACL.SetAuditRuleProtection($False,$True)
	#Set-Acl $absolutePath -ACLObject $FileSACL
	echo $("SACL for " + $absolutePath + " directory successfull apply.")
}

foreach ($userProfile in $userProfiles) {
    foreach ($relativeAuditDir in $relativeAuditDirs) {
        $absoluteAuditDir = $($userProfile.ProfileImagePath + "\" + $relativeAuditDir)

#	    if (Test-Path -Path $absoluteAuditDir -PathType Container) {
	    if (Test-Path -Path $absoluteAuditDir -PathType Container) {
            # Set auditing to root dir
            SetAuditToRootFSObject($absoluteAuditDir)

            # Applying inheritance for child dir
			$childObjects = $(Get-ChildItem -Path $absoluteAuditDir -Recurse)
            if ($childObjects) {
		    	foreach ($childObject in $childObjects) {
		    		SetAuditToChildFSObject($childObject.FullName)
		    	}
            }
	    }
	    else {
		    echo $("Directory " + $absoluteAuditDir + " does not exist.")
	    }
    }
}
	

<#

Source: https://giuoco.org/security/configure-file-and-registry-auditing-with-powershell/

RightsToAudit can have the following values when using FileSystemAuditRule

    FullControl
    DeleteSubdirectoriesAndFiles
    Modify
    ChangePermissions
    TakeOwnership
    ExecuteFile
    ReadData
    ReadAttributes
    ReadExtendedAttributes
    CreateFiles
    AppendData
    WriteAttributes
    WriteExtendedAttributes
    Delete
    ReadPermissions

#>