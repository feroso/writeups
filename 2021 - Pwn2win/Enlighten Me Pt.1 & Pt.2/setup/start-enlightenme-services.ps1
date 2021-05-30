param ($vmname)

$adminUser = 'Administrator'
$password = ''
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credentialAdmin = New-Object System.Management.Automation.PSCredential $adminUser, $securePassword

Invoke-Command -VMName $vmname -Credential $credentialAdmin -ScriptBlock {
	Start-Service -Name "enlightenme"
	
	$adminUserGuest = 'Administrator'
	$passwordUserGuest = ''
	$securePasswordGuest = ConvertTo-SecureString $passwordUserGuest -AsPlainText -Force
	$credentialAdminGuest = New-Object System.Management.Automation.PSCredential $adminUserGuest, $securePasswordGuest
	
	Invoke-Command -VMName "EnlightenMeGuest" -Credential $credentialAdminGuest -ScriptBlock {
		Start-Service -Name "enlightenme"
	}
}