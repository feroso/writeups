param ($vmname)

$adminUser = 'Administrator'
$password = ''
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credentialAdmin = New-Object System.Management.Automation.PSCredential $adminUser, $securePassword

Invoke-Command -VMName $vmname -Credential $credentialAdmin -ScriptBlock {
	$passworduser = ''
	$securePassworduser = ConvertTo-SecureString $passworduser -AsPlainText -Force
	$credentialuser = New-Object System.Management.Automation.PSCredential "EnlightenMe", $securePassworduser
	Invoke-Command -VMName "EnlightenMeGuest" -Credential $credentialuser -ScriptBlock {			
		C:\Users\EnlightenMe\payload.exe
	}
}