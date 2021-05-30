param ($vmname)

$adminUser = 'Administrator'
$password = ''
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credentialAdmin = New-Object System.Management.Automation.PSCredential $adminUser, $securePassword

Invoke-Command -VMName $vmname -Credential $credentialAdmin -ScriptBlock {
	Stop-VM -Name "EnlightenMeGuest" -TurnOff
}

Stop-VM -Name $vmname -TurnOff
