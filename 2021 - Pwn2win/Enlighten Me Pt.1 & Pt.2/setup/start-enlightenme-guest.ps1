param ($vmname)

$adminUser = 'Administrator'
$password = ''
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credentialAdmin = New-Object System.Management.Automation.PSCredential $adminUser, $securePassword

Invoke-Command -VMName $vmname -Credential $credentialAdmin -ScriptBlock {
	do{
		Start-VM "EnlightenMeGuest"
	} while (-not $?)
		
	do{	
		start-sleep -s 1
		Copy-VMFile "EnlightenMeGuest" -SourcePath "C:\Users\Administrator\payload.exe" -DestinationPath "C:\Users\EnlightenMe\payload.exe" -CreateFullPath -FileSource Host -Force 2>&1 | out-null
	} while (-Not $?)
}
