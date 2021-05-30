param ($vmname, $payloadpath)

$adminUser = 'Administrator'
$password = ''
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credentialAdmin = New-Object System.Management.Automation.PSCredential $adminUser, $securePassword

Start-VM $vmname	
do{	
	start-sleep -s 1
	Copy-VMFile $vmname -SourcePath $payloadpath -DestinationPath "C:\Users\Administrator\payload.exe" -CreateFullPath -FileSource Host -Force 2>&1 | out-null
} while (-Not $?)
