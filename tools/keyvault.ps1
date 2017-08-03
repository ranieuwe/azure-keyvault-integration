# Prerequisites
# 1. An existing key vault with access for the current principal (USER)
# 2. An existing app service with administrative/deployment access
# 3. Working Azure subscription 

# See also https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication-configure#azure-ad-token

# Settings
[cmdletbinding()]
param(
	[string] $prefix = 'ronieuwecert',
	[string] $resourceGroupName = $prefix,
	[string] $location = 'westeurope',
	[switch] $import
 
)

$sub = '011d1fae-39f9-495e-a55c-ec4c4219d301' 
$publicIp = "167.220.196.53"
$adAppName = $prefix + "kvwa"
$webAppName = $prefix + "app"
$keyVaultName = $prefix + "kv"
$keyVaultCertificateName = $prefix + "certificate"
$resourceGroupName = $prefix
$location = 'westeurope'
$buildWebApp = $true

# SQL settings
$db = @{}
$db["user"] = "ronieuwe"
$db["sample"] = "AdventureWorksLT"
$db["pass"] = "password"
$db["name"] = $prefix + "sql"
$db["server"] = $prefix + "sqlserver"
$db["serveruser"] = "ronieuwe"
$db["serverpass"] = Read-Host -AsSecureString "Please enter the SQL DB Server password"

$summary = @{}

Import-Module '.\KeyVaultHelper2.psm1'

Try {
  Get-AzureRmContext
} Catch {
  if ($_ -like "*Login-AzureRmAccount to login*") {
    Login-AzureRmAccount -SubscriptionId $sub
  }
}

$executingUser = (Get-AzureRmContext).Account.Id

# Grab the resource group if it exists, if not then create it and then grab it
$rg = Get-AzureRmResourceGroup -Name $resourceGroupName -ev rgNotPresent -ea 0

If ($rgNotPresent) {
	Write-Host "Resource group $resourceGroupName does not exist, creating"
    $rg = New-AzureRmResourceGroup -Name $resourceGroupName -Location $location -Tag $tags
} 

# Create a keyvault if it doesn't exist, otherwise retrieve it
$kv = Get-AzureRmKeyVault -VaultName $keyVaultName -ev kvNotPresent -ea 0

If ($kvNotPresent) {
	# Need to make sure the KV name doesn't exceed 24 characters
	$keyVaultName = $keyVaultName.Substring(0, [System.Math]::Min(24, $keyVaultName.Length))
	Write-Host "Creating keyvault with the name of $keyVaultName"
	$kv = New-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $rg.ResourceGroupName -Location $rg.Location
}

Write-Host "Working with keyvault $keyVaultName"

# Build a Webapp and a SQL database from scratch
if($buildWebApp) {
	$wa = Get-AzureRmWebApp -Name $webAppName
	if(!$wa) {
		$parameters = @{}
		$parameters.Add("name", $webAppName)
		$parameters.Add("sku","Basic")
		$parameters.Add("skuCode","B1")
		$parameters.Add("location","West Europe")
		$parameters.Add("hostingEnvironment","")
		$parameters.Add("hostingPlanName",$webAppName + "-plan")
		$parameters.Add("workerSize","0")
		$parameters.Add("serverFarmResourceGroup",$resourceGroupName)
		$parameters.Add("subscriptionId",$sub)
		$parameters.Add("serverName", $db["server"])
		$parameters.Add("databaseName", $db["name"])
		$parameters.Add("databaseUsername", $db["user"])
		$parameters.Add("databasePassword", $db["pass"])
		$parameters.Add("edition", "Basic")
		$parameters.Add("collation", "SQL_Latin1_General_CP1_CI_AS")
		$parameters.Add("maxSizeBytes", "2147483648")
		$parameters.Add("requestedServiceObjectiveId", "dd6d99bb-f193-4ec1-86f2-43d3bccbc49c")
		$parameters.Add("serverLocation", $location)
		$parameters.Add("administratorLogin", $db["serveruser"])
		$parameters.Add("administratorLoginPassword", $db["serverpass"])
		$parameters.Add("sampleName","AdventureworksLT")
		Write-Host "Creating app service, farm and SQL"
		New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName -Name $webAppName  -TemplateParameterObject $parameters -TemplateFile template.json -NameFromTemplate $webAppName
	}
}

# Give myself the permission to handle certificates
Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -UserPrincipalName $executingUser -PermissionsToCertificates all 

# Make a new self signed cert, alternatively provide your own certificate
$policy = New-AzureKeyVaultCertificatePolicy -SubjectName "CN=$adAppName" -IssuerName Self -ValidityInMonths 12

# Upload the cert into the Key vault
Add-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $keyVaultCertificateName -CertificatePolicy $policy 

# Wait for the certificate to be ready
Start-Sleep -s 30

# Retrieve the cert again
$cert = Get-AzureKeyVaultCertificate -VaultName $keyVaultName -Name $keyVaultCertificateName

Write-Verbose $cert

$summary.Add("Certificate name in KV", $cert.Certificate.FriendlyName)
$summary.Add("Certificate CN", $cert.Certificate.Subject)

# Create an Azure Active Directory application
$app = New-AzureRmADApplication -DisplayName $adAppName -HomePage "https://$adAppName.azurewebsites.net" -IdentifierUris "https://$adAppName"

# Wait for the app to be ready
Start-Sleep -s 5

Write-Verbose $app

$summary.Add("Application ID", $app.ApplicationId)
$summary.Add("Application name", $app.DisplayName)

# Create the credentials
$keyCredential = New-Object -TypeName Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADKeyCredential
$keyCredential.StartDate = $cert.Certificate.NotBefore
$keyCredential.EndDate = $cert.Certificate.NotAfter
$keyCredential.KeyId = [guid]::NewGuid()
$keyCredential.CertValue = [System.Convert]::ToBase64String($cert.Certificate.GetRawCertData())

$sp = New-AzureRmADServicePrincipal -KeyCredentials $keyCredential -ApplicationId $app.ApplicationId 

Write-Verbose $sp

Start-Sleep -s 5

# Give the Microsoft Web Resource Provider read access to our secret, the guid is the static value for the app service
Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ServicePrincipalName 'abfa0a7c-a6b6-4736-8310-5855508787cd' -PermissionsToSecrets get

# grant the apps service principal get access to Key Vault secrets, not necessary but useful to access other strings for example for documentdb
# Set-AzureRmKeyVaultAccessPolicy -VaultName $keyVaultName -ServicePrincipalName $sp.ObjectId -PermissionsToSecrets Get

# Load the cert from the key vault into the webapp
# This is a helper method from the KeyVaultHelper2.psm1
$config = Add-WebAppCertFromKeyVault -WebApp $webAppName -VaultName $keyVaultName -KeyVaultCertName $keyVaultCertificateName

# List our access policies
(Get-AzureRmKeyVault -VaultName $keyVaultName).AccessPolicies

# Remove the permission
Remove-AzureRmKeyVaultAccessPolicy -ServicePrincipalName 'abfa0a7c-a6b6-4736-8310-5855508787cd' -VaultName $keyVaultName

# Make a hole in the firewall for my IP
New-AzureRmSqlServerFirewallRule -ServerName $db["server"] -ResourceGroupName $resourceGroupName -FirewallRuleName "deployment access" -StartIpAddress $publicIp -EndIpAddress $publicIp

# Enable Azure Active Directory access on the SQL instance
Set-AzureRmSqlServerActiveDirectoryAdministrator -DisplayName $executingUser -ServerName $db["server"] -ResourceGroupName $resourceGroupName

<# 
	This step cannot be automated because there is no SQL PowerShell cmdlet that allows to connect 
	to SQL DB using AAD authentication. One needs to be connected to SQL DB through AAD otherwise
	you cannot provision new users on DB level. 
#> 

### Some code to pull out the certificate locally so you can debug with a local instance against the remote SQL DB
if($import) {
	# Get created private key from Azure App Service Certificates
	$kvs = Get-AzureKeyVaultSecret -VaultName $vaultName -Name $certificateName
	$kvsbytes = [System.Convert]::FromBase64String($kvs.SecretValueText)
	$certs = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
	$certs.Import($kvsbytes,$null,[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

	# Get the .pfx file created
	$pfxbytes = $certs.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $password)
	# Export the .pfx file to the Desktop
	$pfxpath = $env:TEMP + "\$certificateName.pfx"
	[System.IO.File]::WriteAllBytes($pfxpath, $pfxbytes)

	Import-PfxCertificate -FilePath ($env:TEMP + "\$certificateName.pfx") -CertStoreLocation Cert:\CurrentUser\My -Password $bla -Exportable
	Remove-Item -Path ($env:TEMP + "\$certificateName.pfx")
}

$summary

# Done