<#
.SYNOPSIS
    Requests the Microsoft.Web RP to retrieve a certificate from Key Vault and deploy it to an Azure Web App.
	It also configures the app setting "WEBSITE_LOAD_CERTIFICATES" (sets to *) to install the certificate on the web site.
.DESCRIPTION
    Both the user and the Microsoft.Web RP must have "get" access to secrets in the vault. Use the following command if you need to grant access to the RP:
    Set-AzureRmKeyVaultAccessPolicy -VaultName $VaultName -ServicePrincipalName abfa0a7c-a6b6-4736-8310-5855508787cd -PermissionsToSecrets get
.PARAMETER Subscription
    Optional. The name of the Azure subscription containing the Key Vault and Web App.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER WebApp
    Required. The name of the Web App site.	
.PARAMETER VaultName
    Required. The name of the Key Vault to retrieve the certificate from.
.PARAMETER KeyVaultCertName
    Required. The name of the certificate to retrieve from Key Vault.
.PARAMETER WebAppCertName
    Optional. The name given to the certificate deployed to the Web App.
    If not specified, this will be the same as the Key Vault certificate name.
.PARAMETER TenantId
    Optional. The GUID of the Azure tenant to use.
    If not specified, the tenant of the current ARM context will be used.
.EXAMPLE
    Add-WebAppCertFromKeyVault -WebApp "MyWebApp" -VaultName "MyKeyVault" -KeyVaultCertName "CertName"
	Retrieves certificate "CertName" from vault "MyKeyVault" and deploys it to Web App "MyWebApp".
    The certificate name in the Web App will be assigned the name "CertName" by default.	
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   January 17, 2017    
.LINK
    https://aka.ms/kvhelper
#>
function Add-WebAppCertFromKeyVault {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",
    [Parameter(Mandatory = $true)]
    [String]$WebApp,
    [Parameter(Mandatory = $true)]
    [String]$VaultName,
    [Parameter(Mandatory = $true)]
    [String]$KeyVaultCertName,
    [Parameter(Mandatory = $false)]
    [String]$WebAppCertName,
    [Parameter(Mandatory = $false)]
    [String]$TenantId	
  )
  
  # check login to AAD
  $rmContext = Login-AzureRm $Subscription
  if (!$rmContext) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }
  
  # if $WebAppCertName not provided, make it the same as $KeyVaultCertName
  if (!$WebAppCertName) {
    $WebAppCertName = $KeyVaultCertName
  }

  # validate vault name
  try {
	$vault = Get-AzureRmKeyVault -VaultName $VaultName -ErrorAction Stop -WarningAction SilentlyContinue
  } catch {
	Write-Error "Vault `"$VaultName`" does not exist in the current RM context. Try adding the -Subscription switch.`n"
	return $null	
  }  
  
<#  
  # verify Key Vault permissions
  $hasPermission = Test-KeyVaultPermissions -Vault $vault -RmContext $rmContext -Action "SecretsRead"
  if (!$hasPermission) {
    if ($hasPermission -eq $false) {
	  Write-Host "Identity $($rmContext.Account.Id) does not have appropriate permissions to vault $VaultName.`n"
	}
    return $null  
  }
#>  
  
  # get tenant ID
  if (!$TenantId) {
    $TenantId = $rmContext.Tenant.TenantId
  }
  
  # get the web site details
  $webAppInfo = Get-AzureRmWebApp -Name $WebApp
  if ($webAppInfo.SiteName -ne $WebApp) {
    Write-Error "Web App `"$WebApp`" not found. Try again with the -Subscription parameter.`n"
    return $null  
  }
  
  # build REST request URI in format:
  # https://management.azure.com/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.Web/certificates/<certName>?api-version=2016-03-01
  $requestUri = "https://management.azure.com/subscriptions/" + $rmContext.Subscription.SubscriptionId
  $requestUri += "/resourceGroups/" + $webAppInfo.ResourceGroup
  $requestUri += "/providers/Microsoft.Web/certificates/" + $WebAppCertName
  $requestUri += "?api-version=2016-03-01"  

  # build request headers
  # call New-AzureRestAuthorizationHeader to get "Authorization" header
  $requestHeaders = New-AzureRestAuthorizationHeader -Resource "https://management.azure.com/" -TenantId $TenantId  
  if (!$requestHeaders) {
	Write-Error "Failed to get Authorization header.`n"
	return $null    
  }
  # add "x-ms-version" header
  $requestHeaders.Add("x-ms-version", "2012-03-01")

  # build request body 	
  $body = @"
{
  "Location": "$($webAppInfo.Location)",
  "Properties": {
    "KeyVaultId": "$($vault.ResourceId)",
    "KeyVaultSecretName": "$($KeyVaultCertName)"
  }
}
"@
  
  # invoke REST call
  Write-Host "Calling Microsoft.Web RP to deploy certificate `"$KeyVaultCertName`" from vault `"$VaultName`" to site `"$WebApp`" as `"$WebAppCertName`"..." -NoNewLine
  try {
    $response = Invoke-RestMethod -Uri $requestUri -Method Put -ContentType "application/json" -Headers $requestHeaders -Body $body
  } catch {
	Write-Error "REST request failed.`n"
	Write-Error $_
	return $null	  
  }
  
  if ($response.properties.thumbprint) {
	  Write-Host "Done.`n"
	  Write-Host "Secret name:`t $($response.name)"
	  Write-Host "Subject name:`t $($response.properties.subjectName)"
	  Write-Host "Issuer name:`t $($response.properties.issuer)"
	  Write-Host "Expires:`t $($response.properties.expirationDate)"
	  Write-Host "Thumbprint:`t $($response.properties.thumbprint)`n"
  } else {
    Write-Host $response
	return $null
  }
  
  # retrieve Web App setting WEBSITE_LOAD_CERTIFICATES
  foreach ($setting in ($webAppInfo.SiteConfig.AppSettings | where {$_.Name -eq "WEBSITE_LOAD_CERTIFICATES"})) {  
    $appSetting = $setting
	break
  }  
  
  # return if setting WEBSITE_LOAD_CERTIFICATES is already set to *
  if ($appSetting.Value -eq "*") {
	Write-Host "App setting WEBSITE_LOAD_CERTIFICATES is already set to *`n"
	return $webAppInfo
  }
  
  # if setting doesn't exist or is blank, set it to * - otherwise append new thumbprint
  if ((!$appSetting) -or ($appSetting.Value -eq "")) {
	Write-Host "Setting WEBSITE_LOAD_CERTIFICATES to *`n"
	$newValue = "*"
	
  } else {		# append new thumbprint
  
    if ($appSetting.Value.ToUpper().Contains($response.properties.thumbprint.ToUpper())) {
	  $newValue = $appSetting.Value
	  Write-Host "Setting WEBSITE_LOAD_CERTIFICATES to $newValue`n"
	} else {
	  $newValue = $appSetting.Value + ", " + $response.properties.thumbprint
	  Write-Host "Setting WEBSITE_LOAD_CERTIFICATES to $newValue`n"
	}  
  }
  
  # build hash table of app settings
  $ht = @{}
  foreach ($appSetting in $webAppInfo.SiteConfig.AppSettings) {
    $ht[$appSetting.Name] = $appSetting.Value  
  }
  
  # add/update the thumbprint
  $ht['WEBSITE_LOAD_CERTIFICATES'] = $newValue
  
  # update the app settings
  Write-Host "Updating Web App setting WEBSITE_LOAD_CERTIFICATES..." -NoNewLine
  try {
    $webAppInfo = Set-AzureRMWebApp -ResourceGroupName $webAppInfo.ResourceGroup -Name $WebApp -AppSettings $ht -ErrorAction Stop
  } catch {
    Write-Error "Failed to update AppSettings.`n"
	return $null
  }
  Write-Host "Done.`n"

  return $webAppInfo
  
}
