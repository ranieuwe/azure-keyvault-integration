
# Date:   		January 31, 2017
# questions:	nicktork@microsoft.com

# recommend upgrade to PowerShell 5 if not already installed
if ($PSVersionTable.PSVersion.Major -lt 5) {
  Write-Host "`nPowerShell version $($PSVersionTable.PSVersion.Major) is installed." -ForegroundColor Yellow
  Write-Host "`nThe KeyVaultHelper2 module has only been tested with PowerShell 5." -ForegroundColor Yellow
  Write-Host "While much of it will work with your version, it may not be fully compatible." -ForegroundColor Yellow
  Write-Host "`nTo upgrade to PowerShell 5, install Windows Management Framework 5.0 from:" -ForegroundColor Yellow
  Write-Host "https://www.microsoft.com/en-us/download/details.aspx?id=50395`n" -ForegroundColor Yellow
}

# check that Azure PowerShell 2.1.0 or later is installed
$minVersion = New-Object Version(2, 1, 0)
Import-Module AzureRM.Profile
$azPsVersion = (Get-Module AzureRM.Profile).Version
if ($azPsVersion -lt $minVersion) {
  Write-Host "`nAzure PowerShell 2.1.0 or later is required by this module.`n" -ForegroundColor Yellow
  if ($PSVersionTable.PSVersion.Major -ge 5) {
    Write-Host "Open an elevated PowerShell console and run the following commands:"
    Write-Host "    Install-Module AzureRM"
    Write-Host "    Install-Module Azure`n"
    Write-Host "Alternatively, " -NoNewLine
  }
  Write-Host "follow instructions from `nhttps://azure.microsoft.com/en-us/documentation/articles/powershell-install-configure/`n"
  Write-Host "After upgrading, open a new PowerShell console and perform the import again.`n" -ForegroundColor Yellow
}

# need to manually import AzureRM.KeyVault module to use its data types before a KeyVault cmdlet is called  
Import-Module AzureRM.KeyVault -Global

<#
.SYNOPSIS
    Creates or imports a certificate to Key Vault using the new certificate type (instead of the generic secret type).
.DESCRIPTION
	Request a self-signed certificate to be created by Key Vault, or have Key Vault request a cert from SSLAdmin on the user's behalf.
	In either case, the private key is never exposed to the user. The cmdlet can also be used to import an existing PFX file or X509 object into Key Vault.
	This cmdlet uses the new certificate type (in preview) rather than storing the certificate as a generic, base64-encoded secret.
	The cmdlet returns a reference to the certificate in Key Vault.
.PARAMETER Subscription
    Optional. The name of the Azure subscription containing the Key Vault.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER VaultName
    Required. The name of the Azure Key Vault to add/update a certificate to.
.PARAMETER CertName
    Required. The name of the certificate object to store in Key Vault.
.PARAMETER CertObject
    An X509Certificate2 object can be specified or received on the pipeline for storing to Key Vault.
    This is used primarily to migrate certificates from the old secret type to the new, native certificate type (see example for details).
.PARAMETER PfxPath
    The path to the PFX file to import to Key Vault.
.PARAMETER PfxPassword
    The password for the PFX file.
.PARAMETER SubjectName
    The subject name of the self-signed or SSLAdmin certificate to be created.
.PARAMETER ValidityInMonths
    The validity period (in months) for self-signed certificates (defaults to 12 months).
.PARAMETER IssuerName
    The issuer name to be used for certificates created by SSLAdmin. If a certificate policy is passed as input, the Issuer from that policy will be used.
.PARAMETER Policy
    For more detailed certificate policy definition, use New-AzureKeyVaultCertificatePolicy to create a policy object and pass that as a parameter (or via the pipeline).
	When used, -SubjectName, -IssuerName and -ValidityInMonths parameters will be ignored.
.PARAMETER Timeout
    The time in seconds to wait for Key Vault to complete a -SelfSigned or -SslAdmin request.
    Defaults to 60 seconds.	
.PARAMETER SelfSigned
    Request Key Vault to create a self-signed certificate.
.PARAMETER SslAdmin
    Have Key Vault request a certificate from SSLAdmin.
.EXAMPLE
    $mySslAdminCert = Set-KeyVaultCertificate -SslAdmin -VaultName "myKeyVault" -CertName "myCert" -SubjectName "www.contoso.com" -IssuerName "myIssuer"
    Requests certificate CN=www.contoso.com from SSLAdmin and stores it in "myKeyVault" as "myCert".
	If the issuer has already been created in this Key Vault it will be used (otherwise a new issuer will be created).
	The private key is never exposed to the requesting user.
.EXAMPLE
    $mySelfSignedCert = Set-KeyVaultCertificate -SelfSigned -VaultName "myKeyVault" -CertName "myCert" -SubjectName "www.contoso.com"
    Requests Key Vault to create self-signed certificate CN=www.contoso.com and store it in "myKeyVault" as "myCert".
	The default validity of 12 months is used unless overridden with -ValidityInMonths.
	The private key is never exposed to the requesting user.
.EXAMPLE
    $myCert = Set-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myCert" -PfxPath .\MyPfx.pfx -PfxPassword "myPfxPassword"
    Imports the PFX file into "myKeyVault" as "myCert".
.EXAMPLE
    Get-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myOldCert" -PrivateKey -SecretPassword 'if_required'  |  Set-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myNewCert"
    Migrate a cert stored in the old secret format to a new cert in the native cert format.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   October 1, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Set-KeyVaultCertificate {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",
    [Parameter(Mandatory = $true, Position = 0)]
    [String]$VaultName,
    [Parameter(Mandatory = $true, Position = 1)]
    [String]$CertName,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "ImportObject")]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertObject,	
    [Parameter(Mandatory = $true, Position = 2, ParameterSetName = "ImportPfx")]
    [String]$PfxPath,	
    [Parameter(Mandatory = $true, Position = 3, ParameterSetName = "ImportPfx")]
    [String]$PfxPassword,
    [Parameter(Mandatory = $false, ParameterSetName = "SelfSigned")]
	[Parameter(ParameterSetName = "SslAdmin")]
    [String]$SubjectName,
    [Parameter(Mandatory = $false, ParameterSetName = "SelfSigned")]
    [String]$ValidityInMonths = "12",
    [Parameter(Mandatory = $false, ParameterSetName = "SslAdmin")]
    [String]$IssuerName,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "SelfSigned")]
	[Parameter(ParameterSetName = "SslAdmin")]
    [Microsoft.Azure.Commands.KeyVault.Models.KeyVaultCertificatePolicy]$Policy,	
    [Parameter(Mandatory = $false, ParameterSetName = "SelfSigned")]
	[Parameter(ParameterSetName = "SslAdmin")]
    [Int]$Timeout = 60,
	[Parameter(Mandatory = $true, ParameterSetName = "SelfSigned")]
    [Switch]$SelfSigned,
	[Parameter(Mandatory = $true, ParameterSetName = "SslAdmin")]
    [Switch]$SslAdmin
  )
  
  # check login to AAD
  $rmContext = Login-AzureRm $Subscription
  if (!$rmContext) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }

  # validate vault name
  try {
	$vault = Get-AzureRmKeyVault -VaultName $VaultName -ErrorAction Stop -WarningAction SilentlyContinue
  } catch {
	Write-Error "Vault `"$VaultName`" does not exist in the current RM context. Try adding the -Subscription switch.`n"
	return $null	
  }
  
  # verify Key Vault permissions
  if ($CertObject -or $PfxPath) {  
    $hasPermission = Test-KeyVaultPermissions -Vault $vault -RmContext $rmContext -Action "CertsImport"
  }
  if ($SelfSigned -or $SslAdmin) {  
    $hasPermission = Test-KeyVaultPermissions -Vault $vault -RmContext $rmContext -Action "CertsAll"
  }  
<#
  if (!$hasPermission) {
    if ($hasPermission -eq $false) {
	  Write-Host "Identity $($rmContext.Account.Id) does not have appropriate permissions to vault $VaultName.`n"
	}
    return $null  
  }
#>  
  
  # validate PFX file path
  if ($PfxPath) {
    if (!(Test-Path $PfxPath)) {
      Write-Error "PFX path `"$PfxPath`" is invalid.`n"
	  return $null
    }
  }
  
  # validate subject name
  if ($SubjectName) {
    if (!($SubjectName.StartsWith("CN=", $true, $null))) {
	  $SubjectName = "CN=" + $SubjectName
	}
  }
  
  # validate -SubjectName is provided if not supplied via -Policy
  if ($SelfSigned -or $SslAdmin) {
    if (!$Policy) {
	  if (!$SubjectName) {
        Write-Error "-SubjectName must be provided if -Policy is not used.`n"
	    return $null	    
	  }
	}  
  }
  
  # validate -IssuerName is provided if not supplied via -Policy
  if ($SslAdmin) {
    if (!$Policy) {
	  if (!$IssuerName) {
        Write-Error "-IssuerName must be provided if -Policy is not used.`n"
	    return $null	    
	  }
	}  
  }
  
  # validate that IssuerName = "Self" if policy is passed as input and -SelfSigned is specified
  if ($SelfSigned -and $Policy) {
	if ($Policy.IssuerName -ne "Self") {
      Write-Error "IssuerName in input policy must be "Self" if -SelfSigned is specified.`n"
	  return $null	    
	}	
  }

  # import cert from X509Certificate2 object ##############################################################################################
  if ($CertObject) {  
  
    Write-Host "Importing cert with subject `"$($CertObject.Subject)`" into `"$VaultName`" as `"$CertName`"... " -NoNewLine    
	try {
	  $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection($CertObject)
	  Import-AzureKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificateCollection $certCollection -ErrorAction Stop
	} catch {
	  Write-Error "Failed to import cert with subject `"$($CertObject.Subject)`" into `"$VaultName`" as `"$CertName`".`n"
	  return $null
	}
	Write-Host "Done.`n"  
  }  
  
  # Import PFX file ######################################################################################################################
  if ($PfxPath) {    
    Write-Host "Importing `"$PfxPath`" into `"$VaultName`" as `"$CertName`"... " -NoNewLine
	try {
	  Import-AzureKeyVaultCertificate -VaultName $VaultName -Name $CertName -FilePath $PfxPath -Password $(ConvertTo-SecureString –String $PfxPassword –AsPlainText –Force) -ErrorAction Stop
	} catch {
	  Write-Error "Failed to import `"$PfxPath`" into `"$VaultName`" as `"$CertName`".`n"
	  return $null
	}
	Write-Host "Done.`n"
  }
  
  # Create self signed cert ##############################################################################################################
  if ($SelfSigned) {
  
    # create certificate policy with Issuer = Self
	if (!$Policy) {
	  try {
        $Policy = New-AzureKeyVaultCertificatePolicy -SubjectName $SubjectName -IssuerName Self -ValidityInMonths $ValidityInMonths -ErrorAction Stop
	  } catch {
	    Write-Error "Failed to create self-signed certificate policy for subject name `"$SubjectName`".`n"
	    return $null
	  }
	}
	
	# create self-signed certificate
	try {
	  Add-AzureKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificatePolicy $Policy -ErrorAction Stop > $null
	} catch {
	  Write-Error "Failed to request self-signed certificate `"$CertName`" in vault `"$VaultName`".`n"
	  return $null
	}
	Write-Host "Creating self-signed certificate:"
    Write-Host "   Name:`t`t $CertName"
	Write-Host "   Subject:`t`t $($Policy.SubjectName)"
	Write-Host "   Validity:`t`t $($Policy.ValidityInMonths) months"
	Write-Host "   Vault:`t`t $VaultName`n"

    # Check for completion (timeout after 60 seconds)
    Check-CertCompletion $VaultName $CertName $Timeout
	
  }
  
  # Request cert from SSLAdmin #########################################################################################################
  if ($SslAdmin) {

    # retrieve list of Issuers in $VaultName
	try {
	  $issuers = Get-AzureKeyVaultCertificateIssuer -VaultName $VaultName -ErrorAction Stop
	} catch {
	  Write-Error "Failed to retrieve certificate Issuers.`n"
	  return $null
	}
	
	# check to see if $IssuerName exists
	$issuerExists = $false
	foreach ($issuer in $issuers) {
	  if ($Policy) {
	    if (($issuer.Name -eq $Policy.IssuerName) -and ($issuer.IssuerProvider -eq "SslAdmin")) {
	      Write-Host "Issuer `"$Policy.IssuerName`" already exists in vault `"$VaultName`".`n"
		  $issuerExists = $true
		  break
	    }
	  } else {
	    if (($issuer.Name -eq $IssuerName) -and ($issuer.IssuerProvider -eq "SslAdmin")) {
	      Write-Host "Issuer `"$IssuerName`" already exists in vault `"$VaultName`".`n"
		  $issuerExists = $true
		  break
	    }
	  }
	}
	
	# if Issuer does not exist, create it
	if (!$issuerExists) {
	  if ($Policy) {
	    Write-Host "Creating certificate Issuer `"$Policy.IssuerName`" of type `"SslAdmin`" in vault `"$VaultName`"... " -NoNewLine
	    try {
		  Set-AzureKeyVaultCertificateIssuer -VaultName $VaultName -IssuerProvider "SslAdmin" -Name $Policy.IssuerName -ErrorAction Stop
	    } catch {
	      Write-Error "SSLAdmin issuer `"$Policy.IssuerName`" could not be created in vault `"$VaultName`".`n"
		  return $null
	    }
	  } else {
	    Write-Host "Creating certificate Issuer `"$IssuerName`" of type `"SslAdmin`" in vault `"$VaultName`"... " -NoNewLine
	    try {
		  Set-AzureKeyVaultCertificateIssuer -VaultName $VaultName -IssuerProvider "SslAdmin" -Name $IssuerName -ErrorAction Stop
	    } catch {
	      Write-Error "SSLAdmin issuer `"$IssuerName`" could not be created in vault `"$VaultName`".`n"
		  return $null
	    }	  
	  }
	  Write-Host "Done.`n"
	}
	
	# Create the certificate policy that defines the certificate details and the issuer
	if (!$Policy) {
	  try {
        $Policy = New-AzureKeyVaultCertificatePolicy -SubjectName $SubjectName -IssuerName $IssuerName -ErrorAction Stop
	  } catch {
	    Write-Error "Failed to create certificate policy for subject name `"$SubjectName`" with issuer name `"$IssuerName`".`n"
	    return $null
	  }
	}
	
	# Request the certificate
	Write-Host "Requesting certificate from SSLAdmin:"
    Write-Host "   Name:`t $CertName"
	Write-Host "   Issuer:`t $($Policy.IssuerName)"
	Write-Host "   Subject:`t $($Policy.SubjectName)"
	Write-Host "   Vault:`t $VaultName`n"
	try {
	  Add-AzureKeyVaultCertificate -VaultName $VaultName -Name $CertName -CertificatePolicy $Policy -ErrorAction Stop | Out-Null
	} catch {
	  Write-Error "Failed to request SSLAdmin certificate `"$CertName`" for vault `"$VaultName`".`n"
	  return $null
	}
	
	# Check for completion
    Check-CertCompletion $VaultName $CertName $Timeout
  }
}

<#
.SYNOPSIS
    Creates or updates a secret in Key Vault with a string (or secure string).
.DESCRIPTION
	Creates or updates a secret in Key Vault.
	Pass a string or secure string as a variable or pipeline input.
	By default, strings will be unescaped (this can be disabled with -NoUnescape).
	The cmdlet returns a reference to the secret in Key Vault.
.PARAMETER Subscription
    Optional. The name of the Azure subscription containing the Key Vault.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER VaultName
    Required. The name of the Azure Key Vault to add/update a secret to.
.PARAMETER SecretName
    Required. The name of the secret object to store in Key Vault.
.PARAMETER SecretString
    The string to store as "SecretName".
	This may be passed as a variable or received from the pipeline.
.PARAMETER SecretSecureString
    Use instead of -SecretString to store a secret held in a SecureString object.
	This may be passed as a variable or received from the pipeline.	
.PARAMETER NoUnescape
    By default, the cmdlet will unescape XML escape characters that may exist in the secrets in your config files.
	Use this switch to disable this behavior.
.EXAMPLE
    $mySecret = $mySecretString | Set-KeyVaultSecret -VaultName "myKeyVault" -SecretName "mySecret"
    Writes the string value from $mySecretString to secret "mySecret" in vault "myKeyVault".
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   August 19, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Set-KeyVaultSecret {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",
    [Parameter(Mandatory = $true, Position = 0)]
    [String]$VaultName,
    [Parameter(Mandatory = $true, Position = 1)]
    [String]$SecretName,
    [Parameter(Mandatory = $true, Position = 2, ValueFromPipeline = $true, ParameterSetName = "String")]
    [String]$SecretString,
    [Parameter(Mandatory = $true, Position = 2, ValueFromPipeline = $true, ParameterSetName = "SecureString")]
    [System.Security.SecureString]$SecretSecureString,
	[Parameter(Mandatory = $false)]
    [Switch]$NoUnescape
	
  )
  
  # check login to AAD
  $rmContext = Login-AzureRm $Subscription
  if (!$rmContext) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
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
  $hasPermission = Test-KeyVaultPermissions -Vault $vault -RmContext $rmContext -Action "SecretsWrite"
  if (!$hasPermission) {
    if ($hasPermission -eq $false) {
	  Write-Host "Identity $($rmContext.Account.Id) does not have appropriate permissions to vault $VaultName.`n"
	}
    return $null  
  }
#>  
  
  # unescape string
  if ($SecretString -and (!$NoUnescape)) {
    Add-Type -AssemblyName System.Web
	$SecretString = [System.Web.HttpUtility]::HtmlDecode($SecretString)  
  }
  
  # convert to secure string
  if ($SecretString) {		# string
    Write-Host "Writing string into `"$VaultName`" as `"$SecretName`"... " -NoNewLine
	$SecretSecureString = $SecretString | ConvertTo-SecureString -AsPlainText -Force
  } else {					# secure string
    Write-Host "Writing secure string into `"$VaultName`" as `"$SecretName`"... " -NoNewLine
  }

  # upload to secret  
  try {
    $secret = Set-AzureKeyVaultSecret -VaultName $VaultName -Name $SecretName -SecretValue $SecretSecureString -ErrorAction Stop
  } catch {
    Write-Error "`nFailed to write `"$SecretName`" to `"$VaultName`".`n"
	return $null    
  }
  Write-Host "Done.`n"
  
  # return reference to secret
  return $secret

}

<#
.SYNOPSIS
    Retrieves certificate (with or without private key) from Key Vault for immediate use, installation in user/computer certificate store, or upload to Azure.
	It can also be used to retrieve certificates (with private keys) that have been stored as Base64-encoded secrets, however this only works with options that use the "secrets" namespace (-CertStore, -ServiceName, -PfxPath and -PrivateKey).
	If a password was used to encrypt the Base64-encoded string, it must be supplied to the -SecretPassword parameter.
.DESCRIPTION
    Retrieves certificate (with or without private key) from Key Vault as X509Certificate2 object for:
      - immediate use by any process that can use an X509Certificate2 object (e.g. authentication, adding a thumbprint to a whitelist etc.)​
	  - installation into the user/computer certificate store (the latter requiring an elevated PowerShell session).
	  - upload to an Azure Cloud Service.
	  - saved as a PFX file (with user-specifed or random password which is returned to the user on the clipboard and function return value).
	  - saved as a .cer file (which does not contain the private key).
.PARAMETER Subscription
    Optional. The name of the Azure subscription containing the Key Vault.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER VaultName
    Required. The name of the Azure Key Vault to retrieve the certificate from.
.PARAMETER CertName
    Required. The name of the certificate object to retrieve.
.PARAMETER CertVersion
    Optional. The certificate version to retrieve.	
.PARAMETER CerPath
    Optional. When specified, the public portion of the certificate is retrieved and saved to the .cer file specified.
.PARAMETER CertStore
    Optional. When specified, the certificate (and private key) is installed into the "CurrentUser" or "LocalMachine" store.
.PARAMETER ServiceName
    Optional. If specified, the certificate (and private key) will be uploaded to the certificate store of this Azure Cloud Service.
	This operation is performed against the Service Management API (instead of ARM), so the user will be prompted for another logon.
.PARAMETER ServiceSubscription
    Optional. If the Cloud Service is in a different subscription from the Key Vault, specify the name of that subscription.
    If the Key Vault and Cloud Service are in the same subscription, this parameter can be omitted.	
.PARAMETER PfxPath
    Optional. When specified, the certificate (and private key) is retrieved and saved to the .pfx file specified.
.PARAMETER PfxPassword
    Optional. The password to encrypt the PFX file with. If not specified, a random password is created, and returned to the user on the clipboard and function return value.
.PARAMETER PfxPasswordLength
    Optional. The length of the random PFX password to be created (defaults to 32 chars).
.PARAMETER PfxPasswordChars
    Optional. The number of non-alphanumeric characters to be used to create the random PFX password (defaults to 4 chars).
.PARAMETER SecretPassword
    This is only required if:
	- the certificate being retrieved was saved in the old Base64-encoded format, AND
	- it was encrypted with a password.
	If so, specify the password to decrypt the Base64-encoded string.
.PARAMETER PrivateKey
    Optional. This allows the certificate (and private key) to be returned as a X509Certificate2 object, without having to perform any other operation (e.g. save as PFX, import to store).
	Without this switch, an X509Certificate2 object is returned, but without the private key.
.EXAMPLE
    $cert = Get-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myCert"
    Retrieves certificate "myCert" (without private key) from "myKeyVault" as an X509Certificate2 object.
.EXAMPLE
    $cert = Get-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myCert" -PrivateKey
    Retrieves certificate "myCert" (with private key) from "myKeyVault" as an X509Certificate2 object.
.EXAMPLE
    $cert = Get-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myCert" -CertStore CurrentUser
    Retrieves certificate "myCert" from "myKeyVault" as an X509Certificate2 object, and stores it in the CurrentUser store.
	Note that you must be running an elevated PowerShell console to install a cert into the LocalMachine store.
.EXAMPLE
    $cert = Get-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myCert" -CerPath myCerFile.cer
    Retrieves certificate "myCert" (without private key) from "myKeyVault" as an X509Certificate2 object, and writes to "myCerFile.cer" in the current directory.
	Specify a full path to save to an alternate location.
.EXAMPLE
    $cert = Get-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myCert" -PfxPath myPfxFile.pfx
    Retrieves certificate "myCert" (with private key) from "myKeyVault" as an X509Certificate2 object, and writes to "myPfxFile.pfx" in the current directory.
	Specify a full path to save to an alternate location.
	Without specifying any other Pfx* parameters, the file will be encrypted with a random 32 char password with 4 non-alphanumeric chars. 
	The password (random or user-specified) will be returned as $cert[1] and is also copied to the clipboard. ($cert[0] is the X509Certificate2 object).
.EXAMPLE
    $cert = Get-KeyVaultCertificate -VaultName "myKeyVault" -CertName "myCert" -ServiceName "myCloudService"
    Retrieves certificate "myCert" (with private key) from "myKeyVault" as an X509Certificate2 object, and uploads it to the certificate store of "myCloudService".
	If the cloud service is in a different subscription from the Key Vault, specify it with -ServiceSubscription.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   August 29, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Get-KeyVaultCertificate {
    
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false, ParameterSetName = "Public")]
	[Parameter(ParameterSetName = "WriteCer")]
	[Parameter(ParameterSetName = "WriteStore")]
	[Parameter(ParameterSetName = "WriteCloudSvc")]
	[Parameter(ParameterSetName = "WritePfx")]
	[Parameter(ParameterSetName = "PrivateKey")]
    [String]$Subscription = "first",  
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Public")]
	[Parameter(ParameterSetName = "WriteCer")]
	[Parameter(ParameterSetName = "WriteStore")]
	[Parameter(ParameterSetName = "WriteCloudSvc")]
	[Parameter(ParameterSetName = "WritePfx")]
	[Parameter(ParameterSetName = "PrivateKey")]	
    [String]$VaultName,
    [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "Public")]
	[Parameter(ParameterSetName = "WriteCer")]
	[Parameter(ParameterSetName = "WriteStore")]
	[Parameter(ParameterSetName = "WriteCloudSvc")]
	[Parameter(ParameterSetName = "WritePfx")]
	[Parameter(ParameterSetName = "PrivateKey")]	
    [String]$CertName,
    [Parameter(Mandatory = $false, ParameterSetName = "Public")]
	[Parameter(ParameterSetName = "WriteCer")]
	[Parameter(ParameterSetName = "WriteStore")]
	[Parameter(ParameterSetName = "WriteCloudSvc")]
	[Parameter(ParameterSetName = "WritePfx")]
	[Parameter(ParameterSetName = "PrivateKey")]	
    [String]$CertVersion,	
    [Parameter(Mandatory = $true, ParameterSetName = "WriteCer")]
    [String]$CerPath,	
	[Parameter(Mandatory = $true, ParameterSetName = "WriteStore")]
	[ValidateSet("CurrentUser","LocalMachine")]
    [string]$CertStore,
	[Parameter(Mandatory = $true, ParameterSetName = "WriteCloudSvc")]
    [string]$ServiceName,
	[Parameter(Mandatory = $false, ParameterSetName = "WriteCloudSvc")]
    [string]$ServiceSubscription,	
    [Parameter(Mandatory = $true, ParameterSetName = "WritePfx")]
    [String]$PfxPath,
    [Parameter(Mandatory = $false, ParameterSetName = "WritePfx")]
    [String]$PfxPassword,
    [Parameter(Mandatory = $false, ParameterSetName = "WritePfx")]
    [Int]$PfxPasswordLength = 32,
    [Parameter(Mandatory = $false, ParameterSetName = "WritePfx")]
    [Int]$PfxPasswordChars = 4,
    [Parameter(Mandatory = $false, ParameterSetName = "WriteStore")]
	[Parameter(ParameterSetName = "WriteCloudSvc")]
	[Parameter(ParameterSetName = "WritePfx")]
	[Parameter(ParameterSetName = "PrivateKey")]	
    [String]$SecretPassword,	
	[Parameter(Mandatory = $true, ParameterSetName = "PrivateKey")]
    [Switch]$PrivateKey
  )

  # check login to AAD
  $rmContext = Login-AzureRm $Subscription
  if (!$rmContext) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }
  
  # validate vault name
  try {
	$vault = Get-AzureRmKeyVault -VaultName $VaultName -ErrorAction Stop -WarningAction SilentlyContinue
  } catch {
	Write-Error "Vault `"$VaultName`" does not exist in the current RM context. Try adding the -Subscription switch.`n"
	return $null	
  }
  
  # OPERATIONS NOT REQUIRING PRIVATE KEY ###################################################################
  if ((!$CertStore) -and (!$ServiceName) -and (!$PfxPath) -and (!$PrivateKey)) {
  
<#  
  # verify Key Vault permissions
  $hasPermission = Test-KeyVaultPermissions -Vault $vault -RmContext $rmContext -Action "CertsRead"
  if (!$hasPermission) {
    if ($hasPermission -eq $false) {
	  Write-Host "Identity $($rmContext.Account.Id) does not have appropriate permissions to vault $VaultName.`n"
	}
    return $null  
  }
#>  
  
    # validate $CerPath (if specified)
	if ($CerPath) {
	  $filePath = Get-Path $CerPath
	  if (!$filePath) {
	    Write-Error "Path `"$CerPath`" is not valid.`n"
		return $null
	  }
	}
  
    # retrieve public portion of certificate from Key Vault certificates endpoint
	Write-Host "`nRetrieving certificate `"$CertName`" (without private key) from vault `"$VaultName`".`n"
    try {
      if ($CertVersion) {
	    $cert = Get-AzureKeyVaultCertificate -VaultName $VaultName -Name $CertName -Version $CertVersion -ErrorAction Stop
	  } else {
	    $cert = Get-AzureKeyVaultCertificate -VaultName $VaultName -Name $CertName -ErrorAction Stop
	  }
    } catch {
	  Write-Error "Failed to retrieve certificate `"$CertName`" from vault `"$VaultName`".`n"
	  return $null
	}

	# Get-AzureKeyVaultCertificate of a certificate created as a generic secret succeeds, but the "Certificate" property is null
    if (!($cert.Certificate)) {
	  Write-Host "Certificate `"$CertName`" cannot be retrieved. It may have been created as a generic secret type (rather than a KV Certificate type)." -ForegroundColor Yellow
	  Write-Host "Retry adding the -PrivateKey switch, and -SecretPassword <the_password> if one was used to encrypt it.`n" -ForegroundColor Yellow
	  return $null
	}
	
	# write to .cer file
    if ($CerPath) {	
	
      Write-Host "Saving certificate `"$CertName`" to .cer file"	  
  	  $certBytes = $cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
      try {
	    [System.IO.File]::WriteAllBytes($filePath, $certBytes)
	  } catch {
	    Write-Error "Unable to write `"$CertName`" to .cer file `"$filePath`".`n"
		return $null
	  }

	  Write-Host "Certificate `"$CertName`" written to `"$filePath`".`n"
    }
  
	return $cert.Certificate
  
  }
  
  # OPERATIONS REQUIRING PRIVATE KEY #######################################################################
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
  
  # validate $PfxPath (if specified)
	if ($PfxPath) {
	  $filePath = Get-Path $PfxPath
	  if (!$filePath) {
	    Write-Error "Path `"$PfxPath`" is not valid.`n"
		return $null
	  }
	}
	
  # if $ServiceName specified, login to SM API and validate $ServiceName
  if ($ServiceName) {
  
    # if $ServiceSubscription is not specified, set it to current RM context
	if (!$ServiceSubscription) {
	  $ServiceSubscription = (Get-AzureRmContext).Subscription.SubscriptionName
	}
	
	# login to Azure SM API and set $ServiceSubscription as active
	$serviceSub = Login-AzureSm $ServiceSubscription
	if (!$serviceSub) {
	  return $null
	}
	
	# validate $ServiceName
	try {
	  $cloudService = Get-AzureService -ServiceName $ServiceName -ErrorAction Stop
	} catch {
	  Write-Error "Cloud service `"$ServiceName`" does not exist in current subscription. Try adding the -ServiceSubscription switch.`n"
	  return $null
	}  
  }  
  
  # Retrieve certificate and private key from Key Vault secrets endpoint as byte array
  Write-Host "Retrieving certificate `"$CertName`" (with private key) from vault `"$VaultName`".`n"
  try {
    if ($CertVersion) {
	  $kvSecret = Get-AzureKeyVaultSecret -VaultName $VaultName -Name $CertName -Version $CertVersion -ErrorAction Stop
	} else {
	  $kvSecret = Get-AzureKeyVaultSecret -VaultName $VaultName -Name $CertName -ErrorAction Stop
	}
  } catch {
    Write-Error "Failed to retrieve certificate `"$CertName`" from vault `"$VaultName`".`n"
	return $null
  }
  $kvSecretBytes = [System.Convert]::FromBase64String($kvSecret.SecretValueText)
  
  # if -PrivateKey switch specifed, return as a X509Certificate2 object #########################
  if ($PrivateKey) {
  
    # Create X509Certificate2 object and import $kvSecretBytes
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    #$cert.Import($kvSecretBytes, $SecretPassword, "PersistKeySet")
	$cert.Import($kvSecretBytes, $SecretPassword, "Exportable")
	return $cert  
  }  
  
  # install the certificate into a local store ##################################################
  if ($CertStore) {
  
    # if installing in "LocalMachine", check that PowerShell session is elevated
	if ($CertStore -eq "LocalMachine") {
	
	  if (!(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
	    Write-Error "You need to be running an elevated PowerShell session to install a certificate in the local machine store.`n"
		return $null
	  }
	}
	
    # Create X509Certificate2 object and import $kvSecretBytes
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($kvSecretBytes, $SecretPassword, "PersistKeySet")
	
    Write-Host "Installing certificate `"$CertName`" into `"$CertStore`" store... " -NoNewLine
	$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", $CertStore)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($cert)
    $store.Close()
	Write-Host "Done.`n"
	return $cert
  }
  
  # install the certificate into an Azure Cloud Service certificate store #######################
  if ($ServiceName) {
  
    # Create X509Certificate2 object and import $kvSecretBytes
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($kvSecretBytes, $SecretPassword, "Exportable")
	
	try {
	  Add-AzureCertificate -ServiceName $ServiceName -CertToDeploy $cert -ErrorAction Stop | Out-Null
	} catch {
	  Write-Error "Failed to upload `"$CertName`" to cloud service `"$ServiceName`".`n"
	  return $null
	}
	Write-Host "Certificate `"$CertName`" uploaded to cloud service `"$ServiceName`".`n"
	return $cert
  }
  
  # save the certificate as a PFX file ##########################################################
  if ($PfxPath) {
    Write-Host "Saving certificate `"$CertName`" to PFX file."
    $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $certCollection.Import($kvSecretBytes, $SecretPassword, "Exportable")

    # Generate random password for PFX if not supplied
	if (!$PfxPassword) {
	  $PfxPassword = New-Password $PfxPasswordLength $PfxPasswordChars
	}

    $protectedCertificateBytes = $certCollection.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $PfxPassword)
    try {
	  [System.IO.File]::WriteAllBytes($filePath, $protectedCertificateBytes)
	} catch {
	  Write-Error "Unable to write `"$CertName`" to PFX file `"$filePath`".`n"
	  return $null
	}
	Write-Host "`nCertificate `"$CertName`" written to:"
	Write-Host $filePath
	Write-Host "`nPFX password is copied to clipboard and function return value.`n"
	Set-Clipboard $PfxPassword
	return $certCollection[0], $PfxPassword
  }
	
}

<#
.SYNOPSIS
    Creates an Azure AD application, and optionally registers a certificate against its service principal.
	If the application already exists, the certificate is added as a credential to the service principal.
.DESCRIPTION
    Creates an Azure AD application. If a certificate is passed (via parameter or the pipeline), a service principal is created and the certificate registered as a credential.
	If no certificate is provided, only the AD application (and not the service principal) will be created.
	If the application already exists, the certificate is added as a credential to the service principal.
	Returns an object with the:
	- AppDisplayName
	- AppIdentifierUri
    - ApplicationId
	- AppObjectId
	- ServicePrincipalObjectId (if certificate passed)
    - CertSubject (if certificate passed)
    - CertThumbprint (if certificate passed)
.PARAMETER Subscription
    Optional. The name of the Azure subscription to set as the current ARM context.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER Cert
    An X509Certificate2 object (without the private key) that will be registered against the application's service principal.
	This may be passed as a variable or received from the pipeline.
.PARAMETER AppName
    The display name to be assigned to the application.
.PARAMETER AppUri
    The identifier URI of the application (this does not need to be resolvable).
	If not specified, http://<AppName> will be used.
.EXAMPLE
    $sp = New-ServicePrincipal -AppName "myApp" -Cert $cert
	Creates Azure AD application "myApp" with Identifier URI http://myApp and registers a certificate (obtained by Get-KeyVaultCertificate) against its service principal.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   October 6, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function New-ServicePrincipal {

  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
    [Parameter(Mandatory = $true)]
	[ValidateLength(3, 63)]
	#[ValidatePattern("^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$")]	
    [String]$AppName,
    [Parameter(Mandatory = $false)]
	[ValidateLength(3, 63)]
	#[ValidatePattern("^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$")]
    [String]$AppUri,
    [Parameter(Mandatory = $false)]
    [Switch]$SuppressConsoleMessages	
  )
  
  # check login to AAD
  if ($SuppressConsoleMessages) {
    $loginResult = Login-AzureRm $Subscription -SuppressConsoleMessages
  } else {
    $loginResult = Login-AzureRm $Subscription
  }
  if (!$loginResult) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }
  
  # set $AppUri to http://<AppName> if not specified
  if (!$AppUri) {
    $AppUri = "http://" + $AppName
  }
  
  # create return object
  $obj = New-Object System.Object  
  
  # create Azure AD application if it doesn't exist
  $adApp = Get-AzureRmADApplication -IdentifierUri $AppUri
  if ($adApp) {
    if (!$SuppressConsoleMessages) {
	  Write-Host "Azure AD application with identifier URI `"$AppUri`" already exists."
	  Write-Host "ApplicationID:   $($adApp.ApplicationId)`n"
	}
  } else {
    Write-Host "Creating application `"$AppName`" ... " -NoNewLine
	try {
      $adApp = New-AzureRmADApplication -DisplayName $AppName -HomePage $AppUri -IdentifierUris $AppUri -ErrorAction Stop
    } catch {
      Write-Error "`nFailed to create application `"$AppName`".`n"
	  return $null
    }
	Write-Host "Done.`n"  
  }
  
  # add results to return object
  $obj | Add-Member -MemberType NoteProperty -Name "AppDisplayName" -Value $adApp.DisplayName
  $obj | Add-Member -MemberType NoteProperty -Name "AppIdentifierUri" -Value $AppUri
  $obj | Add-Member -MemberType NoteProperty -Name "ApplicationId" -Value $adApp.ApplicationId
  $obj | Add-Member -MemberType NoteProperty -Name "AppObjectId" -Value $adApp.ObjectId  
  
  # if cert provided, add as service principal credential
  if ($Cert) {
  
	# convert $Cert to base64 string
	$credValue = [System.Convert]::ToBase64String($Cert.GetRawCertData())
    $now = $Cert.NotBefore
    $expires = $Cert.NotAfter	  
  
    # check if service principal exists
	$sp = Get-AzureRmADServicePrincipal -ServicePrincipalName $AppUri
	
    if ($sp) {		# add credential to existing service principal	  
	  Write-Host "`nAdding certificate `"$($Cert.Subject)`" to service principal `"$AppUri`" ..." -NoNewLine
      try {
        New-AzureRmADSpCredential -ServicePrincipalName $AppUri -CertValue $credValue -StartDate $now -EndDate $expires -ErrorAction Stop | Out-Null
      } catch {
        Write-Error "`nFailed to add certificate `"$($Cert.Subject)`" to service principal `"$AppUri`".`n"
	    return $null
      }
	  Write-Host "Done.`n"	
	
    } else {		# create service principal and add credential	  
	  Write-Host "Creating service principal `"$AppUri`" and adding certificate `"$($Cert.Subject)`" ... " -NoNewLine
      try {
        $sp = New-AzureRmADServicePrincipal -ApplicationId $adApp.ApplicationId -CertValue $credValue -StartDate $now -EndDate $expires -ErrorAction Stop
      } catch {
        Write-Error "`nFailed to create service principal `"$AppUri`".`n"
	    return $null
      }
	  Write-Host "Done.`n"  
    }
	
    # add results to return object
    $obj | Add-Member -MemberType NoteProperty -Name "ServicePrincipalObjectId" -Value $sp.Id
    $obj | Add-Member -MemberType NoteProperty -Name "CertSubject" -Value $Cert.Subject
    $obj | Add-Member -MemberType NoteProperty -Name "CertThumbprint" -Value $Cert.Thumbprint
	
	# build ASAL connection string
	$cs = "AuthenticateAs=App;"
	$cs += "AppId=" + $adApp.ApplicationId
    $cs += ";TenantId=" + (Get-AzureRmContext).Tenant.TenantId
	$cs += ";CertificateSubjectName=" + $Cert.Subject
	$obj | Add-Member -MemberType NoteProperty -Name "ASALConnString" -Value $cs
	
  }
  
  # return results
  return $obj

}

<#
.SYNOPSIS
    Creates a service principal in Azure AD with a certificate provisioned in Key Vault.
.DESCRIPTION
    This cmdlet completes a number of actions to enable secure bootstrapping of an application's secrets in Key Vault:
	- Creates an Azure AD application
	- Creates a self-signed or SSLAdmin certificate in Key Vault with subject name "CN=<client ID>@<tenant id>" (where <client ID> is from the previous step and <tenant id> is the tenant of the user creating it).
	The certificate also has an EKU value that code can use to select it as a certificate to authenticate a service principal (referenced by <client ID> and <tenant id>).
	- Creates a service principal for the application and registers the above certificate as a credential.
	- Grants the service principal access to Key Vault ("get" access to certificates and secrets, "list" access to keys by default).
	Returns an object with the:
	- AppDisplayName
	- AppIdentifierUri
    - ApplicationId
	- AppObjectId
	- ServicePrincipalObjectId
    - CertSubject
    - CertThumbprint
	- CertSecretId (the URI to retrieve the certificate from Key Vault)
.PARAMETER Subscription
    Optional. The name of the Azure subscription to set as the current ARM context.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER AppName
    Required. The display name to be assigned to the application.
.PARAMETER AppUri
    The URI of the application's homepage (this does not need to be resolvable).
	If not specified, http://<AppName> will be used.
.PARAMETER VaultName
    Required. The name of the Azure Key Vault to add/update a certificate to.
.PARAMETER CertName
    Required. The name of the certificate object to store in Key Vault.
.PARAMETER ValidityInMonths
    The validity period (in months) for self-signed certificates (defaults to 12 months).
.PARAMETER Ekus
    By default, an OID will be added to the certificates "enhanced key usage" field to identify it as suitable for Azure AD service principal auth, for libraries that support that feature.
    This can be overridden with 1 or more alternate EKUs if desired.
.PARAMETER IssuerName
    Not required for self-signed certificates. If requesting a certificate from SSLAdmin, specify the Issuer name to be used.
    If a certificate policy is passed as input, the Issuer from that policy will be used.
.PARAMETER Policy
    For more detailed certificate policy definition, use New-AzureKeyVaultCertificatePolicy to create a policy object and pass that as a parameter (or via the pipeline).
	When used, -IssuerName and -ValidityInMonths parameters will be ignored.
.PARAMETER Timeout
    The time in seconds to wait for Key Vault to complete a self-signed or SSLAdmin request.
    Defaults to 60 seconds.
.PARAMETER PermissionsToCertificates
    Array of permissions from {get | list | delete | create | import | update | managecontacts | getissuers | listissuers | setissuers | deleteissuers | all}
    Default is "get".
.PARAMETER PermissionsToSecrets
    Array of permissions from {get | list | set | delete | all}
    Default is "get".
.PARAMETER PermissionsToKeys
    Array of permissions from {decrypt | encrypt | unwrapKey | wrapKey | verify | sign | get | list | update | create | import | delete | backup | restore | all}
    Default is "list".	
.EXAMPLE
    $sp = New-BootstrapIdentity -AppName "myApp" -VaultName "myKeyVault" -CertName "myCert"
    Creates Azure AD application "myApp" with Identifier URI http://myApp and registers a certificate against its service principal.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   October 7, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function New-BootstrapIdentity {

  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",
    [Parameter(Mandatory = $true)]
	[ValidateLength(3, 63)]
	#[ValidatePattern("^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$")]	
    [String]$AppName,
    [Parameter(Mandatory = $false)]
	[ValidateLength(3, 63)]
	#[ValidatePattern("^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$")]
    [String]$AppUri,
    [Parameter(Mandatory = $true)]
    [String]$VaultName,
    [Parameter(Mandatory = $true)]
    [String]$CertName,
	[Parameter(Mandatory = $false)]
    [String]$ValidityInMonths = "12",
	[Parameter(Mandatory = $false)]
    [Collections.Generic.List[String]]$Ekus = "1.3.6.1.4.1.311.91.8.1",		# OID assigned for Azure AD authentication
    [Parameter(Mandatory = $false)]
    [String]$IssuerName = "Self",
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [Microsoft.Azure.Commands.KeyVault.Models.KeyVaultCertificatePolicy]$Policy,	
    [Parameter(Mandatory = $false)]
    [Int]$Timeout = 60,
	[Parameter(Mandatory = $false)]
	[string[]]$PermissionsToCertificates = "get",
	[Parameter(Mandatory = $false)]
	[string[]]$PermissionsToSecrets = "get",
	[Parameter(Mandatory = $false)]
	[string[]]$PermissionsToKeys = "list"
  )

  # check login to AAD
  $loginResult = Login-AzureRm $Subscription
  if (!$loginResult) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }
  
  # set $AppUri to http://<AppName> if not specified
  if (!$AppUri) {
    $AppUri = "http://" + $AppName
  }

  # calling New-ServicePrincipal to create AAD application
  Write-Host "`nCreating Azure AD application." -ForegroundColor Green
  $adApp = New-ServicePrincipal -AppName $AppName -AppUri $AppUri

  # return if Azure AD application is not created
  if (!$adApp) {
    return $null
  }
  
  # build subject name with format: "CN=<Client ID>@<TenantId>"
  $SubjectName = "CN=" + $adApp.ApplicationId + "@" + $loginResult.Tenant.TenantId
  
  # if not provided, create cert policy
  if (!$Policy) {
    try {
      $policy = New-AzureKeyVaultCertificatePolicy -SubjectName $SubjectName -IssuerName $IssuerName -ValidityInMonths $ValidityInMonths -Ekus $Ekus
    } catch {
      Write-Error "Failed to create certificate policy.`n"
      return $null
    }
  }
  
  # request cert
  Write-Host "Requesting Key Vault to generate certificate." -ForegroundColor Green
  if ($IssuerName -eq "Self") {
    $certRef = Set-KeyVaultCertificate -Subscription $Subscription -VaultName $VaultName -CertName $CertName -Policy $policy -SelfSigned
  } else {
    $certRef = Set-KeyVaultCertificate -Subscription $Subscription -VaultName $VaultName -CertName $CertName -Policy $policy -SSLAdmin  
  }

  # return if cert creation fails
  if (!$certRef) {
    Write-Host "Certificate creation failed."
    return $null
  }
  
  # call New-ServicePrincipal again, this time with the cert
  Write-Host "Adding certificate `"$CertName`" to service principal `"$AppUri`".`n" -ForegroundColor Green
  $obj = New-ServicePrincipal -AppName $AppName -AppUri $AppUri -Cert $certRef.Certificate -SuppressConsoleMessages

  # give service principal read access to certs and secrets
  Write-Host "`nGranting service principal access to Key Vault ... " -ForegroundColor Green -NoNewline
  try {
    Set-AzureRmKeyVaultAccessPolicy -VaultName $VaultName -ServicePrincipalName $AppUri -PermissionsToCertificates $PermissionsToCertificates -PermissionsToSecrets $PermissionsToSecrets -PermissionsToKeys $PermissionsToKeys
  } catch {
    Write-Error "Failed to set permissions on vault $VaultName.`n"
  }
  Write-Host "Done.`n" -ForegroundColor Green
  
  # add properties to return object
  $obj | Add-Member -MemberType NoteProperty -Name "CertSecretId" -Value $("https://" + $VaultName + ".vault.azure.net:443/secrets/" + $CertName)
  return $obj  
  
}

<#
.SYNOPSIS
    Polls Key Vault for completion after request for self-signed or SSLAdmin cert from Set-KeyVaultCertificate.
.PARAMETER VaultName
    Required. The name of the Azure Key Vault generating / requesting the certificate.
.PARAMETER CertName
    Required. The name of the certificate being generated / requested.
.PARAMETER Timeout
    The time in seconds to wait for Key Vault to complete a -SelfSigned or -SslAdmin request before timeout.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   August 19, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Check-CertCompletion {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $true, Position = 0)]
    [String]$VaultName,
    [Parameter(Mandatory = $true, Position = 1)]
    [String]$CertName,
    [Parameter(Mandatory = $true, Position = 2)]
    [Int]$Timeout
  )

  for ($i = 0; $i -lt $Timeout; $i++) {
  
    sleep -Seconds 1
	
    try {
	  $request = Get-AzureKeyVaultCertificateOperation -VaultName $VaultName -Name $CertName -ErrorAction Stop
	} catch {
	  Write-Error "Unable to retrieve status of certificate `"$CertName`" from vault `"$VaultName`".`n"
	  return $null
	}
	
	Switch ($request.Status) {
	
	  "inProgress" {
	    Write-Host "." -NoNewLine
	  }
	  
	  "completed" {
	    Write-Host " Done.`n"
		try {
          Get-AzureKeyVaultCertificate -VaultName $VaultName -Name $CertName -ErrorAction Stop
		} catch {
		  Write-Error "Unable to retrieve certificate `"$CertName`" from vault `"$VaultName`".`n"
		  return $null
		}
		return
	  }
	  
	  "failed" {
	    Write-Host "`n`nRequest failed."
		Write-Host "Error code: `t$($request.ErrorCode)"
		Write-Host "Error message: `t$($request.ErrorMessage)`n"
		return $null
	  }	  
	}
  }
	
  # timeout
  Write-Host "`n`nRequest not completed within $Timeout seconds.`n"
  Write-Host "Run the following cmdlet to check status:"
  Write-Host "Get-AzureKeyVaultCertificateOperation -VaultName $VaultName -Name $CertName`n"

}

<#
.SYNOPSIS
    Validate and return the full path specified by the user.
.PARAMETER InputPath
    Required. The user-specified path to resolve and validate.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   August 19, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Get-Path {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $true)]
    [String]$InputPath
  )

  # validate path provided
  $pathElements = $InputPath.Split("\")
  
  # if user specifies format 'file.ext'
  if ($pathElements.Count -eq 1) {
    $outputPath = $pwd.Path + "\" + $InputPath
	return $outputPath
  }
  
  # if user specifies format '.\file.ext'
  if ($pathElements[0] -eq ".") {
    $outputPath = $pwd.Path + $InputPath.TrimStart(".")
	return $outputPath
  }
  
  # if user specifies format '<path>\file.ext'
  $outputPath = ""
  for ($i = 0; $i -lt ($pathElements.Count - 1); $i++) {
    $outputPath += $pathElements[$i] + "\"
  }
  
  # test the path
  if (!(Test-Path $outputPath)) {
	return $null
  }
  
  # $InputPath is valid - return it
  return $InputPath
  
}

<#
.SYNOPSIS
    Logs in to Azure Resource Management (ARM) API and sets the subscription context.
.DESCRIPTION
    Logs in to Azure Resource Management (ARM) API and sets the subscription context.
	Returns the current RM context if successful, or $null if login fails.
.PARAMETER Subscription
    The name of the Azure subscription to set the current RM context to.
	This defaults to "first", in which case the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER SuppressConsoleMessages
    This is used to suppress repeated logon messages where multiple cmdlets are called and each checks authentication state.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   October 14, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Login-AzureRm {

  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",
    [Parameter(Mandatory = $false)]
    [Switch]$SuppressConsoleMessages		
  )

  # get Azure RM context. If it fails, prompt user to login
  try {
    $rmContext = Get-AzureRmContext -ErrorAction Stop
  } catch {
    try {
	  if (!$SuppressConsoleMessages) {
	    Write-Host "`nLogging in to Azure RM API... "
	  }
	  Add-AzureRmAccount -ErrorAction Stop | Out-Null
	} catch {
	  Write-Error "`nLogin failed.`n"
	  return $null
	}
  } 
  if (!$SuppressConsoleMessages) {
    Write-Host "`nLogged into Azure RM API."
  }
  
  # user now logged in, get RM context
  if (!$rmContext) {

    try {
      $rmContext = Get-AzureRmContext -ErrorAction Stop
    } catch {
      Write-Error "Unable to get Azure RM context.`n"
	  return $null
    }
  }

  # if current RM context = $Subscription, return it
  if ($rmContext.Subscription.SubscriptionName -eq $Subscription) {
    if (!$SuppressConsoleMessages) {
	  Write-Host "Current RM context is `"$($rmContext.Subscription.SubscriptionName)`".`n"
	}
    return $rmContext  
  }
  
  # if $Subscription -ne "first", validate $Subscription
  if ($Subscription -ne "first") {
  
    $subValid = $false
  
    # get list of Azure subscriptions
    try {
      $subs = Get-AzureRmSubscription -ErrorAction Stop
    } catch {
      Write-Error "Failed to get Azure subscriptions.`n"
	  return $null
    }
	
    # validate $Subscription
    foreach ($sub in $subs) {

      if ($sub.SubscriptionName -eq $Subscription) {
	    $subValid = $true
	    break	
	  }
    }	
  } else {		# subscription not specified by user, return first subscription in list
  
    if (!$SuppressConsoleMessages) {
	  Write-Host "Subscription not specified - using current RM context: `"$($rmContext.Subscription.SubscriptionName)`"`n"
	}
    return $rmContext
	
  }
  
  # $Subscription is invalid or you don't have access
  if (!$subValid) {
    Write-Error "Subscription `"$Subscription`" is invalid or you don't have access to it.`n"
	return $null
  }
  
  # if current subscription does not match $Subscription, change to it
  if ($rmContext.Subscription.SubscriptionName -ne $Subscription) {
    Write-Host "Changing RM context from `"$($rmContext.Subscription.SubscriptionName)`" to `"$Subscription`"."
	try {
	  $rmContext = Set-AzureRmContext -SubscriptionName $Subscription -ErrorAction Stop
	} catch {
	  Write-Error "Failed to set `"$Subscription`" as the current subscription.`n"
	  return $null
	}
    return $rmContext
  } else {
  
    # return the current context
    if (!$SuppressConsoleMessages) {
	  Write-Host "Current RM context is `"$($rmContext.Subscription.SubscriptionName)`".`n"
	}
    return $rmContext
  }  
}

<#
.SYNOPSIS
    Logs in to Azure Service Management (classic) API and sets the subscription context.
.PARAMETER Subscription
    Required. The name of the Azure subscription to set the current context to.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   August 19, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Login-AzureSm {

  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [String]$Subscription
  )

  # get list of Azure subscriptions
  try {
    $subs = Get-AzureSubscription -ErrorAction Stop		# returns $null if not logged in
  } catch {
    Write-Error "Failed to get Azure subscriptions.`n"
	return $null
  }

  # if not logged in, prompt for login
  if (!$subs) {
    try {
	  Write-Host "Logging in to Azure SM API... " -NoNewLine
	  Add-AzureAccount -ErrorAction Stop | Out-Null
	} catch {
	  Write-Error "`nLogin failed.`n"
	  return $null
	}
	Write-Host "Done.`n"
  
    # now we are logged in, get list of Azure subscriptions
    try {
      $subs = Get-AzureSubscription -ErrorAction Stop
    } catch {
      Write-Error "Failed to get Azure subscriptions.`n"
	  return $null
    }
  } else {
    Write-Host "Logged into Azure SM API."
  }
  
  # validate $Subscription and set as current
  $currentSub = $null
  foreach ($sub in $subs) {

    if ($sub.SubscriptionName -eq $Subscription) {

	  # make $Subscription the current subscription
	  try {
	    Select-AzureSubscription -SubscriptionName $Subscription -Current -ErrorAction Stop
	  } catch {
	    Write-Error "Failed to set `"$Subscription`" as the current subscription.`n"
		return $null
	  }
	  
	  # get the current subscription
	  $currentSub = Get-AzureSubscription -Current
	  break	
	}
  }

  # return the current subscription
  if ($currentSub) {
    Write-Host "Current SM context is `"$($currentSub.SubscriptionName)`".`n"
	return $currentSub
  } else {
    Write-Error "Failed to set `"$Subscription`" as the current subscription.`n"
	return $null
  }

}

<#
.SYNOPSIS
    Takes a string and an X509Certificate2 object and encrypts the string with the public key from the certificate.
.DESCRIPTION
	Takes a string and an X509Certificate2 object and encrypts the string with the public key from the certificate.
	The string can be passed as a parameter or received from the pipeline.
.PARAMETER StringToEncrypt
    Required. This can be passed as a parameter or received from the pipeline.
.PARAMETER Cert
    Required. An X509Certificate2 object containing the public key to do the encryption.
    The cert object can be created in a number of ways, but is intended for use with the Get-KeyVaultCertificate cmdlet which returns this type of object from Key Vault.
.EXAMPLE
    $cert = Get-KeyVaultCertificate -VaultName "myVault" -CertName "myCert"
	PS C:\>$myEncryptedString = 'some_string_to_encrypt' | Encrypt-StringWithCert -Cert $cert
.NOTES
    Alias:	Encrypt-StringWithCert
	Author: Nick Torkington (nicktork@microsoft.com)
    Date:   August 19, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Protect-StringWithCert {

  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
    [String]$StringToEncrypt,
    [Parameter(Mandatory = $true, Position = 1)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
  )
  
  [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null
  $stringBytes = [Text.Encoding]::UTF8.GetBytes($StringToEncrypt)
  $content = New-Object Security.Cryptography.Pkcs.ContentInfo -ArgumentList (,$stringBytes)
  $env = New-Object Security.Cryptography.Pkcs.EnvelopedCms $content
  $env.Encrypt((New-Object System.Security.Cryptography.Pkcs.CmsRecipient($Cert)))
  [Convert]::Tobase64String($env.Encode())

}

<#
.SYNOPSIS
    Returns false if Key Vault name is already in use and true if name is available.
.DESCRIPTION
    The Test-KeyVaultName function uses a DNS lookup to determine if the passed Key Vault name is already in use.
.PARAMETER VaultName
    Key Vault name to validate
.EXAMPLE
    C:\PS>Test-KeyVaultName -VaultName "mydemovault" 
    Returns true if the vault name mydemovault is available. 
.NOTES
    Author: Gerald Steere
    Date:   January 6, 2016
.LINK
    https://aka.ms/kvhelper    
#>
function Test-KeyVaultName {
    
    [CmdletBinding()]

    param(
    [parameter(Mandatory = $true,Position=0,HelpMessage="Globally unique name for your vault")][string] $VaultName
    )

    begin { }

    process
    {
        #Key Vault names are globally unique, make sure URL returns 404 (page doesn't exist)
        $kvdns = $VaultName + ".vault.azure.net";
        if (Resolve-DnsName -Name $kvdns -ErrorAction SilentlyContinue)
        {
            Write-Error("Key Vault $VaultName already exists.");
            return $false;
        }
        return $true;
    }

    end {}
}

<#
.SYNOPSIS
    Returns true if user provided location is valid for Key Vault usage.
.DESCRIPTION
    The Test-KeyVaultLocation function queries the Azure RM Resource Provider to
    determine if the user provided region is valid for creation of a Key Vault.
    If the location is not valid, the available locations are displayed. 
.PARAMETER Location
    Azure Region for creating the Vault in
.EXAMPLE
    C:\PS> Test-KeyVaultlocation -Location "westus"
    Returns true if westus is valid for Key Vault creation
.NOTES
    Author: Gerald Steere
    Date:   January 6, 2016
.LINK
    https://aka.ms/kvhelper
#>
function Test-KeyVaultLocation {
    
    [CmdletBinding()]

    param(
    [parameter(Mandatory = $true,Position=2,HelpMessage="Azure region to create vault in.")][string] $Location
    )

    begin { }

    process
    {
        #check if the user provided location is valid for selected subscription and KeyVault use
        $validlocations = (((Get-AzureRmResourceProvider -ProviderNamespace Microsoft.keyvault).ResourceTypes | Where-Object ResourceTypeName -eq vaults).Locations).Replace(" ","").ToLower();
        if (!($validlocations.Contains($location.Replace(" ","").ToLower())))
        {
            $message = "Invalid location provided for Key Vault usage. Valid locations are:'n" + $validlocations;
            Write-Error $message;
            return $false;
        }
                    
        return $true;
    }

    end {}
}

<#
.SYNOPSIS
    This function calls the Azure Powershell functions necessary to create a new Key Vault.
.DESCRIPTION
    New-AzureKeyVault creates a new Azure RM resource group if needed and then creates a new Key Vault
    based on the user provided values.
.PARAMETER VaultName
    The globally unique name for the Key Vault.
.PARAMETER ResourceGroupName
    Name of the Azure Resource Manager group to create the vault in 
.PARAMETER Location
    Azure Region for creating the Vault in
.PARAMETER HSM
    Use Hardware Security Module for Vault (requires Premium Key Vault)
    Optional - defaults to false
.PARAMETER Deployment
    Enable vault for automated deployment of keys (gives vault access to Azure infrastructure)
    Optional - defaults to false
.EXAMPLE
    C:\PS>New-AzureKeyVault -VaultName "mydemovault" -ResourceGroupName "mydemorg" -Location "westus"
    Creates a new Azure RM resource group mydemorg if it doesn't already exist for the region westus
    then creates a new Azure Key Vault named mydemovault. HSM and Deployment are not enabled for the vault. 
.NOTES
    Author: Gerald Steere
    Date:   January 6, 2016
.LINK
    https://aka.ms/kvhelper
#>
function New-AzureKeyVault {
    
    [CmdletBinding()]

    param(
    [parameter(Mandatory = $true,Position=0,HelpMessage="Globally unique name for your vault")][string] $VaultName,
    [parameter(Mandatory = $true,Position=1,HelpMessage="Resource group for creating vault. Will be created if it doesn't exist.")][string] $ResourceGroupName,
    [parameter(Mandatory = $true,Position=2,HelpMessage="Azure region to create vault in.")][string] $Location,
    [parameter(Mandatory = $false,Position=3,HelpMessage="Use HSM - requires Premium Key Vault")][bool] $HSM = $false,
    [parameter(Mandatory = $false,Position=4,HelpMessage="Enable for deployment - allow access to vault by Azure Infrastructure")][bool] $Deployment = $false
    )

    begin { }

    process
    {

        try
        {
            #check if the passed resource group already exists
            if(!(Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue))
            {
                try
                {
                    New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location;
                }
                catch
                {
                    Write-Error "Unable to create resource group $ResourceGroupName.";
                    return $false;
                }
            }

            #set sku flag based on $HSM switch
            if ($HSM)
            {
                $sku = "premium";
            }
            else
            {
                $sku = "standard";
            }

            #try to create the key vault
            try
            {
                if ($Deployment)
                {
                    New-AzureRMKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName -Location $Location -EnabledForDeployment -Sku $sku;
                }
                else
                {
                    New-AzureRMKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName -Location $Location -Sku $sku;
                }
            }
            catch
            {
                Write-Error("Failed to create Key Vault");
                return $false;
            }
        }
        catch
        {
            Write-Error("Unexpected error occured, exiting");
            return $false;
        }
    }

    end {}
}

<#
.SYNOPSIS
    Generates a new random password with a default of 32 characters and at least 4 special characters. 
.DESCRIPTION
	New-Password uses the System.Web Membership random password generator to create a random password.
    By default, the password will be 32 characters long with a mimimum of 2 special characters, but
    both options can be set by user.  
.PARAMETER Length
	Length of password, defaults to 32
.PARAMETER Specials
	Minimum number of special characters in the password, defaults to 4
.EXAMPLE
    $password = New-Password
    Generates a random 32 character password with at least 4 special characters and sets it to $password
.NOTES
    Author: Gerald Steere
	Date:   June 3, 2016	
.LINK
    https://aka.ms/kvhelper	
#>
function New-Password {
    
    [CmdletBinding()]

    param(
	    [parameter(
            Mandatory = $false,
            Position = 0,
            HelpMessage="The length of the password to generate (defaults to 32)"
            )]
        [int] $Length = 32,
        
        [parameter(
            Mandatory = $false,
            Position = 1,
            HelpMessage="The minimum number of special characters to include (defaults to 4)"
            )]
        [int] $Specials = 4
        )

    begin { }

    process
    {
        #generate a strong password for use with the management cert
		Write-Host "Generating random password with $Length characters."
        [system.reflection.assembly]::LoadwithPartialName("System.Web") | Out-Null;
        $password = [System.Web.Security.Membership]::GeneratePassword($Length,$Specials);

        return $password;
    }

    end {}
}

<#
.SYNOPSIS
    Creates an exportable self-signed certificate in the CurrentUser\My store with the name of CertificateName
.DESCRIPTION
	New-Certificate creates a new self signed certificate in the CurrentUser\My store with the name of CertificateName.
    This certificate differs from that created by New-SelfSignedCertificate on systems prior to Windows 10 in that it 
    is fully exportable. To use this on systems prior to Windows 10, makecert.exe must be in the same director or in the path.
    The certificate is also returned as an X509Certificate2 object.    
.PARAMETER Name
	The subject name to use for the certificate (required)
.EXAMPLE
    New-Certificate -Name "KVDemo-cert" 
    Creates a new certificate with the subject KVDemo-cert and saves it in the CurrentUser\My store
    The certificate is also returned as an X509Certificate2 object
.NOTES
    Author: Gerald Steere
	Date:   June 3, 2016	
.LINK
    https://aka.ms/kvhelper 
#>
function New-Certificate {
    
    [CmdletBinding()]

    param(
	    [parameter(
            Mandatory = $true,
            Position = 0,
            HelpMessage = "The subject name to use for the certificate"
            )]
        [string] $Name
        )

    begin { }

    process
    {
    
        #Try using the new selfsigned certificate cmdlet first, if this fails (versions prior to windows 10), we'll need makecert
    
        try
        {
            $localcert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -DnsName $Name -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -ErrorAction SilentlyContinue;
        }
        catch
        {
            #The easy way didn't work, lets try the hard way
        
            try
            {
                $cn = "CN=" + $Name;
                $c = [System.IO.Path]::GetTempFileName();
                #make cert and put it into the store
                .\makecert.exe -n $cn -m 12 -r -ss 'My' -a 'sha256'-pe $c
                $localCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($c);
            }
            catch
            {
                Write-Host "Couldn't create certificate, is makecert available?"
                return;
            }
            finally
            {
                   del $c -ErrorAction SilentlyContinue;
            }
        }

        return $localcert;
    }

    end { }
}

<#
.SYNOPSIS
    Manage Azure storage accounts and their keys (Create, Delete, GetKey, RotateKey).
	If a Key Vault name is specified, a secret with the same name as the storage account is created / deleted / updated.
.DESCRIPTION
	This cmdlet is designed for use in automated deployment scripts to manage the storage accounts for that deployment.
	It supports 2 main modes of operation:
	   Transient:  the storage access keys are not persisted in Key Vault but instead returned for immediate use.
	   Persistent: the storage access keys are instead written / updated in the specified Key Vault for later retrieval.
	In persistent mode, either a single key is stored, or a JSON object containing both keys is stored (see -Json for details).
	See Examples for detailed usage.
.PARAMETER Subscription
    Optional. The name of the Azure subscription to use.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.	
.PARAMETER StorageAccountName
    Required. The name of the storage account to Create/Delete/GetKey/RotateKey.
.PARAMETER ResourceGroupName
    Required. The Resource Group the storage account resides in.
.PARAMETER Location
    Required with -Create. Specifies the Azure location to create the storage account in.
.PARAMETER Type
    Required with -Create. Specifies the replica type of the storage account to create. Defaults to "Standard_GRS".
.PARAMETER Key
    Required with -GetKey and -RotateKey. Specifies whether to get/rotate "key1" or "key2".
.PARAMETER VaultName
    If specified, the storage access keys will be created / deleted / updated in this Key Vault.
	The vault can be in the same or a different Azure subscription from the storage account.
.PARAMETER DisplayKeys
    Optional (N/A with -Delete). Displays the unencrypted keys on your screen in case you need to copy/paste them.
.PARAMETER Create
    Operation to perform. These are mutually exclusive.
.PARAMETER Delete
    Operation to perform. These are mutually exclusive.
.PARAMETER GetKey
    Operation to perform. These are mutually exclusive.
.PARAMETER RotateKey
    Operation to perform. These are mutually exclusive.
.PARAMETER Json
    If specified, both storage access keys are written to the secret in JSON format.
	Format: {"StorageAccountName":"<value>","PrimaryKey":"<value>","SecondaryKey":"<value>","UseSecondaryKey":"<true|false>"}
	UseSecondaryKey indicates which key was most recently updated.
	If this switch is omitted, only a single storage access key is stored (key1 on -Create, key1/key2 as specified with -GetKey or -RotateKey).
.PARAMETER Overwrite
    During storage account creation, the user will be prompted if a secret with the same name exists in the specified vault.
    If this switch is provided, the secret will be overwritten without prompting.	
.EXAMPLE
	$keys = Manage-StorageAccount -Create -StorageAccountName "mystorageaccount" -ResourceGroupName "myRG" -Location "West US"
    CREATE transient:
	Creates the storage account (defaulting to "Standard_GRS") and returns keys (which contains key1 and key2).
	Use -DisplayKeys to also echo the storage access keys on the console.
.EXAMPLE
	$KVsecret = Manage-StorageAccount -Create -StorageAccountName "mystorageaccount" -ResourceGroupName "myRG" -Location "West US" -VaultName "myKeyVault"
    CREATE persistent:
	Creates the storage account (defaulting to "Standard_GRS") and stores key1 in "myKeyVault" as secret "mystorageaccount".
	The function returns a reference to the Key Vault secret.
	Use -JSON to store both keys as a JSON object, and -DisplayKeys to also echo the storage access keys on the console.
.EXAMPLE
    Manage-StorageAccount -Delete -StorageAccountName "mystorageaccount" -ResourceGroupName "myRG" -VaultName "myKeyVault"
    DELETE the storage account and removes the secret containing the key from Key Vault.
	The secret is assumed to have the same name as the storage account in vault "myKeyVault".
	To delete the storage account without removing the secret, omit -VaultName.
.EXAMPLE
    $KVsecret = Manage-StorageAccount -GetKey -StorageAccountName "mystorageaccount" -ResourceGroupName "myRG" -Key "key1" -VaultName "myKeyVault"
    RETRIEVES key1 of the storage account and stores it as secret "mystorageaccount" in vault "myKeyVault".
	Use -JSON to store both keys as a JSON object (with the retrieved key set as active), and -DisplayKeys to also echo the storage access keys on the console.
	When used with -VaultName, the function returns a reference to the Key Vault secret.
	To just retrieve a storage access key without storing it in Key Vault, omit -VaultName and assign the return value of the function to a variable.
.EXAMPLE
    Manage-StorageAccount -RotateKey -StorageAccountName "mystorageaccount" -ResourceGroupName "myRG" -Key "key1" -VaultName "myKeyVault"
    ROTATE key1 of the storage account and store it as secret "mystorageaccount" in vault "myKeyVault".
	Use -JSON to store both keys as a JSON object (with the rotated key set as active), and -DisplayKeys to also echo the storage access keys on the console.
	When used with -VaultName, the function returns a reference to the Key Vault secret.
	To just rotate a storage access key without storing it in Key Vault, omit -VaultName and assign the return value of the function to a variable.
.NOTES
    Alias:	Manage-StorageAccount
	Author: Nick Torkington (nicktork@microsoft.com)
    Date:   16 October, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Update-StorageAccount {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",
    [Parameter(Mandatory = $true, Position = 0)]
	[ValidateLength(3, 24)]
	[ValidatePattern("^[a-z0-9]+$")]
    [String]$StorageAccountName,
    [Parameter(Mandatory = $true, Position = 1)]
    [String]$ResourceGroupName,
    [Parameter(Mandatory = $true, Position = 2, ParameterSetName = "Create")]
    [String]$Location,
    [Parameter(Mandatory = $false, Position = 3, ParameterSetName = "Create")]
	[ValidateSet("Standard_LRS", "Standard_ZRS", "Standard_GRS", "Standard_RAGRS", "Premium_LRS")]
    [String]$Type = "Standard_GRS",
    [Parameter(Mandatory = $true, Position = 2, ParameterSetName = "RotateKey")]
	[parameter(ParameterSetName = "GetKey")]
    [ValidateSet("key1", "key2")]
	[String]$Key,
	[Parameter(Mandatory = $false)]
	[String]$VaultName,
	[Parameter(Mandatory = $false, ParameterSetName = "Create")]
	[parameter(ParameterSetName = "RotateKey")]
	[parameter(ParameterSetName = "GetKey")]
    [Switch]$DisplayKeys,
	[Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Switch]$Create,
	[Parameter(Mandatory = $false, ParameterSetName = "Delete")]
    [Switch]$Delete,
	[Parameter(Mandatory = $false, ParameterSetName = "GetKey")]
    [Switch]$GetKey,
	[Parameter(Mandatory = $false, ParameterSetName = "RotateKey")]
    [Switch]$RotateKey,
	[Parameter(Mandatory = $false, ParameterSetName = "Create")]
	[parameter(ParameterSetName = "RotateKey")]
	[parameter(ParameterSetName = "GetKey")]	
    [Switch]$Json,
	[Parameter(Mandatory = $false, ParameterSetName = "Create")]
    [Switch]$Overwrite	
  )
  
  # check login to AAD
  $rmContext = Login-AzureRm $Subscription
  if (!$rmContext) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }  

  # validate that storage account exists
  $StorageAccountName = $StorageAccountName.ToLower()
  If ($Create) {	# CREATE operation checks for DNS endpoint
    If (!((Get-AzureRmStorageAccountNameAvailability -Name $StorageAccountName).NameAvailable)) {
	  Write-Error "`nStorage account $($StorageAccountName) name is not available. Exiting...`n"
	  return
    }    
  } else {	# non-CREATE operations check for storage account in defined RG
  
    try {
	  Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop | Out-Null
	} catch {
	  Write-Error "`nStorage account $($StorageAccountName) does not exist. Exiting...`n"
	  return	
	}

  }
  
  # check if the passed resource group already exists. If not, create it
  If(!(Get-AzureRmResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue)) {
    try {
	  New-AzureRmResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
    } catch {
      Write-Error "Unable to create resource group $ResourceGroupName."
      return
    }
  }
  
  # validate location provided
  If ($Location) {
    If (!(Test-KeyVaultLocation $Location)) {
      Write-Error "`nLocation $($Location) is invalid. Exiting...`n"
	  return
    }
  }

  # validate vault name (if provided) and permissions
  If ($VaultName) {

    try {
	  $vault = Get-AzureRmKeyVault -VaultName $VaultName -ErrorAction Stop -WarningAction SilentlyContinue
    } catch {
	  Write-Error "Vault `"$VaultName`" does not exist in the current RM context.`n"
	  return $null	
    }  

<#	
    # verify Key Vault permissions
    $hasPermission = Test-KeyVaultPermissions -Vault $vault -RmContext $rmContext -Action "SecretsWrite"
    if (!$hasPermission) {
      if ($hasPermission -eq $false) {
	    Write-Host "Identity $($rmContext.Account.Id) does not have appropriate permissions to vault $VaultName.`n"
	  }
      return $null  
    }
#>	
  }
  
  # CREATE storage account
  If ($Create) {
  
    # check for existing secret named $StorageAccountName in vault $VaultName
    # if exists and -Create passed, ask user if they want to overwrite
    # skip this check if -Overwrite is passed
	If ((!$Overwrite) -and ($VaultName) -and (Get-AzureKeyVaultSecret -VaultName $VaultName -Name $StorageAccountName -ErrorAction SilentlyContinue)) {
	  Write-Host "`nThere is already a secret named $StorageAccountName in vault $VaultName" -ForegroundColor Yellow
      $userinput = (Read-Host "Press 'y' to overwrite this secret (or any other key to exit)`n").ToUpper()
      If ($userinput -ne "Y") {Return}		  
	}	
  
	# Create storage account
    Write-Host "`nCreating storage account:"
    Write-Host "  Name:`t`t`t" $StorageAccountName
    Write-Host "  Resource Group:`t" $ResourceGroupName
    Write-Host "  Location:`t`t" $Location
    Write-Host "  Type:`t`t`t" $Type "`n"
	try {
      New-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Location $Location -SkuName $Type -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
	} catch {
      Write-Error "Unable to create storage account $StorageAccountName."
      return
	}
	Write-Host "... Done.`n"
  }
  
  # DELETE storage account
  If ($Delete) {
    Write-Host "`nDeleting storage account" $StorageAccountName "from resource group" $ResourceGroupName "... " -NoNewLine
	try {
	  Remove-AzureRmStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop -WarningAction SilentlyContinue
	} catch {
      Write-Error "`nUnable to delete storage account $StorageAccountName.`n"
      return
	}
	Write-Host "Done."
	
	# delete secret if -VaultName specified
	If ($VaultName) {
	
	  # check if secret exists
	  If (Get-AzureKeyVaultSecret -VaultName $VaultName -Name $StorageAccountName -ErrorAction SilentlyContinue) {
	  
	    Write-Host "Deleting secret" $StorageAccountName "from vault $VaultName ... " -NoNewLine
	    try {
	      Remove-AzureKeyVaultSecret -VaultName $VaultName -Name $StorageAccountName -Force -Confirm:$False -ErrorAction Stop
	    } catch {
	      Write-Error "Unable to delete secret $StorageAccountName.`n"
		  return
	    }
	    Write-Host "Done.`n"
	  } else {		# secret does not exist
	    Write-Host "Secret $StorageAccountName does not exist in vault $VaultName.`n"
	  }
	}
  }
  
  # ROTATE storage account key1 or key2
  If ($RotateKey) {
    Write-Host "`nRotating storage account:" $StorageAccountName "key:" $Key
	try {
	  New-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName $Key -ErrorAction Stop | Out-Null
	} catch {
      Write-Error "Unable to rotate $Key of storage account $StorageAccountName."
      return	
	}
  }
  
  # generate secret to return or store in Key Vault (except in -Delete case)
  If (!$Delete) {
  
    # retrieve storage account keys
	try {
	  $storagekeys = Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction Stop
	} catch {
      Write-Error "Unable to retrieve keys of storage account $StorageAccountName."
      return	
	}
	
    # Display storage account keys if -DisplayKeys passed
	If ($DisplayKeys) {
      Write-Host "`nStorage account keys:" -ForegroundColor Yellow
	  ForEach ($storagekey in $storagekeys) {    
        Write-Host "  " $storagekey.KeyName ":`t" $storagekey.Value
      }
	  Write-Host "`n"
    }
	
	# generate secret to store in Key Vault, or just return $storagekeys from function
	If ($VaultName) {
	
	  # build $secret as json with key1 and key2 if -Json specified
	  If ($Json) {
	
	    # Format: {"StorageAccountName":"<value>","PrimaryKey":"<value>","SecondaryKey":"<value>","UseSecondaryKey":"<true|false>"}
        $secret = New-Object System.Object
	    $secret | Add-Member -NotePropertyName "StorageAccountName" -NotePropertyValue $StorageAccountName
	  
        ForEach ($storagekey in $storagekeys) {
	
	      # Add storage account keys
	      If ($storagekey.KeyName -eq "key1") {
	        $secret | Add-Member -NotePropertyName "PrimaryKey" -NotePropertyValue $storagekey.Value
	      } else {
	        $secret | Add-Member -NotePropertyName "SecondaryKey" -NotePropertyValue $storagekey.Value	  
	      }
        }
	  
	    # If "key2" was rotated, set "UseSecondaryKey" to true (so that newest key is active).
        If ($Key -eq "key2") {
	      $secret | Add-Member -NotePropertyName "UseSecondaryKey" -NotePropertyValue "true"
	    } else {	# If "key1" was rotated or storage account has just been created ($Key = null), make "key1" active.
	      $secret | Add-Member -NotePropertyName "UseSecondaryKey" -NotePropertyValue "false"
	    }
	
	    # Convert to JSON as secure string
	    $secret = ConvertTo-Json $secret | ConvertTo-SecureString -AsPlainText -Force
	
	  } else {	# store one key only
	
	    # store key1
	    If ($Create -or ($Key -eq "key1")) {
	  
          ForEach ($storagekey in $storagekeys) {
	  
	        If ($storagekey.KeyName -eq "key1") {
	          $secret = ConvertTo-SecureString $storagekey.Value -AsPlainText -Force
	        }
          }		
	  
	    # store key2
	    } else {
	  
          ForEach ($storagekey in $storagekeys) {
	  
	        If ($storagekey.KeyName -eq "key2") {
	          $secret = ConvertTo-SecureString $storagekey.Value -AsPlainText -Force
	        }
          }	  
	    }
	  }
	
	  # write $secret to Key Vault	
	  Write-Host "`nAdding/updating secret to vault:" $VaultName "... " -NoNewLine
	  try {
	    Set-AzureKeyVaultSecret -VaultName $VaultName -Name $StorageAccountName -SecretValue $secret
	  } catch {
        Write-Error "Unable to write secret $StorageAccountName to vault $VaultName`n."
        return	
	  }
	  Write-Host "Done.`n"
	  
    } else {	# don't store in Key Vault, just return keys
	  
	  If ($Key) {
	    
		ForEach ($storagekey in $storagekeys) {
		  If ($storagekey.KeyName -eq $Key) {
		    return $storagekey.Value
		  }
		}
	  } else {
	    return $storagekeys
	  }
	}
  }
}

<#
.SYNOPSIS
    Authenticates to Azure AD and returns an "Authorization" header for calling the Azure REST APIs. 
.PARAMETER ClientId
    The ID of an app registered in Azure AD to grant the token to.
    If not specified, the app registered by PowerShell will be used.
.PARAMETER TenantId
    The Azure AD tenant to authenticate to.
	If not specified, the Microsoft tenant will be used.
.PARAMETER Resource
    Required. The endpoint you are requesting a token for.
.PARAMETER RedirectUri
    The login URI of the "ClientId" application
.NOTES
    Author: Nick Torkington
    Date:   August 24, 2016
.LINK
    https://aka.ms/kvhelper
#>
function New-AzureRestAuthorizationHeader 
{ 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$false)]
		[String]$ClientId = "1950a258-227b-4e31-a9cf-717495945fc2",		# default to PowerShell client ID
        [Parameter(Mandatory=$false)]
		[String]$TenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47",		# default to Microsoft AAD tenant
        [Parameter(Mandatory=$true)]
		[String]$Resource,
        [Parameter(Mandatory=$false)]
		[String]$RedirectUri = "urn:ietf:wg:oauth:2.0:oob"				# defaults to URI required by PowerShell client ID
    ) 

    # build authorization & redirect URIs
    $authUrl = "https://login.windows.net/$TenantId/"
	$uri = New-Object System.Uri($RedirectUri)

    # Create AuthenticationContext for acquiring token 
	$authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($authUrl)
	
    # acquire token
	try {
	  $authResult = $authContext.AcquireToken($Resource, $ClientId, $uri)
	} catch {
	  Write-Error "Failed to acquire Azure AD token.`n"
	  return $null	
	}

    # compose the access token type and access token for authorization header 
    $authHeader = $authResult.AccessTokenType + " " + $authResult.AccessToken

    # return header as a hash table 
    return @{"Authorization"=$authHeader; "Content-Type"="application/json"}
	
}

<#
.SYNOPSIS
    Lists, adds and deletes the management certificates that have been granted admin rights to Azure subscriptions.
.DESCRIPTION
	This cmdlet has 3 operations:
	  - list the management certificates of a subscription. The details of the certificates are written to the console, and the certificates are returned as an array of X509Certificate2 objects.
    - add an X509Certificate2 object or .cer file as a management certificate of a subscription.
    - delete a management certificate of specified thumbprint from a subscription.  	  
.PARAMETER Subscription
    The subscription to manage. If not specified, the subscription of the current RM context will be used.
.PARAMETER SubscriptionId
    The subscription ID to manage. If not specified, the subscription of the current RM context will be used.
	This can be used instead of -Subscription.
.PARAMETER Cert
    An X509Certificate2 object (without private key) to add as a management certificate.
	This can be passed as a named parameter, or received on the pipeline.
.PARAMETER CertFile
    A .cer file to add as a management certificate.
.PARAMETER DeleteByThumbprint
    The thumbprint of the certificate to delete from the subscription.
.PARAMETER List
    List the management certificates of the subscription.
.PARAMETER MinsToExpiry
    This parameter is only relevant if using the subscription management JIT solution PoC from the "Samples" folder of https://aka.ms/kvhelper.
	It can be used with -Cert or -CertFile to specify the number of minutes until the added management certificate is automatically removed.
.PARAMETER VaultName
    This parameter is only relevant if using the subscription management JIT solution PoC from the "Samples" folder of https://aka.ms/kvhelper.
	It specifies the Key Vault holding the JIT endpoint to be called.
.PARAMETER JitUri
    This parameter is only relevant if using the subscription management JIT solution PoC from the "Samples" folder of https://aka.ms/kvhelper.
	It specifies the secret in Key Vault, which is the JIT endpoint to be called.
.EXAMPLE
    Manage-SubMgmtCert -List
    List the management certificates of the current subscription.
.EXAMPLE
    $cert = Get-KeyVaultCertificate -VaultName "myVault" -CertName "myCert"
	PS C:\>$cert | Manage-SubMgmtCert
    Retrieves a certificate (without private key) from Key Vault and adds as a management certificate.
.EXAMPLE
    Manage-SubMgmtCert -List
	PS C:\>Manage-SubMgmtCert -DeleteByThumbprint "thumbprint"
    List the management certificates of the current subscription and then pass the thumbprint of the one to delete.	
.NOTES
    Alias:	Manage-SubMgmtCert
	Author: Nick Torkington
    Date:   August 29, 2016
.LINK
    https://aka.ms/kvhelper
#>
function Update-SubMgmtCert {

  [CmdletBinding()]  
  param(
	[Parameter(Mandatory = $false)]
    [string]$Subscription = "first",
	[Parameter(Mandatory = $false)]
    [string]$SubscriptionId,	
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "AddFromObject")]
	[Parameter(ParameterSetName = "AddFromObjectJit")]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
    [Parameter(Mandatory = $true, ParameterSetName = "AddFromFile")]
	[Parameter(ParameterSetName = "AddFromFileJit")]
    [string]$CertFile,
    [Parameter(Mandatory = $true, ParameterSetName = "AddFromObjectJit")]
	[Parameter(ParameterSetName = "AddFromFileJit")]
    [int]$MinsToExpiry,
    [Parameter(Mandatory = $true, ParameterSetName = "AddFromObjectJit")]
	[Parameter(ParameterSetName = "AddFromFileJit")]
    [string]$VaultName,
	[Parameter(Mandatory = $true, ParameterSetName = "AddFromObjectJit")]
	[Parameter(ParameterSetName = "AddFromFileJit")]
    [string]$JitUri,
	[Parameter(Mandatory = $true, ParameterSetName = "Delete")]
    [string[]]$DeleteByThumbprint,
	[Parameter(Mandatory = $true, ParameterSetName = "List")]
    [Switch]$List
  )
  
  # check login to AAD
  $rmContext = Login-AzureRm $Subscription
  if (!$rmContext) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }  

  # validate vault name (if passed)
  if ($VaultName) {
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
  }
  
  # get $Cert if passed as .cer file
  if ($CertFile) {
	
	# get full path to .cer file
	$CertFile = Get-Path $CertFile
	  
	# validate path
	if (!(Test-Path $CertFile)) {
	  Write-Error "Path `"$CertFile`" is not valid.`n"
	  return $null
	}
	  
    # import into $Cert
	$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    try {
	  $Cert.Import($CertFile)
	} catch {
	  Write-Error "Failed to import certificate file `"$CertFile`".`n"
	  return $null
	}	  
  }
	
  # validate $Subscription (if passed)
  if ($Subscription -or $SubscriptionId) {
  
    $subValid = $false
	$subs = Get-AzureRmSubscription
	
	foreach ($sub in $subs) {
	
	  if ($Subscription) {
	    if ($sub.SubscriptionName -eq $Subscription) {
	      $subValid = $true
		  $SubscriptionId = $sub.SubscriptionId
		  break
	    }
	  } else {	# $SubscriptionId passed
	    if ($sub.SubscriptionId -eq $SubscriptionId) {
	      $subValid = $true
		  $Subscription = $sub.SubscriptionName
		  break
	    }	  
	  }
	}
	
	if (!$subValid) {
	
	  if ($Subscription) {
	    Write-Error "Subscription `"$Subscription`" is invalid.`n"
	    return $null
	  } else {	# $SubscriptionId passed
	    Write-Error "Subscription `"$SubscriptionId`" is invalid.`n"
	    return $null
      }		
	}
  
  } else {
    # $Subscription or $SubscriptionId not specified - use subscription ID of current RM context
	$Subscription = (Get-AzureRmContext).Subscription.SubscriptionName
	$SubscriptionId = (Get-AzureRmContext).Subscription.SubscriptionId
	Write-Host "`nSubscription parameter not passed - targeting `"$Subscription`"."
  }  
  
  # build REST request URI
  $requestUri = "https://management.core.windows.net/$($SubscriptionId)/certificates"

  # build request headers for Service Management API
  # call New-AzureRestAuthorizationHeader to get "Authorization" header
  $requestHeaders = New-AzureRestAuthorizationHeader -Resource "https://management.core.windows.net/"
  if (!$requestHeaders) {
	Write-Error "Failed to get Authorization header.`n"
	return $null    
  }
  # add "x-ms-version" header
  $requestHeaders.Add("x-ms-version", "2012-03-01")
  
  ##################################################
  # LIST management certificates of the subscription
  if ($List) {
    # invoke REST request
	try {
	  $response = Invoke-RestMethod -Uri $requestUri -Method Get -ContentType "application/xml" -Headers $requestHeaders
	} catch {
	  Write-Error "REST request to list management certs for subscription `"$Subscription`" failed.`n"
	  Write-Error $_
	  return $null	  
	}
	
	if (!$response.SubscriptionCertificates.SubscriptionCertificate) {
	  Write-Host "`nSubscription `"$Subscription`" has 0 management certificates.`n"
	  return $null
	} else {
	  Write-Host "`nListing management certificates for subscription `"$Subscription`":`n"
	}
	
	# create array of cert objects
	$mgmtCerts = @()
	
	foreach ($certElement in $response.SubscriptionCertificates.SubscriptionCertificate) {	
	  $certBytes = [System.Convert]::FromBase64String($certElement.SubscriptionCertificateData)
	  $certObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
	  $certObject.Import($certBytes, $null, "PersistKeySet")
	  Write-Host "   Subject:`t $($certObject.Subject)"
	  Write-Host "   Issuer:`t $($certObject.Issuer)"
	  Write-Host "   Thumbprint:`t $($certObject.Thumbprint)"
	  Write-Host "   Expires:`t $($certObject.NotAfter)`n"
	  $mgmtCerts += $certObject	
	}
	
	Write-Host "Subscription `"$Subscription`" has $($mgmtCerts.Count) management certificates.`n"
	
	# return array of X509Certificate2 objects
	return $mgmtCerts	
  }
  
  ################################################
  # ADD management certificate to the subscription
  if ($Cert) {
  
# build request body
[xml]$requestBody = @"
<SubscriptionCertificate xmlns=`"http://schemas.microsoft.com/windowsazure`">
  <SubscriptionCertificatePublicKey>$([System.Convert]::ToBase64String($Cert.GetPublicKey()))</SubscriptionCertificatePublicKey>
  <SubscriptionCertificateThumbprint>$($Cert.Thumbprint)</SubscriptionCertificateThumbprint>
  <SubscriptionCertificateData>$([System.Convert]::ToBase64String($Cert.RawData))</SubscriptionCertificateData>
</SubscriptionCertificate>
"@

    # check that management cert is not already present
	try {
	  $response = Invoke-RestMethod -Uri $requestUri -Method Get -ContentType "application/xml" -Headers $requestHeaders
	} catch {
	  Write-Error "REST request to list management certs for subscription `"$Subscription`" failed.`n"
	  Write-Error $_
	  return $null	  
	}
	
	foreach ($subCert in $response.SubscriptionCertificates.SubscriptionCertificate) {	  
	  if ($subCert.SubscriptionCertificateThumbprint -eq $Cert.Thumbprint) {
	    Write-Host "`nCertificate with thumbprint `"$($Cert.Thumbprint)`" is already an admin of subscription `"$Subscription`".`n" -ForegroundColor Yellow
		return $null
	  }
	} 

	# invoke REST request to add management cert
	Write-Host "`nUploading certificate `"$($Cert.Subject)`" to subscription `"$Subscription`"... " -NoNewLine
    try {
      $response = Invoke-RestMethod -Uri $requestUri -Method Post -ContentType "application/xml" -Headers $requestHeaders -Body $requestBody
    } catch {
	  Write-Error "`n`nREST request to add management cert `"$($Cert.Subject)`" to subscription `"$Subscription`" failed."
	  Write-Error $_
	  return $null	    
    }	
	Write-Host "Done.`n"
	
	# call Azure Automation webhook to schedule automated cert removal
	if ($MinsToExpiry) {
	
	  Write-Host "Calling Azure Automation webhook to auto-remove cert after $MinsToExpiry minutes.`n"
	  
	  # get Azure Automation webhook URI from Key Vault
	  Write-Host "Fetching URI from secret `"$JitUri`" in vault `"$VaultName`"... " -NoNewLine
	  $requestUri = (Get-AzureKeyVaultSecret -VaultName $VaultName -SecretName $JitUri).SecretValueText
	  Write-Host "Done.`n"
	  
	  # build request headers
	  $requestHeaders = @{"Thumbprint"=$Cert.Thumbprint}		# the thumbprint to schedule for removal
	  $requestHeaders.Add("MinsToExpiry", $MinsToExpiry)		# when to remove it
	  $requestHeaders.Add("SubscriptionId", $SubscriptionId)	# the subscription to remove it from
	  
	  # send request to Azure Automation Webhook
	  Write-Host "Sending request... " -NoNewLine
	  $response = Invoke-WebRequest -Uri $requestUri -Method Post -Headers $requestHeaders
	  if ($response.StatusCode -eq 202) {
	    Write-Host "JIT request accepted.`n"
	  } else {
	    Write-Host "JIT request was not accepted by Webhook.`n" -ForegroundColor Red
	  }	
	}	
  }
  
  #####################################################
  # REMOVE management certificate from the subscription
  if ($DeleteByThumbprint) {
  
    Write-Host "`n"
    for ($i = 0; $i -lt $DeleteByThumbprint.Count; $i++) {
	
      # REST request URI
      $requestUri = "https://management.core.windows.net/$($SubscriptionId)/certificates/" + $DeleteByThumbprint[$i]
	  
	  # check if cert with thumbprint exists
	  try {
	    $response = Invoke-RestMethod -Uri $requestUri -Method Get -Headers $requestHeaders
	  } catch {}
	  
	  if (!$response) {
	    Write-Host "Certificate with thumbprint `"$($DeleteByThumbprint[$i])`" does not exist in subscription `"$Subscription`"." -ForegroundColor Yellow
		continue
	  }	  
	  
      # delete cert
      try {
        $response = Invoke-RestMethod -Uri $requestUri -Method Delete -Headers $requestHeaders
      } catch {
	    Write-Error "REST request to delete management cert with thumbprint `"$($DeleteByThumbprint[$i])`" from subscription `"$Subscription`" failed."
	    Write-Error $_
	    continue    
      }
	  Write-Host "Certificate with thumbprint `"$($DeleteByThumbprint[$i])`" deleted from subscription `"$Subscription`"."
	}
	Write-Host "`n"
  }  
}

<#
.SYNOPSIS
    Grants a user, group or service principal to role assignments for a resource, resource group or subscription.
.DESCRIPTION
	Use either -ResourceId, -ResourceGroup or -Subscription to set the scope of the role assignment.
	If none of these are specified, the role assignment will scoped to the current subscription.
    If the role is not specified, the "Contributor" role is assumed.
.PARAMETER Subscription
    The name of the Azure subscription that will receive the role assignment if -ResourceId or -ResourceGroup is not specified.
	If a value is not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER ResourceGroup
    The name of the resource group to grant access to.
.PARAMETER ResourceId
    The ARM resource ID of the resource to grant access to.
	This parameter accepts pipeline input, so is best used by piping the Id from a GET of the object (see example)
.PARAMETER Group
    The name of the group to grant access to.
.PARAMETER User
    The name of the user to grant access to.
.PARAMETER ServicePrincipal
    The name of the service principal to grant access to. Specify the name as either the identifier URI or application Id - not the display name.
.PARAMETER Role
    The name of the role to assign. Defaults to "Contributor".
	Use Get-AzureRMRoleDefinition to see a list of available roles.
.EXAMPLE
    Set-Permissions -ResourceGroup "myRG" -Group "myGroup"
    Assigns the "Contributor" role over resource group "myRG" to group "myGroup".
.EXAMPLE
    Set-Permissions "myGroup"
    Assigns the "Contributor" role over the current subscription to group "myGroup".
.EXAMPLE
    (Get-AzureRmKeyVault -VaultName "myVault").ResourceId | Set-Permissions -ServicePrincipal http://myserviceprincipal -Role "Key Vault Contributor"
    Pipes the ARM resource ID of Key Vault "myVault" to Set-Permissions, and grants a service principal the "Key Vault Contributor" role.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   October 15, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Set-Permissions {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",
    [Parameter(Mandatory = $false)]
    [String]$ResourceGroup,
    [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
    [String]$ResourceId,	
    [Parameter(Mandatory = $true, ParameterSetName = "Group")]
    [String]$Group,
    [Parameter(Mandatory = $true, ParameterSetName = "User")]
    [String]$User,
    [Parameter(Mandatory = $true, ParameterSetName = "ServicePrincipal")]
    [String]$ServicePrincipal,
    [Parameter(Mandatory = $false)]
    [String]$Role = "Contributor"
  )
  
  # check login to AAD
  $rmContext = Login-AzureRm $Subscription
  if (!$rmContext) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }

  # validate resource group
  if ($ResourceGroup) {
    try {
      $rgs = Get-AzureRmResourceGroup
    } catch {
      Write-Error "Unable to enumerate resource groups.`n"
      return $null
    }
    $rgValid = $false
    foreach ($rg in $rgs) {
      if ($rg.ResourceGroupName -eq $ResourceGroup) {
        $rgValid = $true
        break
      }
    }
    if (!$rgValid) {
      Write-Error "Resource group `"$ResourceGroup`" not found. Try again with the -Subscription parameter.`n"
      return $null
    }
  }

  # validate role
  if ($Role -ne "Contributor") {
      if (!(Get-AzureRmRoleDefinition -Name $Role)) {
          Write-Error "Role `"$Role`" does not exist.`n"
          return $null
      }
  }

  # lookup $Group
  if ($Group) {
      $principal = (Get-AzureRmADGroup -SearchString $Group)[0]
      if (!$principal) {
          Write-Error "Cannot find group `"$Group`".`n"
          return $null
      }      
  }

  # lookup $User
  if ($User) {
      $principal = Get-AzureRmADUser -UserPrincipalName $User
      if (!$principal) {
          Write-Error "Cannot find user `"$User`".`n"
          return $null
      }      
  }

  # lookup $ServicePrincipal
  if ($ServicePrincipal) {
      $principal = Get-AzureRmADServicePrincipal -ServicePrincipalName $ServicePrincipal
      if (!$principal) {
          Write-Error "Cannot find service principal `"$ServicePrincipal`".`n"
          return $null
      }      
  }

  # assign the $principal to the $Role at the resource scope (if specified) and return
  if ($ResourceId) {
    try {
      Write-Host "Assigning role `"$Role`" to `"$($principal.DisplayName)`" over resource `"$ResourceId`"... " -NoNewline
      $result = New-AzureRmRoleAssignment -ObjectId $principal.Id.Guid -Scope $ResourceId -RoleDefinitionName $Role -ErrorAction Stop
	  Write-Host "Done.`n"
	  return $result
    } catch {
      Write-Host "`n"
      Write-Error $_
      return $null
    }
  }
  
  # assign the $principal to the $Role at the resource group scope (if specified) and return
  if ($ResourceGroup) {
    try {
      Write-Host "Assigning role `"$Role`" to `"$($principal.DisplayName)`" over resource group `"$ResourceGroup`"... " -NoNewline
      $result = New-AzureRmRoleAssignment -ObjectId $principal.Id.Guid -ResourceGroupName $ResourceGroup -RoleDefinitionName $Role -ErrorAction Stop
	  Write-Host "Done.`n"
	  return $result
    } catch {
      Write-Host "`n"
      Write-Error $_
      return $null
    }
  }  

  # assign the $principal to the $Role at the subscription scope
  if ($Subscription) {
    try {
      $scope = "/subscriptions/" + $rmContext.Subscription.SubscriptionId
      Write-Host "Assigning role `"$Role`" to `"$($principal.DisplayName)`" over subscription `"$($rmContext.Subscription.SubscriptionName)`"... " -NoNewline
      $result = New-AzureRmRoleAssignment -ObjectId $principal.Id.Guid -Scope $scope -RoleDefinitionName $Role -ErrorAction Stop
	  Write-Host "Done.`n"
	  return $result
    } catch {
      Write-Host "`n"
      Write-Error $_
      return $null
    }
  }    
}

<#
.SYNOPSIS
    Tests whether the identity has permissions to perfrom the desired action.
	Returns $true if identity has permission, $false if it doesn't, or $null on error.
.PARAMETER Vault
    The PSVault object to test permissions on.
.PARAMETER RmContext
    The PSAzureContext that PowerShell is running as.
.PARAMETER Action
    Available actions - "CertsAll", "CertsRead", "CertsImport", "SecretsRead", "SecretsWrite"
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   October 12, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Test-KeyVaultPermissions {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $true)]
    [Microsoft.Azure.Commands.KeyVault.Models.PSVault]$Vault,
    [Parameter(Mandatory = $true)]
    [Microsoft.Azure.Commands.Profile.Models.PSAzureContext]$RmContext,
    [Parameter(Mandatory = $true)]
	[ValidateSet("CertsAll", "CertsRead", "CertsImport", "SecretsRead", "SecretsWrite")]
    [String]$Action
  )
  
  # get object ID from RM context
  Switch ($RmContext.Account.AccountType) {
  
    "User" {
	  $objectId = (Get-AzureRmADUser -UserPrincipalName $RmContext.Account.Id).Id.Guid
	  
	  # if calling user is an MSA, the UPN will not be the email address so will return null
	  if (!$objectId) {
	    
		# check if the user's email address is contained in the UPN (format: <email address>#EXT#*.onmicrosoft.com)
		$str = ($RmContext.Account.Id).Replace("@", "_") + "#"
		$allUsers = Get-AzureRmADUser
		foreach($user in $allUsers) {
		  if ($user.UserPrincipalName.StartsWith($str)) {
		    $objectId = $user.Id.Guid
		    Break
		  }		
		}
	  }
	  
	  # if still cant resolve object ID, throw error and return
	  if (!$objectId) {
        Write-Error "Unable to resolve user $($RmContext.Account.Id).`n"
	    return $null	
	  }
	}
	
	"ServicePrincipal" {
	  $objectId = (Get-AzureRmADServicePrincipal -ServicePrincipalName $RmContext.Account.Id).Id.Guid
	  
	  # if cant resolve object ID, throw error and return
	  if (!$objectId) {
        Write-Error "Unable to resolve user $($RmContext.Account.Id).`n"
	    return $null	
	  }	  
	}
	
	default {
      Write-Error "Account type $($RmContext.Account.AccountType) is not supported.`n"
	  return $null	
	}  
  }  
  
  # get required permissions based on action  
  Switch ($Action) {
	"CertsAll" {
	  $type = "Certs"
	  $requiredPerms = ("all")
	}  
	"CertsRead" {
	  $type = "Certs"
	  $requiredPerms = ("all", "get")
	}
	"CertsImport" {
	  $type = "Certs"
	  $requiredPerms = ("all", "import")
	}
	"SecretsRead" {
	  $type = "Secrets"
	  $requiredPerms = ("all", "get")
	}
	"SecretsWrite" {
	  $type = "Secrets"
	  $requiredPerms = ("all", "set")
	}	  
  }  
  
  # get actual permissions assigned to objectId
  foreach ($accessPolicy in ($Vault.AccessPolicies | where {$_.ObjectId.Guid -eq $objectId})) {

	Switch ($type) {
	  "Certs" {$actualPerms = $accessPolicy.PermissionsToCertificates}
	  "Secrets" {$actualPerms = $accessPolicy.PermissionsToSecrets}
	}
	break	
  }
  
  # return false if object ID has no permissions
  if (!$actualPerms) {
    return $false
  }
  
  # compare permissions
  $result = $actualPerms | where {$requiredPerms -contains $_.ToLower()}
  if ($result) {
    return $true
  } else {
    return $false
  }

}

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

<#
.SYNOPSIS
    Logs in to Azure Resource Management (ARM) API as a service principal and sets the subscription context.
.DESCRIPTION
	If -TenantId, -ApplicationId and -CertThumbprint are not specified, the cmdlet will search the machine's (by default) or user's "My" store for a certificate with EKU for Azure AD authentication (1.3.6.1.4.1.311.91.8.1).
	The ApplicationId and TenantId are expected in the subject name of the certificate. If multiple such certificates are found, the most recently issued one will be used.
	Alternatively, -TenantId, -ApplicationId and -CertThumbprint can be specified to identify and service principal and certificate to use.
	Returns the current RM context if successful, or $null if login fails.
.PARAMETER SubscriptionName
    Optional. The name of the Azure subscription to set the current RM context to.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER SubscriptionId
    Optional. The ID of the Azure subscription to set the current RM context to.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.	
.PARAMETER TenantId
    The TenantId to logon to.
    This is only required if a certificate with EKU for Azure AD authentication (1.3.6.1.4.1.311.91.8.1) is not in the machine's (or user's) "My" store.
.PARAMETER ApplicationId
    The ApplicationId to which the service principal is associated.
    This is only required if a certificate with EKU for Azure AD authentication (1.3.6.1.4.1.311.91.8.1) is not in the machine's (or user's) "My" store.
.PARAMETER CertThumbprint
    The thumbprint of the certificate registered against the service principal. This certificate must be present in the machine's (or user's) "My" store.
	This is only required if a certificate with EKU for Azure AD authentication (1.3.6.1.4.1.311.91.8.1) is not in the machine's (or user's) "My" store.
.PARAMETER CertStore
    Specifies whether to look in the computer or user certificate store. Valid values are "CurrentUser" or "LocalMachine" (the default).
.EXAMPLE
    Login-AzureRmAsServicePrincipal
	Parameters are not required if a certificate with EKU OID 1.3.6.1.4.1.311.91.8.1 is present in the computer's Machine\My store, and subject name is CN=<app ID>@<tenant ID>
.EXAMPLE
    Login-AzureRmAsServicePrincipal -TenantId <TenantId> -ApplicationId "http://myApp" -CertThumbprint <cert thumbprint>
	Use a certificate without the required EKU OID that has been assigned to the service principal of application http://myApp (the application's identifier URI or application ID can be specified - not the display name).
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   October 22, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Add-AzureRmAsServicePrincipal {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $false, ParameterSetName = "LegacyCert")]
	[Parameter(ParameterSetName = "EkuCert")]
    [String]$SubscriptionName,
    [Parameter(Mandatory = $false, ParameterSetName = "LegacyCert")]
	[Parameter(ParameterSetName = "EkuCert")]
    [String]$SubscriptionId,	
    [Parameter(Mandatory = $false, ParameterSetName = "LegacyCert")]
    [String]$TenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47",		# defaults to the Microsoft tenant
    [Parameter(Mandatory = $true, ParameterSetName = "LegacyCert")]
    [String]$ApplicationId,
    [Parameter(Mandatory = $true, ParameterSetName = "LegacyCert")]
    [String]$CertThumbprint,
    [Parameter(Mandatory = $false, ParameterSetName = "LegacyCert")]
	[Parameter(ParameterSetName = "EkuCert")]
	[ValidateSet("CurrentUser","LocalMachine")]
    [String]$CertStore = "LocalMachine"
  )
  
  if (!$CertThumbprint) {		# look for cert with EKU for Azure AD authentication (1.3.6.1.4.1.311.91.8.1)  

    # get certs in local machine or user store that have the EKU
	if ($CertStore -eq "LocalMachine") {
      $certs = Get-ChildItem Cert:\LocalMachine\My | where {$_.EnhancedKeyUsageList.ObjectId -eq "1.3.6.1.4.1.311.91.8.1"}
	} else {
	  $certs = Get-ChildItem Cert:\CurrentUser\My | where {$_.EnhancedKeyUsageList.ObjectId -eq "1.3.6.1.4.1.311.91.8.1"}
	}

    # return if no cert found
    if (!$certs) {
      Write-Host "`nNo certificate with EKU = 1.3.6.1.4.1.311.91.8.1 was found in the local machine store."
	  Write-Host "Try again using -TenantId, -ApplicationId and -CertThumbprint parameters.`n"
	  return $null
    }
  
    # if multiple certs found, choose the one with latest NotBefore date
    if ($certs.GetType().Name -eq "Object[]") {
	
	  $index = 0
	  $latestNotBefore = $certs[0].NotBefore
	  for ($i = 1; $i -lt $certs.Count; $i++) {
	    
		if ($certs[$i].NotBefore -gt $latestNotBefore) {
		  $latestNotBefore = $certs[$i].NotBefore
		  $index = $i
		}
	  }
	  $cert = $certs[$index]

    } else {	# only 1 matching cert found 
	  $cert = $certs
	}
	
	# get values from certificate
	$sn = $cert.Subject.Substring(3).Split("@")
	$ApplicationId = $sn[0]
	$TenantId = $sn[1]
	$CertThumbprint = $cert.Thumbprint
  }

  # authenticate service principal
  Write-Host "`nAuthenticating as service principal..."
  try {
    $rmContext = Add-AzureRmAccount -ServicePrincipal -TenantId $TenantId -ApplicationId $ApplicationId -CertificateThumbprint $CertThumbprint -ErrorAction Stop
  } catch {
    Write-Host "Failed to authenticate service principal:"
	Write-Host "   Tenant ID:`t`t $TenantId"
	Write-Host "   Application ID:`t $ApplicationId"
	Write-Host "   Cert thumbprint:`t $CertificateThumbprint`n"
	Write-Host "Confirm these values and that the service principal has at least Reader role access to at least 1 subscription.`n"
	return $null
  }
  
  # change active subscription if $SubscriptionName passed
  if ($SubscriptionName -and ($rmContext.Context.Subscription.SubscriptionName -ne $SubscriptionName)) {  
    Write-Host "Changing from subscription `"$($rmContext.Context.Subscription.SubscriptionName)`" to `"$SubscriptionName`""
	try {
	  Set-AzureRMContext -SubscriptionName $SubscriptionName -ErrorAction Stop | Out-Null
	} catch {
	  Write-Host "Failed to change to subscription `"$SubscriptionName`"." -ForegroundColor Red
	  Write-Host "Does service principal `"$ApplicationId`" have at least Reader role access to that subscription?`n"
	  return $null
	}
  }
  
  # change active subscription if $SubscriptionId passed
  if ($SubscriptionId -and ($rmContext.Context.Subscription.SubscriptionId -ne $SubscriptionId)) {
    Write-Host "Changing from subscription `"$($rmContext.Context.Subscription.SubscriptionId)`" to `"$SubscriptionId`""
	try {
	  Set-AzureRMContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
	} catch {
	  Write-Host "Failed to change to subscription `"$SubscriptionId`"." -ForegroundColor Red
	  Write-Host "Does service principal `"$ApplicationId`" have at least Reader role access to that subscription?`n"
	  return $null
	}
  }
  
  # return RM context
  return Get-AzureRMContext
}

<#
.SYNOPSIS
    Replaces placeholders in config files with encrypted secrets from Key Vault.
.DESCRIPTION
	This is primarily intended for services using Express v2 for PROD deployments - allowing them to securely develop/debug locally without requiring code changes.
    It does this by mimicking the secret replacement functionality of Ev2 when the application is deployed locally via a different means.
	There are 2 ways to use this:
	  1) Modify the "EncryptWith" value to specify a Key Vault certificate URI. Then use "Get-KeyVaultCertificate" to install that certificate to the machine running the application.
	  2) Specify the thumbprint of an already installed certificate (in the user or machine store). That certificate will be used to encrypt the secrets in the config file.
	The original config file is backed up with a .ORIGINAL extension. 
.PARAMETER Subscription
    Optional. The name of the Azure subscription containing the Key Vault.
	If not specified, the subscription used will be:
	- if not already logged in, the first subscription in the list returned after login.
	- if already logged in, the currently targeted subscription.
.PARAMETER ParametersFile
    The full path and file name of the ARM parameters file containing the replacement directives.
.PARAMETER ConfigBasePath
    (Optional). The path to the Ev2 build root folder.
    If not specified, the parent of the folder containing the parameters file will be assumed. 
.PARAMETER CertThumbprint
    The thumbprint of the certificate to encrypt the secrets with. This certificate must be present in the user's (by default) or machine's "My" store.
.PARAMETER CertStore
    Specifies whether to look in the computer or user certificate store. Valid values are "CurrentUser" (the default) or "LocalMachine".
.EXAMPLE
    Get-SecretsForLocalDeployment -ParametersFile d:\repo\myApp\ServiceGroupRoot\Parameters\AppLoader001.Parameters.json
	Replace placeholders as specified in parameters file, getting secrets and encryption certificates from Key Vault.
.EXAMPLE
    Get-SecretsForLocalDeployment -ParametersFile d:\repo\myApp\ServiceGroupRoot\Parameters\AppLoader001.Parameters.json -CertThumbprint <thumbprint>
	Replace placeholders as specified in parameters file, getting secrets from Key Vault and the encryption certificate from the user's "My" certificate store.
.NOTES
    Author: Nick Torkington (nicktork@microsoft.com)
    Date:   October 22, 2016    
.LINK
    https://aka.ms/kvhelper
#>
function Get-SecretsForLocalDeployment {

  [CmdletBinding()]  
  param(
    [Parameter(Mandatory = $false)]
    [String]$Subscription = "first",    
	[Parameter(Mandatory = $true)]
    [String]$ParametersFile,
    [Parameter(Mandatory = $false)]
    [String]$ConfigBasePath,
    [Parameter(Mandatory = $false)]
    [String]$CertThumbprint,
    [Parameter(Mandatory = $false)]
	[ValidateSet("CurrentUser","LocalMachine")]
    [String]$CertStore = "CurrentUser"
  )
  
  # check login to AAD
  $rmContext = Login-AzureRm $Subscription
  if (!$rmContext) {
    Write-Error "Unable to login to Azure AD.`n"
    return $null
  }  

  # read parameters file (without comments) and convert from Json
  if (!(Test-Path $ParametersFile)) {
    Write-Host "`n`"$ParametersFile`" not found.`n" -ForegroundColor Red
	return $null
  }
  $config = Get-Content($ParametersFile) | where {!($_.Trim().StartsWith("//"))} | ConvertFrom-Json
  
  # get configuration base path
  if ($ConfigBasePath) {
  
    # ensure base path of configuration ends in "\"
    if ($ConfigBasePath.Substring($ConfigBasePath.Length - 1) -ne "\") {
      $ConfigBasePath += "\"
    }
  } else {		# determine base path relative to parameters file
    $paramElements = $ParametersFile.Split("\")
	for ($i = 0; $i -lt ($paramElements.Count - 2); $i++) {
	  $ConfigBasePath += $paramElements[$i] + "\"
	}
  }
  
  # initialize counters
  $replacements = 0
  $skipped = 0
  
  # get cert if specified by thumbprint
  if ($CertThumbprint) {

	if ($CertStore -eq "CurrentUser") {
      $cert = Get-ChildItem Cert:\CurrentUser\My | where {$_.Thumbprint -eq $CertThumbprint}
	} else {
	  $cert = Get-ChildItem Cert:\LocalMachine\My | where {$_.Thumbprint -eq $CertThumbprint}
	}

    # return if no cert found
    if (!$cert) {
      Write-Host "`nNo certificate with thumbprint `"$CertThumbprint`" was found in store `"$CertStore`".`n"
	  return $null
    }
	Write-Host "Encrypting secrets with certificate `"$($cert.Thumbprint)`" installed in store `"$CertStore`".`n"
	$certFromStore = $true
  }

  # iterate through each secret in parameters file
  foreach ($secret in $config.secrets) {

    if ($secret.TargetReference -and ($secret.TargetReference -ne "None")) {
  
      # get the corresponding parameter that points to the config file
      if ($config.parameters.$($secret.TargetReference)) {
	    $configFile = $ConfigBasePath + ($config.parameters.$($secret.TargetReference).value).TrimStart("\")
		if (!(Test-Path $configFile)) {
          Write-Host "`nConfiguration file `"$configFile`" not found.`n" -ForegroundColor Red
	      return $null
        }		
	  }
	  Write-Host "Replacing placeholders with secrets in file:"
      Write-Host $configFile
	
	  # build an array of replacement names
	  $replacementNames = @()
	  foreach ($replacement in ($secret.Replacements | gm -MemberType NoteProperty)) {
	    $replacementNames += $replacement.Name
	  }
	
	  # iterate through each replacement in current secret section
	  foreach ($replacementName in $replacementNames) {
	
	    # check number of replacements to be made and exit loop if zero
		$matches = Get-Content $configFile | where {$_ -Match $replacementName}
		if (!$matches) {
		  Write-Host "`nThere are 0 occurences of `"$replacementName`" in config file."
		  Continue
		}
		Write-Host "`nThere are $($matches.Count) occurences of placeholder `"$replacementName`" in config file."
	
        # get replacement		
		$replacement = $secret.Replacements.$($replacementName)
		
		# check that the value is to be encrypted - otherwise skip it
	    if ($replacement.EncryptWith) {
		
		  # skip if not a valid secret URI
		  if ((!$replacement.SecretId.StartsWith("https://")) -or (!$replacement.SecretId.Contains(".vault.azure.net"))) {
		    Write-Host "Skipping replacement of `"$replacementName`" with SecretId `"$($replacement.SecretId)`"" -ForegroundColor Yellow
			Write-Host "This is not a valid Key Vault secret URI." -ForegroundColor Yellow
			$skipped++
			Continue
		  }
		  
		  # parse URI for secret properties
		  $subString = $replacement.SecretId.SubString(8)
		  $secretVaultName = $subString.Split(".")[0]
		  $secretName = $subString.Split("/")[2]
		  $secretVersion = $subString.Split("/")[3]		# will hold the version number or be null
		  
# confirm whether EV2 supports retrieving certs from the /certificates endpoint
		  # skip if not a valid certificate URI
		  if ((!$replacement.EncryptWith.StartsWith("https://")) -or (!$replacement.EncryptWith.Contains(".vault.azure.net"))) {
		    Write-Host "Skipping replacement of `"$replacementName`" with encryption certificate `"$($replacement.EncryptWith)`"" -ForegroundColor Yellow
			Write-Host "This is not a valid Key Vault certificate URI." -ForegroundColor Yellow
			$skipped++
			Continue
		  }
		  
		  # parse URI for certificate properties
		  $subString = $replacement.EncryptWith.SubString(8)
		  $certVaultName = $subString.Split(".")[0]
		  $certName = $subString.Split("/")[2]
		  $certVersion = $subString.Split("/")[3]		# will hold the version number or be null
		  
		  # retrieve the secret from Key Vault
		  Write-Host "Retrieving secret `"$secretName`" from vault `"$secretVaultName`"... " -NoNewLine
		  try {
		    if ($secretVersion) {
		      $secretText = (Get-AzureKeyVaultSecret -VaultName $secretVaultName -Name $secretName -Version $secretVersion -ErrorAction Stop).SecretValueText
		    } else {
		      $secretText = (Get-AzureKeyVaultSecret -VaultName $secretVaultName -Name $secretName -ErrorAction Stop).SecretValueText
		    }
		  } catch {
		    Write-Error "`nFailed to retrieve secret `"$secretName`" from vault `"$secretVaultName`".`n"
			return $null
		  }
		  Write-Host "Done."
		  
		  # retrieve the encryption certificate from Key Vault if not using cert from local store
		  if (!$certFromStore) {
		  
		    # if cert has same properties as last retrieved cert, skip retrieval
		    if (($certVaultName -eq $lastCertVaultName) -and ($certName -eq $lastCertName) -and ($certVersion -eq $lastCertVersion)) {
		      Write-Host "Reusing encryption certificate `"$certName`"."
		    } else {
  	      
		      # retrieve the cert from Key Vault
		      if ($certVersion) {
		        $cert = Get-KeyVaultCertificate -VaultName $certVaultName -CertName $certName -CertVersion $certVersion -PrivateKey
		      } else {
		        $cert = Get-KeyVaultCertificate -VaultName $certVaultName -CertName $certName -PrivateKey
		      }
		      if (!$cert) {
		        return $null
		      }
		      Write-Host "Done."
		      $lastCertVaultName = $certVaultName
		      $lastCertName = $certName
		      $lastCertVersion = $certVersion
		    }
		  }
		  
		  # encrypt the secret with the cert
		  $encSecret = Encrypt-StringWithCert -StringToEncrypt $secretText -Cert $cert
		  if (!$encSecret) {
		    Write-Error "Failed to encrypt secret with certificate.`n"
			return $null
		  }
		  
		  # get path of config file backup folder and name of backup config file 
		  $configElements = $configFile.Split("\")
		  $backupPath = ""
	      for ($i = 0; $i -lt ($configElements.Count - 1); $i++) {
	        $backupPath += $configElements[$i] + "\"
		  }
		  $backupPath += "ORIGINAL"
		  $backupFileName = $backupPath + "\" + $configElements[$configElements.Length - 1]

		  # create backup folder if it doesn't exist
		  if (!(Test-Path $backupPath)) {
		    New-Item $backupPath -Type Directory | Out-Null
		  }
		  
		  # backup config file
		  if (!(Test-Path $backupFileName)) {
		    Copy-Item $configFile $backupFileName
		  }		  
		  
		  # replace placeholder with encrypted secret
		  Write-Host "Replacing placeholder `"$replacementName`" with encrypted secret... " -NoNewLine -ForegroundColor Green
		  try {
		    (Get-Content $configFile) -Replace ($replacementName, $encSecret) | Out-File $configFile
		  } catch {
		    Write-Error "Failed to update file $configFile`n"
			return $null
		  }
		  Write-Host "Done." -ForegroundColor Green
		  $replacements++
		
	    }
	    else {
	      Write-Host "Skipping replacement of `"$replacementName`" with secret at `"$($replacement.SecretId)`"" -ForegroundColor Yellow
		  Write-Host "You must specify a certificate to encrypt the secret with." -ForegroundColor Yellow
		  $skipped++
	    }	
	  }  
    }
  }
  Write-Host "`nPlaceholders replaced:`t $replacements" -ForegroundColor Green
  Write-Host "Placeholders skipped:`t $skipped`n" -ForegroundColor Green
}

New-Alias -Name Encrypt-StringWithCert -Value Protect-StringWithCert
New-Alias -Name Manage-StorageAccount -Value Update-StorageAccount
New-Alias -Name Manage-SubMgmtCert -Value Update-SubMgmtCert
New-Alias -Name Login-AzureRmAsServicePrincipal -Value Add-AzureRmAsServicePrincipal

Export-ModuleMember -Function Set-KeyVaultCertificate
Export-ModuleMember -Function Set-KeyVaultSecret
Export-ModuleMember -Function Get-KeyVaultCertificate
Export-ModuleMember -Function New-ServicePrincipal
Export-ModuleMember -Function Protect-StringWithCert -Alias *
Export-ModuleMember -Function New-Password
Export-ModuleMember -Function New-AzureKeyVault
Export-ModuleMember -Function New-Certificate
Export-ModuleMember -Function Update-StorageAccount -Alias *
Export-ModuleMember -Function Update-SubMgmtCert -Alias *
Export-ModuleMember -Function Set-Permissions
Export-ModuleMember -Function New-BootstrapIdentity
Export-ModuleMember -Function Test-KeyVaultName
Export-ModuleMember -Function Test-KeyVaultLocation
Export-ModuleMember -Function Test-KeyVaultPermissions
Export-ModuleMember -Function Add-WebAppCertFromKeyVault
Export-ModuleMember -Function Add-AzureRmAsServicePrincipal -Alias *
Export-ModuleMember -Function Get-SecretsForLocalDeployment
