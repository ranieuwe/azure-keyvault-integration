# Settings
$sub = '011d1fae-39f9-495e-a55c-ec4c4219d301' 
$prefix = 'ronieuwecrt'
$adAppName = $prefix + "kvwa"
$webAppName = $prefix + "app"
$resourceGroupName = $prefix

Try {
  Get-AzureRmContext
} Catch {
  if ($_ -like "*Login-AzureRmAccount to login*") {
    Login-AzureRmAccount -SubscriptionId $sub
  }
}

# Grab the resource group if it exists, if not then create it and then grab it
$rg = Get-AzureRmResourceGroup -Name $resourceGroupName -ev rgNotPresent -ea 0

If (!$rgNotPresent) {
	Remove-AzureRmResourceGroup -Name $prefix -Force
} 

$app = Get-AzureRmADApplication -DisplayNameStartWith $adAppName

Remove-AzureRmADApplication -ObjectId $app.ObjectId
