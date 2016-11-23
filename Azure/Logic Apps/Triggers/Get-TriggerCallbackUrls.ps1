#########################################################################################################
# GetTriggerCallbackUrls
# This snippet retrieves the Callback Urls of a given Logic App
# Set these variables
#	$ScriptUser...			User to run the script with (needs to be an AAD User with approriate rights in Azure)
#   $ScriptPassWord...		Password, remove the Read-Host if you do not want to type
#   $ScubscriptionName...	In case you have multiple subscriptions this lets you filter the subscription by Name
#							If your filter applies to multiple subscriptions the first one is used
#	$resourceGroupName...	Name of ResourceGroup the LogicApp is in
#	$logicAppName...		Name of the LogicApp
#	$$LibraryPath_ADAL...	Directory where Microsoft.IdentityModel.Clients.ActiveDirectory.dll is located
#
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
#########################################################################################################

#Define variables
$ScriptUser="<Azure AAD Account, no hotmail!!!>"
$ScriptUserPassWord = ConvertTo-SecureString –String "<Your secret password for test>" –AsPlainText -Force
$ScriptUserPassWord = Read-Host 'What is your password?' -AsSecureString
$subscriptionName = "*Ultimate"         
$resourceGroupName ="LogicAppDemo"
$logicAppName = "LogicApp"
$LibraryPath_ADAL = "..\..\..\Dependencies\AzureAD\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    
#Login to Azure
$Credential = New-Object –TypeName "System.Management.Automation.PSCredential" –ArgumentList $ScriptUser, $ScriptUserPassWord
Login-AzureRmAccount -Credential $Credential
#Locate subscription with Name Filter
$subscriptionId = Get-AzureRmSubscription | where {$_.SubscriptionName -like $subscriptionName} | Select SubscriptionId
$subscriptionId = $subscriptionId[0].SubscriptionId
$subscription = Select-AzureRmSubscription -SubscriptionId $subscriptionId
$tenantId = $subscription.Tenant.TenantId

# Add ADAL Library
Add-Type -Path $LibraryPath_ADAL

#Fetch Authentication Token for 'https://management.core.windows.net/','https://management.azure.com/','https://graph.windows.net'
$resourceUrl = "https://management.azure.com/"
$clientId = "1950a258-227b-4e31-a9cf-717495945fc2" # Powershell - APP ID
$redirectUrl = "urn:ietf:wg:oauth:2.0:oob"
$authString = "https://login.microsoftonline.com/" + $tenantId   # Authority
    
$authenticationContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $authString, $FALSE
$accessToken = $authenticationContext.AcquireToken($resourceUrl, $clientId, $redirectUrl, "Auto").AccessToken
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization","Bearer " +  $accessToken)

# Retrieve the basic definition of the workflow
$resUrl="https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Logic/workflows/$logicAppName"+"?api-version=2015-02-01-preview"
$response = Invoke-RestMethod $resUrl -Method GET -Headers $headers -ContentType "application/json"
# Fetch the triggers definition
$triggers = $response.properties.definition.triggers
# Get the triggers
$triggers = (Get-Member -InputObject $response.properties.definition.triggers -MemberType NoteProperty)
foreach($trigger in $triggers)
{
    $triggerName = $trigger.Name
    $inputSchema = $response.properties.definition.triggers.$triggerName.inputs
    $resUrl = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Logic/workflows/$logicAppName/triggers/$triggerName/listCallbackURL?api-version=2015-08-01-preview"
    $json=""
    $response = Invoke-RestMethod $resUrl -Method Post -Headers $headers -Body $json -ContentType "application/json"
    Write-Host "The callback url of trigger '$triggerName' is"$response.value
}

