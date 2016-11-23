#########################################################################################################
# These collection provides various method to ease the creation of Azure AAD Applications and Service
# Principals. It also allows to define Application Roles and grant OAuth2Permissions.
#
# Methods:
#	AssertNotNull($obj, $msg)
#	Invoke-PostRequestAsJson($uri, $headers, $body)
#	Get-AuthorizationHeaders($tenantId, $resourceUrl, $getBearerHeader=$false, $clientId, $clientSecret=$null)
#	Create-AADApplication($tenantId, $headers, $displayName, $domain, $aadAppIsWebApp, $requiredResourceAccess, $aadAppRoles, $replyUrl=$null, $homePage=$null)
#	Create-AADServicePrincipal($tenantId, $headers, $aadApp, $aadAppRoleAssignmentRequired)
#	Get-PrincipalbyclientId($tenantId, $headers, $clientId)
#	Get-PrincipalbyObjectId($tenantId, $headers, $objectId)
#	Grant-OAuth2Permission($tenantId, $headers, $servicePrincipalId,$permissionScope,$grantDurationInYears,$isAdminConsent,$consentedPrincipalId,$resourcePrincipalId)
#	Grant-OAuth2PermissionWithRequiredResourceAccess($tenantId, $headers, $grantDurationInYears,$isAdminConsent,$servicePrincipalId, $requiredResourceAccess)
#	Get-RessourceAccessByDefinition($definition,$tenantId, $headers)
#	Get-RessourceAccessByName($servicePrincipal,$valueName)
# Sample:
#   Usage Sample Code at the end
#   Search for "REPLACE FOR TEST:" and put in your own values
#
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
#########################################################################################################

# Constants
$graphAPI_resourceUrl = "https://graph.windows.net"
$graphAPI_clientId = "00000002-0000-0000-c000-000000000000" # GraphID - APP ID/ClientID
$powershell_clientId = "1950a258-227b-4e31-a9cf-717495945fc2" # Powershell - APP ID/ClientID

# Variables for Customization

# User and Password
$ScriptUser="REPLACE FOR TEST:<youruser@yourdomain.onmicrosoft.com (No MS-Accounts like Hotmail)>"
# $ScriptUserPassWord = ConvertTo-SecureString –String "REPLACE FOR TEST:<yourSecurePassword>" –AsPlainText -Force
$ScriptUserPassWord = Read-Host 'What is your password?' -AsSecureString

# Subscription + Tenant + Domain
$subscriptionName = "*Ultimate" # REPLACE FOR TEST: with a search string for your subscription        
$domainName = "REPLACE FOR TEST:<www.yourdomain.com>"


############################################################################################################################################
# Assert Helper Function
############################################################################################################################################
function AssertNotNull($obj, $msg){
    if($obj -eq $null -or $obj.Length -eq 0){ 
        Write-Warning $msg
        Exit
    }
}

############################################################################################################################################
# Extension to Invoke-RestMethod Helper to reduce complexity
# Converting the $body to an Json Object
############################################################################################################################################
function Invoke-PostRequestAsJson($uri, $headers, $body)
{
    $json = $body | ConvertTo-Json -Depth 4 -Compress
    return (Invoke-RestMethod $uri -Method Post -Headers $headers -Body $json -ContentType "application/json")
}

############################################################################################################################################
#
# Retrieves a token from AAD and creates an Authorization Header or an an Authorization Bearer Header
#
# tenantId...                  AAD Tenant
# resourceUrl...               Resource we fetch Authentication Token for. Examples: 'https://management.core.windows.net/',
#                                                                                    'https://management.azure.com/',
#                                                                                    'https://graph.windows.net'
# getBearerHeader...           Set this to $true if you want a Bearer Header (This is necessary f.e. for some APIs in Logic Apps)
# clientId...                  ClientID of Azure AD Application you want to authenticate
#                              In the case of Poweshell you can use the well-known ID: "1950a258-227b-4e31-a9cf-717495945fc2"
#                              This wellknown Powershell Client ID does not require a secret (you already authenticated with Powershell to
#                              this app)
# clientSecret...              Secret in case you use a different Azure ID App
#
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
############################################################################################################################################
function Get-AuthorizationHeaders($tenantId, $resourceUrl, $getBearerHeader=$false, $clientId, $clientSecret=$null)
{
    # Add ADAL Library (Nuget Package: https://www.nuget.org/packages/Microsoft.IdentityModel.Clients.ActiveDirectory)
    Add-Type -Path $LibraryPath_ADAL
    
    $redirectUrl = "urn:ietf:wg:oauth:2.0:oob"
    $authString = "https://login.microsoftonline.com/" + $tenantId   # Authority

    if ($clientSecret -eq $null){
        $authenticationContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $authString, $FALSE
        $accessToken = $authenticationContext.AcquireToken($resourceUrl, $clientId, $redirectUrl, "Auto").AccessToken
    }else{
        $clientCredentials = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential -ArgumentList $clientId, $clientSecret
        $authenticationContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $authString, $FALSE
        $accessToken = $authenticationContext.AcquireToken($resourceUrl, $clientCredentials).AccessToken
    }

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    if ($getBearerHeader -eq $true){
        $headers.Add("Authorization", "Bearer $accessToken")
    }else{
        $headers.Add("Authorization", $accessToken)
    }
    return $headers
}

############################################################################################################################################
#
# Creates an AAD Application in you Tenant if it does not already exist and returns an Powershell AzureRM Instance of the AAD App
# 
# $tenantId...                TenantId
# $headers...                 Authentication Headers
#
# $displayName...             Display Name of the AAD Application
# $domain...                  Your Domain (This will generate an APPIDURL like this: "https://<yourdomain>/<displayname>"
# $aadAppIsWebApp...          $true: This is an AAD Web APP - $false: This is an AAD Native App (Implicit Grants)
# $requiredResourceAccess...  Structure which describes which scope and which AAD Apps you are requesting access to
#                             This can be built easily with the utility function "Get-RessourceAccessByDefinition"
# $aadAppRoles...             Structure describing the APplication Roles the APP supports. if not required set to $null
# $replyUrl...                Reply Url for AAD Web APP
# $homePage...                Url where this Application can be accessed by the end user. 
#                             Listed f.e. at: https://account.activedirectory.windowsazure.com/
#
# RETURNS...                  returns an object representing the new created AAD APP
# REMARKS...                  If there is an AAD App with that name it is not created again!
# 
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
############################################################################################################################################
function Create-AADApplication($tenantId, $headers, $displayName, $domain, $aadAppIsWebApp, $requiredResourceAccess, $aadAppRoles, $replyUrl=$null, $homePage=$null)
{
    $resourceUrl = "https://graph.windows.net"
    $graphAPIFormat = $resourceUrl + "/" + $tenantId + "/{0}?api-version=1.5"

    $aadApp_AppIdUrl = "https://" + $domain + "/" + $displayName
    # Does Application already exist?
    $app_Application = (Get-AzureRmADApplication -DisplayNameStartWith $displayName)
    if ($app_Application.Count -eq 0){
        if ($replyUrl -eq $null){
            $replyUrl = "http://localhost:1234/PlaceHolder"
        }
        if ($homePage -eq $null){
            $homePage = "http://localhost:1234/PlaceHolder"
        }
	    $uri = [string]::Format($graphAPIFormat, "applications")
        $aadApp = @{}

        if ($aadAppIsWebApp -eq $true){
	        $aadApp = @{
		        displayName = $displayName
		        identifierUris = @($aadApp_AppIdUrl)
		        homepage = $homePage 
		        replyUrls = @($replyUrl) 
	        }
        }else
        {
	        $aadApp = @{
			    publicClient = "true"
		        displayName = $displayName
		        identifierUris = @($aadApp_AppIdUrl)
		        homepage = $homePage 
			    replyUrls = @("urn:ietf:wg:oauth:2.0:oob") # localhost
	        }
        }
        if ($requiredResourceAccess -ne $null){
            $aadApp.requiredResourceAccess = $requiredResourceAccess
        }
        if ($aadAppRoles -ne $null){
            $aadApp.appRoles = $aadAppRoles
        }

        # Create AAD AOO with POST Request
        $aadApp = Invoke-PostRequestAsJson $uri $headers $aadApp
	    AssertNotNull $aadApp 'Web Application Creation Failed'
	    $aadAppclientId = $aadApp.appId
        # Unfortunatly those two Application (Graph/AZureRMApp) have different named properties
        $app_Application = (Get-AzureRmADApplication -ApplicationId $aadApp.appId)[0]
	    Write-Host 'AAD Application Created:' $aadApp.appId
        return $app_Application
    }else{
	    $aadAppclientId = $app_Application[0].ApplicationId.ToString()
	    Write-Verbose "AAD Application found: $displayName"
        return $app_Application
    }
}

############################################################################################################################################
#
# Creates an AAD Service Principal for a created AAD APP with "Create-AADApplication"
# 
# tenantId...                        TenantId
# headers...                         Authentication Headers
# aadApp...                          AAD App (Powershell AzureRM - Do not use the structure returned by graph.windows.net!)
# aadAppRoleAssignmentRequired...    Does this app requires Roles to be assigned to users. Only necessary if AppRoles where defined.
#
# RETURNS...                         returns an object representing the new created AAD Principal (!! FROM GRAPH.Windows.NET !!)
# REMARKS...                         If there is an AAD Principal with that name it is not created again!
#                                    Instead it will be fetched from graph.windows.net
# 
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
############################################################################################################################################
function Create-AADServicePrincipal($tenantId, $headers, $aadApp, $aadAppRoleAssignmentRequired)
{
    $resourceUrl = "https://graph.windows.net"
    $graphAPIFormat = $resourceUrl + "/" + $tenantId + "/{0}?api-version=1.5"

    # Create a Service Principal
    $displayName = $aadApp.DisplayName
    $aadApp_servicePrincipal = Get-AzureRmADServicePrincipal | Where-Object { $_.DisplayName -eq $displayName }
    if ($aadApp_servicePrincipal.Count -eq 0){
	    $uri = [string]::Format($graphAPIFormat, "servicePrincipals")
	    $servicePrincipal = @{
		    accountEnabled = "true"
		    appId = $aadApp.ApplicationId
		    displayName = $aadApp.displayName
		    appRoleAssignmentRequired = $aadAppRoleAssignmentRequired
	    }
	    $servicePrincipal = Invoke-PostRequestAsJson $uri $headers $servicePrincipal
	    $aadAppServicePrincipalID = $servicePrincipal.objectId
	    Write-Verbose "Principal for AAD Application '$aadApp_Name' created."
        return $servicePrincipal
    }else{
	    Write-Verbose "Principal for AAD Application '$aadApp_Name' found."
	    $aadAppServicePrincipalID = $aadApp_servicePrincipal[0].Id.ToString()
        # Override Principal as we have a different set of properties with AzureRM Powershell Object and Graph API
        $uri = [string]::Format($graphAPIFormat, "servicePrincipals") + '&$filter=objectId eq '+"'$aadAppServicePrincipalID'"
        $servicePrincipal = (Invoke-RestMethod $uri -Headers $headers).value
        return $servicePrincipal
    }
}

############################################################################################################################################
# 
# This helper retrieves a Principal from graph.windows.net associated with an AAD app by the AAD Apps ClientID/APP ID. 
#
# tenantId...                        TenantId
# headers...                         Authentication Headers
# $clientId...                       clientId of the AAD APP we are looking for the Service Principal 
# 
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
############################################################################################################################################
function Get-PrincipalbyclientId($tenantId, $headers, $clientId){
    $resourceUrl = "https://graph.windows.net"
    $graphAPIFormat = $resourceUrl + "/" + $tenantId + "/{0}?api-version=1.5"
    $uri = [string]::Format($graphAPIFormat, "servicePrincipals") + '&$filter=appId eq '+"'$clientId'"
    $servicePrincipal = (Invoke-RestMethod $uri -Headers $headers).value
    return $servicePrincipal  # Get OID with .objectId
}

############################################################################################################################################
# 
# This helper retrieves a Principal from graph.windows.net by its unique object identifier. 
#
# tenantId...                        TenantId
# headers...                         Authentication Headers
# $objectId...                       Unique object identifier of the Service Principal 
# 
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
############################################################################################################################################
function Get-PrincipalbyObjectId($tenantId, $headers, $objectId){
    $resourceUrl = "https://graph.windows.net"
    $graphAPIFormat = $resourceUrl + "/" + $tenantId + "/{0}?api-version=1.5"
    $uri = [string]::Format($graphAPIFormat, "servicePrincipals") + '&$filter=objectId eq '+"'$objectId'"
    $servicePrincipal = (Invoke-RestMethod $uri -Headers $headers).value
    return $servicePrincipal  # Get OID with .objectId
}

############################################################################################################################################
#
# Method to grant OAUth2Permissions for a single Resource with multiple scopes. 
#
# $tenantId...             TenantId
# headers...               Authentication Headers
# $servicePrinciaplID...   ID of the Principal to whom we grant the OAuth2 Permissions
# $permissionScope...      Scope of Permission (f.e. GraphAPI "User.Read", Custom App "user_impersonation"
#                          Multiple scopes can be defined by separating them by a blank like "User.Read Group.Read.All"
# $grantDurationInYears... Duration of the grant in years (f.e. 1800, bascially forever, until our ancestors have to maintain this code)
# $isAdminConsent...       If $true the permission is consented by an admin to all principals, otherwise to a specific principal
# $consentedPrincipalId... Ignored if $isAdminConsent -eq $ true, else the consented principal
# $resourcePrincipalId...  ID of the Principal that is associated with the Resource we grant access to within the scope
#
# Further readings:        https://msdn.microsoft.com/en-us/Library/Azure/Ad/Graph/api/entity-and-complex-type-reference 
# 
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
############################################################################################################################################
function Grant-OAuth2Permission($tenantId, $headers, $servicePrincipalId,$permissionScope,$grantDurationInYears,$isAdminConsent,$consentedPrincipalId,$resourcePrincipalId)
{
    $resourceUrl = "https://graph.windows.net"
    $graphAPIFormat = $resourceUrl + "/" + $tenantId + "/{0}?api-version=1.5"
    if ($isAdminConsent -eq $true){
        $consentType = "AllPrincipals"
    }else{
        $consentType = "Principal"
        AssertNotNull $consentedPrincipalId 'Missing parameter consentedPrincipalId'
    }
    #OAuth2PermissionGrant
    $uri = [string]::Format($graphAPIFormat, "oauth2PermissionGrants")
    $oauth2PermissionGrants = @{
	    clientId = $servicePrincipalId
	    consentType = $consentType
	    resourceId = $resourcePrincipalId
	    scope = $permissionScope
	    startTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffff")
	    expiryTime = (Get-Date).AddYears($grantDurationInYears).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffff")
    }
    Invoke-PostRequestAsJson $uri $headers $oauth2PermissionGrants | Out-Null
}

############################################################################################################################################
#
# Method to grant OAUth2Permissions for multiple Resources with multiple scopes. We use the same structure we used while creating an Azure 
# AAD App. This can be built easily with Get-RessourceAccessByDefinition. (see samples)
#
# $tenantId...                    TenantId
# headers...                      Authentication Headers
# $grantDurationInYears...        Duration of the grant in years (f.e. 1800, bascially forever, until our ancestors have to maintain this code)
# $isAdminConsent...              If $true the permission is consented by an admin to all principals, otherwise to a specific principal
# $servicePrinciaplID...          ID of the Principal to whom we grant the OAuth2 Permissions
# aadAppRequiredResourceAccess...
# $requiredResourceAccess...      Structure which describes which scope and which AAD Apps you are requesting access to
#                                 This can be built easily with the utility function "Get-RessourceAccessByDefinition"
#
# Further readings:               https://msdn.microsoft.com/en-us/Library/Azure/Ad/Graph/api/entity-and-complex-type-reference 
# REMARKS...                      If an OAuth2PermissionGrant for an Resource exists it is replaced by the new one!
# 
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
############################################################################################################################################
function Grant-OAuth2PermissionWithRequiredResourceAccess($tenantId, $headers, $grantDurationInYears,$isAdminConsent,$servicePrincipalId, $requiredResourceAccess)
{
    $resourceUrl = "https://graph.windows.net"
    $graphAPIFormat = $resourceUrl + "/" + $tenantId + "/{0}?api-version=1.5"
    if ($isAdminConsent -eq $true){
        $consentType = "AllPrincipals"
    }else{
        $consentType = "Principal"
        AssertNotNull $consentedPrincipalId 'Missing parameter consentedPrincipalId'
    }

    #OAuth2PermissionGrant
    foreach($reqResAccess in $requiredResourceAccess){
        $resourceClientId = $reqResAccess.resourceAppId
        $resourceprincipal = Get-PrincipalbyClientId -tenantId $tenantId -headers $headers -clientId $resourceClientId 
        $oauth2PermissionGrants = @{
	        clientId = $servicePrincipalId
	        consentType = $consentType
	        resourceId = $resourceprincipal.objectId
	        startTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffff")
	        expiryTime = (Get-Date).AddYears($grantDurationInYears).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffffff")
        }
        # Delete grants to the same resource if there are any 
        # Better would be extending existing scopes instead of replacing the whole item
        $grantResourceId = $resourceprincipal.objectId
        $uri = [string]::Format($graphAPIFormat, "oauth2PermissionGrants") + '&$filter=clientId eq '+"'$servicePrincipalId' and resourceId eq '$grantResourceId'"
        $existingGrants = (Invoke-RestMethod -Method Get -uri $uri -Headers $headers).value
        foreach($grant in $existingGrants){
	        $objectId = $grant.objectId
	        $uri = [string]::Format($graphAPIFormat, "oauth2PermissionGrants/"+$objectId)
	        Invoke-WebRequest -uri $uri -Method Delete -Headers $headers  | Out-Null
        }

        $scope=""
        foreach($resAccess in $reqResAccess.resourceAccess){
            $searchResult = ($resourceprincipal.oauth2Permissions | select value, id | Where-Object {$_.id -eq $resAccess.id})
	        $scope += " "+$searchResult[0].value
        }
        $oauth2PermissionGrants.scope = $scope
        $uri = [string]::Format($graphAPIFormat, "oauth2PermissionGrants")
        Invoke-PostRequestAsJson $uri $headers $oauth2PermissionGrants | Out-Null
    }
}

############################################################################################################################################
#
# This helper lets you define the required permissions with name instead of UIDs and the ClientID of the Resource APP 
# It creates a structure that can be passed to 
#    
#     *) Create-AADApplication
#     *) Grant-OAuth2PermissionWithRequiredResourceAccess
#
# definition...                  A structure in the following form:
#
#    $resourceAccessDefinition = @(@{
#                                     clientId = $graphAPI_clientId
#                                     permissions = @("user.read", "Group.Read.All")
#                                },
#                                @{
#                                    clientId = $otherAADApp.ApplicationId
#                                    permissions = @("user_impersonation")
#                                 }
#                                )
#
# $tenantId...                  TenantId
# headers...                    Authentication Headers
#
############################################################################################################################################
function Get-RessourceAccessByDefinition($definition,$tenantId, $headers){
    # Required Access to resources (Voraussetzung für die Dinge die wir dann beim Principal der Native APp hinzuzügen.
    $requiredResourceAccess = @()

    foreach($appAccess in $definition){
        $principal = Get-PrincipalbyclientId -tenantId $tenantId -headers $headers -clientId $appAccess.clientId
        $resAccessForPrincipal = @{
	                resourceAppId = $principal.appId
	                resourceAccess = @()
                   }
        foreach($perm in $appAccess.permissions){
            $resAccess = Get-RessourceAccessByName -servicePrincipal $principal -valueName $perm
            $resAccessForPrincipal.resourceAccess = $resAccessForPrincipal.resourceAccess + $resAccess    
        }
        $requiredResourceAccess+=$resAccessForPrincipal
    }
    return $requiredResourceAccess
}

############################################################################################################################################
# 
# Helper function used by "Get-RessourceAccessByDefinition" - It retrieves the unique ID of a scope by the name of the scope and
#                                                             constructs the RessourceAccess structure (scope) 
#
# $servicePrincipal...      servicePrincipal data from graph.windows.net
# $valueName...             permission for Graph API f.e. (User.Read, Group.Read.All, Directory.Read.All,...) or 
#                           for custom Web AAD Apps (user_impersonation)
#                           To get a complete list from a Principal call 
#                                PS> $principal.oauth2Permissions | Select value
# 
# Author:		Andreas Pollak 
# Copyright:	(c) by SpectoLogic
############################################################################################################################################
function Get-RessourceAccessByName($servicePrincipal,$valueName)
{
    $searchResult = ($servicePrincipal.oauth2Permissions | select value, id | Where-Object {$_.value -eq $valueName})
    if ($searchResult -ne $null){
    $result = @{
		            id = $searchResult.id  
		            type= "Scope"
	           }
        return $result
    }else{
        return $null
    }
}

################################################################################################################################################
# USAGE EXAMPLE
################################################################################################################################################

#Login to Azure
$Credential = New-Object –TypeName "System.Management.Automation.PSCredential" –ArgumentList $ScriptUser, $ScriptUserPassWord
Login-AzureRmAccount -Credential $Credential

#Locate subscription with Name Filter
$subscriptionId = Get-AzureRmSubscription | where {$_.SubscriptionName -like $subscriptionName} | Select SubscriptionId
$subscriptionId = $subscriptionId[0].SubscriptionId
$subscription = Select-AzureRmSubscription -SubscriptionId $subscriptionId
$tenantId = $subscription.Tenant.TenantId

#Define our Application
#REPLACE FOR TEST:
$aadAppName = "LogicAppDemoAADApp"         # Azure AAD App Name
$aadAppIsWebApp = $true                    # if false it is a native Client Application
$aadAppRoleAssignmentRequired = $true      # We want Role Assignment in our sample
$aadAppRoles =                             # Declare App Role Structure
@{
	allowedMemberTypes = @("User")
	description = "ReadOnly roles have limited query access"
	displayName = "ReadOnly"
	id = [guid]::NewGuid()
	isEnabled = "true"
	value = "User"
},
@{
	allowedMemberTypes = @("User")
	description = "Admins can manage roles and perform all task actions"
	displayName = "Admin"
	id = [guid]::NewGuid()
	isEnabled = "true"
	value = "Admin"
}

# We want to grant our new AAD App access to another AAD Web App
# Therefore we need to provide the ClientID of the other AAD Web App
$otherAADAppId = "REPLACE FOR TEST:<a ClientID of one of your Azure AAD Web Apps>"
$otherAADApp = (Get-AzureRmADApplication -ApplicationId $otherAADAppId)
                  
# Define OAuth2Permissions we do want to grant
# REPLACE FOR TEST:
$aadAppRequiredResourceAccessDefinition = @(@{
                                                clientId = $graphAPI_clientId
                                                permissions = @("user.read", "Group.Read.All")
                                             },
                                            @{
                                                clientId = $otherAADApp.ApplicationId
                                                permissions = @("user_impersonation")
                                             }
                                           )


# Path to Active Directory Authentication Library (Microsoft.IdentityModel.Clients.ActiveDirectory.dll)
$LibraryPath_ADAL = "..\..\..\Dependencies\AzureAD\Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
# Aquire Authentication Headers
$headers = Get-AuthorizationHeaders -tenantId $tenantId -resource $graphAPI_resourceUrl -clientId $powershell_clientId -isBearer $false

# Build OAuth2Permission Structure
$requiredResourceAccess = Get-RessourceAccessByDefinition -definition $aadAppRequiredResourceAccessDefinition -tenantId $tenantId -headers $headers

$aadApp = Create-AADApplication -tenantId $tenantId -headers $headers -aadApp_Name $aadAppName -domain $domainName -aadAppIsWebApp $aadAppIsWebApp -requiredResourceAccess $requiredResourceAccess -aadAppRoles $aadAppRoles
$servicePrincipal = Create-AADServicePrincipal -tenantId $tenantId -headers $headers -aadApp $aadApp -aadAppRoleAssignmentRequired $true 
$aadAppServicePrincipalID = $servicePrincipal.objectId   

Grant-OAuth2PermissionWithRequiredResourceAccess -tenantId $tenantId -headers $headers -grantDurationInYears 1800 -isAdminConsent $true -servicePrincipalId $aadAppServicePrincipalID -requiredResourceAccess $requiredResourceAccess
# The above line could be replaced with this: (but who wants to :-))  
#
# $graphAPI_Principal = Get-PrincipalbyclientId -tenantId $tenantId -headers $headers -clientId $graphAPI_clientId
# $graphAPI_ServicePrincipalId = $graphAPI_Principal.objectId
# Grant-OAuth2Permission -tenantId $tenantId  -headers $headers-servicePrincipalId $aadAppServicePrincipalID -permissionScope "User.Read Group.Read.All" -grantDurationInYears 1800 -resourcePrincipalId $graphAPI_ServicePrincipalId -isAdminConsent $true
#
# $otherAADPrincipal = Get-PrincipalbyclientId -tenantId $tenantId -headers $headers -clientId $otherAADAppId
# $otherAADPrincipalID = $otherAADPrincipal.objectId
# Grant-OAuth2Permission -tenantId $tenantId  -headers $headers-servicePrincipalId $aadAppServicePrincipalID -permissionScope "user_impersonation" -grantDurationInYears 1800 -resourcePrincipalId $otherAADPrincipalID -isAdminConsent $true



