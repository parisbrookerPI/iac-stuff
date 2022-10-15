#Author: Niklas Tinner, 25.09.2022

###############
## Variables ##
###############

#Specify the Managed Identity. You can find it in the Azure resource instance under Managed Identity, or in the Enterprise Applications, when filtering for "Managed Identity"
$ObjectPrincipalID = "57998069-95b6-454f-9865-0f173c4b03a3"
#Specify the app, where the access should be granted for. Microsoft Graph ID is the same in all tenants = "00000003-0000-0000-c000-000000000000"
$appId = "00000003-0000-0000-c000-000000000000"
#Specify the API permissions
$permissions = "Directory.read.all" #Example: "Directory.Read.All", "Device.Read.All" find all at: https://learn.microsoft.com/en-us/graph/permissions-reference

###############
## Execution ##
###############

#Make sure, the module AzureAD is installed (Install-Module AzureAD) and connect to AzureAD. Authenticate with an account that has Application Administrator role assigned.
Connect-AzureAD

#Find the application in AzureAD through the previously specified $appId
$app = Get-AzureADServicePrincipal -Filter "AppId eq '$appId'"

#Assign all permissions to the Managed Identity service principal
foreach ($permission in $permissions)
{
   $role = $app.AppRoles | where Value -Like $permission | Select-Object -First 1
   New-AzureADServiceAppRoleAssignment -Id $role.Id -ObjectId $ObjectPrincipalID -PrincipalId $ObjectPrincipalID -ResourceId $app.ObjectId
}

###############
## Reference ##
###############
#Find more information in the corresponding blog post: https://oceanleaf.ch/azure-managed-identity/





$ObjIdDev =  "57998069-95b6-454f-9865-0f173c4b03a3"

$PermissionMap = @{
    '00000003-0000-0000-c000-000000000000' = @( # Microsoft Graph
        'User.Read.All'
        'Group.Read.All'
        'Group.ReadWrite.All'
        'Sites.Read.All'
        'Directory.Read.All'
        'Sites.ReadWrite.All'
    )
}

# Connect-AzureAD

# Get Service Principal using ObjectId
$ManagedIdentity = Get-AzureADServicePrincipal -ObjectId $ObjIdDev

Get-AzureADServicePrincipal -All $true | Where-Object { $_.AppId -in $PermissionMap.Keys} -PipelineVariable SP | ForEach-Object {

    $SP.AppRoles | Where-Object { $_.Value -in $PermissionMap[$SP.AppId] -and $_.AllowedMemberTypes -contains "Application" } -PipelineVariable AppRole | ForEach-Object {
        try {
            New-AzureAdServiceAppRoleAssignment -ObjectId $ManagedIdentity.ObjectId `
                                            -PrincipalId $ManagedIdentity.ObjectId `
                                            -ResourceId $SP.ObjectId `
                                            -Id $_.Id `
                                            -ErrorAction Stop
        } catch [Microsoft.Open.AzureAD16.Client.ApiException] {
            if ($_.Exception.Message -like '*Permission being assigned already exists on the object*') {
                'Permission {0} already set on {1}.' -f $AppRole.Value, $SP.DisplayName | Write-Warning
            } else {
                throw $_.Exception
            }
        }
    }
}