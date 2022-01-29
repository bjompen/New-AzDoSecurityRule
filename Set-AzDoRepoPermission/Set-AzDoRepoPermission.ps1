<#
.SYNOPSIS
    Set Git level group permissions on projects, repos, and branches in Azure DevOps.
.DESCRIPTION
    This function sets Git access rights on a group in Azure DevOps. 
    You can set access on 
        - Projects
        - Repositories
        - Branches
    
    Some access rights will not have any effect on some levels.
    You may select the same rule for Allow and Deny, but it should not work (And maybe i should build a fail safe for this sometime...)

    The following settings are possible to set.
    bit 	name                    displayName
    --- 	----                    -----------
    1 		Administer              Administer
    2 		GenericRead             Read
    4 		GenericContribute       Contribute
    8 		ForcePush               Force push (rewrite history and delete branches)
    16 		CreateBranch            Create branch
    32 		CreateTag               Create tag
    64 		ManageNote              Manage notes
    128 	PolicyExempt            Bypass policies when pushing
    256 	CreateRepository        Create repository
    512 	DeleteRepository        Delete repository
    1024 	RenameRepository        Rename repository
    2048 	EditPolicies            Edit policies
    4096 	RemoveOthersLocks       Remove others' locks
    8192 	ManagePermissions       Manage permissions
    16384 	PullRequestContribute   Contribute to pull requests
    32768 	PullRequestBypassPolicy Bypass policies when completing pull requests
.EXAMPLE
    PS C:\> $Splat = @{
    >>    AzDoUserName = 'bjompen'
    >>    AzDoToken = 'MySuperSecretPATFromAzureDevOps'
    >>    OrganizationName = 'BjompenOrg' 
    >>    ProjectName = 'TheBjompenProject'
    >>    GroupName = '[BjompenOrg]\BjompGroup'
    >>    Allow = EditPolicies ,ManageNote
    >>    }
    PS C:\> Set-AzDoRepoPermission @splat
    
    This command will give [BjompenOrg]\BjompGroup the EditPolicies (Edit policies) and ManageNote (Manage notes) access to all repos existing and created in the TheBjompenProject project
.EXAMPLE
    PS C:\> $Splat = @{
    >>    AzDoUserName = 'bjompen'
    >>    AzDoToken = 'MySuperSecretPATFromAzureDevOps'
    >>    OrganizationName = 'BjompenOrg' 
    >>    ProjectName = 'TheBjompenProject'
    >>    RepoName = 'BjompensRepo'
    >>    GroupName = '[BjompenOrg]\BjompGroup'
    >>    Deny = CreateBranch, EditPolicies
    >>    }
    PS C:\> Set-AzDoRepoPermission @splat
    
    This command will deny [BjompenOrg]\BjompGroup the CreateBranch (Create branch) and EditPolicies (Edit policies) access to the BjompensRepo repo in the TheBjompenProject project
.EXAMPLE
    PS C:\> $Splat = @{
    >>    AzDoUserName = 'bjompen'
    >>    AzDoToken = 'MySuperSecretPATFromAzureDevOps'
    >>    OrganizationName = 'BjompenOrg' 
    >>    ProjectName = 'TheBjompenProject'
    >>    RepoName = 'BjompensRepo'
    >>    Branch = 'feature'
    >>    GroupName = '[BjompenOrg]\BjompGroup'
    >>    Allow = ForcePush, CreateBranch, ManageNote
    >>    Deny = RenameRepository, DeleteRepository
    >>    }
    PS C:\> Set-AzDoRepoPermission @splat
    
    This command will allow [BjompenOrg]\BjompGroup the 
        - ForcePush (Force push (rewrite history and delete branches))
        - CreateBranch (Create branch)
        - ManageNote (Manage notes)
    and deny [BjompenOrg]\BjompGroup the
        - RenameRepository (Rename repository)
        - DeleteRepository (Delete repository)
    access to the feature branch in the BjompensRepo repo in the TheBjompenProject project
#>

function Set-AzDoRepoPermission {
    [CmdletBinding()]
    param (
        # Username to connect to Azure DevOps. Owner of the PAT.
        [Parameter(Mandatory)]
        [string]$AzDoUserName,

        # PAT, Personal access token used to access Azure DevOps.
        [Parameter(Mandatory)]
        [string]$AzDoToken,

        # Name of the Azure DevOps Organization
        [Parameter(Mandatory)]
        [string]$OrganizationName,

        # Name of the Azure DevOps Project
        [Parameter(Mandatory)]
        [string]$ProjectName,

        # Name of the repository to set access in. If no repois set access will be set on all repos in project.
        [Parameter()]
        [string]$RepoName,

        # Branch to set access to. If no branch is set, access will be set on all branches of the repo.
        [Parameter()]
        [string]$branch,

        # Name of group to give access to in the format '[OrganizationName]\Groupname' or '[Projectname]\Groupname'
        [Parameter(Mandatory)]
        [ValidateScript({$_ -like '`[*`]\*'}, ErrorMessage = 'Group needs to be in format "[OrganizationName]\Groupname" or "[Projectname]\Groupname"')]
        [string]$GroupName,
        
        # Rules to allow. This will overwrite any previously set allow or deny rules of this kind for this user in this scope. A rule can not be set in both allow and deny.
        [Parameter()]
        [ValidateSet('Administer','GenericRead','GenericContribute','ForcePush','CreateBranch','CreateTag','ManageNote','PolicyExempt','CreateRepository', 'DeleteRepository','RenameRepository','EditPolicies','RemoveOthersLocks','ManagePermissions','PullRequestContribute','PullRequestBypassPolicy')]
        [string[]]$Allow,
        
        # Rules to deny. This will overwrite any previously set allow or deny rules of this kind for this user in this scope. A rule can not be set in both allow and deny.
        [Parameter()]
        [ValidateSet('Administer','GenericRead','GenericContribute','ForcePush','CreateBranch','CreateTag','ManageNote','PolicyExempt','CreateRepository', 'DeleteRepository','RenameRepository','EditPolicies','RemoveOthersLocks','ManagePermissions','PullRequestContribute','PullRequestBypassPolicy')]
        [string[]]$Deny
    )

    # Stolen and adapted from https://jessehouwing.net/azure-devops-git-setting-default-repository-permissions/
    function ConvertToHex {
        param (
            $string
        )
        
        $split = $string.Split("/")
        
        $out = $split | ForEach-Object {
            -join ($_ | Format-Hex -Encoding Unicode | Select-Object -Expand Bytes | ForEach-Object { '{0:x2}' -f $_ })
        }
        
        $out -join "/"
    }

    # Access is set in a binary value sum.
    # https://docs.microsoft.com/en-us/rest/api/azure/devops/security/security-namespaces/query?view=azure-devops-rest-6.0
    [Flags()] enum AccessLevels {
        Administer              = 1
        GenericRead             = 2
        GenericContribute       = 4
        ForcePush               = 8
        CreateBranch            = 16
        CreateTag               = 32
        ManageNote              = 64
        PolicyExempt            = 128
        CreateRepository        = 256
        DeleteRepository        = 512
        RenameRepository        = 1024
        EditPolicies            = 2048
        RemoveOthersLocks       = 4096
        ManagePermissions       = 8192
        PullRequestContribute   = 16384
        PullRequestBypassPolicy = 32768
    }

    # Set rules int value
    if ($null -eq $Allow) {
        $allowRules = 0
    }
    else {
        $allowRules = ([accesslevels]$Allow).value__
    }
    if ($null -eq $Deny) {
        $denyRules = 0
    }
    else {
        $denyRules = ([accesslevels]$Deny).value__
    }
    
    # Create the header to authenticate to Azure DevOps
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $AzDoUserName, $AzDoToken)))
    $Header = @{
        Authorization = ("Basic {0}" -f $base64AuthInfo)
    }
    Remove-Variable AzDoToken

    
    # Get needed data about repo
    # Even if we wont set access to a specific repo we can use the same API call to get the project data we always need.
    $ReposUri = "https://dev.azure.com/$OrganizationName/$ProjectName/_apis/git/repositories?api-version=7.1-preview.1"
    $RepoData = (Invoke-RestMethod $ReposUri -Headers $Header).value
    
    # Construct path to access level
    $AccessPath = "repoV2/$($RepoData[0].project.id)"
    
    if (-not [string]::IsNullOrEmpty($RepoName)) {
        $SelectedRepoDetails = $RepoData | Where-Object -Property Name -EQ $RepoName
        $AccessPath = "$AccessPath/$($SelectedRepoDetails.id)"
    }

    if (-not [string]::IsNullOrEmpty($branch)) {
        $BranchData = ConvertToHex $branch
        $AccessPath = "$AccessPath/refs/heads/$BranchData"
    }
    
    # Get group data. The Git permissions API Requires PUID of the group as input, and this requires two requests.
    $GroupUri = "https://vssps.dev.azure.com/$OrganizationName/_apis/graph/groups?api-version=7.1-preview.1"
    $AllGroups = Invoke-RestMethod $GroupUri -Headers $Header

    $GroupSubjectDescriptor = ($AllGroups.value | Where-Object -Property PrincipalName -eq $GroupName).Descriptor
    $GroupDetailsUri = "https://vssps.dev.azure.com/$OrganizationName/_apis/identities?subjectDescriptors=$GroupSubjectDescriptor&queryMembership=None&api-version=7.1-preview.1"

    $GroupDescriptor = (Invoke-RestMethod $GroupDetailsUri -Headers $Header).value.descriptor

    # Create the body and post the new Git permission.
    $uri = "https://dev.azure.com/$OrganizationName/_apis/AccessControlEntries/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"

    $PostBody =  @{
        token = $AccessPath
        merge = $true
        accessControlEntries = @(@{
            descriptor = $GroupDescriptor
            allow = $allowRules
            deny = $denyRules
        })
    } | ConvertTo-Json

    $InvokeSplat = @{
        Uri = $uri 
        Method = 'Post'
        Body  = $PostBody
        Headers = $Header
        ContentType = 'application/json'
    }

    Invoke-RestMethod @InvokeSplat

}
