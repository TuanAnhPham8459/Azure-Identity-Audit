<#
.SYNOPSIS
    Seeds a lab Microsoft Entra ID tenant with a fake company ("Northwind Bakery")
    and 8 deliberately planted identity mistakes.

.DESCRIPTION
    ONLY run this in a directory you own and are Global Administrator of.
    Every object it creates is tagged so cleanup-lab.ps1 can find and remove it:
      - users:  companyName = "Northwind Bakery (lab)"
      - groups: displayName starts with "NW-", description contains "NorthwindLab"
      - app:    tag "NorthwindLab"

    Planted mistakes:
      1  Too many Global Admins        (4 extra users get Global Administrator)
      2  Guest with admin rights       (invited guest gets User Administrator)
      3  Leaver still enabled          (j.leaver, department "Former staff")
      4  Users with no MFA method      (most users have only a password)
      5  Long-lived app secret         (Inventory-Sync, 2-year client secret)
      6  Over-permissioned app         (Inventory-Sync, Graph Directory.ReadWrite.All)
      7  Shared admin account          (it-admin-shared is a Global Admin)
      8  Security defaults off         (you switch this off by hand in the portal)

    The script is safe to re-run: objects that already exist are skipped.

.EXAMPLE
    pwsh ./seed-lab.ps1 -TenantId <tenant-id> -GuestEmail "your.other.email@example.com"
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $GuestEmail,
    # Abort if the directory already has more than this many users that the lab did not create.
    # Protects you from seeding a real school or work tenant by mistake.
    [int] $MaxForeignUsers = 25
)

$ErrorActionPreference = 'Stop'
$LabTag     = 'NorthwindLab'
$LabCompany = 'Northwind Bakery (lab)'
$GraphAppId = '00000003-0000-0000-c000-000000000000'

function Invoke-WithRetry {
    # Newly created directory objects can take a few seconds to replicate.
    param([scriptblock] $Script, [string] $What, [int] $Tries = 8)
    for ($i = 1; $i -le $Tries; $i++) {
        try { return & $Script }
        catch {
            if ($i -eq $Tries) { throw "Failed: $What. $($_.Exception.Message)" }
            Start-Sleep -Seconds (3 * $i)
        }
    }
}

function New-TempPassword {
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnpqrstuvwxyz', '23456789', '!@#$%*-_=+?')
    $rng  = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $byte = New-Object byte[] 1
    $pick = {
        param($s)
        do { $rng.GetBytes($byte) } while ($byte[0] -ge (256 - (256 % $s.Length)))
        $s[$byte[0] % $s.Length]
    }
    $chars = @()
    foreach ($s in $sets) { $chars += & $pick $s }                     # one of each class
    $all = -join $sets
    while ($chars.Count -lt 16) { $chars += & $pick $all }
    -join ($chars | Sort-Object { [guid]::NewGuid() })
}

# ---------------------------------------------------------------- connect
$scopes = @(
    'User.ReadWrite.All', 'Group.ReadWrite.All', 'RoleManagement.ReadWrite.Directory',
    'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'User.Invite.All',
    'UserAuthenticationMethod.ReadWrite.All', 'Directory.Read.All'
)
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome
$ctx = Get-MgContext
if ($ctx.TenantId -ne $TenantId) { throw "Connected to tenant $($ctx.TenantId), expected $TenantId. Stopping." }

$org    = Get-MgOrganization
$domain = (Get-MgDomain -All | Where-Object IsDefault).Id
Write-Host "Tenant: $($org.DisplayName)  ($domain)" -ForegroundColor Cyan

# Safety: a lab directory should be almost empty.
$existing = Get-MgUser -All -Property Id, UserPrincipalName, CompanyName, Mail
$foreign  = @($existing | Where-Object { $_.CompanyName -ne $LabCompany })
if ($foreign.Count -gt $MaxForeignUsers) {
    throw "This directory already has $($foreign.Count) users. It does not look like a personal lab tenant. Stopping."
}

# ---------------------------------------------------------------- roles
function Get-RoleDefinitionId([string] $Name) {
    $r = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$Name'"
    if (-not $r) { throw "Role '$Name' not found." }
    $r.Id
}
$GlobalAdminId = Get-RoleDefinitionId 'Global Administrator'
$UserAdminId   = Get-RoleDefinitionId 'User Administrator'

function Grant-Role([string] $PrincipalId, [string] $RoleId, [string] $Label) {
    $already = Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$PrincipalId' and roleDefinitionId eq '$RoleId'"
    if ($already) { Write-Host "  role already assigned: $Label"; return }
    Invoke-WithRetry -What "assign role to $Label" -Script {
        New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $PrincipalId -RoleDefinitionId $RoleId -DirectoryScopeId '/' | Out-Null
    }
    Write-Host "  role assigned: $Label"
}

# ---------------------------------------------------------------- groups
Write-Host "`nGroups" -ForegroundColor Cyan
$groups = @{}
foreach ($dept in 'Bakery', 'Sales', 'Office') {
    $name = "NW-$dept"
    $g = Get-MgGroup -Filter "displayName eq '$name'"
    if (-not $g) {
        $g = New-MgGroup -DisplayName $name -MailEnabled:$false -SecurityEnabled -MailNickname "nw-$($dept.ToLower())" `
                         -Description "$LabTag department group: $dept"
        Write-Host "  created $name"
    } else { Write-Host "  exists  $name" }
    $groups[$dept] = $g.Id
}

# ---------------------------------------------------------------- users
# Alias, Given, Surname, Department, Title, Group, GlobalAdmin, HasPhoneMfa
$staff = @(
    @('nw.owner',        'Olivia', 'Baker',   'Office',       'Owner',              'Office', $true,  $false),
    @('nw.manager',      'Marco',  'Rossi',   'Office',       'Operations Manager', 'Office', $true,  $false),
    @('nw.dev',          'Devon',  'Clarke',  'Office',       'Developer',          'Office', $true,  $false),
    @('nw.accounts',     'Priya',  'Shah',    'Office',       'Accountant',         'Office', $true,  $false),
    @('nw.baker1',       'Sam',    'Lee',     'Bakery',       'Head Baker',         'Bakery', $false, $true),
    @('nw.baker2',       'Ana',    'Silva',   'Bakery',       'Baker',              'Bakery', $false, $true),
    @('nw.baker3',       'Tom',    'Nguyen',  'Bakery',       'Baker',              'Bakery', $false, $false),
    @('nw.sales1',       'Grace',  'Kim',     'Sales',        'Sales Lead',         'Sales',  $false, $false),
    @('nw.sales2',       'Liam',   'OConnor', 'Sales',        'Sales Associate',    'Sales',  $false, $false),
    @('nw.driver',       'Noah',   'Patel',   'Sales',        'Delivery Driver',    'Sales',  $false, $false),
    @('j.leaver',        'Jamie',  'Leaver',  'Former staff', 'Baker (left)',       'Bakery', $false, $false),  # mistake 3
    @('it-admin-shared', '',       '',        'IT',           'Shared IT account',  'Office', $true,  $false)   # mistake 7
)

Write-Host "`nUsers (temporary passwords are shown once, here only)" -ForegroundColor Cyan
$created = @()
foreach ($s in $staff) {
    $alias, $given, $sur, $dept, $title, $grp, $isGa, $hasPhone = $s
    $upn  = "$alias@$domain"
    $user = $existing | Where-Object UserPrincipalName -eq $upn
    if (-not $user) {
        $display = if ($given) { "$given $sur" } else { 'IT Admin (shared)' }
        $pw = New-TempPassword
        $params = @{
            AccountEnabled    = $true
            DisplayName       = $display
            MailNickname      = $alias.Replace('.', '')
            UserPrincipalName = $upn
            Department        = $dept
            JobTitle          = $title
            CompanyName       = $LabCompany
            UsageLocation     = 'CA'
            PasswordProfile   = @{ Password = $pw; ForceChangePasswordNextSignIn = $true }
        }
        if ($given) { $params.GivenName = $given; $params.Surname = $sur }
        $user = New-MgUser @params
        Write-Host ("  created {0,-38} temp password: {1}" -f $upn, $pw)
    } else { Write-Host "  exists  $upn" }

    Invoke-WithRetry -What "add $alias to NW-$grp" -Script {
        try { New-MgGroupMember -GroupId $groups[$grp] -DirectoryObjectId $user.Id }
        catch { if ($_.Exception.Message -notmatch 'already exist') { throw } }
    }
    if ($isGa) { Grant-Role $user.Id $GlobalAdminId "Global Administrator -> $alias" }    # mistakes 1 and 7

    if ($hasPhone) {   # a couple of users DO have MFA, so the audit has to tell them apart
        # The authentication-methods service can return 403 for a user created seconds ago,
        # until the new account replicates. Retry, and never let this step stop the seed.
        try {
            $methods = Invoke-WithRetry -What "read phone methods for $alias" -Tries 10 -Script {
                Get-MgUserAuthenticationPhoneMethod -UserId $user.Id
            }
            if (-not $methods) {
                Invoke-WithRetry -What "add phone method to $alias" -Tries 10 -Script {
                    New-MgUserAuthenticationPhoneMethod -UserId $user.Id -PhoneType 'mobile' -PhoneNumber ('+1 555555{0:D4}' -f (Get-Random -Maximum 9999)) | Out-Null
                }
                Write-Host "  phone MFA method added for $alias"
            } else { Write-Host "  phone MFA method already set for $alias" }
        } catch {
            Write-Warning "Could not add a phone MFA method for $alias yet. Re-run the script in a few minutes to finish this step. ($($_.Exception.Message.Split([Environment]::NewLine)[0]))"
        }
    }
    $created += [pscustomobject]@{ Alias = $alias; Upn = $upn; Department = $dept; GlobalAdmin = $isGa; HasMfa = $hasPhone }
}

# ---------------------------------------------------------------- guest (mistake 2)
Write-Host "`nGuest" -ForegroundColor Cyan
$guest = $existing | Where-Object { $_.Mail -eq $GuestEmail }
if (-not $guest) {
    $inv = New-MgInvitation -InvitedUserEmailAddress $GuestEmail -InvitedUserDisplayName 'Vendor (Northwind POS support)' `
                            -InviteRedirectUrl 'https://myapps.microsoft.com' -SendInvitationMessage:$false
    $guestId = $inv.InvitedUser.Id
    Invoke-WithRetry -What 'tag guest' -Script { Update-MgUser -UserId $guestId -CompanyName $LabCompany }
    Write-Host "  invited $GuestEmail (no email sent)"
} else { $guestId = $guest.Id; Write-Host "  exists  $GuestEmail" }
Grant-Role $guestId $UserAdminId 'User Administrator -> guest'

# ---------------------------------------------------------------- app (mistakes 5 and 6)
Write-Host "`nApp registration" -ForegroundColor Cyan
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
$roleRW  = $graphSp.AppRoles | Where-Object Value -eq 'Directory.ReadWrite.All'

$app = Get-MgApplication -Filter "displayName eq 'Inventory-Sync'" | Where-Object { $_.Tags -contains $LabTag }
if (-not $app) {
    $app = New-MgApplication -DisplayName 'Inventory-Sync' -Tags @($LabTag) -Notes 'Northwind lab: syncs stock levels.' `
        -RequiredResourceAccess @(@{ ResourceAppId = $GraphAppId; ResourceAccess = @(@{ Id = $roleRW.Id; Type = 'Role' }) })
    Write-Host '  created app Inventory-Sync'
} else { Write-Host '  exists  app Inventory-Sync' }

$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
if (-not $sp) { $sp = Invoke-WithRetry -What 'create service principal' -Script { New-MgServicePrincipal -AppId $app.AppId -Tags @($LabTag) } }

$hasGrant = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id | Where-Object AppRoleId -eq $roleRW.Id
if (-not $hasGrant) {
    Invoke-WithRetry -What 'grant Directory.ReadWrite.All' -Script {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $roleRW.Id | Out-Null
    }
    Write-Host '  granted Graph Directory.ReadWrite.All (application) with admin consent'
}

if (-not ($app.PasswordCredentials | Where-Object DisplayName -eq 'inventory-sync-2yr')) {
    # The secret value is deliberately discarded. Nothing in this lab needs it.
    Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = 'inventory-sync-2yr'; EndDateTime = (Get-Date).ToUniversalTime().AddYears(2)
    } | Out-Null
    Write-Host '  added 2-year client secret (value not shown on purpose)'
}

# ---------------------------------------------------------------- manifest / answer key
$manifest = [ordered]@{
    createdAt = (Get-Date).ToString('s')
    domain    = $domain
    users     = $created
    guest     = $GuestEmail
    app       = 'Inventory-Sync'
    planted   = @(
        '1 Too many Global Admins: nw.owner, nw.manager, nw.dev, nw.accounts',
        '2 Guest with User Administrator',
        '3 j.leaver enabled, department Former staff',
        '4 No MFA method: everyone except nw.baker1 and nw.baker2',
        '5 Inventory-Sync 2-year client secret',
        '6 Inventory-Sync has Graph Directory.ReadWrite.All (application)',
        '7 it-admin-shared is a Global Admin',
        '8 Security defaults off (manual step)'
    )
}
$manifest | ConvertTo-Json -Depth 5 | Out-File -Encoding utf8 ./lab-manifest.json

Write-Host "`nDone. Answer key written to lab-manifest.json (no passwords or secrets in it)." -ForegroundColor Green
Write-Host 'Manual step for mistake 8: Entra ID > Overview > Properties > Manage security defaults > Disabled.' -ForegroundColor Yellow
