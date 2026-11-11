<#
.SYNOPSIS
    Read-only identity audit for a Microsoft Entra ID tenant (and optionally one Azure subscription).

.DESCRIPTION
    Connects with read-only Microsoft Graph scopes, runs the checks below and writes
    findings.csv, findings.json and report.md to -OutDir. It never changes the tenant.

      ID-01  More than 4 (or fewer than 2) enabled Global Admins
      ID-02  Guests holding privileged directory roles
      ID-03  Shared / generic accounts holding privileged roles
      ID-04  Enabled leavers; members with no sign-in for -StaleDays (needs P1/P2)
      ID-05  Enabled members with no MFA method (Critical if admin and nothing enforces MFA)
      ID-06  App secrets valid for more than 365 days, or already expired
      ID-07  Apps registered in this tenant holding high-risk Graph application permissions
      ID-08  Security defaults off and no Conditional Access policy requiring MFA
      AZ-01  Owner / User Access Administrator assigned straight to a user (needs -SubscriptionId)

    With -Baseline pointing at an earlier findings.json, the report adds a before/after table.

.EXAMPLE
    pwsh ./audit-identities.ps1 -TenantId <tenant-id> -OutDir ./audit-BEFORE
    pwsh ./audit-identities.ps1 -TenantId <tenant-id> -OutDir ./audit-AFTER -Baseline ./audit-BEFORE/findings.json
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [string] $OutDir = ('./audit-' + (Get-Date -Format 'yyyyMMdd-HHmm')),
    [string] $SubscriptionId,
    [string] $Baseline,
    [int]    $StaleDays = 90,
    [int]    $MaxGlobalAdmins = 4,
    [int]    $MaxSecretDays = 365
)

$ErrorActionPreference = 'Stop'
$findings = New-Object System.Collections.Generic.List[object]
$coverage = New-Object System.Collections.Generic.List[string]
$sevRank  = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }

function Add-Finding {
    param([string] $Check, [string] $Severity, [string] $Title, [string] $Target, [string] $Detail, [string] $Fix)
    $findings.Add([pscustomobject]@{
        Check = $Check; Severity = $Severity; Title = $Title; Target = $Target; Detail = $Detail; Remediation = $Fix
        Key   = "$Check|$Target"
    })
}

# Roles treated as privileged (can change identities, security config or apps).
$PrivilegedRoles = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'User Administrator', 'Authentication Administrator', 'Helpdesk Administrator', 'Password Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Security Administrator',
    'Conditional Access Administrator', 'Hybrid Identity Administrator', 'Groups Administrator',
    'Exchange Administrator', 'SharePoint Administrator', 'Intune Administrator', 'Billing Administrator',
    'Authentication Policy Administrator', 'Domain Name Administrator', 'External Identity Provider Administrator'
)
# Graph application permissions that amount to tenant takeover or mass data access.
$HighRiskGraphPerms = @(
    'Directory.ReadWrite.All', 'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All',
    'Application.ReadWrite.All', 'Application.ReadWrite.OwnedBy', 'User.ReadWrite.All', 'Group.ReadWrite.All',
    'GroupMember.ReadWrite.All', 'Domain.ReadWrite.All', 'Policy.ReadWrite.ConditionalAccess',
    'UserAuthenticationMethod.ReadWrite.All', 'Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All',
    'Sites.FullControl.All', 'Sites.ReadWrite.All', 'Directory.Read.All', 'Mail.Read', 'Files.Read.All'
)
$SharedNamePattern = '(^|[.\-_])(shared|generic|admin|administrator|svc|service|team|ops|helpdesk|support|it)([.\-_0-9]|$)'
$MfaTypes = @(
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod', '#microsoft.graph.phoneAuthenticationMethod',
    '#microsoft.graph.fido2AuthenticationMethod', '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod',
    '#microsoft.graph.softwareOathAuthenticationMethod', '#microsoft.graph.platformCredentialAuthenticationMethod',
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'
)
# Which Authentication methods policy configuration(s) must be enabled for a registered method to be usable.
# A phone number counts if either SMS or Voice is enabled. Types not listed here are not governed by that policy.
$MethodPolicyIds = @{
    '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' = @('MicrosoftAuthenticator')
    '#microsoft.graph.phoneAuthenticationMethod'                  = @('Sms', 'Voice')
    '#microsoft.graph.fido2AuthenticationMethod'                  = @('Fido2')
    '#microsoft.graph.softwareOathAuthenticationMethod'           = @('SoftwareOath')
    '#microsoft.graph.temporaryAccessPassAuthenticationMethod'    = @('TemporaryAccessPass')
}

# ---------------------------------------------------------------- connect (read-only scopes)
$scopes = @('Directory.Read.All', 'RoleManagement.Read.Directory', 'UserAuthenticationMethod.Read.All',
            'Application.Read.All', 'Policy.Read.All', 'AuditLog.Read.All')
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome
$ctx = Get-MgContext
if ($ctx.TenantId -ne $TenantId) { throw "Connected to tenant $($ctx.TenantId), expected $TenantId. Stopping." }
$org = Get-MgOrganization
Write-Host "Auditing $($org.DisplayName) (read-only)" -ForegroundColor Cyan

# ---------------------------------------------------------------- licensing
$skus  = @(Get-MgSubscribedSku -All)
$plans = $skus | Where-Object { $_.CapabilityStatus -eq 'Enabled' } | ForEach-Object { $_.ServicePlans.ServicePlanName }
$hasP1 = [bool]($plans | Where-Object { $_ -in @('AAD_PREMIUM', 'AAD_PREMIUM_P2') })
$hasP2 = [bool]($plans | Where-Object { $_ -eq 'AAD_PREMIUM_P2' })
$licence = if ($hasP2) { 'Entra ID P2' } elseif ($hasP1) { 'Entra ID P1' } else { 'Entra ID Free' }
Write-Host "Licence: $licence"

# ---------------------------------------------------------------- directory data
$userProps = 'id,displayName,userPrincipalName,userType,accountEnabled,department,givenName,surname,createdDateTime,mail'
$signInOk = $false
if ($hasP1) {
    try { $users = @(Get-MgUser -All -Property "$userProps,signInActivity"); $signInOk = $true }
    catch { $coverage.Add("Sign-in activity could not be read ($($_.Exception.Message)); stale-account check skipped.") }
}
if (-not $signInOk) { $users = @(Get-MgUser -All -Property $userProps) }
$userById = @{}; foreach ($u in $users) { $userById[$u.Id] = $u }

$roleDefs = @(Get-MgRoleManagementDirectoryRoleDefinition -All)
$roleName = @{}; foreach ($r in $roleDefs) { $roleName[$r.Id] = $r.DisplayName }

$assignments = @(Get-MgRoleManagementDirectoryRoleAssignment -All | ForEach-Object {
    [pscustomobject]@{ PrincipalId = $_.PrincipalId; Role = $roleName[$_.RoleDefinitionId]; Kind = 'active' }
})
if ($hasP2) {
    try {
        $assignments += @(Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All | ForEach-Object {
            [pscustomobject]@{ PrincipalId = $_.PrincipalId; Role = $roleName[$_.RoleDefinitionId]; Kind = 'eligible (PIM)' }
        })
    } catch { $coverage.Add('PIM eligible role assignments could not be read; only active assignments were checked.') }
} else {
    $coverage.Add('No P2 licence: only active (permanent) role assignments are checked. PIM eligible assignments are not visible.')
}
$privAssign  = @($assignments | Where-Object { $_.Role -in $PrivilegedRoles })
$privUserIds = @($privAssign | Where-Object { $userById.ContainsKey($_.PrincipalId) } | Select-Object -ExpandProperty PrincipalId -Unique)
$nonUserPriv = @($privAssign | Where-Object { -not $userById.ContainsKey($_.PrincipalId) })
if ($nonUserPriv) {
    $coverage.Add("$($nonUserPriv.Count) privileged role assignment(s) are held by groups or service principals; group members were not expanded.")
}
function Get-Roles([string] $Id) { ($privAssign | Where-Object PrincipalId -eq $Id | ForEach-Object { "$($_.Role) [$($_.Kind)]" }) -join '; ' }

# ---------------------------------------------------------------- ID-08 first (it changes ID-05 severity)
$sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
$caMfa = @()
$caReadable = $true
try {
    $caMfa = @(Get-MgIdentityConditionalAccessPolicy -All | Where-Object {
        $_.State -eq 'enabled' -and ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.AuthenticationStrength)
    })
} catch { $caReadable = $false }
if (-not $hasP1) { $coverage.Add('No P1/P2 licence: Conditional Access is unavailable, so ID-08 only checks security defaults.') }
elseif (-not $caReadable) { $coverage.Add('Conditional Access policies could not be read; ID-08 only checked security defaults.') }

$mfaEnforced = $sd.IsEnabled -or ($caMfa.Count -gt 0)
if (-not $mfaEnforced) {
    Add-Finding 'ID-08' 'Critical' 'Security defaults off and no Conditional Access requires MFA' 'tenant' `
        'Nothing in the tenant forces users or admins to use MFA.' `
        'Entra ID > Overview > Properties > Manage security defaults > Enabled (or build CA policies with P1).'
} elseif (-not $sd.IsEnabled) {
    Add-Finding 'ID-08' 'Info' 'Security defaults off; MFA enforced by Conditional Access' 'tenant' `
        ("Enabled CA policies requiring MFA: " + (($caMfa | ForEach-Object DisplayName) -join ', ')) `
        'Confirm the CA policies cover all users and all admins, with only break-glass accounts excluded.'
}

# ---------------------------------------------------------------- ID-01 Global Admin count
$gaIds = @($privAssign | Where-Object { $_.Role -eq 'Global Administrator' } | Select-Object -ExpandProperty PrincipalId -Unique)
$gaEnabled = @($gaIds | Where-Object { $userById.ContainsKey($_) -and $userById[$_].AccountEnabled })
$gaNames = ($gaEnabled | ForEach-Object { $userById[$_].UserPrincipalName }) -join ', '
if ($gaEnabled.Count -gt $MaxGlobalAdmins) {
    Add-Finding 'ID-01' 'High' "Too many Global Admins ($($gaEnabled.Count))" 'Global Administrator' `
        "Enabled Global Admins: $gaNames" `
        'Keep 2 (your admin + one break-glass). Move the others to narrower roles such as User Administrator.'
} elseif ($gaEnabled.Count -lt 2) {
    Add-Finding 'ID-01' 'Medium' "Only $($gaEnabled.Count) Global Admin" 'Global Administrator' `
        "Enabled Global Admins: $gaNames" 'Add a break-glass account so one lost device cannot lock you out.'
}

# ---------------------------------------------------------------- ID-02 / ID-03 privileged guests and shared accounts
foreach ($id in $privUserIds) {
    $u = $userById[$id]
    $roles = Get-Roles $id
    if ($u.UserType -eq 'Guest') {
        $sev = if ($u.AccountEnabled) { 'High' } else { 'Low' }
        Add-Finding 'ID-02' $sev 'Guest holds a privileged role' $u.UserPrincipalName "Roles: $roles. Enabled: $($u.AccountEnabled)" `
            'Remove the role. For vendors, use time-boxed PIM eligibility or an access package instead.'
    }
    $local = ($u.UserPrincipalName -split '@')[0].ToLower()
    if ($u.UserType -ne 'Guest' -and $local -notmatch '#ext#' -and $local -match $SharedNamePattern) {
        $sev = if ($u.AccountEnabled) { 'High' } else { 'Low' }
        Add-Finding 'ID-03' $sev 'Shared / generic account holds a privileged role' $u.UserPrincipalName `
            "Roles: $roles. Enabled: $($u.AccountEnabled). A shared login means no one can be held accountable for its actions." `
            'Disable it, remove its roles and give each admin a named account.'
    }
}

# ---------------------------------------------------------------- ID-04 leavers and stale accounts
$cutoff = (Get-Date).ToUniversalTime().AddDays(-$StaleDays)
foreach ($u in $users | Where-Object { $_.AccountEnabled }) {
    if ($u.Department -match 'former|leaver|left|terminated|offboard') {
        Add-Finding 'ID-04' 'Medium' 'Leaver account still enabled' $u.UserPrincipalName "Department: '$($u.Department)'" `
            'Disable the account, remove group memberships and roles, record the date.'
        continue
    }
    if ($signInOk -and $u.UserType -eq 'Member') {
        $last = $u.SignInActivity.LastSignInDateTime
        $created = [datetime]$u.CreatedDateTime
        if (($last -and $last -lt $cutoff) -or (-not $last -and $created -lt $cutoff)) {
            $when = if ($last) { $last.ToString('yyyy-MM-dd') } else { 'never' }
            Add-Finding 'ID-04' 'Medium' "No sign-in for $StaleDays+ days" $u.UserPrincipalName "Last sign-in: $when" `
                'Confirm with the manager, then disable or delete.'
        }
    }
}
if (-not $signInOk) { $coverage.Add("No sign-in activity (needs P1/P2): ID-04 only finds leavers by department name, not accounts unused for $StaleDays days.") }

# ---------------------------------------------------------------- ID-05 MFA methods
# A registered method only protects the user if the tenant's Authentication methods policy allows it.
# Example: new tenants disable SMS/Voice, so a registered phone number shows as "Disabled by policy".
$enabledMethodPolicies = $null
try {
    $amPolicy = Get-MgPolicyAuthenticationMethodPolicy
    $enabledMethodPolicies = @($amPolicy.AuthenticationMethodConfigurations | Where-Object { $_.State -eq 'enabled' } | ForEach-Object { $_.Id })
    if ($amPolicy.PolicyMigrationState -and $amPolicy.PolicyMigrationState -ne 'migrationComplete') {
        $coverage.Add("Authentication methods policy migration is '$($amPolicy.PolicyMigrationState)': legacy MFA/SSPR settings may still allow methods this audit treats as disabled.")
    }
} catch {
    $coverage.Add('Authentication methods policy could not be read: ID-05 counts every registered MFA method as usable, even ones the policy disables.')
}
function Test-MethodUsable([string] $Type) {
    if ($null -eq $enabledMethodPolicies) { return $true }
    if (-not $MethodPolicyIds.ContainsKey($Type)) { return $true }
    return [bool]($MethodPolicyIds[$Type] | Where-Object { $_ -in $enabledMethodPolicies })
}

foreach ($u in $users | Where-Object { $_.AccountEnabled -and $_.UserType -eq 'Member' }) {
    try { $methods = @(Get-MgUserAuthenticationMethod -UserId $u.Id) }
    catch { $coverage.Add("Could not read authentication methods for $($u.UserPrincipalName)."); continue }
    $types    = @($methods | ForEach-Object { $_.AdditionalProperties['@odata.type'] } | Where-Object { $_ -in $MfaTypes })
    $usable   = @($types | Where-Object { Test-MethodUsable $_ })
    $disabled = @($types | Where-Object { -not (Test-MethodUsable $_) } | ForEach-Object { ($_ -replace '#microsoft.graph.', '') -replace 'AuthenticationMethod$', '' })
    if ($usable.Count -eq 0) {
        $isAdmin = $privUserIds -contains $u.Id
        if ($mfaEnforced) { $sev = if ($isAdmin) { 'Medium' } else { 'Low' } }
        else              { $sev = if ($isAdmin) { 'Critical' } else { 'High' } }
        $who = if ($isAdmin) { "Admin ($(Get-Roles $u.Id))" } else { 'Standard user' }
        $why = if ($mfaEnforced) { 'MFA is enforced, so they must register at next sign-in.' } else { 'A stolen password is enough to sign in.' }
        if ($disabled.Count -gt 0) {
            $title = 'MFA method registered but disabled by policy'
            $what  = "Registered: $($disabled -join ', '), but the Authentication methods policy disables it, so only the password works."
        } else {
            $title = 'No MFA method registered'
            $what  = 'Only a password.'
        }
        Add-Finding 'ID-05' $sev $title $u.UserPrincipalName "$who. $what $why" `
            'Turn on security defaults (or CA) and have the user register Microsoft Authenticator.'
    }
}
$coverage.Add('ID-05 checks registered methods against the Authentication methods policy, not whether MFA was actually used at sign-in. Guests register MFA in their home tenant and are not checked.')

# ---------------------------------------------------------------- ID-06 / ID-07 apps
$apps = @(Get-MgApplication -All)
$now = (Get-Date).ToUniversalTime()
foreach ($a in $apps) {
    foreach ($c in $a.PasswordCredentials) {
        $life = ($c.EndDateTime - $c.StartDateTime).TotalDays
        $label = "$($a.DisplayName) / secret '$($c.DisplayName)'"
        if ($c.EndDateTime -lt $now) {
            Add-Finding 'ID-06' 'Low' 'Expired app secret still present' $label "Expired $($c.EndDateTime.ToString('yyyy-MM-dd'))" 'Delete it.'
        } elseif ($life -gt $MaxSecretDays) {
            Add-Finding 'ID-06' 'Medium' "App secret valid for $([int]$life) days" $label `
                "Expires $($c.EndDateTime.ToString('yyyy-MM-dd')). A leaked long-lived secret stays useful to an attacker for years." `
                "Rotate to a secret of 6 months or less, or use a certificate / managed identity."
        }
    }
}

$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$graphRole = @{}; foreach ($r in $graphSp.AppRoles) { $graphRole[$r.Id] = $r.Value }
$ownSps = @(Get-MgServicePrincipal -All -Filter "appOwnerOrganizationId eq $TenantId" -ConsistencyLevel eventual -CountVariable n)
foreach ($sp in $ownSps) {
    $risky = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id |
        Where-Object { $_.ResourceId -eq $graphSp.Id -and $graphRole[$_.AppRoleId] -in $HighRiskGraphPerms } |
        ForEach-Object { $graphRole[$_.AppRoleId] })
    if ($risky) {
        Add-Finding 'ID-07' 'High' 'App holds high-risk Graph application permissions' $sp.DisplayName `
            "Application permissions (no user needed): $($risky -join ', ')" `
            'Remove them and grant only what the app needs (for example User.Read.All instead of Directory.ReadWrite.All).'
    }
}
$coverage.Add('ID-07 checks apps registered in this tenant only, and Microsoft Graph application permissions only (not delegated grants or other APIs).')

# ---------------------------------------------------------------- AZ-01 Azure RBAC (optional)
if ($SubscriptionId) {
    try {
        Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
        Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId -WarningAction SilentlyContinue | Out-Null
        $me = (Get-AzContext).Account.Id
        $rbac = @(Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" |
            Where-Object { $_.ObjectType -eq 'User' -and $_.RoleDefinitionName -in @('Owner', 'User Access Administrator', 'Role Based Access Control Administrator') })
        foreach ($r in $rbac) {
            $isMe = ($r.SignInName -eq $me)
            $sev = if ($isMe) { 'Low' } else { 'Medium' }
            $note = if ($isMe) { 'This is the account running the audit (normal for a personal subscription).' } else { 'Assigned directly to a person.' }
            Add-Finding 'AZ-01' $sev "Direct $($r.RoleDefinitionName) on Azure scope" "$($r.SignInName) @ $($r.Scope)" $note `
                'Assign Reader or Contributor through a group, at resource-group scope.'
        }
    } catch { $coverage.Add("AZ-01 did not run: $($_.Exception.Message)") }
} else {
    $coverage.Add('AZ-01 (Azure RBAC) skipped: no -SubscriptionId given.')
}

# ---------------------------------------------------------------- output
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$sorted = @($findings | Sort-Object { $sevRank[$_.Severity] }, Check, Target)
$sorted | Select-Object Check, Severity, Title, Target, Detail, Remediation |
    Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $OutDir 'findings.csv')

$maskedTenant = $TenantId.Substring(0, 8) + '-...'
$result = [ordered]@{
    generatedAt = (Get-Date).ToString('s'); tenant = $maskedTenant; licence = $licence
    securityDefaults = [bool]$sd.IsEnabled; findings = $sorted; coverage = $coverage
}
$result | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 (Join-Path $OutDir 'findings.json')

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# Entra ID identity audit')
[void]$md.AppendLine('')
[void]$md.AppendLine("Generated $($result.generatedAt) | tenant $maskedTenant | $licence | security defaults: $(if ($sd.IsEnabled) {'on'} else {'off'})")
[void]$md.AppendLine('')
[void]$md.AppendLine('## Summary')
[void]$md.AppendLine('')
[void]$md.AppendLine('| Severity | Count |'); [void]$md.AppendLine('|---|---|')
foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') {
    [void]$md.AppendLine("| $s | $(@($sorted | Where-Object Severity -eq $s).Count) |")
}

if ($Baseline) {
    $before = (Get-Content $Baseline -Raw | ConvertFrom-Json).findings
    $nowKeys = @{}; foreach ($f in $sorted) { $nowKeys[$f.Key] = $f }
    $beforeKeys = @{}; foreach ($f in $before) { $beforeKeys[$f.Key] = $f }
    [void]$md.AppendLine(''); [void]$md.AppendLine('## Before / after'); [void]$md.AppendLine('')
    [void]$md.AppendLine('| Check | Target | Before | After | Status |'); [void]$md.AppendLine('|---|---|---|---|---|')
    foreach ($b in ($before | Sort-Object { $sevRank[$_.Severity] }, Check)) {
        $a = $nowKeys[$b.Key]
        if (-not $a) { $status = 'Resolved'; $after = '-' }
        elseif ($sevRank[$a.Severity] -gt $sevRank[$b.Severity]) { $status = 'Reduced'; $after = $a.Severity }
        else { $status = 'Still open'; $after = $a.Severity }
        [void]$md.AppendLine("| $($b.Check) | $($b.Target) | $($b.Severity) | $after | $status |")
    }
    foreach ($a in $sorted | Where-Object { -not $beforeKeys.ContainsKey($_.Key) }) {
        [void]$md.AppendLine("| $($a.Check) | $($a.Target) | - | $($a.Severity) | New |")
    }
}

[void]$md.AppendLine(''); [void]$md.AppendLine('## Findings')
foreach ($f in $sorted) {
    [void]$md.AppendLine('')
    [void]$md.AppendLine("### [$($f.Severity)] $($f.Check): $($f.Title)")
    [void]$md.AppendLine("- **Target:** $($f.Target)")
    [void]$md.AppendLine("- **Detail:** $($f.Detail)")
    [void]$md.AppendLine("- **Fix:** $($f.Remediation)")
}
[void]$md.AppendLine(''); [void]$md.AppendLine('## Coverage notes'); [void]$md.AppendLine('')
foreach ($c in $coverage) { [void]$md.AppendLine("- $c") }
$md.ToString() | Out-File -Encoding utf8 (Join-Path $OutDir 'report.md')

# ---------------------------------------------------------------- console summary
Write-Host ''
$sorted | Group-Object Severity | Sort-Object { $sevRank[$_.Name] } | ForEach-Object { Write-Host ("{0,-9} {1}" -f $_.Name, $_.Count) }
Write-Host "`nWrote findings.csv, findings.json and report.md to $OutDir" -ForegroundColor Green
