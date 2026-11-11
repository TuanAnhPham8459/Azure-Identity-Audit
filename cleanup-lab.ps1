<#
.SYNOPSIS
    Removes everything seed-lab.ps1 created. Run with -WhatIf first to preview.

.DESCRIPTION
    Deletes only tagged lab objects:
      - users whose companyName is "Northwind Bakery (lab)", plus the guest invited with -GuestEmail
      - groups named NW-* whose description contains "NorthwindLab"
      - app registrations tagged "NorthwindLab" (their service principals go with them)
    It never deletes the account you are signed in with, and never touches your break-glass account.
    Deleted users and apps stay in Entra ID's recycle bin for 30 days, then disappear on their own.

.EXAMPLE
    pwsh ./cleanup-lab.ps1 -TenantId <tenant-id> -GuestEmail "your.other.email@example.com" -WhatIf
    pwsh ./cleanup-lab.ps1 -TenantId <tenant-id> -GuestEmail "your.other.email@example.com"
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)] [string] $TenantId,
    [Parameter(Mandatory)] [string] $GuestEmail
)

$ErrorActionPreference = 'Stop'
$LabTag     = 'NorthwindLab'
$LabCompany = 'Northwind Bakery (lab)'

Connect-MgGraph -TenantId $TenantId -Scopes 'User.ReadWrite.All', 'Group.ReadWrite.All', 'Application.ReadWrite.All', 'Directory.Read.All' -NoWelcome
if ((Get-MgContext).TenantId -ne $TenantId) { throw "Connected to the wrong tenant. Stopping." }
$meId = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id').id

$users = @(Get-MgUser -All -Property Id, UserPrincipalName, CompanyName, Mail |
    Where-Object { ($_.CompanyName -eq $LabCompany -or $_.Mail -eq $GuestEmail) -and $_.Id -ne $meId })
$groups = @(Get-MgGroup -All -Filter "startswith(displayName,'NW-')" | Where-Object { $_.Description -like "*$LabTag*" })
$apps   = @(Get-MgApplication -All | Where-Object { $_.Tags -contains $LabTag })

Write-Host "Found $($users.Count) users, $($groups.Count) groups, $($apps.Count) apps to remove." -ForegroundColor Cyan

foreach ($a in $apps) {
    if ($PSCmdlet.ShouldProcess($a.DisplayName, 'Delete app registration')) { Remove-MgApplication -ApplicationId $a.Id; Write-Host "  deleted app   $($a.DisplayName)" }
}
foreach ($g in $groups) {
    if ($PSCmdlet.ShouldProcess($g.DisplayName, 'Delete group')) { Remove-MgGroup -GroupId $g.Id; Write-Host "  deleted group $($g.DisplayName)" }
}
foreach ($u in $users) {
    # Deleting a user also removes their directory role assignments.
    if ($PSCmdlet.ShouldProcess($u.UserPrincipalName, 'Delete user')) { Remove-MgUser -UserId $u.Id; Write-Host "  deleted user  $($u.UserPrincipalName)" }
}

if (Test-Path ./lab-manifest.json) {
    if ($PSCmdlet.ShouldProcess('lab-manifest.json', 'Delete local answer key')) { Remove-Item ./lab-manifest.json }
}

Write-Host "`nDone. Last steps by hand:" -ForegroundColor Green
Write-Host '  1. Entra ID > Overview > Properties > Manage security defaults > Enabled'
Write-Host '  2. If you made a break-glass account for the lab and no longer need it, delete it yourself.'
Write-Host '  3. If you gave a user Owner on your subscription (mistake 9), remove that role assignment.'
