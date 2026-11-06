<#
.SYNOPSIS  Folder permission helpers shared by install.ps1 (and tested on their own by tests/unit/test_deploy.py).

.DESCRIPTION
  The core runs from the checkout with your rights and your API token. On a default Windows install a folder
  made directly under C:\ is changeable by every signed-in account ("Authenticated Users: Modify"), so on a
  machine with a second account that account could replace the code the core runs. Get-ChangeableByOthers names
  such accounts; Protect-Folder restricts a folder to you, SYSTEM and Administrators.
#>

# Principals that may change the folder without it being a problem: the owner, SYSTEM, Administrators,
# TrustedInstaller, and CREATOR OWNER / OWNER RIGHTS (placeholders that mean "whoever owns the item").
function Test-TrustedSid {
    param([Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$Sid)
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().User
    return ($Sid -eq $me) -or $Sid.IsWellKnown([Security.Principal.WellKnownSidType]::LocalSystemSid) `
        -or $Sid.IsWellKnown([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid) `
        -or $Sid.Value -eq 'S-1-3-0' -or $Sid.Value -eq 'S-1-3-4' -or $Sid.Value.StartsWith('S-1-5-80-')
}

function Get-ChangeableByOthers {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $rights = [Security.AccessControl.FileSystemRights]
    $change = $rights::WriteData -bor $rights::AppendData -bor $rights::CreateFiles -bor $rights::Delete `
        -bor $rights::ChangePermissions -bor $rights::TakeOwnership
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        if ($rule.AccessControlType -ne 'Allow' -or (($rule.FileSystemRights -band $change) -eq 0)) { continue }
        $sid = $null
        try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]) } catch { }
        if ($sid -and (Test-TrustedSid $sid)) { continue }
        if (-not $found.Contains($rule.IdentityReference.Value)) { $found.Add($rule.IdentityReference.Value) }
    }
    return , $found.ToArray()
}

function Protect-Folder {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    # A fresh ACL: inheritance off (and what was inherited dropped), every earlier grant gone, then exactly
    # three: you, SYSTEM and Administrators, each with full control of the folder and what it will contain.
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $flags = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $full = [Security.AccessControl.FileSystemRights]::FullControl
    $allow = [Security.AccessControl.AccessControlType]::Allow
    $sids = @(
        [Security.Principal.WindowsIdentity]::GetCurrent().User,
        (New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::LocalSystemSid), $null),
        (New-Object Security.Principal.SecurityIdentifier ([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid), $null)
    )
    foreach ($sid in $sids) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule $sid, $full, $flags, ([Security.AccessControl.PropagationFlags]::None), $allow))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

# A folder that is certainly a MIRAGE install or data folder (so a typo cannot point a delete at something else).
function Test-MirageInstall {
    param([Parameter(Mandatory)][string]$Path)
    return (Test-Path -LiteralPath (Join-Path $Path 'agent\Mirage.Agent.exe'))
}

function Test-MirageData {
    param([Parameter(Mandatory)][string]$Path)
    foreach ($marker in 'agent.json', 'core.token', 'pipe.secret', 'spool.jsonl', 'flagged.json', 'quarantine') {
        if (Test-Path -LiteralPath (Join-Path $Path $marker)) { return $true }
    }
    return $false
}

# How many quarantined files have not been restored (their only copy is in the quarantine folder).
function Get-UnrestoredCount {
    param([Parameter(Mandatory)][string]$DataDir)
    $quarantine = Join-Path $DataDir 'quarantine'
    if (-not (Test-Path -LiteralPath $quarantine)) { return 0 }
    $count = 0
    foreach ($record in (Get-ChildItem -LiteralPath $quarantine -Filter record.json -Recurse -Depth 1 -File -ErrorAction SilentlyContinue)) {
        try {
            $state = (Get-Content -LiteralPath $record.FullName -Raw | ConvertFrom-Json).state
            if ($state -in 'quarantined', 'moving', 'copied') { $count++ }
        } catch { $count++ }   # a record that cannot be read is treated as unrestored: never guess
    }
    return $count
}

# True when $child is $parent or lies below it (a separator is required, so C:\a\bc is not under C:\a\b).
function Test-IsUnder {
    param([Parameter(Mandatory)][string]$Child, [Parameter(Mandatory)][string]$Parent)
    $c = [IO.Path]::GetFullPath($Child).TrimEnd('\') + '\'
    $p = [IO.Path]::GetFullPath($Parent).TrimEnd('\') + '\'
    return $c.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)
}
