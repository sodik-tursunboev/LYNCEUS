<#
.SYNOPSIS  Does what this process writes to the registry reach Windows? And what does Windows itself see?

.DESCRIPTION
  A program started from inside a packaged (MSIX) app, for example a terminal embedded in such an app,
  gets a PRIVATE copy of the current user's registry: it can write "start at logon" and read it back, and
  Windows never sees it. That happened to a Lynceus install on 2026-11-07 (ADR-024): everything looked
  registered from the installing shell, nothing was, and after the next restart the old agent started
  with no engine. So registration is never trusted from the process that made it: these helpers ask WMI,
  which runs outside every app, what Windows really has. They only read (the probe writes one
  throwaway value and removes it).
#>

$script:HKCU = [uint32]2147483649   # HKEY_CURRENT_USER for StdRegProv

function Invoke-WindowsRegistry {
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][hashtable]$Arguments)
    $Arguments['hDefKey'] = $script:HKCU
    return Invoke-CimMethod -Namespace 'root/default' -ClassName 'StdRegProv' -MethodName $Method -Arguments $Arguments -ErrorAction Stop
}

# $true: a value written by this process is visible to Windows. $false: it went to a private copy
# (run this from a normal PowerShell window instead). $null: could not tell (WMI did not answer).
function Test-RegistryReachesWindows {
    $key = 'Software\Lynceus.RegistryProbe.' + [guid]::NewGuid().ToString('N')
    try {
        New-Item -Path "HKCU:\$key" -Force | Out-Null
        Set-ItemProperty -Path "HKCU:\$key" -Name 'probe' -Value '1'
        $seen = Invoke-WindowsRegistry 'GetStringValue' @{ sSubKeyName = $key; sValueName = 'probe' }
        return ($seen.ReturnValue -eq 0 -and $seen.sValue -eq '1')
    } catch {
        return $null
    } finally {
        Remove-Item -Path "HKCU:\$key" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# The value names under a key of the current user as Windows sees them; $null when the key is absent.
function Get-WindowsRegistryValueNames {
    param([Parameter(Mandatory)][string]$SubKey)
    $r = Invoke-WindowsRegistry 'EnumValues' @{ sSubKeyName = $SubKey }
    if ($r.ReturnValue -ne 0) { return $null }
    return , @($r.sNames | Where-Object { $null -ne $_ })
}

function Test-WindowsRegistryKey {
    param([Parameter(Mandatory)][string]$SubKey)
    return (Invoke-WindowsRegistry 'EnumValues' @{ sSubKeyName = $SubKey }).ReturnValue -eq 0
}

function Get-WindowsRegistryString {
    param([Parameter(Mandatory)][string]$SubKey, [Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    $r = Invoke-WindowsRegistry 'GetStringValue' @{ sSubKeyName = $SubKey; sValueName = $Name }
    if ($r.ReturnValue -ne 0) { return $null }
    return $r.sValue
}

# The names of the sandbox (AppContainer) profiles registered for this user, as Windows sees them.
function Get-WindowsSandboxProfiles {
    $base = 'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
    $keys = Invoke-WindowsRegistry 'EnumKey' @{ sSubKeyName = $base }
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($sid in @($keys.sNames | Where-Object { $null -ne $_ })) {
        $moniker = Get-WindowsRegistryString "$base\$sid" 'Moniker'
        if ($moniker) { $found.Add($moniker) }
    }
    return , $found.ToArray()
}

# What Windows has registered for Lynceus (and what the old name left), as one object.
function Get-LynceusRegistration {
    $run = Get-WindowsRegistryValueNames 'Software\Microsoft\Windows\CurrentVersion\Run'
    $profiles = Get-WindowsSandboxProfiles
    return [pscustomobject]@{
        RunLynceus    = [bool]($run -contains 'LynceusAgent')
        RunTarget     = Get-WindowsRegistryString 'Software\Microsoft\Windows\CurrentVersion\Run' 'LynceusAgent'
        RunOldName    = [bool]($run -contains 'MirageAgent')
        EdgeBridge    = Test-WindowsRegistryKey 'Software\Microsoft\Edge\NativeMessagingHosts\com.lynceus.agent'
        ChromeBridge  = Test-WindowsRegistryKey 'Software\Google\Chrome\NativeMessagingHosts\com.lynceus.agent'
        EdgeOldName   = Test-WindowsRegistryKey 'Software\Microsoft\Edge\NativeMessagingHosts\com.mirage.agent'
        ChromeOldName = Test-WindowsRegistryKey 'Software\Google\Chrome\NativeMessagingHosts\com.mirage.agent'
        Sandbox       = [bool]($profiles -contains 'lynceus.parser')
        SandboxOld    = [bool]($profiles -contains 'mirage.parser')
    }
}
