# Fingerprint a host's DCOM hardening state and coercion triggers, to triage the
# level-2 coercion hunt.
#
# The coerced OXID resolution auth level is forced to packet integrity on a host
# that has the DCOM hardening client-side raise (KB5004442, shipped 2022-11-08,
# locked 2023-03-14). On such a host no trigger yields a level-2 (CONNECT)
# context, so the LDAP relay write cannot land. A host behind that patch can
# still yield level 2 via a non-elevating service such as AxInstSV.
#
# This reports build, UBR, the enforcement registry value, the newest installed
# update, and the state of the known trigger services. The probe exe reads the
# actual coerced auth level and is the ground truth. This only ranks hosts.
#
#   powershell -ExecutionPolicy Bypass -File .\fingerprint_dcom_enforcement.ps1

$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$req = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Ole\AppCompat' `
    -Name 'RequireIntegrityActivationAuthenticationLevel' -ErrorAction SilentlyContinue
    ).RequireIntegrityActivationAuthenticationLevel
$hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1

$reqStr = if ($null -eq $req) { 'unset(default)' } else { "$req" }
$hfStr = if ($hf) { "$($hf.HotFixID)@$(($hf.InstalledOn).ToString('yyyy-MM-dd'))" } else { 'na' }

[pscustomobject]@{
    Host         = $env:COMPUTERNAME
    Product      = $cv.ProductName
    Display      = $cv.DisplayVersion
    Build        = "$($cv.CurrentBuildNumber).$($cv.UBR)"
    ReqIntegrity = $reqStr
    LastHotfix   = $hfStr
} | Format-List

# Known machine-account DCOM coercion triggers. A service that is present and not
# disabled is the precondition for using it. Feed the CLSID to the probe exe,
# which reads the actual coerced auth level, the value that decides whether the
# LDAP write can land.
$triggers = @(
    @{ Name = 'AxInstSV';             CLSID = '{90F18417-F0F1-484E-9D3C-59DCEEE5DBD8}' }
    @{ Name = 'McpManagementService'; CLSID = '{A9819296-E5B3-4E67-8226-5E72CE9E1FB7}' }
)
Write-Host "Known coercion-trigger services:"
foreach ($t in $triggers) {
    $s = Get-Service $t.Name -ErrorAction SilentlyContinue
    if ($null -eq $s) {
        "  {0,-22} not present" -f $t.Name
    } else {
        $w = Get-CimInstance Win32_Service -Filter "Name='$($t.Name)'" -ErrorAction SilentlyContinue
        "  {0,-22} status={1} start={2} acct={3}  {4}" -f `
            $t.Name, $s.Status, $s.StartType, $w.StartName, $t.CLSID
    }
}
