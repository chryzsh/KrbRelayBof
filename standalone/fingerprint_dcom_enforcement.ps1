# Fingerprint a host's DCOM hardening state, to triage the level-2 coercion hunt.
#
# The coerced OXID resolution auth level is forced to packet integrity on a host
# that has the DCOM hardening client-side raise (KB5004442, shipped 2022-11-08,
# locked 2023-03-14). On such a host no trigger yields a level-2 (CONNECT)
# context, so the LDAP relay write cannot land. A host behind that patch can
# still yield level 2 via a non-elevating service such as AxInstSv.
#
# This reports build, UBR, the enforcement registry value, and the newest
# installed update, then prints a triage verdict. The probe exe is the ground
# truth. This only ranks hosts worth probing.
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
