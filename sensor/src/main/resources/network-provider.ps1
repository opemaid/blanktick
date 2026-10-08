# Blanktick sensor — user-level outbound-TCP tap.
#
# Emits one tab-separated line per NEW established remote connection:
#   <epochMillis>\t<pid>\t<image>\t<remoteAddress>\t<remotePort>\tTCP
#
# Polls Get-NetTCPConnection. The ETW Kernel-Network provider (admin) sees every
# connection the instant it opens; this poll can miss a very short-lived one.
$ErrorActionPreference = 'SilentlyContinue'

$seen = @{}
$loopback = @('127.0.0.1', '::1', '0.0.0.0', '::')

while ($true) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    foreach ($c in Get-NetTCPConnection -State Established) {
        $ra = $c.RemoteAddress
        if ($loopback -contains $ra) { continue }
        $key = "$($c.OwningProcess)|$ra|$($c.RemotePort)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $img = ''
            $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) { $img = $proc.ProcessName + '.exe' }
            "$now`t$($c.OwningProcess)`t$img`t$ra`t$($c.RemotePort)`tTCP"
        }
    }
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 1500
}
