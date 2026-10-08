# Blanktick sensor — user-level DNS tap.
#
# Emits one tab-separated line per NEW resolver-cache entry:
#   <epochMillis>\t<queryName>
#
# Polls Get-DnsClientCache. The cache is machine-wide and not attributed to a
# process, so no pid is carried. The ETW DNS-Client provider (admin) sees each
# live query with the process that made it.
$ErrorActionPreference = 'SilentlyContinue'

$seen = @{}
# Prime with what is already cached, so only names resolved from now on are emitted.
foreach ($e in Get-DnsClientCache) { if ($e.Entry) { $seen[$e.Entry] = $true } }

while ($true) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    foreach ($e in Get-DnsClientCache) {
        $n = $e.Entry
        if (-not $n) { continue }
        if (-not $seen.ContainsKey($n)) {
            $seen[$n] = $true
            "$now`t$n"
        }
    }
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 2000
}
