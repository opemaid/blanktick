# Blanktick sensor — privileged, event-driven process tap.
#
# Emits the same tab-separated line as the poll tap:
#   <epochMillis>\t<pid>\t<ppid>\t<parentImage>\t<image>\t<commandLine>
#
# Source: Win32_ProcessStartTrace — the WMI surface of the NT kernel's process
# ETW trace. Unlike the poll tap this is push-based (no gap between ticks, so a
# process that starts and exits in a millisecond is still seen) and machine-wide
# (every user's processes, not just yours). It requires administrator rights; a
# non-elevated subscription yields nothing, so we say so up front and stop rather
# than pretend to watch.
$ErrorActionPreference = 'SilentlyContinue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
"#elevated=$($isAdmin.ToString().ToLower())"
[Console]::Out.Flush()
if (-not $isAdmin) { return }

Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier BtProcStart | Out-Null
try {
    while ($true) {
        $evt = Wait-Event -SourceIdentifier BtProcStart -Timeout 2
        if ($evt) {
            $e = $evt.SourceEventArgs.NewEvent
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            # $pid is a PowerShell automatic variable — never reuse it here.
            $childId = $e.ProcessID
            $parentId = $e.ParentProcessID
            $image = $e.ProcessName
            # Best-effort enrichment; a very short-lived process may already be gone.
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$childId"
            $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$parentId"
            $pname = if ($parent) { $parent.Name } else { '' }
            $cl = if ($proc -and $proc.CommandLine) { $proc.CommandLine -replace "[`t`r`n]", ' ' } else { '' }
            "$now`t$childId`t$parentId`t$pname`t$image`t$cl"
            Remove-Event -SourceIdentifier BtProcStart -ErrorAction SilentlyContinue
            [Console]::Out.Flush()
        }
    }
} finally {
    Unregister-Event -SourceIdentifier BtProcStart -ErrorAction SilentlyContinue
}
