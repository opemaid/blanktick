# Blanktick sensor — user-level process-start tap.
#
# Emits one tab-separated line per NEW process:
#   <epochMillis>\t<pid>\t<ppid>\t<parentImage>\t<image>\t<commandLine>
#
# This is the elevation-free fallback source. It polls Win32_Process and reports
# starts it had not seen before. The privileged provider (an ETW Kernel-Process
# session) sees starts the instant they happen, for every user, and cannot miss a
# short-lived process the way a poll between two ticks can — that one needs admin.
$ErrorActionPreference = 'SilentlyContinue'

# Prime with what is already running, so only genuinely new starts are emitted.
$seen = @{}
foreach ($p in Get-CimInstance Win32_Process) { $seen[$p.ProcessId] = $true }

while ($true) {
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $procs = Get-CimInstance Win32_Process
    $byId = @{}
    foreach ($p in $procs) { $byId[$p.ProcessId] = $p }
    foreach ($p in $procs) {
        if (-not $seen.ContainsKey($p.ProcessId)) {
            $seen[$p.ProcessId] = $true
            $parent = $byId[$p.ParentProcessId]
            $pname = if ($parent) { $parent.Name } else { '' }
            $cl = if ($p.CommandLine) { $p.CommandLine -replace "[`t`r`n]", ' ' } else { '' }
            "$now`t$($p.ProcessId)`t$($p.ParentProcessId)`t$pname`t$($p.Name)`t$cl"
        }
    }
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 800
}
