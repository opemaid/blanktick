# Blanktick sensor - privileged process tap via Sysmon ProcessCreate (EID 1).
#
# Emits the same tab-separated line as the other process taps:
#   <epochMillis>\t<pid>\t<ppid>\t<parentImage>\t<image>\t<commandLine>
#
# Source: Sysmon Operational log, Event ID 1 (ProcessCreate). EID 1 carries
# ParentImage and CommandLine INSIDE the event, captured at the kernel
# process-creation callback and persisted to the log, so a parent that spawns a
# shell and exits in a millisecond is still recorded with its parentage intact.
#
# It tails the log by RecordId with a time overlap, NOT by wall-clock windows: a
# window-boundary poll was dropping the agent's own ProcessStart (so DYN-AI-001,
# which must first tag the agent and then see its child shell, never fired). A
# strictly-increasing RecordId cursor plus an overlapping StartTime re-read makes
# the tail lossless and duplicate-free. Needs a Sysmon config that logs
# ProcessCreate, and admin to read the log.
$ErrorActionPreference = 'SilentlyContinue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
"#elevated=$($isAdmin.ToString().ToLower())"
[Console]::Out.Flush()

$has = [bool](Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
if ($has) { "#source=sysmon-eid1" } else { "#source=none" }
[Console]::Out.Flush()
if (-not $has) { return }

# Prime the cursor at the current end of the log so only NEW starts are emitted,
# the same discipline the poll tap uses.
$maxId = 0L
$latest = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1 } -MaxEvents 1 -ErrorAction SilentlyContinue
if ($latest) { $maxId = [long]$latest.RecordId }

while ($true) {
    # Re-read a 5s overlap every poll; the RecordId cursor dedups, so nothing is
    # dropped at a boundary and nothing is emitted twice.
    $events = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=(Get-Date).AddSeconds(-5) } -ErrorAction SilentlyContinue |
        Sort-Object RecordId
    foreach ($ev in $events) {
        $rid = [long]$ev.RecordId
        if ($rid -le $maxId) { continue }
        $maxId = $rid
        $x = [xml]$ev.ToXml()
        $d = @{}
        foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $pidv = if ($d['ProcessId']) { $d['ProcessId'] } else { '-1' }
        $ppid = if ($d['ParentProcessId']) { $d['ParentProcessId'] } else { '-1' }
        $img = $d['Image']
        $pimg = $d['ParentImage']
        $cl = if ($d['CommandLine']) { $d['CommandLine'] -replace "[`t`r`n]", ' ' } else { '' }
        "$now`t$pidv`t$ppid`t$pimg`t$img`t$cl"
    }
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 700
}
