# Blanktick sensor - credential-access (lsass handle) tap.
#
# Emits one tab-separated line per handle-open to a sensitive process:
#   <epochMillis>\t<pid>\t<image>\t<targetImage>\t<access>
#
# Credential theft reads lsass memory. One process opening a handle to another
# is not something a user-level poll of Win32_Process can see; it needs a source
# that records cross-process access. In priority order this tap uses whichever
# is present:
#   1. Sysmon - Operational log, Event ID 10 (ProcessAccess). The design spec's
#      source; a Pro deployment ships a Sysmon config that logs access to lsass.
#   2. Defender ASR - the "block credential stealing from lsass" rule, in audit
#      or block mode, writes Windows Defender/Operational 1121/1122 naming the
#      process that touched lsass. Native, no third-party install.
# If neither is present it prints #source=none and stops: credential theft is
# then UNOBSERVED and reported as a gap, never as clean.
#
# Both sources are tailed by a strictly-increasing RecordId cursor with a time
# overlap, so no event is dropped at a poll boundary and none is emitted twice.
# Reading these Operational logs needs administrator rights.
$ErrorActionPreference = 'SilentlyContinue'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
"#elevated=$($isAdmin.ToString().ToLower())"
[Console]::Out.Flush()

$hasSysmon = [bool](Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
$defLog = 'Microsoft-Windows-Windows Defender/Operational'
$hasDef = [bool](Get-WinEvent -ListLog $defLog -ErrorAction SilentlyContinue)

if ($hasSysmon) { "#source=sysmon" } elseif ($hasDef) { "#source=defender-asr" } else { "#source=none" }
[Console]::Out.Flush()
if (-not $hasSysmon -and -not $hasDef) { return }

function Prime($log, $id) {
    $e = Get-WinEvent -FilterHashtable @{ LogName=$log; Id=$id } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) { return [long]$e.RecordId } else { return 0L }
}
$sysMax = if ($hasSysmon) { Prime 'Microsoft-Windows-Sysmon/Operational' 10 } else { 0L }
$defMax = if ($hasDef) { Prime $defLog @(1121, 1122) } else { 0L }

while ($true) {
    $since = (Get-Date).AddSeconds(-5)
    if ($hasSysmon) {
        $evs = Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Sysmon/Operational'; Id=10; StartTime=$since } -ErrorAction SilentlyContinue |
            Sort-Object RecordId
        foreach ($ev in $evs) {
            $rid = [long]$ev.RecordId
            if ($rid -le $sysMax) { continue }
            $sysMax = $rid
            $x = [xml]$ev.ToXml(); $d = @{}
            foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
            if ($d['TargetImage'] -notmatch 'lsass\.exe$') { continue }
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            $src = $d['SourceImage']
            $spid = if ($d['SourceProcessId']) { $d['SourceProcessId'] } else { '-1' }
            $acc = if ($d['GrantedAccess']) { $d['GrantedAccess'] } else { '' }
            "$now`t$spid`t$src`t$($d['TargetImage'])`t$acc"
        }
    }
    if ($hasDef) {
        $evs = Get-WinEvent -FilterHashtable @{ LogName=$defLog; Id=1121, 1122; StartTime=$since } -ErrorAction SilentlyContinue |
            Sort-Object RecordId
        foreach ($ev in $evs) {
            $rid = [long]$ev.RecordId
            if ($rid -le $defMax) { continue }
            $defMax = $rid
            $x = [xml]$ev.ToXml(); $d = @{}
            foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } }
            $proc = if ($d['Process']) { $d['Process'] } else { $d['Path'] }
            if (-not $proc) { continue }
            if ($d['ID'] -and $d['ID'] -notmatch '9e6c4e1f') { continue }
            $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            "$now`t-1`t$proc`tC:\Windows\System32\lsass.exe`tASR"
        }
    }
    [Console]::Out.Flush()
    Start-Sleep -Milliseconds 1500
}
