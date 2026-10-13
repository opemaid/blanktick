# Blanktick sensor - file-integrity tap (ransomware shapes).
#
# Emits two tab-separated record kinds, distinguished by a leading token:
#   FILE  \t <at> \t <pid> \t <image> \t <path> \t <op> \t <highEntropy>
#   VSSDEL\t <at> \t <pid> \t <image> \t <commandLine>
#
# Two independent ransomware tells, from two native sources, no third-party
# install and no kernel driver:
#
#  * FILE - a FileSystemWatcher over the user's document folders. On each write
#    the first 4 KB is read and its Shannon entropy measured; only writes whose
#    entropy is in the ciphertext range (>= 7.8 bits/byte) are emitted, as
#    op=ENCRYPT_SUSPECTED. Without a minifilter the OS does not tell a user-level
#    watcher WHICH process wrote the file, so pid is -1. The burst rule still
#    fires on a mass-encryption run (it counts encryption-shaped writes in a
#    short window); it just cannot name the process, so enforcement degrades
#    from kill to alert. A Pro deployment with Sysmon FileCreate (EID 11) or a
#    minifilter restores per-process attribution.
#
#  * VSSDEL - a poll of new processes whose command line deletes volume shadow
#    copies or disables recovery (vssadmin/wmic/wbadmin/bcdedit/diskshadow/
#    PowerShell Win32_ShadowCopy). This path keeps the real pid, so its response
#    stays kill.
$ErrorActionPreference = 'SilentlyContinue'

# Watch documents and the desktop, NOT Pictures: photos (JPEG/PNG/HEIC) are
# inherently high-entropy, so a bulk import there would trip the burst on benign
# activity. Documents are the real ransomware target.
$roots = @(
    [Environment]::GetFolderPath('MyDocuments'),
    [Environment]::GetFolderPath('Desktop')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique

# Extensions that are legitimately high-entropy (compressed/media). A bulk copy
# or archive-extract of these must not count as encryption. Ransomware that
# encrypts them rewrites to a NEW extension, which is not on this list, so it is
# still caught.
# Global so the Register-ObjectEvent action block (a different scope) can see it.
$global:btBenignHighEntropyExt = @(
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tif', '.tiff', '.heic', '.heif',
    '.mp4', '.mov', '.avi', '.mkv', '.webm', '.mp3', '.m4a', '.flac', '.ogg',
    '.zip', '.7z', '.rar', '.gz', '.bz2', '.xz', '.jar'
)

$watchers = @()
$onChange = {
    $path = $Event.SourceEventArgs.FullPath
    try {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return }
        if ([IO.Path]::GetExtension($path).ToLower() -in $global:btBenignHighEntropyExt) { return }
        $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        try {
            $buf = New-Object byte[] 4096
            $read = $fs.Read($buf, 0, 4096)
        } finally { $fs.Close() }
        if ($read -le 0) { return }
        $freq = New-Object 'double[]' 256
        for ($i = 0; $i -lt $read; $i++) { $freq[$buf[$i]]++ }
        $entropy = 0.0
        foreach ($c in $freq) {
            if ($c -gt 0) { $p = $c / $read; $entropy -= $p * [Math]::Log($p, 2) }
        }
        if ($entropy -lt 7.8) { return }
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        [Console]::Out.WriteLine("FILE`t$now`t-1`t`t$path`tENCRYPT_SUSPECTED`ttrue")
        [Console]::Out.Flush()
    } catch {}
}
foreach ($r in $roots) {
    $w = New-Object IO.FileSystemWatcher $r, '*.*'
    $w.IncludeSubdirectories = $true
    $w.NotifyFilter = [IO.NotifyFilters]::LastWrite -bor [IO.NotifyFilters]::FileName
    Register-ObjectEvent -InputObject $w -EventName Changed -Action $onChange | Out-Null
    Register-ObjectEvent -InputObject $w -EventName Created -Action $onChange | Out-Null
    $w.EnableRaisingEvents = $true
    $watchers += $w
}

# Shadow-copy deletion: catch new processes whose command line removes backups.
$vssNames = @('vssadmin.exe','wmic.exe','wbadmin.exe','bcdedit.exe','diskshadow.exe','powershell.exe','pwsh.exe')
$vssPattern = '(?i)(delete\s+shadows|shadowcopy\s+delete|delete\s+catalog|delete\s+systemstatebackup|recoveryenabled\s+no|resize\s+shadowstorage|Win32_ShadowCopy|Remove-?\s*CimInstance.*ShadowCopy)'
# Key on pid + creation time, not pid alone: Windows reuses pids, and a pid-only
# "seen" set would skip a later malicious vssadmin that happens to reuse a pid we
# already marked. The composite key is unique per process instance.
function ProcKey($proc) { return "$($proc.ProcessId)|$($proc.CreationDate)" }
$seen = @{}
foreach ($p in Get-CimInstance Win32_Process) { $seen[(ProcKey $p)] = $true }

try {
    while ($true) {
        foreach ($p in Get-CimInstance Win32_Process) {
            $key = ProcKey $p
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $cl = if ($p.CommandLine) { $p.CommandLine -replace "[`t`r`n]", ' ' } else { '' }
            if (($p.Name.ToLower() -in $vssNames) -and ($cl -match $vssPattern)) {
                $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                [Console]::Out.WriteLine("VSSDEL`t$now`t$($p.ProcessId)`t$($p.Name)`t$cl")
            }
        }
        [Console]::Out.Flush()
        Start-Sleep -Milliseconds 800
    }
} finally {
    foreach ($w in $watchers) { $w.EnableRaisingEvents = $false; $w.Dispose() }
    Get-EventSubscriber | Unregister-Event -ErrorAction SilentlyContinue
}
