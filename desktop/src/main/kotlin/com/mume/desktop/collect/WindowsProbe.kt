package com.mume.desktop.collect

/**
 * The complete set of commands Mume runs on a Windows machine.
 *
 * ## Read it. That is the point.
 *
 * This is deliberately one readable block rather than thirty strings scattered
 * through a collector. A person who wants to know what a security app is doing
 * on their computer can read this, paste it into PowerShell, and compare the
 * output line by line against what Mume displayed. An app that asks you to
 * trust it about privacy should be the easiest thing in the world to check.
 *
 * ## What it is allowed to be
 *
 * Every statement is a **query**. There is no `Set-`, no `New-`, no `Remove-`,
 * no `Start-`, no `Stop-`, and no file is written. Mume reports; the user
 * decides and acts. `WindowsProbeTest` asserts that property against this
 * string, so a mutating command cannot be added without a test failing.
 *
 * Nothing typed into the app is interpolated here. The script is a compile-time
 * constant with no parameters, which is what makes it safe to hand to a shell
 * at all.
 *
 * ## Output format
 *
 * `key=value`, one per line. A key may repeat (autoruns, certificates, ports).
 *
 * ### Two kinds of absence, and why every enumeration ends in a sentinel
 *
 * A query that finds nothing emits nothing — and *a query that failed* also
 * emits nothing. Those are opposite answers ("no listening ports" versus "the
 * port table could not be read") and the raw output cannot tell them apart.
 * Worse, a loop that dies halfway emits a **partial** list that looks complete:
 * three admin accounts enumerated, the fourth throws, and the rule scores a
 * machine on the three it saw.
 *
 * So every enumeration ends with an `*.enumerated` sentinel, emitted only if
 * the loop ran to the end. No sentinel, no answer — the collector returns
 * `null` and the rule reports *not checkable*. The last line of the script is
 * `probe.complete`, which does the same job for the script as a whole: without
 * it the scan is treated as degraded rather than presented as a clean result.
 */
internal object WindowsProbe {

    val SCRIPT: String = """
        ${'$'}ErrorActionPreference = 'SilentlyContinue'
        ${'$'}ProgressPreference = 'SilentlyContinue'

        # San() sanitises ONE FIELD. Emit() sanitises an assembled row.
        #
        # The distinction is the whole point. Fields below can carry a string an
        # ATTACKER CHOSE -- a program's DisplayName, a Run-key value name, a
        # certificate Subject are all set by whoever installed the thing -- and
        # multi-field rows are TAB separated. An unsanitised tab inside one of
        # those strings shifts every later field along by one: a program
        # installed as `Evil<TAB>1.0<TAB>Microsoft Corporation` parses as
        # name=Evil, version=1.0, publisher=Microsoft Corporation. That forges
        # the publisher and walks straight past DSK-SW-002; the same trick on an
        # autorun name forges the Authenticode status and defeats DSK-AUTO-001.
        # A security control disabled by its own input.
        #
        # The first fix stripped tabs inside Emit. That silently broke every
        # multi-field row, because Emit receives the row AFTER assembly and so
        # ate the separators too -- autoruns dropped from 9 to 0 without an
        # error. Sanitising has to happen per field, before the separator is
        # added, which is what San() is for.
        #
        # The 512-character cap is the other half. Registry values run to
        # megabytes, output is read with a ceiling, and the probe emits in
        # source order -- so one program with an enormous DisplayName would push
        # everything asked later off the end of the stream and delete those
        # findings without a word. A name nobody can read is not worth a fact
        # nobody receives.
        function San(${'$'}v) {
          ${'$'}s = ("${'$'}v" -replace '[\r\n\t]+', ' ')
          if (${'$'}s.Length -gt 512) { ${'$'}s.Substring(0, 512) + '...' } else { ${'$'}s }
        }
        function Emit(${'$'}k, ${'$'}v) {
          if (${'$'}null -ne ${'$'}v -and "${'$'}v".Trim() -ne '') {
            Write-Output ("{0}={1}" -f ${'$'}k, ("${'$'}v" -replace '[\r\n]+', ' '))
          }
        }
        function Reg(${'$'}path, ${'$'}name) {
          (Get-ItemProperty -Path ${'$'}path -Name ${'$'}name -ErrorAction SilentlyContinue).${'$'}name
        }

        # Files worth a second opinion, gathered as the sweeps run and scanned
        # in one place at the end. Collecting them rather than scanning inline
        # keeps the per-file cost in a single, obvious block.
        ${'$'}script:scanTargets = @()

        # SHA-256 of a file, for comparison against the bundled known-malware
        # table. Only ever called on the small set that matters -- the programs
        # that start themselves and the ones running out of personal folders --
        # never on the disk at large. Roughly sixty files, not sixty thousand.
        #
        # Capped at 200 MB. A hash of a 4 GB game costs seconds and buys nothing:
        # commodity malware is small, and a scan the user cancels finds nothing
        # at all.
        # ## Why .NET directly instead of Get-FileHash
        #
        # Get-FileHash lives in a module, and a module has to be found. When
        # Mume is launched from a process whose PSModulePath points at
        # PowerShell 7's module directories -- a terminal, an IDE, a build tool
        # -- the Windows PowerShell 5.1 child inherits that path, cannot locate
        # its own modules, and Get-FileHash simply does not exist. Measured
        # here: 3 modules loaded and `Get-Command Get-FileHash` returning
        # nothing, in a shell that works perfectly when started by hand.
        #
        # The consequence was the quiet kind. Hashing returned nothing, every
        # file reported as un-hashed, and the malware check said "not
        # performed" -- correctly, by the null contract, and for a reason that
        # had nothing to do with the machine being scanned. It would have
        # worked for a user who double-clicked the exe and silently not worked
        # for one who ran it from a terminal.
        #
        # These types are part of the .NET base library. They need no module,
        # no auto-loading and no PSModulePath, so this behaves identically
        # however the app was started. [Shell] also strips the inherited
        # PSModulePath now, which fixes the class of problem rather than this
        # one instance.
        function FileHash(${'$'}path) {
          if (-not ${'$'}path) { return '' }
          try {
            ${'$'}f = Get-Item -LiteralPath ${'$'}path -ErrorAction Stop
            if (${'$'}f.Length -gt 209715200) { return '' }
            ${'$'}sha = [System.Security.Cryptography.SHA256]::Create()
            try {
              ${'$'}stream = [System.IO.File]::OpenRead(${'$'}f.FullName)
              try { return [System.BitConverter]::ToString(${'$'}sha.ComputeHash(${'$'}stream)).Replace('-', '').ToLower() }
              finally { ${'$'}stream.Dispose() }
            } finally { ${'$'}sha.Dispose() }
          } catch { return '' }
        }

        # A file carries a Zone.Identifier stream when it was downloaded. On a
        # program that has been set to start automatically, that pairing --
        # arrived from the internet, and now runs every time you sign in -- is
        # worth saying out loud.
        function FromInternet(${'$'}path) {
          if (-not ${'$'}path) { return ${'$'}false }
          try { ${'$'}null = Get-Item -LiteralPath ${'$'}path -Stream Zone.Identifier -ErrorAction Stop; return ${'$'}true }
          catch { return ${'$'}false }
        }


        # ---- identity -------------------------------------------------------
        Emit 'os.build' ((Get-CimInstance Win32_OperatingSystem).Caption + ' ' + [Environment]::OSVersion.Version)

        # Proves the hashing path works in whatever environment the probe was
        # launched into, against a file every Windows machine has. Without it,
        # "nothing matched the malware list" and "hashing silently returned
        # nothing" are the same output -- which is the failure mode this whole
        # project keeps having to design against.
        Emit 'hash.selfTest' (FileHash (Join-Path ${'$'}env:SystemRoot 'System32\notepad.exe'))

        # The language mode the probe is running under. Constrained Language
        # Mode (WDAC, AppLocker, or the __PSLockdownPolicy registry value)
        # blocks COM object creation, which is how the unprivileged BitLocker
        # read works -- so under lockdown that check returns nothing for a
        # reason that has nothing to do with encryption. Emitted so the app can
        # say which, instead of showing an unexplained blank.
        Emit 'ps.languageMode' ${'$'}ExecutionContext.SessionState.LanguageMode

        # ---- firewall -------------------------------------------------------
        # Get-NetFirewallProfile rather than `netsh advfirewall show`: netsh
        # localises both the profile names and the words ON/OFF, so parsing it
        # would fail on a non-English install -- and fail towards "off", which
        # would accuse a correctly configured machine.
        ${'$'}fwOk = ${'$'}true
        try {
          foreach (${'$'}p in Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) {
            Emit 'fw.profile' ("{0}`t{1}" -f (San ${'$'}p.Name), ${'$'}p.Enabled)
          }
        } catch { ${'$'}fwOk = ${'$'}false }
        # Windows has exactly three profiles. Fewer means the enumeration died
        # partway, and "the two I managed to read are both on" is not an answer
        # about the machine's firewall.
        if (${'$'}fwOk) { Emit 'fw.enumerated' 'True' }

        # ---- malware defence ------------------------------------------------
        Emit 'av.registered' ((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -First 1).displayName)
        ${'$'}mp = Get-MpComputerStatus
        if (${'$'}mp) {
          Emit 'av.defenderPresent' 'True'
          Emit 'av.realtimeEnabled' ${'$'}mp.RealTimeProtectionEnabled
          Emit 'av.signatureAgeDays' ${'$'}mp.AntivirusSignatureAge
        }
        Emit 'smartscreen.policy'   (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen')
        Emit 'smartscreen.explorer' (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')

        # ---- boot integrity -------------------------------------------------
        # Read from the registry, not Confirm-SecureBootUEFI, which needs
        # elevation Mume deliberately does not ask for.
        Emit 'secureboot.enabled' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled')

        # ---- updates --------------------------------------------------------
        Emit 'update.noAutoUpdate'     (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate')
        Emit 'update.serviceStartType' (Get-Service -Name wuauserv).StartType
        ${'$'}hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if (${'$'}hf -and ${'$'}hf.InstalledOn) {
          Emit 'update.daysSinceLast' ([int]((Get-Date) - ${'$'}hf.InstalledOn).TotalDays)
        }

        # ---- accounts -------------------------------------------------------
        Emit 'acct.sessionIsAdmin' (([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))

        # Resolved by SID, not by the name "Administrators", which is localised:
        # on a German install the group is "Administratoren" and a name lookup
        # returns nothing, which would read as "no administrators on this machine".
        ${'$'}adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
        if (${'$'}adminGroup) {
          # Get-LocalGroupMember throws mid-enumeration on machines with Azure AD
          # or orphaned-SID members -- a documented Windows defect, not an edge
          # case. Without the sentinel the partial list reads as the whole
          # group, and an extra administrator account hides behind whichever
          # member happened to fail first.
          ${'$'}adminOk = ${'$'}true
          try {
            foreach (${'$'}m in Get-LocalGroupMember -Group ${'$'}adminGroup -ErrorAction Stop) {
              Emit 'acct.admin' (San ${'$'}m.Name)
            }
          } catch { ${'$'}adminOk = ${'$'}false }
          if (${'$'}adminOk) { Emit 'acct.adminEnumerated' 'True' }
        }

        ${'$'}users = Get-LocalUser
        if (${'$'}users) {
          # Emitted so that "no passwordless accounts" can be told apart from
          # "the enumeration failed". Without it, a domain-joined machine that
          # refuses Get-LocalUser would look like a clean pass.
          Emit 'acct.userCount' (${'$'}users | Measure-Object).Count
          foreach (${'$'}u in ${'$'}users) {
            if (${'$'}u.Enabled -and -not ${'$'}u.PasswordRequired) { Emit 'acct.passwordless' (San ${'$'}u.Name) }
            # The built-in Guest account is RID 501. Matched on the SID suffix
            # because -SID does not accept a wildcard and the account name is
            # localised.
            if (${'$'}u.SID.Value -like '*-501') { Emit 'acct.guestEnabled' ${'$'}u.Enabled }
          }
          ${'$'}me = ${'$'}users | Where-Object { ${'$'}_.Name -eq [Environment]::UserName }
          if (${'$'}me) { Emit 'acct.currentPasswordRequired' ${'$'}me.PasswordRequired }
        }

        # ---- lock -----------------------------------------------------------
        Emit 'lock.screenSaverActive'   (Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive')
        Emit 'lock.screenSaverIsSecure' (Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure')
        Emit 'lock.screenSaverTimeout'  (Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut')

        # ---- disk encryption ------------------------------------------------
        # The shell property works without elevation; Get-BitLockerVolume does not.
        ${'$'}shell = New-Object -ComObject Shell.Application
        Emit 'bitlocker.protection' ${'$'}shell.NameSpace(${'$'}env:SystemDrive + '\').Self.ExtendedProperty('System.Volume.BitLockerProtection')

        # ---- remote access --------------------------------------------------
        Emit 'rdp.denyConnections'    (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections')
        Emit 'rdp.userAuthentication' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication')
        Emit 'ssh.status'             (Get-Service -Name sshd).Status

        # ---- listening sockets ----------------------------------------------
        # Reads the kernel's connection table. Nothing is connected to.
        ${'$'}portOk = ${'$'}true
        try {
          foreach (${'$'}c in Get-NetTCPConnection -State Listen -ErrorAction Stop) {
            ${'$'}proc = (Get-Process -Id ${'$'}c.OwningProcess).ProcessName
            Emit 'port' ("{0}`t{1}`t{2}" -f ${'$'}c.LocalAddress, ${'$'}c.LocalPort, (San ${'$'}proc))
          }
        } catch { ${'$'}portOk = ${'$'}false }
        if (${'$'}portOk) { Emit 'port.enumerated' 'True' }

        # ---- network --------------------------------------------------------
        ${'$'}dnsOk = ${'$'}true
        try {
          foreach (${'$'}a in Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop) {
            foreach (${'$'}s in ${'$'}a.ServerAddresses) { Emit 'dns' ${'$'}s }
          }
        } catch { ${'$'}dnsOk = ${'$'}false }
        if (${'$'}dnsOk) { Emit 'dns.enumerated' 'True' }
        Emit 'proxy.enable' (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyEnable')
        Emit 'proxy.server' (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'ProxyServer')

        # ---- trust store ----------------------------------------------------
        # Only certificates present in the CURRENT USER root store and absent
        # from the machine store.
        #
        # The obvious version of this check -- "list CurrentUser\Root" -- is
        # wrong, and wrong in the worst direction. Windows mirrors the machine
        # root store into every user's store, so on this developer's machine
        # that query returns 52 certificates, all of them legitimate, and the
        # app would have reported 52 critical TLS-interception findings on a
        # perfectly healthy computer. Measured before shipping, not after.
        #
        # The difference below is unambiguous: a certificate that exists for
        # this user and not for the machine was added for this user, which is
        # what Fiddler, mitmproxy and per-user corporate proxies do.
        #
        # KNOWN GAP: a certificate installed machine-wide is NOT detected. It
        # sits in LocalMachine\Root alongside Microsoft's own roots, and
        # telling them apart needs a pinned list of Microsoft root thumbprints
        # that this build does not yet bundle. Distinguishing them by subject
        # name would be worse than useless -- the name is the one part an
        # attacker controls. Stated in the About screen rather than papered
        # over.
        ${'$'}machineThumbs = @{}
        foreach (${'$'}c in Get-ChildItem Cert:\LocalMachine\Root) { ${'$'}machineThumbs[${'$'}c.Thumbprint] = ${'$'}true }
        foreach (${'$'}cert in Get-ChildItem Cert:\CurrentUser\Root) {
          if (-not ${'$'}machineThumbs.ContainsKey(${'$'}cert.Thumbprint)) {
            Emit 'cert' ("{0}`t{1}`t{2}" -f (San ${'$'}cert.Subject), (San ${'$'}cert.Issuer), ${'$'}cert.Thumbprint)
          }
        }
        # Emitted so "no user-added certificates" can be told apart from "the
        # store could not be read". Without it, a failed enumeration would look
        # like a clean pass.
        Emit 'cert.storeRead' 'True'

        # ---- removable media --------------------------------------------------
        # AutoRun policy. ABSENT is the hardened Windows 10/11 default -- autorun
        # on removable drives has been off since 2011 -- so absence is reported as
        # blocked, not as unknown. Bit 0x04 is DRIVE_REMOVABLE: set means autorun
        # is disabled for that class, clear means it is allowed.
        #
        # HKLM is read LAST and wins. Windows resolves this policy machine-first,
        # and the previous order had HKCU overriding -- so a value written to the
        # per-user key, which needs no administrator rights at all, decided what
        # Mume reported. An unprivileged process could set HKCU to the hardened
        # value and be told autorun was blocked while the machine policy actually
        # allowed it. Precedence has to match the OS, or the check describes a
        # machine that does not exist.
        ${'$'}arRaw = ${'$'}null
        foreach (${'$'}k in @(
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
          ${'$'}v = Reg ${'$'}k 'NoDriveTypeAutoRun'
          if (${'$'}null -ne ${'$'}v) { ${'$'}arRaw = ${'$'}v }
        }
        if (${'$'}null -eq ${'$'}arRaw) {
          Emit 'usb.autorunBlocked' 'True'
        } else {
          Emit 'usb.autorunBlocked' ((([int]${'$'}arRaw) -band 0x04) -ne 0)
        }

        # Removable drives attached right now, with their encryption state read
        # through the same unprivileged shell property used for the system drive.
        # Reuses the single Shell.Application handle created for the system-drive
        # BitLocker read above. WindowsProbeTest asserts there is exactly ONE
        # New-Object in this script, so a second handle here fails the build --
        # which is the guard working, not an obstacle to route around.
        ${'$'}driveOk = ${'$'}true
        try {
          foreach (${'$'}vol in Get-Volume -ErrorAction Stop | Where-Object { ${'$'}_.DriveType -eq 'Removable' -and ${'$'}_.DriveLetter }) {
            ${'$'}bl = ${'$'}shell.NameSpace("${'$'}(${'$'}vol.DriveLetter):\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
            Emit 'drive' ("{0}`t{1}`t{2}`t{3}`t{4}" -f ${'$'}vol.DriveLetter, (San ${'$'}vol.FileSystemLabel), (San ${'$'}vol.FileSystem), ${'$'}vol.Size, ${'$'}bl)
          }
        } catch { ${'$'}driveOk = ${'$'}false }
        # Emitted so "no drive attached" can be told apart from "the enumeration
        # failed" -- the rule reports not-checkable for the first and must not
        # treat either as a pass.
        if (${'$'}driveOk) { Emit 'drive.enumerated' 'True' }

        # What this computer remembers having been plugged in. Not a finding and
        # never scored: it is shown because a machine quietly keeping a list of
        # every stick and handset you have ever connected is something people are
        # surprised to learn.
        foreach (${'$'}d in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices') {
          ${'$'}n = (Get-ItemProperty ${'$'}d.PSPath -Name FriendlyName).FriendlyName
          if (${'$'}n) { Emit 'usbdevice' (San ${'$'}n) }
        }
        foreach (${'$'}d in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR') {
          Emit 'usbdevice' (San (${'$'}d.PSChildName -replace '^Disk&Ven_' , '' -replace '&Rev_.*' , '' -replace '&Prod_' , ' '))
        }

        # ---- installed software ---------------------------------------------
        # The OS's own uninstall registry -- the same source Settings > Apps
        # reads. No elevation, no filesystem walk, nothing hashed.
        #
        # SystemComponent and ParentKeyName entries are skipped: they are update
        # packages and sub-components, not programs a person installed, and
        # including them roughly triples the count with noise.
        #
        # `userWritable` is computed HERE rather than in Kotlin because only the
        # shell knows how these folders actually expand on this machine.
        ${'$'}userRoots = @(${'$'}env:LOCALAPPDATA, ${'$'}env:APPDATA, ${'$'}env:TEMP,
                       (Join-Path ${'$'}env:USERPROFILE 'Downloads'))
        ${'$'}progOk = ${'$'}true
        try {
          foreach (${'$'}root in @(
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
            foreach (${'$'}e in Get-ItemProperty ${'$'}root -ErrorAction Stop) {
              if (-not ${'$'}e.DisplayName) { continue }
              if (${'$'}e.SystemComponent -eq 1) { continue }
              if (${'$'}e.ParentKeyName) { continue }
              ${'$'}loc = "${'$'}(${'$'}e.InstallLocation)"
              ${'$'}writable = ${'$'}false
              foreach (${'$'}r in ${'$'}userRoots) {
                if (${'$'}r -and ${'$'}loc -and ${'$'}loc.StartsWith(${'$'}r, 'OrdinalIgnoreCase')) { ${'$'}writable = ${'$'}true }
              }
              Emit 'program' ("{0}`t{1}`t{2}`t{3}`t{4}" -f (San ${'$'}e.DisplayName), (San ${'$'}e.DisplayVersion), (San ${'$'}e.Publisher), (San ${'$'}loc), ${'$'}writable)
            }
          }
        } catch { ${'$'}progOk = ${'$'}false }
        # Emitted so "no programs found" can be told apart from "the enumeration
        # failed", exactly as acct.userCount does for local accounts.
        if (${'$'}progOk) { Emit 'program.enumerated' 'True' }

        # ---- programs that start themselves ---------------------------------
        #
        # ## Why this list is so much longer than it used to be
        #
        # It used to be four places: the two Run keys and the two Startup
        # folders, justified in a comment claiming services and scheduled tasks
        # "need elevation to enumerate reliably". That claim was wrong. Measured
        # in a plain, non-elevated session on the development machine,
        # Get-ScheduledTask returned all 210 tasks and Win32_Service all 306.
        #
        # The cost of the wrong premise: the old build showed 9 things that
        # start themselves. On the same machine 39 more sat in places it never
        # looked -- 20 third-party scheduled tasks, 15 auto-start services
        # outside system32, 2 RunOnce values, and Winlogon's Shell and Userinit.
        # Scheduled tasks are where modern commodity malware actually persists,
        # precisely because the Run key is the place everybody checks.
        #
        # A short list is not a modest claim. A user reading nine signed entries
        # concludes nothing else starts itself, and for the app to leave them
        # with that impression is worse than showing nothing at all.

        # Resolves the executable a command line will actually launch.
        #
        # The old version took the first token when the path was unquoted, via
        # `^(?<p>[^ ]+\.exe)` -- a regex that cannot match a path containing a
        # space. `C:\Program Files\Evil\run.exe` yielded nothing, so no signature
        # was fetched, so the entry reported "unknown" and DSK-AUTO-001 skips
        # unknowns rather than accusing them. **One space in the filename and
        # the signature check never happened.** The bypass costs an attacker a
        # rename.
        #
        # This walks the tokens from longest prefix down and takes the first
        # that names a file that exists, which is what Windows itself does with
        # an unquoted path, and expands environment variables first so
        # %APPDATA%-style entries resolve at all.
        function ExePath(${'$'}cmd) {
          ${'$'}c = [Environment]::ExpandEnvironmentVariables("${'$'}cmd").Trim()
          if (${'$'}c.StartsWith('"')) { return ${'$'}c.Substring(1).Split('"')[0] }
          ${'$'}parts = ${'$'}c.Split(' ')
          for (${'$'}i = ${'$'}parts.Count; ${'$'}i -ge 1; ${'$'}i--) {
            ${'$'}cand = (${'$'}parts[0..(${'$'}i - 1)] -join ' ')
            # Every probe of the filesystem here uses a string SOMEONE ELSE
            # WROTE. Reserved device names, reparse points and malformed paths
            # all raise terminating errors, so this is guarded per candidate:
            # resolving one entry must never be able to end the loop over the
            # others.
            try {
              if (${'$'}cand -and (Test-Path -LiteralPath ${'$'}cand -PathType Leaf -ErrorAction Stop)) { return ${'$'}cand }
            } catch { }
          }
          return ${'$'}null
        }

        # Windows' own signed binaries, abused to run someone else's code. An
        # entry whose Authenticode status is a proud "Valid" because it launches
        # rundll32 or mshta is the single most common way a malicious autorun
        # looks legitimate, and reporting only the signature actively misleads.
        # Two names are deliberately absent: the download-capable pair whose
        # mere presence as a string trips the probe's own no-network gate.
        # That gate greps the script for network verbs and cannot tell a
        # comparison list from a call, which is exactly the bluntness that
        # makes it worth having. Weakening it to admit two rare entries in an
        # advisory, unscored flag would be trading the app's central promise
        # for a rounding error -- so the flag gives them up instead.
        ${'$'}lolbins = @('rundll32','regsvr32','mshta','wscript','cscript','powershell',
                     'pwsh','cmd','msiexec','installutil','regasm','regsvcs','certutil',
                     'msbuild','forfiles','conhost')

        # ## Every step below is guarded, and that is not defensive padding
        #
        # Get-AuthenticodeSignature throws IOException on a Windows app
        # execution alias -- the reparse-point stubs under WindowsApps that
        # Test-Path happily confirms exist. Microsoft Teams ships with exactly
        # such a Run entry on a stock Windows 11, and one unguarded call to it
        # aborted the enumeration of every other Run key on the machine.
        #
        # The generalised version of that is an attack. These paths come from
        # registry values anyone can write, so if one bad target ends the loop,
        # then ADDING A SINGLE JUNK RUN ENTRY DELETES EVERY OTHER RUN FINDING --
        # a one-line way to blind the check, and exactly the bug class this
        # pass set out to close, reintroduced by the fix for it. Failing to
        # inspect one entry must cost that entry and nothing else.
        function EmitAuto(${'$'}name, ${'$'}location, ${'$'}kind, ${'$'}cmd) {
          ${'$'}exe = ExePath ${'$'}cmd
          if (${'$'}exe) { ${'$'}script:scanTargets += ${'$'}exe }
          ${'$'}status = ''
          if (${'$'}exe) {
            try { ${'$'}status = (Get-AuthenticodeSignature -LiteralPath ${'$'}exe -ErrorAction Stop).Status }
            catch { ${'$'}status = '' }
          }
          ${'$'}lol = ${'$'}false
          if (${'$'}exe) {
            # GetFileNameWithoutExtension throws on invalid path characters
            # under Windows PowerShell 5.1, and the path came from the registry.
            try {
              ${'$'}base = [System.IO.Path]::GetFileNameWithoutExtension(${'$'}exe)
              if (${'$'}base -and (${'$'}lolbins -contains ${'$'}base.ToLower())) { ${'$'}lol = ${'$'}true }
            } catch { }
          }
          Emit 'autorun' ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}`t{8}" -f (San ${'$'}name), (San ${'$'}location), (San ${'$'}cmd), ${'$'}status, ${'$'}kind, ${'$'}lol, (FromInternet ${'$'}exe), (FileHash ${'$'}exe), (San ${'$'}exe))
        }

        function EmitRun(${'$'}key, ${'$'}kind) {
          ${'$'}props = Get-ItemProperty ${'$'}key
          if (-not ${'$'}props) { return }
          foreach (${'$'}p in ${'$'}props.PSObject.Properties) {
            if (${'$'}p.Name -like 'PS*') { continue }
            EmitAuto ${'$'}p.Name ${'$'}key ${'$'}kind "${'$'}(${'$'}p.Value)"
          }
        }

        # Each source is enumerated and reported SEPARATELY.
        #
        # The first version of this wrapped all seven in one try/catch with a
        # single sentinel, and on this very machine it returned nothing at all:
        # a handful of Image File Execution Options subkeys deny read access to
        # a non-elevated user, `Get-ChildItem` raised SecurityException, and one
        # unreadable registry key deleted forty-odd findings from six sources
        # that had worked perfectly.
        #
        # Which is the same failure this whole pass is about -- a partial
        # collection silently becoming the whole answer -- just inverted, and
        # caught only because the sentinel made it visible instead of quiet.
        # An all-or-nothing marker is the wrong shape for a multi-source sweep.
        #
        # So: `autorun.read` per source that completed, `autorun.failed` per
        # source that did not, and rows from the sources that worked are kept.
        # The app can then say "six of seven places, and here is the one it
        # could not read", which is the true statement. Neither "here is
        # everything" nor silence is.
        function Source(${'$'}kind, ${'$'}block) {
          try { & ${'$'}block; Emit 'autorun.read' ${'$'}kind }
          catch { Emit 'autorun.failed' ${'$'}kind }
        }

        # Run and RunOnce, per-user and machine, 64-bit and 32-bit views. The
        # WOW6432Node keys matter: the uninstall scan above already reads the
        # 32-bit view, so omitting it here was an inconsistency rather than a
        # decision -- a 32-bit program was visible in the software list and
        # invisible in the autorun list.
        Source 'Run and RunOnce keys' {
          EmitRun 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' 'Run'
          EmitRun 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' 'Run'
          EmitRun 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' 'RunOnce'
          EmitRun 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' 'RunOnce'
          EmitRun 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' 'Run (32-bit)'
          EmitRun 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce' 'RunOnce (32-bit)'
        }

        Source 'Startup folders' {
          foreach (${'$'}dir in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
            if (${'$'}dir -and (Test-Path ${'$'}dir)) {
              foreach (${'$'}f in Get-ChildItem ${'$'}dir -File -ErrorAction Stop) {
                EmitAuto ${'$'}f.BaseName ${'$'}dir 'Startup folder' ${'$'}f.FullName
              }
            }
          }
        }

        # Winlogon Shell and Userinit run before the desktop appears. Stock
        # values are explorer.exe and userinit.exe; anything appended to them is
        # a classic and very quiet persistence.
        Source 'Winlogon' {
          ${'$'}wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
          foreach (${'$'}n in @('Shell', 'Userinit')) {
            ${'$'}v = Reg ${'$'}wl ${'$'}n
            if (${'$'}v) { EmitAuto ${'$'}n ${'$'}wl 'Winlogon' "${'$'}v" }
          }
        }

        # Image File Execution Options: a Debugger value silently substitutes
        # one program for another every time the named one is launched.
        #
        # Enumerated key by key. Several subkeys are ACL'd against a normal user
        # -- that is ordinary on a healthy machine, not a symptom -- so a denial
        # marks the source incomplete rather than discarding the keys that were
        # readable. This is the source that would genuinely benefit from
        # elevation, and the only one, which is worth saying out loud in an app
        # that declines to ask for it.
        ${'$'}ifeoErr = @()
        Source 'Image File Execution Options' {
          foreach (${'$'}k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue -ErrorVariable +ifeoErr) {
            ${'$'}dbg = (Get-ItemProperty ${'$'}k.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
            if (${'$'}dbg) { EmitAuto ${'$'}k.PSChildName 'Image File Execution Options' 'IFEO debugger' "${'$'}dbg" }
          }
          # -ErrorVariable, not a try/catch. SilentlyContinue means the denied
          # subkeys never raise anything to catch -- they are simply skipped --
          # so the first version of this claimed to detect denial and silently
          # could not. The error variable is the only thing that records that
          # keys were passed over.
          if (${'$'}ifeoErr) { throw 'one or more subkeys denied read access' }
        }

        # Scheduled tasks. Microsoft's own are excluded by path: there are
        # roughly 190 of them, they are signed by the OS vendor, and listing
        # them would bury the handful that are not. Disabled tasks and tasks
        # with no trigger cannot start anything, so they are not "programs that
        # start themselves".
        Source 'Scheduled tasks' {
          foreach (${'$'}t in Get-ScheduledTask -ErrorAction Stop) {
            if (${'$'}t.TaskPath -like '\Microsoft\*') { continue }
            if (${'$'}t.State -eq 'Disabled') { continue }
            if (-not ${'$'}t.Triggers) { continue }
            foreach (${'$'}a in ${'$'}t.Actions) {
              if (-not ${'$'}a.Execute) { continue }
              ${'$'}full = ${'$'}a.Execute
              if (${'$'}a.Arguments) { ${'$'}full = "${'$'}(${'$'}a.Execute) ${'$'}(${'$'}a.Arguments)" }
              EmitAuto ${'$'}t.TaskName ("Scheduled task " + ${'$'}t.TaskPath) 'Scheduled task' ${'$'}full
            }
          }
        }

        # Auto-start services outside the system directories. Everything in
        # system32/SysWOW64 is Windows' own; a service that starts itself from
        # Program Files or a user folder is the interesting case.
        Source 'Services' {
          foreach (${'$'}s in Get-CimInstance Win32_Service -ErrorAction Stop) {
            if (${'$'}s.StartMode -ne 'Auto') { continue }
            if (-not ${'$'}s.PathName) { continue }
            if (${'$'}s.PathName -match 'system32|SysWOW64') { continue }
            EmitAuto ${'$'}s.Name 'Service' 'Service' ${'$'}s.PathName
          }
        }

        # ---- persistence, the quiet half ------------------------------------
        #
        # ## Why these look different from the Run keys above
        #
        # Everything below is a place where Windows itself keeps a list, and
        # where the STOCK CONTENTS ARE KNOWN AND NARROW. Printing the list would
        # be useless -- 20 netsh helpers, 18 per-user COM registrations, 6 print
        # monitors, all of them legitimate on a machine nobody has touched. That
        # is the difference between this and Autoruns: Autoruns shows you four
        # hundred rows and declines to say which matter, which is the right
        # choice for an expert tool and the wrong one here.
        #
        # So each source below reports its DELTA FROM STOCK, the same design as
        # the certificate check further up, which reports the user store minus
        # the machine store rather than the 52 certificates a naive query
        # returns. Measured on the development machine: every one of these
        # yields ZERO rows on a healthy install, which is what makes them
        # shippable rather than noise.

        # WMI event subscriptions: a filter, a consumer, and a binding between
        # them. Fileless, survives reboot, invisible to every Run-key checker,
        # and the reason "check your startup folder" stopped being adequate
        # advice a decade ago.
        #
        # Windows ships exactly one, the SCM event log filter, and it is
        # excluded by name -- without that, this rule would fire on every
        # machine alive.
        Source 'WMI event subscriptions' {
          foreach (${'$'}b in Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop) {
            ${'$'}fname = ''
            ${'$'}query = ''
            foreach (${'$'}f in Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue) {
              if (${'$'}b.Filter -match [regex]::Escape(${'$'}f.Name)) { ${'$'}fname = ${'$'}f.Name; ${'$'}query = ${'$'}f.Query }
            }
            if (${'$'}fname -eq 'SCM Event Log Filter') { continue }
            EmitAuto ${'$'}fname 'WMI subscription' 'WMI subscription' "${'$'}(${'$'}b.Consumer) :: ${'$'}query"
          }
        }

        # COM hijacking. A CLSID registered under HKEY_CURRENT_USER SHADOWS the
        # machine-wide one of the same ID, so a component Windows loads for its
        # own reasons quietly loads someone else's DLL instead. It needs no
        # administrator rights whatsoever.
        #
        # The shadow is the whole signal. A per-user CLSID that exists ONLY in
        # HKCU is an ordinary private registration -- there are 18 of them here.
        # One that also exists in HKLM is overriding something.
        Source 'COM registrations' {
          foreach (${'$'}k in Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction Stop) {
            ${'$'}ip = Get-ItemProperty "${'$'}(${'$'}k.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
            if (-not ${'$'}ip) { continue }
            if (-not (Test-Path "HKLM:\Software\Classes\CLSID\${'$'}(${'$'}k.PSChildName)\InprocServer32")) { continue }
            EmitAuto ${'$'}k.PSChildName 'HKCU COM class' 'COM hijack' "${'$'}(${'$'}ip.'(default)')"
          }
        }

        # AppInit_DLLs loads a library into essentially every process that uses
        # user32. Empty on a healthy machine; anything at all here is worth a
        # look.
        Source 'AppInit DLLs' {
          foreach (${'$'}p in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
            ${'$'}v = Reg ${'$'}p 'AppInit_DLLs'
            if (${'$'}v -and "${'$'}v".Trim() -ne '') { EmitAuto 'AppInit_DLLs' ${'$'}p 'AppInit DLL' "${'$'}v" }
          }
        }

        # Active Setup runs a command once per user at first sign-in. Filtered
        # to StubPath values that name a file somewhere other than the system
        # directories -- the ten Microsoft entries here are switches and
        # fragments like '/UserInstall', not paths, and a naive filter reports
        # two of them.
        Source 'Active Setup' {
          foreach (${'$'}k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' -ErrorAction Stop) {
            ${'$'}sp = (Get-ItemProperty ${'$'}k.PSPath -Name StubPath -ErrorAction SilentlyContinue).StubPath
            if (-not ${'$'}sp) { continue }
            if (${'$'}sp -notmatch '[\\/]') { continue }
            if (${'$'}sp -match 'system32|SysWOW64|Program Files') { continue }
            EmitAuto ${'$'}k.PSChildName 'Active Setup' 'Active Setup' "${'$'}sp"
          }
        }

        # Winlogon Notify packages, and the per-user Load/Run values that
        # predate the Run keys. Both keys are absent on a modern install, so
        # anything present is by definition not stock.
        Source 'Winlogon notify and legacy Load/Run' {
          foreach (${'$'}k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' -ErrorAction SilentlyContinue) {
            ${'$'}dll = (Get-ItemProperty ${'$'}k.PSPath -Name DllName -ErrorAction SilentlyContinue).DllName
            if (${'$'}dll) { EmitAuto ${'$'}k.PSChildName 'Winlogon Notify' 'Winlogon notify' "${'$'}dll" }
          }
          foreach (${'$'}n in @('Load', 'Run')) {
            ${'$'}v = Reg 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' ${'$'}n
            if (${'$'}v) { EmitAuto ${'$'}n 'Windows NT CurrentVersion Windows' 'Legacy Load/Run' "${'$'}v" }
          }
          foreach (${'$'}h in @('HKCU:', 'HKLM:')) {
            ${'$'}props = Get-ItemProperty "${'$'}h\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -ErrorAction SilentlyContinue
            if (-not ${'$'}props) { continue }
            foreach (${'$'}p in ${'$'}props.PSObject.Properties) {
              if (${'$'}p.Name -like 'PS*') { continue }
              EmitAuto ${'$'}p.Name "${'$'}h Explorer policy Run" 'Policy Run' "${'$'}(${'$'}p.Value)"
            }
          }
        }

        # Three lists Windows loads DLLs from, each with a known stock value.
        # A print monitor or time provider is named by a bare filename when it
        # lives in system32; a path separator means it does not.
        Source 'System DLL lists' {
          ${'$'}np = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'Notification Packages' -ErrorAction Stop).'Notification Packages'
          foreach (${'$'}n in ${'$'}np) {
            # scecli is stock everywhere; rassfm appears on domain controllers.
            if (${'$'}n -in @('scecli', 'rassfm')) { continue }
            EmitAuto ${'$'}n 'LSA Notification Packages' 'LSA package' "${'$'}n.dll"
          }
          foreach (${'$'}k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors' -ErrorAction SilentlyContinue) {
            ${'$'}d = (Get-ItemProperty ${'$'}k.PSPath -Name Driver -ErrorAction SilentlyContinue).Driver
            if (${'$'}d -and ${'$'}d -match '[\\/]') { EmitAuto ${'$'}k.PSChildName 'Print monitor' 'Print monitor' "${'$'}d" }
          }
          foreach (${'$'}k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders' -ErrorAction SilentlyContinue) {
            ${'$'}d = (Get-ItemProperty ${'$'}k.PSPath -Name DllName -ErrorAction SilentlyContinue).DllName
            if (${'$'}d -and ${'$'}d -notmatch 'system32') { EmitAuto ${'$'}k.PSChildName 'Time provider' 'Time provider' "${'$'}d" }
          }
          ${'$'}nsh = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NetSh' -ErrorAction SilentlyContinue
          if (${'$'}nsh) {
            foreach (${'$'}p in ${'$'}nsh.PSObject.Properties) {
              if (${'$'}p.Name -like 'PS*') { continue }
              # Stock helpers are bare DLL names resolved out of system32.
              if ("${'$'}(${'$'}p.Value)" -match '^[A-Za-z0-9_.-]+\.dll${'$'}') { continue }
              EmitAuto ${'$'}p.Name 'Netsh helper' 'Netsh helper' "${'$'}(${'$'}p.Value)"
            }
          }
          ${'$'}be = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute -ErrorAction SilentlyContinue).BootExecute
          foreach (${'$'}b in ${'$'}be) {
            if (${'$'}b -eq 'autocheck autochk *') { continue }
            EmitAuto 'BootExecute' 'Session Manager' 'Boot execute' "${'$'}b"
          }
        }

        # ---- what is running, and whether it is pretending ---------------------
        #
        # ## This is the one part of Mume that looks for malware
        #
        # It does not scan the disk, hash every file, or carry signatures. What
        # it does is check the small set of programs that matter -- the ones
        # running right now -- for a technique that cannot be done without
        # lying: **using the name of a core Windows binary from the wrong
        # place**. A real svchost.exe lives in System32. A copy of anything else
        # called svchost.exe, running out of AppData, is not a false positive
        # waiting to happen; there is no innocent reason to do it.
        #
        # The expected home is per binary, and that had to be measured. A single
        # shared "must be in System32" list reports explorer.exe twice on every
        # Windows machine, because Explorer genuinely lives in C:\Windows. With
        # the per-binary table below: zero on a healthy machine.
        #
        # Roughly a third of processes will not give up their path to an
        # unprivileged caller (337 of 514 here). Those are skipped rather than
        # guessed at, and the count of skipped ones is reported, because "I
        # looked at every process" would be false.
        ${'$'}sysBinaries = @{
          'svchost' = 'sys'; 'lsass' = 'sys'; 'csrss' = 'sys'; 'winlogon' = 'sys';
          'services' = 'sys'; 'smss' = 'sys'; 'taskhostw' = 'sys'; 'dwm' = 'sys';
          'conhost' = 'sys'; 'spoolsv' = 'sys'; 'wininit' = 'sys'; 'rundll32' = 'sys';
          'ctfmon' = 'sys'; 'sihost' = 'sys'; 'runtimebroker' = 'sys';
          'searchindexer' = 'sys'; 'dllhost' = 'sys'; 'wuauclt' = 'sys';
          'regsvr32' = 'sys'; 'mshta' = 'sys'; 'wscript' = 'sys'; 'cscript' = 'sys';
          'explorer' = 'win'
        }

        ${'$'}procOk = ${'$'}true
        ${'$'}procNoPath = 0
        try {
          foreach (${'$'}p in Get-Process -ErrorAction Stop) {
            # Per process, and this is the third time in this file that mattered.
            # Reading .Path on a protected process raises a terminating error --
            # not a null, an exception -- so an unguarded loop stops at the first
            # system process and emits NOTHING. It did exactly that on the first
            # run: 0 rows, no error, and only the enumeration sentinel to show
            # for it. Same shape as the Run-key sweep that one WindowsApps stub
            # aborted, and the persistence sweep that one denied registry key
            # emptied. A failure to inspect one item must cost that item alone.
            ${'$'}path = ${'$'}null
            try { ${'$'}path = ${'$'}p.Path } catch { ${'$'}path = ${'$'}null }
            if (-not ${'$'}path) { ${'$'}procNoPath++; continue }
            ${'$'}n = ${'$'}p.ProcessName.ToLower()
            # Deliberately not named "home". That is a read-only automatic
            # variable in PowerShell, and assigning to it throws
            # SessionStateUnauthorizedAccessException -- which the outer
            # catch swallowed, so the whole process sweep returned zero
            # rows and no sentinel. The sentinel is what made it visible.
            ${'$'}expectedHome = ${'$'}sysBinaries[${'$'}n]
            ${'$'}masq = ''
            if (${'$'}expectedHome -eq 'sys') {
              if (${'$'}path -notmatch '\\Windows\\(System32|SysWOW64|WinSxS)\\') { ${'$'}masq = ${'$'}p.ProcessName }
            } elseif (${'$'}expectedHome -eq 'win') {
              # Directly inside the Windows directory, not a subfolder of it.
              if (${'$'}path -notmatch '^[A-Za-z]:\\Windows\\[^\\]+${'$'}') { ${'$'}masq = ${'$'}p.ProcessName }
            }
            # Only the interesting ones are signature-checked: doing it for all
            # 337 costs seconds and tells us nothing about Windows' own files.
            ${'$'}script:scanTargets += ${'$'}path
            ${'$'}userland = ${'$'}path -match 'AppData|\\Temp\\|\\Downloads\\|\\Users\\Public'
            ${'$'}sig = ''
            if (${'$'}masq -or ${'$'}userland) {
              try { ${'$'}sig = (Get-AuthenticodeSignature -LiteralPath ${'$'}path -ErrorAction Stop).Status } catch { ${'$'}sig = '' }
            }
            if (${'$'}masq -or ${'$'}userland) {
              Emit 'process' ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f (San ${'$'}p.ProcessName), (San ${'$'}path), ${'$'}sig, (San ${'$'}masq), (FromInternet ${'$'}path), (FileHash ${'$'}path))
            }
          }
        } catch { ${'$'}procOk = ${'$'}false }
        if (${'$'}procOk) {
          Emit 'process.enumerated' 'True'
          # Reported rather than hidden: a third of processes refuse their path
          # to an unprivileged caller, and "I checked everything" would be false.
          Emit 'process.pathUnreadable' ${'$'}procNoPath
        }

        # ---- asking Windows Defender about the files that matter --------------
        #
        # ## The best malware verdict available offline is already installed
        #
        # Mume ships a table of known-bad hashes. It is stale the day it is
        # built and it is defeated by recompiling the file. Meanwhile every
        # Windows machine has a scanner with signatures a few hours old, and it
        # is sitting right there. Asking it is strictly better than anything
        # Mume could bundle.
        #
        # What Mume contributes is *which files to ask about*. Defender's
        # real-time protection checks files as they are written and opened; a
        # file that arrived before a signature existed can sit on disk unflagged
        # until something touches it, and the full scan that would find it is
        # the thing nobody ever runs. Mume already knows the sixty files that
        # matter -- the ones that start themselves and the ones running out of
        # personal folders -- so it hands Defender exactly those. Measured: 33
        # milliseconds each, about two seconds for the set.
        #
        # ## -DisableRemediation is not optional here
        #
        # Without it, Defender QUARANTINES what it finds. Measured: "found 1
        # threats. Cleaning started..." and the file was gone. That would make
        # Mume a program that silently changes your computer, which is the one
        # thing this app promises never to do -- and it would do it through a
        # side effect of asking a question. With the flag the file is left
        # exactly where it was, the detection is reported to us and not raised
        # in Defender's own interface, and the user decides.
        #
        # WindowsProbeTest asserts the flag is present on every invocation.
        #
        # ## The exit code is a trap, twice over
        #
        # Without -DisableRemediation a detection exits **0**, because
        # remediation succeeded. With the flag a detection exits **2** -- but so
        # does a file that does not exist. Neither number alone distinguishes
        # "clean" from "threat", so the verdict is read from the output text and
        # only for files confirmed to exist. Third time in this probe that the
        # obvious signal turned out to be a lie.
        #
        # ## What this costs against the no-network promise
        #
        # Mume still makes no network connection; the bytecode gate still
        # forbids one. It asks a component that is already running and already
        # scanning these files to report what it thinks. Defender then behaves
        # as Defender always behaves, which -- depending on the user's own cloud
        # protection setting -- may include contacting Microsoft. That is stated
        # plainly rather than buried, because "we never touch the network" and
        # "we never cause anything to touch the network" are different claims
        # and only the first one is true.
        ${'$'}mpCmdRun = Join-Path ${'$'}env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
        ${'$'}defenderUsable = ${'$'}false
        if ((Test-Path -LiteralPath ${'$'}mpCmdRun) -and ${'$'}mp -and ${'$'}mp.AntivirusEnabled) {
          ${'$'}defenderUsable = ${'$'}true
          Emit 'av.scannerAvailable' 'True'
        } else {
          Emit 'av.scannerAvailable' 'False'
        }

        function AskDefender(${'$'}path) {
          if (-not ${'$'}defenderUsable) { return '' }
          if (-not ${'$'}path) { return '' }
          # Confirmed to exist first: a missing file exits 2, exactly like a
          # detection, so skipping this check would invent threats.
          if (-not (Test-Path -LiteralPath ${'$'}path -PathType Leaf)) { return '' }
          try {
            ${'$'}out = & ${'$'}mpCmdRun -Scan -ScanType 3 -File ${'$'}path -DisableRemediation 2>&1 | Out-String
            if (${'$'}out -match 'found\s+(\d+)\s+threat') {
              if ([int]${'$'}Matches[1] -gt 0) { return 'threat' }
            }
            if (${'$'}out -match 'found no threats') { return 'clean' }
            return ''
          } catch { return '' }
        }

        foreach (${'$'}t in (${'$'}script:scanTargets | Select-Object -Unique)) {
          ${'$'}verdict = AskDefender ${'$'}t
          if (${'$'}verdict) { Emit 'avscan' ("{0}`t{1}" -f (San ${'$'}t), ${'$'}verdict) }
        }
        if (${'$'}defenderUsable) { Emit 'avscan.enumerated' 'True' }

        # ---- hardening settings ----------------------------------------------
        # Individually small, jointly the difference between a machine that
        # resists a foothold and one that hands over cached credentials. All
        # readable without elevation.
        Emit 'hard.enableLua'          (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA')
        Emit 'hard.consentPrompt'      (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin')
        Emit 'hard.runAsPPL'           (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL')
        Emit 'hard.wdigest'            (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential')
        Emit 'hard.smb1'               (Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1')
        Emit 'hard.llmnr'              (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast')
        Emit 'hard.autoAdminLogon'     (Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon')
        # The VALUE is never emitted, only whether one exists. It is a password
        # in cleartext; an app that reads it into its own output has made the
        # problem worse in the course of reporting it.
        if (Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword') {
          Emit 'hard.autoLogonPasswordStored' 'True'
        } else {
          Emit 'hard.autoLogonPasswordStored' 'False'
        }
        Emit 'hard.psV2Present' (Test-Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine')
        Emit 'hard.winrmStatus'        (Get-Service -Name WinRM).Status
        Emit 'hard.remoteRegistry'     (Get-Service -Name RemoteRegistry).Status
        Emit 'hard.settingsRead' 'True'

        # ---- what the antivirus itself is doing -------------------------------
        # Mume is not a malware scanner and never will be: it has no network, so
        # no reputation lookup, and no file scanner. What it CAN do -- and what
        # nothing else on a consumer machine seems to -- is audit the scanner
        # that IS installed. A disabled behaviour monitor, tamper protection
        # switched off, or a threat the product found and never resolved are all
        # local facts, and all of them mean the AV is not doing what its own
        # dashboard implies.
        if (${'$'}mp) {
          Emit 'av.tamperProtected'  ${'$'}mp.IsTamperProtected
          Emit 'av.behaviorMonitor'  ${'$'}mp.BehaviorMonitorEnabled
          Emit 'av.ioavProtection'   ${'$'}mp.IoavProtectionEnabled
          Emit 'av.networkInspection' ${'$'}mp.NISEnabled
          Emit 'av.antispyware'      ${'$'}mp.AntispywareEnabled
        }
        # IsActive is the signal, and it had to be measured to find that out.
        # ActionSuccess reads True even for detections whose status says the
        # action failed, so a rule built on it could never fire. Get-MpThreat
        # models current state rather than history, and IsActive is the field
        # that means "this is still here".
        ${'$'}threats = Get-MpThreat
        if (${'$'}null -ne ${'$'}threats) {
          Emit 'av.threatsKnown' (${'$'}threats | Measure-Object).Count
          foreach (${'$'}t in ${'$'}threats) {
            if (${'$'}t.IsActive) { Emit 'av.threatActive' (San ${'$'}t.ThreatName) }
          }
          Emit 'av.threatsRead' 'True'
        }
        # Defender exclusion paths are the single highest-signal thing here --
        # adding one is a standard step in a compromise -- and they are NOT
        # readable without elevation: Get-MpPreference returns the literal
        # string "N/A: Must be an administrator to view exclusions". Emitted as
        # a known blind spot rather than as an empty list, because an empty list
        # would read as "no exclusions configured", which is a different and
        # much more reassuring claim than the truth.
        ${'$'}excl = (Get-MpPreference).ExclusionPath
        if (${'$'}excl -and "${'$'}excl" -notmatch 'must be an administrator') {
          Emit 'av.exclusionsReadable' 'True'
          foreach (${'$'}e in ${'$'}excl) { Emit 'av.exclusion' (San ${'$'}e) }
        } else {
          Emit 'av.exclusionsReadable' 'False'
        }

        # ---- completion ------------------------------------------------------
        # The last line of the script, and the one that says the rest can be
        # believed. PowerShell can be killed partway through -- by a crash, by a
        # policy, or by any process running as this user that would rather the
        # scan did not finish -- and the output up to that point looks exactly
        # like a successful run of a smaller script. Without this line the app
        # would render a confident, mostly-green report built from however far
        # the probe happened to get.
        Emit 'probe.complete' 'True'
    """.trimIndent()
}
