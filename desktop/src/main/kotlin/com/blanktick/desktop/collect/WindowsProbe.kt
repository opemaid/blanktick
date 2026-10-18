package com.blanktick.desktop.collect

/**
 * The complete set of commands Blanktick runs on a Windows machine.
 *
 * ## Read it. That is the point.
 *
 * This is deliberately one readable block rather than thirty strings scattered
 * through a collector. A person who wants to know what a security app is doing
 * on their computer can read this, paste it into PowerShell, and compare the
 * output line by line against what Blanktick displayed. An app that asks you to
 * trust it about privacy should be the easiest thing in the world to check.
 *
 * ## What it is allowed to be
 *
 * Every statement is a **query**. There is no `Set-`, no `New-`, no `Remove-`,
 * no `Start-`, no `Stop-`, and no file is written. Blanktick reports; the user
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
        # Blanktick is launched from a process whose PSModulePath points at
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
          # Skipped entirely when the installed scanner is available to
          # answer instead. The bundled table exists as the fallback for
          # a machine whose antivirus is absent or disabled, so computing
          # it alongside a working scanner is work whose answer is
          # already known and weaker.
          if (${'$'}script:defenderUsable) { return '' }
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

        # Like FileHash but without the "skip when a scanner is present" gate:
        # the vulnerable-driver check is independent of the antivirus, because a
        # driver with a known flaw is a problem whether or not the scanner flags
        # it, and most will not be flagged at all (they are signed, legitimate
        # software). Still read-only and never throws out.
        #
        # Capped at 16 MiB, far lower than FileHash's 200 MiB: a real kernel
        # driver is tiny (RTCore64 is 14 KB; the LOLDrivers samples are all well
        # under a megabyte), so anything larger is a GPU or AV blob that cannot
        # be a match. Measured: two such outliers (one 108 MiB) turned a 2-second
        # sweep into 42, for files that could never be on the list.
        function DriverHash(${'$'}path) {
          if (-not ${'$'}path) { return '' }
          try {
            ${'$'}f = Get-Item -LiteralPath ${'$'}path -ErrorAction Stop
            if (${'$'}f.Length -gt 16777216) { return '' }
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
        # Whether the installed scanner can be asked. Determined HERE, next to
        # the Defender status it depends on, because two things later in the
        # script branch on it -- and one of them, the hashing, runs long
        # before the scan block. Set it late and the hash is computed for
        # every file anyway, which is the work this flag exists to avoid.
        ${'$'}script:mpCmdRun = Join-Path ${'$'}env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
        ${'$'}script:defenderUsable = ${'$'}false
        if ((Test-Path -LiteralPath ${'$'}script:mpCmdRun) -and ${'$'}mp -and ${'$'}mp.AntivirusEnabled) {
          ${'$'}script:defenderUsable = ${'$'}true
          Emit 'av.scannerAvailable' 'True'
        } else {
          Emit 'av.scannerAvailable' 'False'
        }

        Emit 'smartscreen.policy'   (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen')
        Emit 'smartscreen.explorer' (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled')

        # ---- boot integrity -------------------------------------------------
        # Read from the registry, not Confirm-SecureBootUEFI, which needs
        # elevation Blanktick deliberately does not ask for.
        Emit 'secureboot.enabled' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled')

        # ---- updates --------------------------------------------------------
        Emit 'update.noAutoUpdate'     (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate')
        Emit 'update.serviceStartType' (Get-Service -Name wuauserv).StartType
        ${'$'}hf = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if (${'$'}hf -and ${'$'}hf.InstalledOn) {
          Emit 'update.daysSinceLast' ([int]((Get-Date) - ${'$'}hf.InstalledOn).TotalDays)
        }

        # ---- accounts -------------------------------------------------------
        # Kept in a script var too: the Defender-exclusion read below gates on
        # the real elevation state rather than string-matching an English error.
        ${'$'}script:isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        Emit 'acct.sessionIsAdmin' ${'$'}script:isAdmin

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

        # ---- is anything actually reachable? ---------------------------------
        #
        # ## Listening is not the same as reachable, and the firewall knows
        #
        # "25 services are listening on every interface" is true on a stock
        # Windows machine and tells a person almost nothing, because Windows
        # blocks inbound by default. The question worth answering is which of
        # them the firewall actually lets through -- and the firewall is right
        # there, holding the answer.
        #
        # The join is on the PROGRAM, not the port. That took a measurement to
        # get right: joining on port says everything is allowed, because
        # Windows' rules are overwhelmingly per-application with LocalPort=Any.
        # 254 inbound allow rules on this machine, 72 naming a specific program.
        #
        # Measured result: of 25 sockets bound to all interfaces, 2 belong to a
        # program with an inbound allow rule -- and they are the developer's own
        # HTTP servers. The old rule called that "17 services reachable from the
        # whole network" and charged 9 points for it.
        #
        # The honesty half matters as much: most listening sockets belong to
        # system processes whose path an unprivileged caller cannot read, so
        # they cannot be attributed to a rule at all. Those are counted and
        # reported as unattributed rather than assumed either way. "2 reachable"
        # and "23 I could not attribute" are both true; "17 reachable" was not.
        ${'$'}fwAppOk = ${'$'}true
        try {
          # ONE pipeline, not one per rule.
          #
          # The obvious loop -- foreach rule, pipe that rule to the filter
          # cmdlet -- costs about 0.4 seconds EACH, and there are 254 inbound
          # allow rules on an ordinary machine. That is 100 seconds, which took
          # the whole probe past its 90-second ceiling, so it returned nothing,
          # so every check reported not-checkable, and the app printed a
          # confident 100/100 off two checks. Piping the whole set through once
          # costs about three seconds.
          #
          # Only the SET of permitted programs is needed, so which rule a filter
          # came from does not matter, and the association can be thrown away.
          ${'$'}allowedApps = @{}
          foreach (${'$'}af in (Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -PolicyStore ActiveStore -ErrorAction Stop |
                            Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)) {
            if (${'$'}af.Program -and ${'$'}af.Program -ne 'Any') { ${'$'}allowedApps[${'$'}af.Program.ToLower()] = ${'$'}true }
          }
          ${'$'}unattributed = 0
          foreach (${'$'}c in Get-NetTCPConnection -State Listen -ErrorAction Stop) {
            if (${'$'}c.LocalAddress -notin @('0.0.0.0', '::')) { continue }
            ${'$'}pp = ${'$'}null
            try { ${'$'}pp = (Get-Process -Id ${'$'}c.OwningProcess -ErrorAction Stop).Path } catch { ${'$'}pp = ${'$'}null }
            if (-not ${'$'}pp) { ${'$'}unattributed++; continue }
            if (${'$'}allowedApps.ContainsKey(${'$'}pp.ToLower())) {
              Emit 'reachable' ("{0}`t{1}" -f ${'$'}c.LocalPort, (San ${'$'}pp))
            }
          }
          Emit 'reachable.unattributed' ${'$'}unattributed
        } catch { ${'$'}fwAppOk = ${'$'}false }
        if (${'$'}fwAppOk) { Emit 'reachable.enumerated' 'True' }

        # ---- machine-wide root certificates ----------------------------------
        #
        # Closes a gap this probe documented and could not previously answer. A
        # certificate installed machine-wide sits in LocalMachine\Root beside
        # Microsoft's own roots, and the comment above says telling them apart
        # needs a pinned list of thumbprints this build does not bundle.
        #
        # It does not need one. Windows already knows which roots it delivered:
        # they are listed under AuthRoot, the auto-update mechanism. And Windows
        # records when each root's registry key was written. A root that was
        # added AFTER the operating system was installed and did NOT arrive
        # through Microsoft's own update channel was put there by somebody.
        #
        # Two oracles rather than one, because either alone is wrong. AuthRoot
        # by itself flags 14 certificates on this machine -- all legitimate,
        # all shipped inside the Windows image rather than auto-updated. Install
        # date by itself would miss nothing but explain nothing. Together: zero
        # on a healthy machine, measured.
        #
        # Enterprise-deployed roots are excluded. On a managed laptop a root
        # pushed by group policy is normal, and accusing the IT department is
        # how a security tool gets uninstalled.
        ${'$'}rootOk = ${'$'}true
        try {
          ${'$'}installed = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).InstallDate
          ${'$'}autoRoots = @{}
          foreach (${'$'}k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates' -ErrorAction SilentlyContinue) {
            ${'$'}autoRoots[${'$'}k.PSChildName] = ${'$'}true
          }
          ${'$'}enterprise = @{}
          foreach (${'$'}k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\EnterpriseCertificates\ROOT\Certificates' -ErrorAction SilentlyContinue) {
            ${'$'}enterprise[${'$'}k.PSChildName] = ${'$'}true
          }
          foreach (${'$'}k in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates' -ErrorAction Stop) {
            if (${'$'}autoRoots.ContainsKey(${'$'}k.PSChildName)) { continue }
            if (${'$'}enterprise.ContainsKey(${'$'}k.PSChildName)) { continue }
            if (${'$'}k.LastWriteTime -le ${'$'}installed.AddDays(1)) { continue }
            ${'$'}cert = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
              Where-Object { ${'$'}_.Thumbprint -eq ${'$'}k.PSChildName }
            if (${'$'}cert) {
              Emit 'machinecert' ("{0}`t{1}`t{2}" -f (San ${'$'}cert.Subject), (San ${'$'}cert.Issuer), ${'$'}cert.Thumbprint)
            }
          }
        } catch { ${'$'}rootOk = ${'$'}false }
        if (${'$'}rootOk) { Emit 'machinecert.enumerated' 'True' }

        # ---- pending updates, without asking Microsoft -----------------------
        #
        # This check was previously reported as permanently not-performed,
        # because enumerating pending updates means the Windows Update Agent,
        # and the Agent contacts Microsoft.
        #
        # It does not have to. The Agent keeps a local catalogue of what it
        # already knows applies to this machine, and setting Online to false
        # searches that cache without opening a connection. So the honest answer
        # changes from "we will not ask" to "here is what your computer already
        # knows is waiting" -- which is what the user wanted in the first place.
        #
        # The offline flag is load-bearing and WindowsProbeTest asserts it. With
        # it left at the default this becomes a network call inside an app whose
        # central promise is that it never makes one.
        ${'$'}wuOk = ${'$'}true
        try {
          ${'$'}wuSession = New-Object -ComObject Microsoft.Update.Session
          ${'$'}wuSearcher = ${'$'}wuSession.CreateUpdateSearcher()
          ${'$'}wuSearcher.Online = ${'$'}false
          ${'$'}wuResult = ${'$'}wuSearcher.Search("IsInstalled=0 AND Type='Software' AND IsHidden=0")
          Emit 'update.pendingCount' ${'$'}wuResult.Updates.Count
          foreach (${'$'}u in ${'$'}wuResult.Updates) {
            ${'$'}sev = ${'$'}u.MsrcSeverity
            if (${'$'}sev) { Emit 'update.pendingSeverity' (San ${'$'}sev) }
          }
        } catch { ${'$'}wuOk = ${'$'}false }
        if (${'$'}wuOk) { Emit 'update.pendingRead' 'True' }

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
        # Blanktick reported. An unprivileged process could set HKCU to the hardened
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
        # Two sources, together the same set Settings > Apps shows: the OS's own
        # uninstall registry (below) and the Store/UWP package list (further down).
        # No elevation, no filesystem walk, nothing hashed.
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

        # Microsoft Store / UWP apps are NOT in the uninstall registry, but
        # Settings > Apps lists them too -- so a list built from the registry
        # alone is short by roughly half (measured on the dev machine: 79 registry
        # entries, 81 Store apps). Read-only, no elevation. Frameworks (runtime
        # libraries) and System-signed packages are skipped for the same reason
        # SystemComponent is above: they are not programs a person chose to
        # install. Publisher is the certificate subject; its CN is pulled out so
        # it reads "Microsoft Corporation", not the whole distinguished name.
        # Store apps live under a protected root, so userWritable is always false.
        # Best-effort: a failure here still leaves the registry list intact, so
        # it does not clear the enumerated sentinel below.
        try {
          foreach (${'$'}a in Get-AppxPackage -ErrorAction Stop) {
            if (${'$'}a.IsFramework) { continue }
            if (${'$'}a.SignatureKind -eq 'System') { continue }
            if (-not ${'$'}a.Name) { continue }
            ${'$'}pub = "${'$'}(${'$'}a.Publisher)" -replace '^CN=([^,]+).*', '${'$'}1'
            Emit 'program' ("{0}`t{1}`t{2}`t{3}`t{4}" -f (San ${'$'}a.Name), (San "${'$'}(${'$'}a.Version)"), (San ${'$'}pub), (San "${'$'}(${'$'}a.InstallLocation)"), ${'$'}false)
          }
        } catch { }

        # Emitted so "no programs found" can be told apart from "the enumeration
        # failed", exactly as acct.userCount does for local accounts. Gated on the
        # uninstall-registry pass, which is the load-bearing source; the Store
        # enumeration above is additive and best-effort.
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
          #
          # Each denied subkey is NAMED rather than failing the whole source.
          # Throwing here marked IFEO unread -- and withheld the entire score --
          # on a healthy machine where 81 of 82 keys read and the 82nd was
          # DefenderAgentScan.exe, which Defender locks to protect itself. Only a
          # denial of the IFEO key itself (or one with no target) is a real
          # blind spot, and that still fails the source.
          foreach (${'$'}e in ${'$'}ifeoErr) {
            ${'$'}t = "${'$'}(${'$'}e.TargetObject)"
            ${'$'}leaf = if (${'$'}t) { Split-Path ${'$'}t -Leaf } else { '' }
            if (-not ${'$'}leaf -or ${'$'}leaf -eq 'Image File Execution Options') { throw 'IFEO itself denied read access' }
            Emit 'autorun.denied' "Image File Execution Options\${'$'}leaf"
          }
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
            # The cheap shadow test runs FIRST. An HKCU CLSID matters only when
            # it OVERRIDES an HKLM one; the vast majority are private per-user
            # registrations. Reading InprocServer32 for every one of several
            # thousand keys cost about 160 seconds of the probe's budget on a
            # developer machine -- a Test-Path existence check per key, then the
            # InprocServer32 read only for the handful that actually shadow,
            # produces the identical result far faster.
            if (-not (Test-Path "HKLM:\Software\Classes\CLSID\${'$'}(${'$'}k.PSChildName)\InprocServer32")) { continue }
            ${'$'}ip = Get-ItemProperty "${'$'}(${'$'}k.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
            if (-not ${'$'}ip) { continue }
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
        # ## This is the one part of Blanktick that looks for malware
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
        # A signed binary can have a dozen live instances -- a browser and its
        # renderers, an editor and its helpers all share one .exe on disk.
        # Signature-verifying and hashing a 240 MB file once PER INSTANCE cost
        # minutes (ten Code.exe instances at ~6 seconds each, measured). The
        # verdict is a property of the file, not the instance, so each distinct
        # path is examined once; the seen set makes that so.
        ${'$'}procSeen = @{}
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
            # Same binary already examined this run: skip the expensive signature
            # and hash. A duplicate instance tells us nothing new about the file.
            if (${'$'}procSeen.ContainsKey(${'$'}path)) { continue }
            ${'$'}procSeen[${'$'}path] = ${'$'}true
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
            ${'$'}userland = ${'$'}path -match 'AppData|\\Temp\\|\\Downloads\\|\\Users\\Public'
            ${'$'}sig = ''
            if (${'$'}masq -or ${'$'}userland) {
              try { ${'$'}sig = (Get-AuthenticodeSignature -LiteralPath ${'$'}path -ErrorAction Stop).Status } catch { ${'$'}sig = '' }
            }
            if (${'$'}masq -or ${'$'}userland) {
              # Only the shortlist, matching what this block claims to
              # examine. Adding every process with a readable path put
              # ~150 files through the scanner instead of the twenty
              # that the comment above promises.
              ${'$'}script:scanTargets += ${'$'}path
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
        # Blanktick ships a table of known-bad hashes. It is stale the day it is
        # built and it is defeated by recompiling the file. Meanwhile every
        # Windows machine has a scanner with signatures a few hours old, and it
        # is sitting right there. Asking it is strictly better than anything
        # Blanktick could bundle.
        #
        # What Blanktick contributes is *which files to ask about*. Defender's
        # real-time protection checks files as they are written and opened; a
        # file that arrived before a signature existed can sit on disk unflagged
        # until something touches it, and the full scan that would find it is
        # the thing nobody ever runs. Blanktick already knows the sixty files that
        # matter -- the ones that start themselves and the ones running out of
        # personal folders -- so it hands Defender exactly those. Measured: 33
        # milliseconds each, about two seconds for the set.
        #
        # ## -DisableRemediation is not optional here
        #
        # Without it, Defender QUARANTINES what it finds. Measured: "found 1
        # threats. Cleaning started..." and the file was gone. That would make
        # Blanktick a program that silently changes your computer, which is the one
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
        # Blanktick still makes no network connection; the bytecode gate still
        # forbids one. It asks a component that is already running and already
        # scanning these files to report what it thinks. Defender then behaves
        # as Defender always behaves, which -- depending on the user's own cloud
        # protection setting -- may include contacting Microsoft. That is stated
        # plainly rather than buried, because "we never touch the network" and
        # "we never cause anything to touch the network" are different claims
        # and only the first one is true.

        function AskDefender(${'$'}path) {
          if (-not ${'$'}script:defenderUsable) { return '' }
          if (-not ${'$'}path) { return '' }
          # Confirmed to exist first: a missing file exits 2, exactly like a
          # detection, so skipping this check would invent threats.
          if (-not (Test-Path -LiteralPath ${'$'}path -PathType Leaf)) { return '' }
          try {
            ${'$'}out = & ${'$'}script:mpCmdRun -Scan -ScanType 3 -File ${'$'}path -DisableRemediation 2>&1 | Out-String
            ${'$'}code = ${'$'}LASTEXITCODE
            # Exit code is locale-independent; the text match only works on
            # English Windows. With the file's existence already confirmed above,
            # MpCmdRun exits 2 on a detection and 0 when clean. Trust the code
            # first, fall back to the English text so this never regresses where
            # it already worked.
            if (${'$'}code -eq 2) { return 'threat' }
            if (${'$'}out -match 'found\s+(\d+)\s+threat' -and [int]${'$'}Matches[1] -gt 0) { return 'threat' }
            if (${'$'}code -eq 0 -or ${'$'}out -match 'found no threats') { return 'clean' }
            return ''
          } catch { return '' }
        }

        # MpCmdRun -Scan costs seconds PER FILE, and scanTargets grows with every
        # autorun exe and every userland (AppData) process -- dozens on an
        # ordinary machine. Unbounded, this loop could run the whole probe past
        # its time ceiling, at which point PowerShell is killed and the ENTIRE
        # scan is discarded (score suppressed) -- the worst outcome. Bound it two
        # ways: a count cap and a cumulative wall-clock budget, checked before
        # each call. Autorun targets are appended before userland ones, so the
        # cap keeps the higher-risk persistence entries. A target left unscanned
        # simply gets no verdict downstream (not-asked), never a false "clean".
        # (A single hung MpCmdRun can still overrun one budget check; the
        # Shell-level timeout is the backstop. A per-call timeout is tracked in
        # docs/production-readiness.md.)
        ${'$'}avScanCap = 20
        ${'$'}avBudgetMs = 45000
        ${'$'}avSw = [System.Diagnostics.Stopwatch]::StartNew()
        ${'$'}avDone = 0
        foreach (${'$'}t in (${'$'}script:scanTargets | Select-Object -Unique)) {
          if (${'$'}avDone -ge ${'$'}avScanCap) { break }
          if (${'$'}avSw.Elapsed.TotalMilliseconds -ge ${'$'}avBudgetMs) { break }
          ${'$'}verdict = AskDefender ${'$'}t
          ${'$'}avDone++
          if (${'$'}verdict) { Emit 'avscan' ("{0}`t{1}" -f (San ${'$'}t), ${'$'}verdict) }
        }
        if (${'$'}script:defenderUsable) { Emit 'avscan.enumerated' 'True' }

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

        # ---- the Windows baseline other auditors check (BaselineRules.kt) ----
        # Added 2026-09-25 after a setting-by-setting comparison with apotrope,
        # HardeningKitty and Harden-Windows-Security. Every query below was run
        # NON-ELEVATED on Windows 11 Home 26200 first; Get-Tpm was rejected for
        # exactly that reason (it returns nothing without admin). Where "none"
        # is a real answer, a *.read sentinel separates it from "could not ask".
        Emit 'hard.secureDesktop'      (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop')
        Emit 'hard.edition'            (Reg 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'EditionID')
        Emit 'hard.sac'                (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState')
        Emit 'hard.scriptBlockLogging' (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging')
        try {
          ${'$'}dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
          Emit 'hard.vbsRunning'   (@(${'$'}dg.SecurityServicesRunning) -join ',')
          Emit 'hard.vbsAvailable' (@(${'$'}dg.AvailableSecurityProperties) -join ',')
          Emit 'hard.vbsRead' 'True'
        } catch { }
        try {
          ${'$'}tpm = @(Get-PnpDevice -Class SecurityDevices -ErrorAction Stop | Where-Object { ${'$'}_.FriendlyName -match 'Trusted Platform Module' })
          Emit 'hard.tpmStatus' ${'$'}(if (${'$'}tpm.Count -eq 0) { 'None' } else { "${'$'}(${'$'}tpm[0].Status)" })
        } catch { }
        # Only an explicit OFF counts: NOTSET is the OS default, which is ON for
        # every mitigation listed. Mandatory ASLR is left out because its OS
        # default is off, so reading it would accuse every stock machine.
        try {
          ${'$'}sm = Get-ProcessMitigation -System -ErrorAction Stop
          ${'$'}pairs = @(
            @('DEP', ${'$'}sm.DEP.Enable), @('Bottom-up ASLR', ${'$'}sm.ASLR.BottomUp),
            @('High-entropy ASLR', ${'$'}sm.ASLR.HighEntropy), @('Control Flow Guard', ${'$'}sm.CFG.Enable),
            @('SEHOP', ${'$'}sm.SEHOP.Enable), @('Heap integrity', ${'$'}sm.Heap.TerminateOnError))
          foreach (${'$'}p in ${'$'}pairs) { if ("${'$'}(${'$'}p[1])" -eq 'OFF') { Emit 'hard.mitigationOff' ${'$'}p[0] } }
          Emit 'hard.mitigationRead' 'True'
        } catch { }
        try {
          ${'$'}sc = Get-SmbClientConfiguration -ErrorAction Stop
          Emit 'hard.smbClientSign'    ${'$'}sc.RequireSecuritySignature
          Emit 'hard.smbInsecureGuest' ${'$'}sc.EnableInsecureGuestLogons
        } catch { }
        try { Emit 'hard.smbServerSign' (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch { }
        # 0 = "from DHCP" (which means on, on a home router) and 1 = on.
        try {
          ${'$'}nb = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
            Where-Object { ${'$'}_.TcpipNetbiosOptions -eq 0 -or ${'$'}_.TcpipNetbiosOptions -eq 1 })
          Emit 'hard.netbiosAdapters' ${'$'}nb.Count
        } catch { }
        Emit 'hard.spooler' (Get-Service -Name Spooler -ErrorAction SilentlyContinue).Status
        try { Emit 'hard.sharedPrinters' @(Get-CimInstance Win32_Printer -ErrorAction Stop | Where-Object { ${'$'}_.Shared }).Count } catch { }
        # net accounts is the only non-elevated reader of the lockout policy, and
        # its labels are localised. English is matched exactly; anything else
        # emits nothing and the rule reports "not checkable", never a guess.
        foreach (${'$'}l in @(net accounts 2>${'$'}null)) {
          if (${'$'}l -match '^Lockout threshold:\s*(\S+)') {
            ${'$'}v = ${'$'}Matches[1]
            if (${'$'}v -eq 'Never') { Emit 'acct.lockoutThreshold' '0' }
            elseif (${'$'}v -match '^\d+${'$'}') { Emit 'acct.lockoutThreshold' ${'$'}v }
          }
        }
        try {
          ${'$'}ba = Get-LocalUser -ErrorAction Stop | Where-Object { ${'$'}_.SID.Value -like '*-500' }
          if (${'$'}ba) { Emit 'acct.builtinAdminEnabled' ${'$'}ba.Enabled }
        } catch { }
        # A service path with a space, not in quotes, is tried one truncated
        # prefix at a time. Paths under the Windows folder are skipped: an
        # ordinary user cannot write there, so no prefix of them is plantable.
        try {
          foreach (${'$'}svc in Get-CimInstance Win32_Service -ErrorAction Stop) {
            ${'$'}p = "${'$'}(${'$'}svc.PathName)".Trim()
            if (-not ${'$'}p -or ${'$'}p.StartsWith('"')) { continue }
            ${'$'}i = ${'$'}p.ToLower().IndexOf('.exe')
            if (${'$'}i -lt 0) { continue }
            ${'$'}exe = ${'$'}p.Substring(0, ${'$'}i + 4)
            if (${'$'}exe -notmatch ' ') { continue }
            if (${'$'}exe.StartsWith(${'$'}env:windir, [StringComparison]::OrdinalIgnoreCase)) { continue }
            Emit 'svc.unquoted' (San ${'$'}svc.Name)
          }
          Emit 'svc.unquotedRead' 'True'
        } catch { }
        # Saved Remote Desktop credentials. cmdkey lists them without elevation;
        # the passwords are never read, only that TERMSRV targets exist and how
        # many. Generic saved credentials are not counted -- they are stock.
        # Emitted even when zero, so the rule reads "none saved" as a pass
        # rather than "not checkable".
        try {
          ${'$'}rdp = @(cmdkey /list 2>${'$'}null | Select-String -SimpleMatch 'TERMSRV/').Count
          Emit 'cred.savedRdp' ${'$'}rdp
        } catch { }
        # Office macro policy. Absent keys are the modern safe default (macros
        # carrying a mark-of-the-web are blocked, VBA is warned about), so an
        # unset value emits nothing. Only an explicit weakening is listed:
        # blockcontentexecutionfrominternet=0 (internet macros un-blocked) or
        # vbawarnings=1 (enable all macros). Both the per-user hive and the
        # policy hive are read. 'office.read' is emitted only when an Office app
        # key was actually found, so the rule reports "not checkable" rather
        # than passing on a machine with no Office at all.
        try {
          ${'$'}officeSeen = ${'$'}false
          # Per-user settings and per-user policy (HKCU), plus machine-wide GPO
          # policy (HKLM\Software\Policies): a GPO that weakens macros lands in
          # the HKLM policy hive, which is world-readable without elevation. The
          # Policies key is not WOW64-redirected, so one path covers 32- and
          # 64-bit Office.
          foreach (${'$'}root in @('HKCU:\Software\Microsoft\Office','HKCU:\Software\Policies\Microsoft\Office','HKLM:\Software\Policies\Microsoft\Office')) {
            if (-not (Test-Path ${'$'}root)) { continue }
            foreach (${'$'}ver in Get-ChildItem ${'$'}root -ErrorAction SilentlyContinue |
                Where-Object { ${'$'}_.PSChildName -match '^\d+\.\d+${'$'}' }) {
              foreach (${'$'}app in @('Word','Excel','PowerPoint','Outlook','Access','Publisher','Visio')) {
                ${'$'}appKey = Join-Path ${'$'}ver.PSPath ${'$'}app
                if (-not (Test-Path ${'$'}appKey)) { continue }
                ${'$'}officeSeen = ${'$'}true
                ${'$'}sec = Join-Path ${'$'}appKey 'Security'
                if (-not (Test-Path ${'$'}sec)) { continue }
                ${'$'}sp = Get-ItemProperty -LiteralPath ${'$'}sec -ErrorAction SilentlyContinue
                if (${'$'}sp.blockcontentexecutionfrominternet -eq 0) { Emit 'office.macroWeak' (San ("${'$'}{app}: internet macros unblocked")) }
                if (${'$'}sp.vbawarnings -eq 1) { Emit 'office.macroWeak' (San ("${'$'}{app}: all macros enabled")) }
              }
            }
          }
          if (${'$'}officeSeen) { Emit 'office.read' 'True' }
        } catch { }
        # Bring-your-own-vulnerable-driver (BYOVD). A legitimately signed driver
        # with a known flaw lets a program on this machine reach the kernel --
        # the usual way an endpoint protection product is switched off before
        # ransomware runs. Every loaded driver up to DriverHash's 16 MiB cap is
        # hashed and its hash emitted for the collector to confirm against the
        # bundled LOLDrivers list. Matching by hash, not filename, is deliberate:
        # a renamed copy of a vulnerable driver keeps its hash, and the public
        # guidance is explicit that a name match is neither necessary nor
        # sufficient. Measured ~2.3s for ~200 drivers. Read-only: nothing is
        # loaded, unloaded, or changed.
        try {
          foreach (${'$'}d in Get-CimInstance Win32_SystemDriver -ErrorAction Stop |
              Where-Object { ${'$'}_.State -eq 'Running' }) {
            ${'$'}pn = "${'$'}(${'$'}d.PathName)".Trim()
            if (-not ${'$'}pn) { continue }
            ${'$'}pn = ${'$'}pn -replace '^\\\?\?\\', ''
            ${'$'}leaf = ([System.IO.Path]::GetFileName(${'$'}pn)).ToLower()
            ${'$'}dh = DriverHash ${'$'}pn
            if (${'$'}dh) { Emit 'driver.loaded' ("{0}`t{1}" -f (San ${'$'}leaf), ${'$'}dh) }
          }
          Emit 'driver.enumerated' 'True'
        } catch { }
        Emit 'hard.settingsRead' 'True'

        # ---- what the antivirus itself is doing -------------------------------
        # Blanktick is not a malware scanner and never will be: it has no network, so
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
          # PUAProtection: 1 = block (2 = audit only, which blocks nothing).
          # EnableControlledFolderAccess: 1 = on, 3 = block disk writes only.
          ${'$'}mpp = Get-MpPreference
          if (${'$'}mpp) {
            Emit 'av.pua' ${'$'}mpp.PUAProtection
            Emit 'av.cfa' ${'$'}mpp.EnableControlledFolderAccess
          }
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
        # Gate on the real elevation state, not Defender's English refusal
        # string: on non-English Windows the localized "must be an administrator"
        # message would not match, so the sentence itself was emitted as an
        # exclusion path and invented as a finding. When elevated, the read is
        # trustworthy (an empty result then genuinely means none configured);
        # when not, it is an honest blind spot.
        if (${'$'}script:isAdmin) {
          Emit 'av.exclusionsReadable' 'True'
          ${'$'}excl = (Get-MpPreference).ExclusionPath
          if (${'$'}excl) { foreach (${'$'}e in ${'$'}excl) { Emit 'av.exclusion' (San ${'$'}e) } }
        } else {
          Emit 'av.exclusionsReadable' 'False'
        }

        # ---- the AI surface --------------------------------------------------
        #
        # ## Why a consumer security app should look at this at all
        #
        # Two things arrived on ordinary machines in the last couple of years and
        # neither is audited by anything: a **local model server**, which is an
        # unauthenticated HTTP API by default, and a **tool configuration**,
        # which is a plain JSON file listing programs a language model is allowed
        # to run.
        #
        # The second is the interesting one. An entry in that file grants a model
        # the ability to execute a command, and the file lives in AppData where
        # any program running as the user can append to it. It is a persistence
        # and execution mechanism that appears in no Run key, no scheduled task
        # and no service list -- so every autorun checker ever written, including
        # the one above, looks straight past it.
        #
        # Blanktick does not judge whether the tools are appropriate. The user chose
        # them. It reports what was granted, because almost nobody has read that
        # file since the day they pasted something into it.

        # MCP configurations, which are the tool grants.
        ${'$'}aiConfigs = @(
          (Join-Path ${'$'}env:APPDATA 'Claude\claude_desktop_config.json'),
          (Join-Path ${'$'}env:USERPROFILE '.claude.json'),
          (Join-Path ${'$'}env:USERPROFILE '.cursor\mcp.json'),
          (Join-Path ${'$'}env:USERPROFILE '.codeium\windsurf\mcp_config.json')
        )
        ${'$'}aiOk = ${'$'}true
        try {
          foreach (${'$'}cfg in ${'$'}aiConfigs) {
            if (-not (Test-Path -LiteralPath ${'$'}cfg -PathType Leaf)) { continue }
            ${'$'}raw = Get-Content -LiteralPath ${'$'}cfg -Raw -ErrorAction Stop

            # Credential-shaped strings. The COUNT is emitted and the value never
            # is -- the same rule the auto-logon password check follows, for the
            # same reason: an app that copies a secret into its own report has
            # made the problem worse while describing it.
            ${'$'}secretPattern = '(sk-[A-Za-z0-9_\-]{20,})|(AIza[0-9A-Za-z_\-]{30,})|(ghp_[A-Za-z0-9]{30,})|("[A-Z_]*(?:API_?KEY|TOKEN|SECRET)"\s*:\s*"[^"]{12,}")'
            ${'$'}hits = [regex]::Matches(${'$'}raw, ${'$'}secretPattern).Count
            if (${'$'}hits -gt 0) { Emit 'ai.configSecrets' ("{0}`t{1}" -f (San ${'$'}cfg), ${'$'}hits) }

            ${'$'}parsed = ${'$'}null
            try { ${'$'}parsed = ${'$'}raw | ConvertFrom-Json } catch { ${'$'}parsed = ${'$'}null }
            if (-not ${'$'}parsed -or -not ${'$'}parsed.mcpServers) { continue }
            foreach (${'$'}sv in ${'$'}parsed.mcpServers.PSObject.Properties) {
              ${'$'}launcher = "${'$'}(${'$'}sv.Value.command)"
              Emit 'ai.mcpServer' ("{0}`t{1}`t{2}" -f (San ${'$'}sv.Name), (San ${'$'}launcher), (San ${'$'}cfg))
            }
          }
        } catch { ${'$'}aiOk = ${'$'}false }
        if (${'$'}aiOk) { Emit 'ai.configsRead' 'True' }

        # Windows Recall keeps screenshots of everything you do, plus text
        # extracted from them, in a local database. Nothing leaves the machine,
        # which is genuinely better than the alternative -- and it also means
        # anything that can read your files can read a searchable history of
        # every screen you have looked at.
        #
        # Absent on hardware without a neural processor, which is most machines,
        # and the check reports not-applicable there rather than passing.
        ${'$'}recallStore = Join-Path ${'$'}env:LOCALAPPDATA 'CoreAIPlatform.00\UKP'
        if (Test-Path -LiteralPath ${'$'}recallStore) {
          Emit 'ai.recallStorePresent' 'True'
          ${'$'}snaps = (Get-ChildItem ${'$'}recallStore -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
          Emit 'ai.recallArtifacts' ${'$'}snaps
        }
        ${'$'}recallOffUser = Reg 'HKCU:\Software\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis'
        ${'$'}recallOffMachine = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI' 'DisableAIDataAnalysis'
        if (${'$'}null -ne ${'$'}recallOffMachine) { Emit 'ai.recallDisabled' (${'$'}recallOffMachine -eq 1) }
        elseif (${'$'}null -ne ${'$'}recallOffUser) { Emit 'ai.recallDisabled' (${'$'}recallOffUser -eq 1) }

        # ---- completion ------------------------------------------------------
        # The last line of the script, and the one that says the rest can be
        # believed. PowerShell can be killed partway through -- by a crash, by a
        # policy, or by any process running as this user that would rather the
        # scan did not finish -- and the output up to that point looks exactly
        # like a successful run of a smaller script. Without this line the app
        # would render a confident, mostly-green report built from however far
        # the probe happened to get.
        # ---- Browser extensions ------------------------------------------
        # Read from local profile manifests only -- no network, no store
        # lookup. Provenance (DSK-EXT-001) is normalised to a small vocabulary;
        # broad-reach permissions (DSK-EXT-002) are split host-vs-api. Every
        # field is San()'d before the tab join, same as every other row here.
        function BtSplitPerms(${'$'}perms) {
          ${'$'}h=@(); ${'$'}a=@()
          foreach (${'$'}p in ${'$'}perms) {
            if (${'$'}null -eq ${'$'}p) { continue }
            ${'$'}s = "${'$'}p"
            if (${'$'}s -eq '<all_urls>' -or ${'$'}s -match '://' -or ${'$'}s -match '^\*') { ${'$'}h += ${'$'}s } else { ${'$'}a += ${'$'}s }
          }
          ,@(${'$'}h, ${'$'}a)
        }
        # Chrome stores the display name as a __MSG_key__ placeholder for
        # localised extensions; resolve it from the extension's own _locales so
        # the finding reads as a name and not as a token.
        function BtChromeName(${'$'}profDir, ${'$'}id, ${'$'}man) {
          ${'$'}n = "${'$'}(${'$'}man.name)"
          if (${'$'}n -notlike '__MSG_*') { return ${'$'}n }
          ${'$'}key = (${'$'}n -replace '^__MSG_','' -replace '__${'$'}','')
          ${'$'}loc = "${'$'}(${'$'}man.default_locale)"; if (-not ${'$'}loc) { ${'$'}loc = 'en' }
          ${'$'}extDir = Join-Path ${'$'}profDir ('Extensions\' + ${'$'}id)
          ${'$'}verDir = Get-ChildItem -LiteralPath ${'$'}extDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
          if (${'$'}verDir) {
            ${'$'}msgPath = Join-Path ${'$'}verDir.FullName ('_locales\' + ${'$'}loc + '\messages.json')
            if (-not (Test-Path -LiteralPath ${'$'}msgPath)) {
              ${'$'}anyLoc = Get-ChildItem -LiteralPath (Join-Path ${'$'}verDir.FullName '_locales') -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
              if (${'$'}anyLoc) { ${'$'}msgPath = Join-Path ${'$'}anyLoc.FullName 'messages.json' }
            }
            if (Test-Path -LiteralPath ${'$'}msgPath) {
              ${'$'}msgs = Get-Content -LiteralPath ${'$'}msgPath -Raw -Encoding UTF8 -ErrorAction SilentlyContinue | ConvertFrom-Json
              foreach (${'$'}prop in ${'$'}msgs.PSObject.Properties) {
                if (${'$'}prop.Name -ieq ${'$'}key -and ${'$'}prop.Value.message) { return "${'$'}(${'$'}prop.Value.message)" }
              }
            }
          }
          return ${'$'}n
        }
        ${'$'}btChromiumLoc = @{ 1='store'; 2='external'; 3='registry'; 4='unpacked'; 6='external'; 7='policy'; 9='unpacked'; 10='policy' }
        ${'$'}btBrowsers = @(
          @{ Name='Chrome';  Root=(Join-Path ${'$'}env:LOCALAPPDATA 'Google\Chrome\User Data') }
          @{ Name='Edge';    Root=(Join-Path ${'$'}env:LOCALAPPDATA 'Microsoft\Edge\User Data') }
          @{ Name='Brave';   Root=(Join-Path ${'$'}env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data') }
          @{ Name='Vivaldi'; Root=(Join-Path ${'$'}env:LOCALAPPDATA 'Vivaldi\User Data') }
          @{ Name='Opera';   Root=(Join-Path ${'$'}env:APPDATA 'Opera Software\Opera Stable') }
        )
        foreach (${'$'}b in ${'$'}btBrowsers) {
          if (-not (Test-Path -LiteralPath ${'$'}b.Root)) { continue }
          Emit 'browser.ext.read' 'True'
          ${'$'}profDirs = @()
          if (${'$'}b.Name -eq 'Opera') { ${'$'}profDirs += ${'$'}b.Root }
          else {
            ${'$'}def = Join-Path ${'$'}b.Root 'Default'
            if (Test-Path -LiteralPath ${'$'}def) { ${'$'}profDirs += ${'$'}def }
            Get-ChildItem -LiteralPath ${'$'}b.Root -Directory -ErrorAction SilentlyContinue | Where-Object { ${'$'}_.Name -like 'Profile *' } | ForEach-Object { ${'$'}profDirs += ${'$'}_.FullName }
          }
          foreach (${'$'}profDir in ${'$'}profDirs) {
            ${'$'}prefPath = Join-Path ${'$'}profDir 'Secure Preferences'
            if (-not (Test-Path -LiteralPath ${'$'}prefPath)) { ${'$'}prefPath = Join-Path ${'$'}profDir 'Preferences' }
            if (-not (Test-Path -LiteralPath ${'$'}prefPath)) { continue }
            ${'$'}settings = ${'$'}null
            try {
              ${'$'}json = Get-Content -LiteralPath ${'$'}prefPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
              ${'$'}settings = ${'$'}json.extensions.settings
            } catch { Emit 'browser.ext.unread' (San ("${'$'}(${'$'}b.Name):${'$'}(Split-Path ${'$'}profDir -Leaf)")); continue }
            if (${'$'}null -eq ${'$'}settings) { continue }
            foreach (${'$'}prop in ${'$'}settings.PSObject.Properties) {
              ${'$'}id = ${'$'}prop.Name
              ${'$'}ext = ${'$'}prop.Value
              ${'$'}man = ${'$'}ext.manifest
              if (${'$'}null -eq ${'$'}man) { continue }
              if (${'$'}man.theme) { continue }
              ${'$'}locNum = 0; try { ${'$'}locNum = [int]${'$'}ext.location } catch {}
              if (${'$'}locNum -eq 5 -or ${'$'}locNum -eq 8) { continue }
              ${'$'}source = ${'$'}btChromiumLoc[${'$'}locNum]; if (-not ${'$'}source) { ${'$'}source = 'unknown' }
              if (${'$'}ext.from_webstore -eq ${'$'}true -and ${'$'}source -eq 'unknown') { ${'$'}source = 'store' }
              ${'$'}dr = @(${'$'}ext.disable_reasons) | Where-Object { ${'$'}null -ne ${'$'}_ -and "${'$'}_" -ne '0' }
              ${'$'}enabled = (${'$'}dr.Count -eq 0)
              ${'$'}perms = @()
              if (${'$'}man.permissions) { ${'$'}perms += ${'$'}man.permissions }
              if (${'$'}man.optional_permissions) { ${'$'}perms += ${'$'}man.optional_permissions }
              if (${'$'}man.host_permissions) { ${'$'}perms += ${'$'}man.host_permissions }
              ${'$'}sp = BtSplitPerms ${'$'}perms
              ${'$'}name = try { BtChromeName ${'$'}profDir ${'$'}id ${'$'}man } catch { "${'$'}(${'$'}man.name)" }
              Emit 'browser.ext' ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}" -f (San ${'$'}b.Name),(San ${'$'}id),(San ${'$'}name),(San "${'$'}(${'$'}man.version)"),${'$'}source,${'$'}enabled,(San (${'$'}sp[0] -join ' ')),(San (${'$'}sp[1] -join ' ')))
            }
          }
        }
        # Firefox keeps a single extensions.json per profile, a different shape.
        ${'$'}ffRoot = Join-Path ${'$'}env:APPDATA 'Mozilla\Firefox\Profiles'
        if (Test-Path -LiteralPath ${'$'}ffRoot) {
          foreach (${'$'}fp in (Get-ChildItem -LiteralPath ${'$'}ffRoot -Directory -ErrorAction SilentlyContinue)) {
            ${'$'}extJson = Join-Path ${'$'}fp.FullName 'extensions.json'
            if (-not (Test-Path -LiteralPath ${'$'}extJson)) { continue }
            Emit 'browser.ext.read' 'True'
            try {
              ${'$'}data = Get-Content -LiteralPath ${'$'}extJson -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
              foreach (${'$'}a in ${'$'}data.addons) {
                if (${'$'}a.type -ne 'extension') { continue }
                if (${'$'}a.location -eq 'app-builtin' -or ${'$'}a.location -eq 'app-system-defaults') { continue }
                ${'$'}src = 'unknown'
                switch -Wildcard ("${'$'}(${'$'}a.location)") {
                  'app-profile'  { ${'$'}src = if (${'$'}a.foreignInstall -eq ${'$'}true) { 'sideload' } else { 'store' } }
                  'winreg-app-*' { ${'$'}src = 'registry' }
                  'app-system-*' { ${'$'}src = 'external' }
                  default        { ${'$'}src = 'unknown' }
                }
                if (${'$'}null -ne ${'$'}a.signedState -and [int]${'$'}a.signedState -lt 2 -and ${'$'}src -eq 'store') { ${'$'}src = 'sideload' }
                ${'$'}perms = @(); ${'$'}origins = @()
                if (${'$'}a.userPermissions) {
                  if (${'$'}a.userPermissions.permissions) { ${'$'}perms += ${'$'}a.userPermissions.permissions }
                  if (${'$'}a.userPermissions.origins) { ${'$'}origins += ${'$'}a.userPermissions.origins }
                }
                ${'$'}enabled = (${'$'}a.active -eq ${'$'}true)
                Emit 'browser.ext' ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}`t{6}`t{7}" -f 'Firefox',(San "${'$'}(${'$'}a.id)"),(San "${'$'}(${'$'}a.defaultLocale.name)"),(San "${'$'}(${'$'}a.version)"),${'$'}src,${'$'}enabled,(San (${'$'}origins -join ' ')),(San (${'$'}perms -join ' ')))
              }
            } catch { Emit 'browser.ext.unread' (San ("Firefox:" + ${'$'}fp.Name)) }
          }
        }

        Emit 'probe.complete' 'True'
    """.trimIndent()
}
