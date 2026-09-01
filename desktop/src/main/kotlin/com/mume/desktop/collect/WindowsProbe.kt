package com.mume.desktop.collect

/**
 * The complete set of commands Mume runs on a Windows machine.
 *
 * ## Read it. That is the point.
 *
 * This is deliberately one readable block rather than twenty-five strings
 * scattered through a collector. A person who wants to know what a security app
 * is doing on their computer can read this, paste it into PowerShell, and
 * compare the output line by line against what Mume displayed. An app that asks
 * you to trust it about privacy should be the easiest thing in the world to
 * check.
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
 * A query that finds nothing emits nothing, and the absent key is read as
 * *unknown* — never as a negative answer.
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
        function San(${'$'}v) { ("${'$'}v" -replace '[\r\n\t]+', ' ') }
        function Emit(${'$'}k, ${'$'}v) {
          if (${'$'}null -ne ${'$'}v -and "${'$'}v".Trim() -ne '') {
            Write-Output ("{0}={1}" -f ${'$'}k, ("${'$'}v" -replace '[\r\n]+', ' '))
          }
        }
        function Reg(${'$'}path, ${'$'}name) {
          (Get-ItemProperty -Path ${'$'}path -Name ${'$'}name -ErrorAction SilentlyContinue).${'$'}name
        }

        # ---- identity -------------------------------------------------------
        Emit 'os.build' ((Get-CimInstance Win32_OperatingSystem).Caption + ' ' + [Environment]::OSVersion.Version)

        # ---- firewall -------------------------------------------------------
        # Get-NetFirewallProfile rather than `netsh advfirewall show`: netsh
        # localises both the profile names and the words ON/OFF, so parsing it
        # would fail on a non-English install -- and fail towards "off", which
        # would accuse a correctly configured machine.
        foreach (${'$'}p in Get-NetFirewallProfile -PolicyStore ActiveStore) {
          Emit 'fw.profile' ("{0}`t{1}" -f (San ${'$'}p.Name), ${'$'}p.Enabled)
        }

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
          foreach (${'$'}m in Get-LocalGroupMember -Group ${'$'}adminGroup) { Emit 'acct.admin' ${'$'}m.Name }
        }

        ${'$'}users = Get-LocalUser
        if (${'$'}users) {
          # Emitted so that "no passwordless accounts" can be told apart from
          # "the enumeration failed". Without it, a domain-joined machine that
          # refuses Get-LocalUser would look like a clean pass.
          Emit 'acct.userCount' (${'$'}users | Measure-Object).Count
          foreach (${'$'}u in ${'$'}users) {
            if (${'$'}u.Enabled -and -not ${'$'}u.PasswordRequired) { Emit 'acct.passwordless' ${'$'}u.Name }
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
        foreach (${'$'}c in Get-NetTCPConnection -State Listen) {
          ${'$'}proc = (Get-Process -Id ${'$'}c.OwningProcess).ProcessName
          Emit 'port' ("{0}`t{1}`t{2}" -f ${'$'}c.LocalAddress, ${'$'}c.LocalPort, (San ${'$'}proc))
        }

        # ---- network --------------------------------------------------------
        foreach (${'$'}a in Get-DnsClientServerAddress -AddressFamily IPv4) {
          foreach (${'$'}s in ${'$'}a.ServerAddresses) { Emit 'dns' ${'$'}s }
        }
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
        ${'$'}arRaw = ${'$'}null
        foreach (${'$'}k in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer')) {
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
        foreach (${'$'}vol in Get-Volume | Where-Object { ${'$'}_.DriveType -eq 'Removable' -and ${'$'}_.DriveLetter }) {
          ${'$'}bl = ${'$'}shell.NameSpace("${'$'}(${'$'}vol.DriveLetter):\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
          Emit 'drive' ("{0}`t{1}`t{2}`t{3}`t{4}" -f ${'$'}vol.DriveLetter, (San ${'$'}vol.FileSystemLabel), (San ${'$'}vol.FileSystem), ${'$'}vol.Size, ${'$'}bl)
        }
        # Emitted so "no drive attached" can be told apart from "the enumeration
        # failed" -- the rule reports not-checkable for the first and must not
        # treat either as a pass.
        Emit 'drive.enumerated' 'True'

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
        foreach (${'$'}root in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
          foreach (${'$'}e in Get-ItemProperty ${'$'}root) {
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
        # Emitted so "no programs found" can be told apart from "the enumeration
        # failed", exactly as acct.userCount does for local accounts.
        Emit 'program.enumerated' 'True'

        # ---- programs that start themselves ---------------------------------
        function EmitRun(${'$'}key) {
          ${'$'}props = Get-ItemProperty ${'$'}key
          if (-not ${'$'}props) { return }
          foreach (${'$'}p in ${'$'}props.PSObject.Properties) {
            if (${'$'}p.Name -like 'PS*') { continue }
            ${'$'}cmd = "${'$'}(${'$'}p.Value)"
            ${'$'}exe = ${'$'}null
            if (${'$'}cmd.StartsWith('"')) {
              ${'$'}exe = ${'$'}cmd.Substring(1).Split('"')[0]
            } elseif (${'$'}cmd -match '^(?<p>[^ ]+\.exe)') {
              ${'$'}exe = ${'$'}Matches['p']
            }
            ${'$'}status = ''
            if (${'$'}exe -and (Test-Path -LiteralPath ${'$'}exe)) {
              ${'$'}status = (Get-AuthenticodeSignature -LiteralPath ${'$'}exe).Status
            }
            Emit 'autorun' ("{0}`t{1}`t{2}`t{3}" -f (San ${'$'}p.Name), ${'$'}key, (San ${'$'}cmd), ${'$'}status)
          }
        }
        EmitRun 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        EmitRun 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'

        foreach (${'$'}dir in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
          if (${'$'}dir -and (Test-Path ${'$'}dir)) {
            foreach (${'$'}f in Get-ChildItem ${'$'}dir -File) {
              ${'$'}status = (Get-AuthenticodeSignature -LiteralPath ${'$'}f.FullName).Status
              Emit 'autorun' ("{0}`t{1}`t{2}`t{3}" -f (San ${'$'}f.BaseName), ${'$'}dir, (San ${'$'}f.FullName), ${'$'}status)
            }
          }
        }
    """.trimIndent()
}
