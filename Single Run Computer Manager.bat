@echo off
setlocal enabledelayedexpansion
title Single Run Computer Manager (Google Services, Temp Files, etc)
::whoami | findstr /i /C:"nt authority\System" >nul || whoami /user | findstr /i /C:S-1-5-18 >nul || ( call :RunAsTI "%~f0" %* & exit /b )
whoami | findstr /i /C:"nt authority\System" >nul || (whoami /user | findstr /i /C:"S-1-5-18" >nul || (call :RunAsTI "%~f0" %* & exit /b))
powercfg.exe -h off
netsh int teredo set state servername=0.0.0.0
REM *** Tweaks in One Category ***
sc stop AdobeARMservice /y
sc stop diagnosticshub.standardcollector.service /y
sc stop DiagTrack /y
sc stop RemoteRegistry /y
sc stop WMPNetworkSvc /y
sc stop wuauserv /y
net stop bits /y
net stop cryptSvc /y
net stop DoSvc /y
net stop EventLog /y
net stop msiserver /y
net stop UsoSvc /y
net stop winmgmt /y
net stop wuauserv /y
sc stop usosvc /y
sc stop cryptSvc /y
sc stop bits /y
sc stop msiserver /y
sc stop eventlog /y
powercfg -x -standby-timeout-dc 0
powercfg /x -standby-timeout-dc 0
powercfg -x -standby-timeout-ac 0
powercfg /x -standby-timeout-ac 0
schtasks /change /tn "CCleaner Update" /disable
schtasks /change /tn "GoogleUpdateTaskMachineCore" /disable
schtasks /change /tn "GoogleUpdateTaskMachineUA" /disable
schtasks /change /tn "MicrosoftEdgeUpdateTaskMachineCore" /disable
schtasks /change /tn "MicrosoftEdgeUpdateTaskMachineUA" /disable
schtasks /change /tn "Optimize Thumbnail Cache" /disable
schtasks /change /tn "svchost" /disable
schtasks /delete /tn "CCleaner Update" /f
schtasks /delete /tn "Explorer" /f
schtasks /delete /tn "GoogleUpdateTaskMachineCore" /f
schtasks /delete /tn "GoogleUpdateTaskMachineUA" /f
schtasks /delete /tn "MicrosoftEdgeUpdateTaskMachineCore" /f
schtasks /delete /tn "MicrosoftEdgeUpdateTaskMachineUA" /f
schtasks /delete /tn "Optimize Thumbnail Cache" /f
schtasks /delete /tn "svchost" /f
schtasks /End /TN "\Microsoft\Windows\Wininet\CacheTask"
taskkill /im MoUsoCoreWorker.exe /f
taskkill /im msi.exe /f
taskkill /im sihclient.exe /f
taskkill /im UsoClient.exe /f
taskkill /im usocoreworker.exe /f
taskkill /im wuauclt.exe /f
taskkill /IM eventvwr.msc /F
taskkill /f /fi "IMAGENAME eq bonjour*"
taskkill /f /fi "IMAGENAME eq CCleaner*"
taskkill /f /fi "IMAGENAME eq DCIService*"
taskkill /f /fi "IMAGENAME eq dfxshared*"
taskkill /f /fi "IMAGENAME eq Edge*"
taskkill /f /fi "IMAGENAME eq EdgeUpdate*"
taskkill /f /fi "IMAGENAME eq Google*"
taskkill /f /fi "IMAGENAME eq jusched*"
taskkill /f /fi "IMAGENAME eq lavasoft*"
taskkill /f /fi "IMAGENAME eq maintenanceservice*"
taskkill /f /fi "IMAGENAME eq mdns*"
taskkill /f /fi "IMAGENAME eq MicrosoftEdgeUpdate*"
taskkill /f /fi "IMAGENAME eq mscorsvw*"
taskkill /f /fi "IMAGENAME eq PresentationFontCache*"
taskkill /f /fi "IMAGENAME eq reporter*"
taskkill /f /fi "IMAGENAME eq Software_reporter_tool*"
taskkill /f /fi "IMAGENAME eq WebCompanion*"
taskkill /f /fi "IMAGENAME eq WLIDSVC*"
taskkill /f /fi "IMAGENAME eq WSHelper*"
taskkill /f /fi "IMAGENAME eq GoogleUpdate*"
taskkill /f /fi "IMAGENAME eq GUpdate*"
taskkill /f /fi "IMAGENAME eq ktpcntr*"
taskkill /f /fi "IMAGENAME eq RemindersServer*"
taskkill /f /fi "IMAGENAME eq SearchUI*"
taskkill /f /fi "IMAGENAME eq ShellExperienceHost*"
taskkill /f /fi "IMAGENAME eq wpscenter*"
taskkill /f /fi "IMAGENAME eq wpscloudsvr*"
taskkill /im mobsync.exe" /f
echo You are clearing cache files (WAIT UNTIL PROCESSED)
takeown /f "%LocalAppData%\Microsoft Games" /r /d y
takeown /f "%LocalAppData%\Microsoft\Windows\Explorer" /r /d y
takeown /f "%LocalAppData%\Microsoft\Windows\WebCache" /r /d y
takeown /f "%ProgramFiles%\Microsoft Games" /r /d y
takeown /f "%ProgramFiles(x86)%\Microsoft" /r /d y
del /s /f /q "%LocalAppData%\D3DSCache\*"
del /s /f /q "%LocalAppData%\Microsoft\Windows\WebCache\*"
del /s /f /q "%ProgramData%\Package Cache\*"
del /s /f /q "%ProgramData%\USOShared\Logs\*"
del /s /f /q "%SystemDrive%\Windows\Downloaded Program Files\*"
del /s /f /q "%SystemDrive%\Windows\ff*.tmp"
del /s /f /q "%SystemDrive%\Windows\spool\printers\*"
del /s /f /q "%SystemDrive%\Windows\Temp\*"
del /s /f /q "%SystemRoot%\inf\setupapi.*.log"
del /s /f /q "%SystemRoot%\Panther\*"
del /s /f /q "%WINDIR%\*.bak"
del /s /f /q "%WINDIR%\Logs\*"
del /s /f /q "%WINDIR%\Minidump\*"
del /s /f /q "%WINDIR%\Prefetch\*"
del /s /f /q "%WINDIR%\SoftwareDistribution\DeliveryOptimization\*"
del /s /f /q "%WINDIR%\SoftwareDistribution\Download\*"
del /s /f /q "%WINDIR%\System32\LogFiles\*"
del /s /f /q "%WINDIR%\System32\mobsync.exe"
del /s /f /q "%WINDIR%\System32\winevt\Logs\*"
del /s /f /q "%WINDIR%\Temp\*"
del /s /f /q "%WINDIR%\WinSxS\Backup\*"
del /s /f /q "%WINDIR%\winsxs\pending.xml"
del /q "%localappdata%\IconCache.db"
del /q "%localappdata%\Microsoft\Windows\Explorer\thumbcache_*"
rd /q /s "%LocalAppData%\Microsoft\OneDrive"
rd /q /s "%ProgramData%\Adguard\Logs"
rd /q /s "%ProgramData%\Adguard\Logs\host"
rd /q /s "%ProgramData%\Adguard\Logs\service"
rd /q /s "%ProgramData%\Adguard\Logs\tools"
rd /q /s "%ProgramData%\Auslogics\Disk Defrag"
rd /q /s "%ProgramData%\Malwarebytes\MBAMService\logs"
rd /q /s "%ProgramData%\Microsoft OneDrive"
rd /q /s "%ProgramData%\Microsoft\Windows\WER"
rd /q /s "%ProgramData%\Oracle\Java"
rd /q /s "%ProgramData%\USOPrivate\UpdateStore"
rd /q /s "%ProgramFiles%\Apple Software Update"
rd /q /s "%ProgramFiles%\Bonjour"
rd /q /s "%ProgramFiles%\Common Files\Microsoft Shared\Windows Live"
rd /q /s "%ProgramFiles%\Google\Temp"
rd /q /s "%ProgramFiles%\Microsoft Games"
rd /q /s "%ProgramFiles%\Microsoft\EdgeUpdate"
rd /q /s "%ProgramFiles%\Windows Defender"
rd /q /s "%ProgramFiles(x86)%\Apple Software Update"
rd /q /s "%ProgramFiles(x86)%\Bonjour"
rd /q /s "%ProgramFiles(x86)%\Common Files\Java\Java Update"
rd /q /s "%ProgramFiles(x86)%\Common Files\Wondershare\Wondershare Helper Compact"
rd /q /s "%ProgramFiles(x86)%\DFX\Universal\Apps"
rd /q /s "%ProgramFiles(x86)%\Google\CrashReports"
rd /q /s "%ProgramFiles(x86)%\Google\GoogleUpdater"
rd /q /s "%ProgramFiles(x86)%\Google\Temp"
rd /q /s "%ProgramFiles(x86)%\Google\Update"
rd /q /s "%ProgramFiles(x86)%\Lavasoft"
rd /q /s "%ProgramFiles(x86)%\Microsoft\EdgeUpdate"
rd /q /s "%ProgramFiles(x86)%\Microsoft\EdgeUpdate"
rd /q /s "%ProgramFiles(x86)%\Microsoft\Temp"
rd /q /s "%ProgramFiles(x86)%\Mozilla Maintenance Service"
rd /q /s "%ProgramFiles(x86)%\Windows Defender"
rd /q /s "%SystemDrive%\$Windows.~BT"
rd /q /s "%SystemDrive%\$Windows.~WS"
rd /q /s "%SystemDrive%\$WinREAgent"
rd /q /s "%SystemDrive%\AMD"
rd /q /s "%SystemDrive%\drivers"
rd /q /s "%SystemDrive%\OneDriveTemp"
rd /q /s "%SystemDrive%\Users\defaultuser0"
rd /q /s "%SystemDrive%\Windows\cookies"
rd /q /s "%SystemDrive%\Windows\Logs"
rd /q /s "%SystemDrive%\Windows\servicing\LCU"
rd /q /s "%SystemDrive%\Windows\SoftwareDistribution\DataStore"
rd /q /s "%SystemDrive%\Windows\tempor~1"
rd /q /s "%SystemDrive%\Windows\tmp"
rd /q /s "%SystemDrive%\Windows\Webcache"
rd /q /s "%UserProfile%\AppData\Local\AdvinstAnalytics"
rd /q /s "%UserProfile%\AppData\Local\Application Data\Microsoft\Windows\WebCache"
rd /q /s "%UserProfile%\AppData\Local\CrashDumps"
rd /q /s "%UserProfile%\AppData\Local\Google\Chrome\User Data\SwReporter"
rd /q /s "%UserProfile%\AppData\Local\Google\Software Reporter Tool"
rd /q /s "%UserProfile%\AppData\Local\Microsoft\Windows Mail"
rd /q /s "%UserProfile%\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5"
rd /q /s "%UserProfile%\AppData\Local\Microsoft\Windows\WebCache"
rd /q /s "%UserProfile%\AppData\LocalLow\Sun\Java\Deployment\cache"
rd /q /s "%UserProfile%\AppData\Roaming\BitTorrent\updates"
rd /q /s "%UserProfile%\AppData\Roaming\DRPSu"
rd /q /s "%UserProfile%\AppData\Roaming\kingsoft\wps\addons\pool"
rd /q /s "%UserProfile%\AppData\Roaming\Smadav"
rd /q /s "%UserProfile%\AppData\Roaming\Tencent\TxGameAssistant\GameDownload"
rd /q /s "%UserProfile%\OneDrive"
rd C:\OneDriveTemp /Q /S
reg.exe add "HKLM\System\ControlSet001\services\Fax" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\services\NvTelemetryContainer" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\services\WSearch" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AcrylicDNSProxySvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Adguard Service" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BFE" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BITS" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Dhcp" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\GoogleChromeElevationService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MBAMService" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MozillaMaintenance" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RpcLocator" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Schedule" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Spooler" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Themes" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UnsignedThemes" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\W32Time" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Wlansvc" /v "start" /t REG_DWORD /d "2" /f
@echo off && powershell.exe -ExecutionPolicy Bypass -Command "Get-ScheduledTask | Where-Object { $_.TaskName -like '*Google*' -or $_.TaskName -like '*GoogleUpdate*' -or $_.TaskName -like '*Mozilla*' -or $_.TaskName -like '*Edge*' -or $_.TaskName -like '*Avast*' -or $_.TaskName -like '*Edge*' -or $_.TaskName -like '*Opera*' -or $_.TaskName -like '*EdgeUpdate*' -or $_.TaskName -like '*Brave*' } | Unregister-ScheduledTask -Confirm:$false"
@echo off & schtasks /query /tn "CleanTempLogOn" >nul 2>&1 && (schtasks /delete /tn "CleanTempLogOn" /f) & schtasks /create /tn "CleanTempLogOn" /tr "cmd.exe /c rmdir /s /q \"%TEMP%\" && mkdir \"%TEMP%\"" /sc onlogon /rl highest /ru "SYSTEM" /f & powershell -Command "Add-Type -AssemblyName System.Windows.Forms; $action1 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c rmdir /s /q \"C:\ProgramData\Adguard\Logs\" && mkdir \"C:\ProgramData\Adguard\Logs\"'; $action2 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c rmdir /s /q \"C:\ProgramData\Malwarebytes\MBAMService\logs\" && mkdir \"C:\ProgramData\Malwarebytes\MBAMService\logs\"'; $action3 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c rmdir /s /q \"C:\Windows\Logs\" && mkdir \"C:\Windows\Logs\"'; $action4 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c rmdir /s /q \"C:\Windows\SoftwareDistribution\" && mkdir \"C:\Windows\SoftwareDistribution\"'; $task = Get-ScheduledTask -TaskName \"CleanTempLogOn\"; $task.Actions.Clear(); $task.Actions += $action1; $task.Actions += $action2; $task.Actions += $action3; $task.Actions += $action4; Set-ScheduledTask -TaskName \"CleanTempLogOn\" -Action $task.Actions -Trigger $task.Triggers -User $task.Principal.UserId"
for %%D in (%SystemDrive% B: D: E: F: G: H: I: J: K:) do @if exist %%D\ (del /f /s /q %%D\$Recycle.Bin\*.* >nul 2>&1 & rd /s /q %%D\$Recycle.Bin >nul 2>&1 & echo Cleaned %%D\$Recycle.Bin || echo Failed %%D\$Recycle.Bin)
for /D %%D in (C: D: E: F: G: H: I: J: K:) do @if exist %%D\Users\ (for /D %%U in (%%D\Users\*) do @if exist "%%U\AppData\Local\Temp" (del /f /s /q "%%U\AppData\Local\Temp\*.*" >nul 2>&1 & rd /s /q "%%U\AppData\Local\Temp" >nul 2>&1 & md "%%U\AppData\Local\Temp" >nul 2>&1 & echo Cleaned "%%U\AppData\Local\Temp"))
REM Define a list of executable names to block, separated by spaces
set executables="wpscloudsvr.exe mobsync.exe CompatTelRunner.exe DeviceCensus.exe Software_reporter_tool.exe GoogleUpdate.exe maintenanceservice.exe bonjour.exe jusched.exe crashreporter.exe CompatTelRunner.exe DeviceCensus.exe Software_reporter_tool.exe MicrosoftEdgeUpdate.exe upfc.exe"
REM Loop through each executable and add the IFEO debugger entry
for %%i in (%executables%) do (
    reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\%%i" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
    echo Added IFEO debugger for %%i
)
echo All specified executables have been blocked.
powershell.exe "Enable-WindowsOptionalFeature -Online -FeatureName "DirectPlay" -NoRestart"
vssadmin delete shadows /all /quiet
vssadmin delete shadows /for=c: /all /quiet
winmgmt /salvagerepository
net start msiserver
sc config w32time start= auto
w32tm /config /update /manualpeerlist:time.google.com /syncfromflags:manual /reliable:yes
w32tm /config /reliable:yes
net stop w32time
net start w32time
w32tm /resync
pause
echo Going for Services
sc config AJRouter start=disabled
sc config BraveUpdate start=disabled
sc config edgeupdate start=disabled
sc config edgeupdatem start=disabled
sc config gupdate start=disabled
sc config gupdatem start=disabled
sc config MozillaMaintenance start=disabled
sc config AXInstSV start=disabled
sc config diagnosticshub.standardcollector.service start=disabled
sc config DmEnrollmentSvc start=disabled
sc config gupdate start= disabled
sc config gupdatem start= disabled
sc config lfsvc start=disabled
sc config NcdAutoSetup start=disabled
sc config p2pimsvc start=disabled
sc config p2psvc start=disabled
sc config PNRPAutoReg start=disabled
sc config PNRPsvc start=disabled
sc config RetailDemo start=disabled
sc config SmsRouter start=disabled
sc config SSDPSRV start=disabled
sc config WalletService start=disabled
sc config WMPNetworkSvc start=disabled
sc config WSearch start=disabled
sc config XblAuthManager start=disabled
sc config XblGameSave start=disabled
sc config XboxNetApiSvc start=disabled
wmic product where name="Mozilla Maintenance Service" call uninstall /nointeractive >nul 2>&1
echo Managing the Systems issues
::takeown /f C:\Windows.old /r /d "y
::takeown /f C:\Windows\logs /r /d "y
REM ; Setup DNS Servers on DHCP Enabled Network
REM ; wmic nicconfig where DHCPEnabled=TRUE call SetDNSServerSearchOrder ("94.140.14.14","174.138.21.128")
REM ; Setup IP, Gateway and DNS Servers based on the MAC address (To Enable DHCP: wmic nicconfig where macaddress="28:E3:47:18:70:3D" call enabledhcp)
REM ; wmic nicconfig where macaddress="68:F7:28:0F:B6:D5" call EnableStatic ("10.10.10.20"), ("255.255.255.0")
REM ; wmic nicconfig where macaddress="68:F7:28:0F:B6:D5" call SetDNSServerSearchOrder ("176.103.130.131","176.103.130.130")
REM ; wmic nicconfig where macaddress="68:F7:28:0F:B6:D5" call SetGateways ("10.10.10.10")
reg.exe add "HKCR\AllFileSystemObjects" /v "DefaultDropEffect" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "ShutdownWithoutLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "8000" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "3000" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "ShutdownWithoutLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "SnapToDEFAULTButton" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Control Panel\Desktop" /v "SnapWindows" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v OEMBackground /T REG_DWORD /d 00000001 /f
reg.exe add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DisableEdgeDesktopShortcutCreation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "IconUnderline" /t REG_DWORD /d "3" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoSaveSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoTaskGrouping" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoThemesTab" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarGlomming" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarSmallIcons" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startMenuLogOff" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startupDelayInMSec" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapAssist" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapAssistIgnore" /t REG_DWORD /d 0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d 600 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconVerticalSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowNetworkIcon" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCache" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailMode" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailQuality" /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "start_TrackProgs" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers" /v "HandlerForRemovableDrive" /t REG_SZ /d "MSAutoPlay" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers" /v "HandlerForRemovableMedia" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "ForceClassicControlPanel" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicstartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicstartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{208D2C60-3AEA-1069-A2D7-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{871C5380-42A0-1069-A2EA-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{0DDD015D-B06C-45D5-8C4C-F59713854639}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{A0C69A99-21C8-4671-8703-7934162FCF1D}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{D3162B92-9365-467A-956B-92703ACA08AF}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoControlPanel" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFolderOptions" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoViewContextMenu" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoring" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoringRunningNotification" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "disableNotificationCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\System" /v "DisableCMD" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" /v "EnableMtcUvc" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoSaveSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoThemesTab" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowDriveLettersFirst" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startMenuLogOff" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconVerticalSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCache" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailMode" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "HandlerForRemovableDrive" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "HandlerForRemovableMedia" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ShutdownWithoutLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" /v "AllowOSUpgrade" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\BraveSoftware\Update" /v AutoUpdateCheckPeriodMinutes /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v AutoUpdateCheckPeriodMinutes /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v DisableAutoUpdateChecksCheckboxValue /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v DisableGoogleUpdateService /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v AutoUpdateCheckPeriodMinutes /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v UpdateDefault /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Setup" /v "ConcurrentDownloads" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Warn" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v DisableAppUpdate /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Opera Software\Opera Stable" /v DisableAutoUpdate /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg.exe add "HKLM\System\ControlSet001\Control\SESSION MANAGER\MEMORY MANAGEMENT\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "6000" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CrashControl" /v DumpType /t REG_DWORD /d 0 /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CrashControl" /v LogEvent /t REG_DWORD /d 0 /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CrashControl" /v SendAlert /t REG_DWORD /d 0 /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveDnsProbeHost" /t REG_SZ /d "dns.google" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveDnsProbeHostV6" /t REG_SZ /d "dns.google" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbeContent" /t REG_SZ /d "Google Connect Test" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbeContentV6" /t REG_SZ /d "Google Connect Test" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbeHost" /t REG_SZ /d "www.google.com" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "ActiveWebProbeHostV6" /t REG_SZ /d "ipv6.google.com" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "DisablePassivePolling" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "WebProbeTimeout" /t REG_DWORD /d "5000" /f
reg.exe add "HKLM\System\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d "0" /f
reg.exe delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
reg.exe delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg.exe delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
reg.exe delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\reg.exeedit" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\reg.exeedit\Favorites" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify" /v IconStreams /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify" /v PastIconsStream /f
reg.exe delete "HKLM\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
reg.exe delete "HKLM\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg.exe delete "HKLM\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Applets\reg.exeedit" /va /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Applets\reg.exeedit\Favorites" /va /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DDD015D-B06C-45D5-8C4C-F59713854639}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088E3905-0323-4B02-9826-5D99428E115F}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0C69A99-21C8-4671-8703-7934162FCF1D}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{D3162B92-9365-467A-956B-92703ACA08AF}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088E3905-0323-4B02-9826-5D99428E115F}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{D3162B92-9365-467A-956B-92703ACA08AF}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f >nul 2>&1
reg.exe delete "HKLM\System\CurrentControlSet\services\LDrvSvc" /f
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppXPackage -AllUsers | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register ([System.IO.Path]::Combine($_.InstallLocation, 'AppXManifest.xml'))}"
endlocal

#:RunAsTI snippet to run as TI/System, with innovative HKCU load, ownership privileges, high priority, and Explorer support
set ^ #=& set "0=%~f0"& set 1=%*& powershell -c iex(([io.file]::ReadAllText($env:0)-split'#\:RunAsTI .*')[1])& exit /b
function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='Control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="Explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='Control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
}; $A=,$env:1-split'"([^"]+)"|([^ ]+)',2|%{$_.Trim(' ')}; RunAsTI $A[1] $A[2]; #:RunAsTI 
