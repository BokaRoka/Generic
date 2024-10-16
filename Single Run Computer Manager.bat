@echo off & @SETLOCAL enableextensions
title Single Run Computer Manager (Google Services, Temp Files, etc)

:: [info] to integrate in .bat files, add RunAsTI snippet on bottom and this line before main code
whoami|findstr /i /c:"nt authority\SYSTEM" >nul || ( call :RunAsTI "%~f0" %* & exit/b )
powercfg.exe -h off
sc config w32time start= auto
w32tm /config /update /manualpeerlist:time.google.com /syncfromflags:manual /reliable:yes
w32tm /config /reliable:yes
netsh int teredo set state servername=0.0.0.0
REM *** Tweaks in One Category ***
net stop wuauserv
net stop cryptSvc
net stop bits
net stop msiserver
taskkill /f /fI "IMAGENAME eq bonjour*"
taskkill /f /fI "IMAGENAME eq CCleaner*"
taskkill /f /fI "IMAGENAME eq dfxshared*"
taskkill /f /fI "IMAGENAME eq lavasoft*"
taskkill /f /fI "IMAGENAME eq DCIService*"
taskkill /f /fI "IMAGENAME eq WebCompanion*"
taskkill /f /fI "IMAGENAME eq Google*"
taskkill /f /fI "IMAGENAME eq jusched*"
taskkill /f /fI "IMAGENAME eq maintenanceservice*"
taskkill /f /fI "IMAGENAME eq mdns*"
taskkill /f /fI "IMAGENAME eq mscorsvw*"
taskkill /f /fI "IMAGENAME eq MicrosoftEdgeUpdate*"
taskkill /f /fI "IMAGENAME eq EdgeUpdate*"
taskkill /f /fI "IMAGENAME eq Edge*"
taskkill /f /fI "IMAGENAME eq PresentationFontCache*"
taskkill /f /fI "IMAGENAME eq reporter*"
taskkill /f /fI "IMAGENAME eq SOFTWARE_reporter_tool*"
taskkill /f /fI "IMAGENAME eq WLIDSVC*"
taskkill /f /fI "IMAGENAME eq WSHelper*"
taskkill /f /im RemindersServer.exe
taskkill /f /im SearchUI.exe
taskkill /f /im ShellExperienceHost.exe
taskkill /im ktpcntr.exe /f
taskkill /im wpscenter.exe /f
taskkill /im wpscloudsvr.exe /f
sc config AJRouter start=disabled
sc config AppReadiness start=disabled
sc config AXInstSV start=disabled
sc config diagnosticshub.standardcollector.service start=disabled
sc config DmEnrollmentSvc start=disabled
sc config gupdate start= disabled
sc config gupdatem start= disabled
sc config icssvc start=disabled
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
sc.exe start w32time task_started
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
schtasks /delete /tn "explorer" /f
schtasks /delete /tn "GoogleUpdateTaskMachineCore" /f
schtasks /delete /tn "GoogleUpdateTaskMachineUA" /f
schtasks /delete /tn "MicrosoftEdgeUpdateTaskMachineCore" /f
schtasks /delete /tn "MicrosoftEdgeUpdateTaskMachineUA" /f
schtasks /delete /tn "Optimize Thumbnail Cache" /f
schtasks /delete /tn "svchost" /f
takeown /f %LocalAppData%\Microsoft Games\ /r /d y
takeown /f %LocalAppData%\Microsoft\Windows\Explorer\ /r /d y
takeown /f %ProgramFiles%\Microsoft Games\ /r /d y
takeown /f %ProgramFiles(x86)%\Microsoft\ /r /d y
takeown /f C:\Windows.old /r /d y
taskkill /im mobsync.exe /f
REM ; Setup DNS Servers on DHCP Enabled Network
REM ; wmic nicconfig where DHCPEnabled=TRUE call SetDNSServerSearchOrder ("94.140.14.14","174.138.21.128")
REM ; Setup IP, Gateway and DNS Servers based on the MAC address (To Enable DHCP: wmic nicconfig where macaddress="28:E3:47:18:70:3D" call enabledhcp)
REM ; wmic nicconfig where macaddress="68:F7:28:0F:B6:D5" call EnableStatic ("10.10.10.20"), ("255.255.255.0")
REM ; wmic nicconfig where macaddress="68:F7:28:0F:B6:D5" call SetDNSServerSearchOrder ("176.103.130.131","176.103.130.130")
REM ; wmic nicconfig where macaddress="68:F7:28:0F:B6:D5" call SetGateways ("10.10.10.10")
reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "ForceClassicControlPanel" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{208D2C60-3AEA-1069-A2D7-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{871C5380-42A0-1069-A2EA-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoControlPanel" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoFolderOptions" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoViewContextMenu" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\SOFTWARE\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "disableNotificationCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "DisableCMD" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SYSTEMToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableLUA" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Setup" /v "ConcurrentDownloads" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "ShellSmartScreenLevel" /t REG_SZ /d "Warn" /f
reg.exe add "HKLM\SYSTEM\ControlSet001\Control\SESSION MANAGER\MEMORY MANAGEMENT\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SYSTEM\ControlSet001\services\Fax" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\SYSTEM\ControlSet001\services\NvTelemetryContainer" /v "Start" /t REG_DWORD /d "4" /f
REM ; Set Control Panel on Classic View and small icons
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "StartupPage" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowDriveLettersFirst" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "6000" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /ve /t REG_SZ /d "" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "DisablePassivePolling" /t REG_DWORD /d "0" /f
reg.exe add "HKCR\AllFileSYSTEMObjects" /v "DefaultDropEffect" /t REG_DWORD /d "1" /f
del "%WINDIR%\SYSTEM32\mobsync.exe" /s /f /q
rd "C:\Windows\Temp" /q /s
rd "C:\Windows\SOFTWAREDistribution\DataStore" /q /s
rd "C:\Windows\Logs" /q /s
rd "C:\Windows\Webcache" /q /s
rd "%LocalAppData%\Microsoft\OneDrive" /q /s
rd "%ProgramData%\Adguard\Logs" /q /s
rd "%ProgramData%\Auslogics\Disk Defrag" /q /s
rd "%ProgramData%\Malwarebytes\MBAMService\logs" /q /s
rd "%ProgramData%\Microsoft OneDrive" /q /s
rd "%ProgramData%\Microsoft\Windows\WER" /q /s
rd "%ProgramData%\Oracle\Java" /q /s
rd "%ProgramFiles%\Apple SOFTWARE Update" /q /s
rd "%ProgramFiles%\Bonjour" /q /s
rd "%ProgramFiles%\Common Files\Microsoft Shared\Windows Live" /q /s
rd "%ProgramFiles%\Microsoft Games" /q /s
rd "%ProgramFiles%\Microsoft\EdgeUpdate" /q /s
rd "%ProgramFiles%\Windows Defender" /q /s
rd "%ProgramFiles(x86)%\Apple SOFTWARE Update" /q /s
rd "%ProgramFiles(x86)%\Bonjour" /q /s
rd "%ProgramFiles(x86)%\Common Files\Java\Java Update" /q /s
rd "%ProgramFiles(x86)%\Common Files\Wondershare\Wondershare Helper Compact" /q /s
rd "%ProgramFiles(x86)%\DFX\Universal\Apps" /q /s
rd "%ProgramFiles(x86)%\Google\CrashReports" /q /s
rd "%ProgramFiles(x86)%\Google\Temp" /q /s
rd "%ProgramFiles(x86)%\Google\Update" /q /s
rd "%ProgramFiles(x86)%\Lavasoft" /q /s
rd "%ProgramFiles(x86)%\Microsoft\EdgeUpdate" /q /s
rd "%ProgramFiles(x86)%\Mozilla Maintenance Service" /q /s
rd "%ProgramFiles(x86)%\Windows Defender" /q /s
rd "%SYSTEMDrive%\AMD" /q /s
rd "%SYSTEMDrive%\drivers" /q /s
rd "%SYSTEMDrive%\Users\defaultuser0" /q /s
rd "%UserProfile%\AppData\Local\AdvinstAnalytics" /q /s
rd "%UserProfile%\AppData\Local\Application Data\Microsoft\Windows\WebCache" /q /s
rd "%UserProfile%\AppData\Local\CrashDumps" /q /s
rd "%UserProfile%\AppData\Local\Google\Chrome\User Data\SwReporter" /q /s
rd "%UserProfile%\AppData\Local\Google\SOFTWARE Reporter Tool" /q /s
rd "%UserProfile%\AppData\Local\Microsoft\Windows Mail" /q /s
rd "%UserProfile%\AppData\Local\Microsoft\Windows\Temporary Internet Files" /q /s
rd "%UserProfile%\AppData\Local\Microsoft\Windows\WebCache" /q /s
rd "%UserProfile%\AppData\Local\Temp" /q /s
rd "%UserProfile%\AppData\LocalLow\Sun\Java\Deployment\cache" /q /s
rd "%UserProfile%\AppData\Roaming\BitTorrent\updates" /q /s
rd "%UserProfile%\AppData\Roaming\DRPSu" /q /s
rd "%UserProfile%\AppData\Roaming\Smadav" /q /s
rd "%UserProfile%\AppData\Roaming\Tencent\TxGameAssistant\GameDownload" /q /s
rd "%UserProfile%\OneDrive" /q /s
rd C:\OneDriveTemp /Q /S
reg.exe add "HKCU\SOFTWARE\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_SZ /d 0 /f
reg.exe add "HKCU\SOFTWARE\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_SZ /d 0 /f
reg.exe add "HKCU\SOFTWARE\Piriform\CCleaner" /v "Monitoring" /t REG_SZ /d 0 /f
reg.exe add "HKCU\SOFTWARE\Piriform\CCleaner" /v "SYSTEMMonitoring" /t REG_SZ /d 0 /f
reg.exe add "HKCU\SOFTWARE\Piriform\CCleaner" /v "SYSTEMMonitoringRunningNotification" /t REG_SZ /d 0 /f
reg.exe add "HKCU\SOFTWARE\Piriform\CCleaner" /v "UpdateAuto" /t REG_SZ /d 0 /f
reg.exe add "HKCU\SOFTWARE\Piriform\CCleaner" /v "UpdateCheck" /t REG_SZ /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AcrylicDNSProxySvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Adguard Service" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dhcp" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wlansvc" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Themes" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UnsignedThemes" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MBAMService" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MozillaMaintenance" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RpcLocator" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Schedule" /v "Start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\SOFTWARE\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_SZ /d 0 /f
reg.exe add "HKLM\SOFTWARE\Piriform\CCleaner" /v "(Cfg)SOFTWAREUpdater" /t REG_SZ /d 0 /f
reg.exe add "HKLM\SOFTWARE\Piriform\CCleaner" /v "(Cfg)SOFTWAREUpdaterIpm" /t REG_SZ /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d 0 /f
reg.exe add "HKLM\SYSTEM\ControlSet001\services\WSearch" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "%%windir%%\SYSTEM32\taskkill.exe" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v "Debugger" /t REG_SZ /d "%%windir%%\SYSTEM32\taskkill.exe" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SOFTWARE_reporter_tool.exe" /v "Debugger" /t REG_SZ /d "%%windir%%\SYSTEM32\taskkill.exe" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\maintenanceservice.exe" /v "Debugger" /t REG_SZ /d "%%windir%%\SYSTEM32\taskkill.exe" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\bonjour.exe" /v "Debugger" /t REG_SZ /d "%%windir%%\SYSTEM32\taskkill.exe" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\jusched.exe" /v "Debugger" /t REG_SZ /d "%%windir%%\SYSTEM32\taskkill.exe" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\crashreporter.exe" /v "Debugger" /t REG_SZ /d "%%windir%%\SYSTEM32\taskkill.exe" /f
reg.exe delete "HKLM\SYSTEM\CurrentControlSet\services\LDrvSvc" /f
net start msiserver
w32tm /resync
exit

:RunAsTI: #1 snippet to run as TI/SYSTEM, with /high priority, /priv ownership, explorer and HKCU load
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("SYSTEM.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("SYSTEM.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
$S=[string]; $F="kernel","advapi","advapi",($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]),($U,$S,$I,$I,$D[9]),($U,$S,$I,$I,[byte[]],$I)
0..2|% {$9=$D[0]."DefinePInvokeMeth`od"(("CreateProcess","RegOpenKeyEx","RegSetValueEx")[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
$DF=0,($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
1..5|% {$k=$_;$n=1;$AveYo=1; $DF[$_]|% {$9=$D[$k]."DefineFie`ld"('f'+$n++,$_,6)}}; $T=@(); 0..5|% {$T+=$D[$_]."CreateT`ype"()}
0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -force}; function F ($1,$2) {$T[0]."GetMeth`od"($1).invoke(0,$2)};
if (!$ti) { $g=0; "TrustedInstaller","lsass"|% {if (!$g) {net1 start $_ 2>&1 >$null; $g=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M($1,$2,$3){$M."GetMeth`od"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H+=M "AllocHG`lobal" $I $_};
 M "WriteInt`Ptr" ($P,$P) ($H[0],$g.Handle); $A1.f1=131072;$A1.f2=$Z;$A1.f3=$H[0];$A2.f1=1;$A2.f2=1;$A2.f3=1;$A2.f4=1;$A2.f6=$A1
 $A3.f1=10*$Z+32;$A4.f1=$A3;$A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false); $w=0x0E080600
 $out=@($null,"powershell -win 1 -nop -c iex `$env:A",0,0,0,$w,0,$null,($A4 -as $T[4]),($A5 -as $T[5])); F "CreateProcess" $out
} else { $env:A=''; $PRIV=[uri].module.gettype("SYSTEM.Diagnostics.Process")."GetMeth`ods"(42) |? {$_.Name -eq "SetPrivilege"}
 "SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege","SeRestorePrivilege" |% {$PRIV.Invoke(0, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $LNK=$HKU; $reg=@($HKU,"S-1-5-18",8,2,($LNK -as $D[9])); F "RegOpenKeyEx" $reg; $LNK=$reg[4]
 function SYM($1,$2){$b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");@($2,"SymbolicLinkValue",0,6,[byte[]]$b,$b.Length)}
 F "RegSetValueEx" (SYM $(($key-split'\\')[1]) $LNK); $EXP="HKLM:\SOFTWARE\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}"
 $r="explorer"; if (!$cmd) {$cmd='C:\'}; $dir=test-path -lit ((($cmd -split '^("[^"]+")|^([^\s]+)') -ne'')[0].trim('"')) -type 1
 if (!$dir) {$r="start `"$id`" /high /w"}; sp $EXP RunAs '' -force; start cmd -args ("/q/x/d/r title $id && $r",$cmd) -wait -win 1
 do {sleep 3} while ((gwmi win32_process -filter 'name="explorer.exe"'|? {$_.getownersid().sid -eq "S-1-5-18"}))
 F "RegSetValueEx" (SYM ".Default" $LNK); sp $EXP RunAs "Interactive User" -force } # lean and mean snippet by Mithun, 2018-2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>  RunAsTI $env:1;  #:RunAsTI:
