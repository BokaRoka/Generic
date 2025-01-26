@echo off
setlocal enabledelayedexpansion
Color 1B
title ALL IN ONE (Mega MOD by BokaRoka)

whoami | findstr /i /C:"nt authority\System" >nul || whoami /user | findstr /i /C:S-1-5-18 >nul || ( call :RunAsTI "%~f0" %* & exit /b )

REM *** All the Tweaks in One Category ***
powercfg.exe -h off
powercfg /h off
taskkill /f /fi "IMAGENAME eq bonjour*" & taskkill /f /fi "IMAGENAME eq CCleaner*" & taskkill /f /fi "IMAGENAME eq DCIService*" & taskkill /f /fi "IMAGENAME eq dfxshared*" & taskkill /f /fi "IMAGENAME eq Edge*" & taskkill /f /fi "IMAGENAME eq EdgeUpdate*" & taskkill /f /fi "IMAGENAME eq MicrosoftEdgeUpdate*" & taskkill /f /fi "IMAGENAME eq Google*" & taskkill /f /fi "IMAGENAME eq jusched*" & taskkill /f /fi "IMAGENAME eq lavasoft*" & taskkill /f /fi "IMAGENAME eq maintenanceservice*" & taskkill /f /fi "IMAGENAME eq mdns*" & taskkill /f /fi "IMAGENAME eq mscorsvw*" & taskkill /f /fi "IMAGENAME eq PresentationFontCache*" & taskkill /f /fi "IMAGENAME eq reporter*" & taskkill /f /fi "IMAGENAME eq Software_reporter_tool*" & taskkill /f /fi "IMAGENAME eq WebCompanion*" & taskkill /f /fi "IMAGENAME eq WLIDSVC*" & taskkill /f /fi "IMAGENAME eq WSHelper*" & taskkill /f /fi "IMAGENAME eq GoogleUpdate*" & taskkill /f /fi "IMAGENAME eq GUpdate*" & taskkill /f /fi "IMAGENAME eq ktpcntr*" & taskkill /f /fi "IMAGENAME eq RemindersServer*" & taskkill /f /fi "IMAGENAME eq SearchUI*" & taskkill /f /fi "IMAGENAME eq ShellExperienceHost*" & taskkill /f /fi "IMAGENAME eq update*" & taskkill /f /fi "IMAGENAME eq wpscenter*" & taskkill /f /fi "IMAGENAME eq wpscloudsvr*" & taskkill /f /im RemindersServer.exe & taskkill /f /im SearchUI.exe & taskkill /f /im ShellExperienceHost.exe
schtasks.exe /change /TN "explorer" /disable
takeown /f "C:\Windows\System32\EOSNotify.exe"
icacls "C:\Windows\System32\EOSNotify.exe" /grant administrators:F
icacls "C:\Windows\System32\EOSNotify.exe" /inheritance:r /deny System:F /grant Administrators:F
del /f "C:\Windows\System32\EOSNotify.exe"
sc stop AdobeARMservice
sc stop diagnosticshub.standardcollector.service
sc stop DiagTrack
sc stop RemoteRegistry
sc stop WMPNetworkSvc
sc stop wuauserv
sc stop usosvc
sc stop Dnscache
sc stop cryptSvc
sc stop bits
sc stop msiserver
cls
reg.exe delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg.exe delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCU\AppEvents\Schemes\Apps" /f
reg.exe delete "HKCU\Control Panel\don't load" /v "appwiz.cpl" /f
reg.exe delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" /v "NoProgramsAndFeatures" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" /v "NoProgramsCPL" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags" /v "UpgradeEligible" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags" /v "UpgradeEligible" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DDD015D-B06C-45D5-8C4C-F59713854639}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DDD015D-B06C-45D5-8C4C-F59713854639}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4EBB-811F-33C572699FDE}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3add1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088E3905-0323-4B02-9826-5D99428E115F}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088E3905-0323-4B02-9826-5D99428E115F}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0C69A99-21C8-4671-8703-7934162FCF1D}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0C69A99-21C8-4671-8703-7934162FCF1D}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43BF-BE83-3742FED03C9C}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{D3162B92-9365-467A-956B-92703ACA08AF}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{D3162B92-9365-467A-956B-92703ACA08AF}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4EBB-811F-33C572699FDE}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3add1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24AD3AD4-A569-4530-98E1-AB02F9417AA8}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088E3905-0323-4B02-9826-5D99428E115F}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088E3905-0323-4B02-9826-5D99428E115F}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43BF-BE83-3742FED03C9C}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{D3162B92-9365-467A-956B-92703ACA08AF}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{D3162B92-9365-467A-956B-92703ACA08AF}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f >nul 2>&1
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /f >nul 2>&1
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /f
::Google Chrome and Firefox Browsers Tweaks
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "AllowFileSelectionDialogs" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "AppAutoUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "BackgroundAppUpdate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "BlockAboutSupport" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableAppUpdate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableBuiltinPDFViewer" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableDefaultBrowserAgent" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableFeedbackCommands" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableFirefoxAccounts" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableFirefoxScreenshots" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableFirefoxStudies" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableForgetButton" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableMasterPasswordCreation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisablePocket" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableProfileImport" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableProfileRefresh" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableSafeMode" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableSetDesktopBackground" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableTelemetry" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableThirdPartyModuleBlocking" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DontCheckDEFAULTBrowser" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "LegacyProfiles" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "ManualAppUpdateOnly" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "NetworkPrediction" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "NewTabPage" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "NoDEFAULTBookmarks" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "OfferToSaveLogins" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "ShowHomeButton" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "UseSystemPrintDialog" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Cookies" /v "DEFAULT" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\DisableSecurityBypass" /v "InvalidCertificate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\DisableSecurityBypass" /v "SafeBrowsing" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "Cryptomining" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "EmailTracking" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "Fingerprinting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "Locked" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "Value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Highlights" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Locked" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Pocket" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Search" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Snippets" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "SponsoredPocket" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "SponsoredTopSites" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "TopSites" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxSuggest" /v "ImproveSuggest" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxSuggest" /v "Locked" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxSuggest" /v "SponsoredSuggestions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxSuggest" /v "WebSuggestions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FlashPlugin" /v "DEFAULT" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FlashPlugin" /v "Locked" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Homepage" /v "Locked" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Homepage" /v "URL" /t REG_SZ /d "https://google.com" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\InstallAddonsPermission" /v "DEFAULT" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\PDFjs" /v "EnablePermissions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\PDFjs" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Permissions\Camera" /v "BlockNewRequests" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Permissions\Location" /v "BlockNewRequests" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Permissions\Microphone" /v "BlockNewRequests" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\PictureInPicture" /v "Enabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "app.Update.auto" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.cache.disk.enable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.fixup.dns_first_for_single_words" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.safebrowsing.malware.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.safebrowsing.phishing.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.search.Update" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.tabs.warnOnClose" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.taskbar.previews.enable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "datareporting.policy.dataSubmissionPolicyBypassNotification" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "dom.disable_window_flip" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "extensions.htmlaboutaddons.recommendations.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "geo.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "security.ssl.errorReporting.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown" /v "Cache" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown" /v "OfflineApps" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "ExtensionRecommendations" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "FeatureRecommendations" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "Locked" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "MoreFromMozilla" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "SkipOnboarding" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "UrlbarInterventions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "WhatsNew" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AbusiveExperienceInterventionEnforce" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AccessCodeCastEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AccessControlAllowMethodsInCORSPreflightSpecConformant" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AccessibilityImageLabelsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AdsSettingForIntrusiveAdsSites" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AdvancedProtectionDeepScanningEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AllowBackForwardCacheForCacheControlNoStorePageEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AllowDinosaurEasterEgg" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AllowFileSelectionDialogs" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ApplicationBoundEncryptionEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AudioProcessHighPriorityEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AutoplayAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "BatterySaverModeAvailability" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "BrowserGuestModeEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "BrowserGuestModeEnforced" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "BrowserLabsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "BrowserSignin" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeForTestingAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeVariations" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ClickToCallEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudAPAuthEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudManagementEnrollmentMandatory" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudUserPolicyMerge" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudUserPolicyOverridesCloudMachinePolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CommandLineFlagSecurityWarningsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ComponentUpdatesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CORSNonWildcardRequestHeadersSupport" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CreateThemesSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CSSCustomStateDeprecatedSyntaxEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DataUrlInSvgUseEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTBrowserSettingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTGeolocationSetting" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTInsecureContentSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTJavaScriptJitSetting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTLocalFontsSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTMediaStreamSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTNotificationsSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTPluginsSetting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSearchProviderEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSearchProviderImageURLPostParams" /t REG_SZ /d "content={google:imageThumbnail},url={google:imageURL},sbisrc={google:imageSearchSource}" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSearchProviderKeyword" /t REG_SZ /d "googl" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSearchProviderName" /t REG_SZ /d "Google" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSearchProviderSearchURL" /t REG_SZ /d "{google:baseURL}search?q={searchTerms}&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:searchClient}{google:sourceId}ie={inputEncoding}" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSearchProviderSearchURLPostParams" /t REG_SZ /d "q={searchTerms},ie=utf-8,oe=utf-8" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSearchProviderSuggestURL" /t REG_SZ /d "{google:baseURL}complete/search?output=chrome&q={searchTerms}" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSearchProviderSuggestURLPostParams" /t REG_SZ /d "q={searchTerms},ie=utf-8,oe=utf-8" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSensorsSetting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTSerialGuardSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTWebBluetoothGuardSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTWebHidGuardSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTWebUsbGuardSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTWindowManagementSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DEFAULTWindowPlacementSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DeletingUndecryptablePasswordsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DesktopSharingHubEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DeviceMetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DevToolsGenAiSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DisableSafeBrowsingProceedAnyway" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DomainReliabilityAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DownloadRestrictions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DynamicCodeSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ExtensionManifestV2Availability" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ExtensionUnpublishedAvailability" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "FeedbackSurveysEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ForceGoogleSafeSearch" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ForcePermissionPolicyUnloadDEFAULTEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ForceYouTubeRestrict" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "FullscreenAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "GenAILocalFoundationalModelSettings" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "GloballyScopeHTTPAuthCacheEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "GoogleSearchSidePanelEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HeadlessMode" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HelpMeWriteSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HideWebStoreIcon" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HighEfficiencyModeEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HistoryClustersVisible" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HistorySearchSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HomepageIsNewTabPage" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HomepageLocation" /t REG_SZ /d "google.com" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "IntensiveWakeUpThrottlingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "KeyboardFocusableScrollersEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "LensDesktopNTPSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "LensRegionSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MediaRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MediaRouterCastAllowAllIPs" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "NewTabPageLocation" /t REG_SZ /d "google.com" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "NTPCardsVisible" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "OptimizationGuideFetchingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PasswordLeakDetectionEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PasswordProtectionWarningTrigger" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrefixedVideoFullscreenApiAvailability" /t REG_SZ /d "enabled" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrintHeaderFooter" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrintingEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PromotionalTabsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PromotionsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "RestoreOnstartup" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ShowCastSessionsstartedByOtherDevices" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ShowFullUrlsInAddressBar" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ShowHomeButton" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SideSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SpellcheckEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SpellCheckServiceEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "TranslateEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist" /v "1" /t REG_SZ /d "bnomihfieiccainjcjblhegjgglakjdd" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist" /v "1" /t REG_SZ /d "ngpampappnmepgilojfohadhhmbhlaek" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "20800" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v "CloudPolicyOverridesPlatformPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v "InstallDefault" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v "Install{4CCED17F-7852-4AFC-9E9E-C89D8795BDD2}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v "Install{ADDE8406-A0F3-4AC2-8878-ADC0BD37BD86}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v "ProxyMode" /t REG_SZ /d "direct" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v "TargetChannel{8A69D345-D564-463C-AFF1-A69D9E530F96}" /t REG_SZ /d "extended" /f
reg.exe add "HKLM\Software\Policies\Google\Update" /v "UpdateDefault" /t REG_DWORD /d "3" /f
echo Disabling Edge Updates and unwanted services...
reg.exe add "HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
reg.exe add "HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI" /v "EnableCortana" /t REG_DWORD /d "0" /f
reg.exe add "HKCR\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\ServiceUI" /v "NewTabPageDisplayOption" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\BooksLibrary" /v "EnableExtendedBooksTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DisableEdgeDesktopShortcutCreation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v "EnableExtendedBooksTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableRecentApps" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "TurnOffBackstack" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AdsSettingForIntrusiveAdsSites" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowGamesMenu" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AutofillAddressEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "BackgroundTemplateListUpdatesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "BingAdsSuppression" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "BingAdsSuppression" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "BrowserSignin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "BuiltInDnsClientEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ConfigureOnlineTextToSpeech" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ConfigureShare" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "CopilotCDPPageContext" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "CopilotPageContext" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "DefaultBrowserSettingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "DiagnosticData" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "DiscoverPageContextEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "Edge3PSerpTelemetryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeCollectionsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeDiscoverEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeEnhanceImagesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeFollowEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EnableMediaRouter" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ExperimentationAndConfigurationServiceControl" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ExperimentationAndConfigurationServiceControl" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ExtensionManifestV2Availability" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "FamilySafetySettingsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ForceSync" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "InAppSupportEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "LocalProvidersEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "MediaRouterCastAllowAllIPs" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "MicrosoftEdgeInsiderPromotionEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageAllowedBackgroundTypes" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageBingChatEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageHideDefaultTopSites" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageHideDefaultTopSites" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPagePrerenderEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageQuickLinksEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NonRemovableProfileEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ProactiveAuthEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "PromotionalTabsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "RelatedMatchesCloudServiceEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ResolveNavigationErrorsUseWebService" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchbarAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchbarIsEnabledOnstartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowAcrobatSubscriptionButton" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowCastIconInToolbar" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowMicrosoftRewards" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowOfficeShortcutInFavoritesBar" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SignInCtaOnNtpEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SiteSafetyServicesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SpeechRecognitionEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "StandaloneHubsSidebarEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SyncDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "TrackingPrevention" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "WebWidgetAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "WebWidgetIsEnabledOnstartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "startupBoostEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "InstallDefault" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "UpdateDefault" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "UpdatesSuppressedDurationMin" /t REG_DWORD /d "1440" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "UpdatesSuppressedstartHour" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "UpdatesSuppressedstartMin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\CollectionsServicesAndExportsBlockList" /v "1" /t REG_SZ /d "pinterest_suggestions" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\CollectionsServicesAndExportsBlockList" /v "2" /t REG_SZ /d "collections_share" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "BackgroundModeEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "LocalProvidersEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "NewTabPagePrerenderEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "ResolveNavigationErrorsUseWebService" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "ShowMicrosoftRewards" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v "SyncDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "1" /t REG_SZ /d "favorites" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "2" /t REG_SZ /d "settings" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "3" /t REG_SZ /d "passwords" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "4" /t REG_SZ /d "addressesAndMore" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "5" /t REG_SZ /d "extensions" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "6" /t REG_SZ /d "history" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "7" /t REG_SZ /d "openTabs" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\SyncTypesListDisabled" /v "8" /t REG_SZ /d "collections" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v "AllowConfigurationUpdateForBooksLibrary" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v "EnableExtendedBooksTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "AlwaysEnableBooksLibrary" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "DisableStore" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Reliability" /v "AutoRecoveryTimeout" /t REG_DWORD /d "6" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "AutomaticManagedPagefile" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingCombining" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_SZ /d "" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_SZ /d "C:\pagefile.sys 0 0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_SZ /d "D:\pagefile.sys 0 0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagingFiles" /t REG_SZ /d "E:\pagefile.sys 0 0" /f
echo Main REGEDIT Entries
fsutil behavior set DisableCompression 1
reg.exe add "HKCR\AllFileSystemObjects" /v "DefaultDropEffect" /t REG_DWORD /d "1" /f
reg.exe add "HKCR\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo" /v "ProgrammaticAccessOnly" /t REG_SZ /d "" /f
reg.exe add "HKCR\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt\Shell\ShellCreateVideo" /v "ProgrammaticAccessOnly" /t REG_SZ /d "" /f
reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "0" /f
reg.exe add "HKCR\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /v "SortOrderIndex" /t REG_DWORD /d "66" /f
reg.exe add "HKCR\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2961178893" /f
reg.exe add "HKCR\CLSID\{323CA680-C24D-4099-B94D-446DD2D7249E}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2693792000" /f
reg.exe add "HKCR\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2685403136" /f
reg.exe add "HKCR\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2953052260" /f
reg.exe add "HKCR\lnkfile" /v "EditFlags" /t REG_DWORD /d "1" /f
reg.exe add "HKCR\lnkfile" /v "FriendlyTypeName" /t REG_SZ /d "@shell32.dll,-4153" /f
reg.exe add "HKCR\lnkfile" /v "IsShortcut" /t REG_SZ /d "" /f
reg.exe add "HKCR\lnkfile" /v "NeverShowExt" /t REG_SZ /d "" /f
reg.exe add "HKCR\lnkfile" /ve /t REG_SZ /d "Shortcut" /f
reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /ve /f
reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /f
reg.exe add "HKCU\Control Panel\Accessibility" /v "DynamicScrollbars" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "8000" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "3000" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "OEMBackground" /t REG_DWORD /d "00000001" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "ShutdownWithoutLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "SnapToDefaultButton" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "SnapWindows" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconSpacing" /t REG_SZ /d "-1120" /f
reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1120" /f
reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "IconVerticalSpacing" /t REG_SZ /d "-1125" /f
reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\International" /v "iFirstDayOfWeek" /t REG_SZ /d "6" /f
reg.exe add "HKCU\Control Panel\International" /v "iFirstWeekOfYear" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\International" /v "iLZero" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\International" /v "iMeasure" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\International" /v "iNegCurr" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\International" /v "iNegNumber" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\International" /v "Locale" /t REG_SZ /d "00000409" /f
reg.exe add "HKCU\Control Panel\International" /v "LocaleName" /t REG_SZ /d "en-US" /f
reg.exe add "HKCU\Control Panel\International" /v "NumShape" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\International" /v "s1159" /t REG_SZ /d "AM" /f
reg.exe add "HKCU\Control Panel\International" /v "s2359" /t REG_SZ /d "PM" /f
reg.exe add "HKCU\Control Panel\International" /v "sCountry" /t REG_SZ /d "United States" /f
reg.exe add "HKCU\Control Panel\International" /v "sCurrency" /t REG_SZ /d "$" /f
reg.exe add "HKCU\Control Panel\International" /v "sDate" /t REG_SZ /d "-" /f
reg.exe add "HKCU\Control Panel\International" /v "sDecimal" /t REG_SZ /d "." /f
reg.exe add "HKCU\Control Panel\International" /v "sLanguage" /t REG_SZ /d "ENU" /f
reg.exe add "HKCU\Control Panel\International" /v "sList" /t REG_SZ /d "," /f
reg.exe add "HKCU\Control Panel\International" /v "sLongDate" /t REG_SZ /d "dddd, dd MMMM, yyyy" /f
reg.exe add "HKCU\Control Panel\International" /v "sNativeDigits" /t REG_SZ /d "0123456789" /f
reg.exe add "HKCU\Control Panel\International" /v "sShortDate" /t REG_SZ /d "dd-MMM-yy" /f
reg.exe add "HKCU\Control Panel\International" /v "sShortTime" /t REG_SZ /d "hh:mm tt" /f
reg.exe add "HKCU\Control Panel\International" /v "sTime" /t REG_SZ /d ":" /f
reg.exe add "HKCU\Control Panel\International" /v "sTimeFormat" /t REG_SZ /d "hh:mm:ss tt" /f
reg.exe add "HKCU\Control Panel\International" /v "sYearMonth" /t REG_SZ /d "MMMM, yyyy" /f
reg.exe add "HKCU\Control Panel\International\Geo" /v "Nation" /t REG_SZ /d "244" /f
reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptout" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
reg.exe add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg" /v "NoOpenWith" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /v "SortOrderIndex" /t REG_DWORD /d "69" /f
reg.exe add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "ImplicitFeedback" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Clipboard" /v "CloudClipboardAutomaticUpload" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Clipboard" /v "EnableClipboardHistory" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Clipboard" /v "EnableCloudClipboard" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\CTF\LangBar" /v "ShowStatus" /t REG_DWORD /d "3" /f
reg.exe add "HKCU\Software\Microsoft\CTF\LangBar" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\CTF\LangBar" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\CTF\LangBar" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "SpecificGPUOptionApplicable" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\DirectX\GraphicsSettings" /v "SwapEffectUpgradeCache" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Driver Signing" /v "Policy" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Feeds" /v "SyncStatus" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowstartupPanel" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "EnableXBGM" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "10" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Messaging" /v "CloudServiceSyncEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "DetailedFeedback" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "OnlineServicesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Notepad" /v "iPointSize" /t REG_DWORD /d "90" /f
reg.exe add "HKCU\Software\Microsoft\Notepad" /v "lfFaceName" /t REG_SZ /d "Fixedsys" /f
reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_QWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableInkingWithTouch" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\VSCommon\16.0\IntelliCode" /v "DisableRemoteAnalysis" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\VSCommon\17.0\IntelliCode" /v "DisableRemoteAnalysis" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "LegacyDefaultPrinterMode" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "DisabledByUser" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Bluetooth" /v "QuickPair" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v "BluetoothLastDisabledNearShare" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "start_NotifyNewApps" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353699Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353701Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353702Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000326Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "6Wunderkinder.Wunderlist_b4cwydgxqx59r" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.BingFinance_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.BingNews_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.BingWeather_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.FreshPaint_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.NetworkSpeedTest_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.Office.Sway_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.RemoteDesktop_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.WindowsAlarms_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "DiscontinueEOS" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "DontRemindMe" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "LastRunTimestamp" /t REG_QWORD /d "0x0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "TimestampOverride" /t REG_QWORD /d "0x0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "IconUnderline" /t REG_DWORD /d "3" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoSaveSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoTaskGrouping" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoThemesTab" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startMenuLogOff" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startupDelayInMSec" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarGlomming" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarSmallIcons" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoPlayHandersEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapAssist" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapAssistIgnore" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "200" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideDrivesWithNoMedia" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowFrequent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "start_TrackProgs" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCache" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailLivePreviewHoverTime" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailMode" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailQuality" /t REG_DWORD /d "50" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers" /v "HandlerForRemovableDrive" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers" /v "HandlerForRemovableMedia" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "ForceClassicControlPanel" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "startupPage" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{208D2C60-3AEA-1069-A2D7-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{871C5380-42A0-1069-A2EA-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{0DDD015D-B06C-45D5-8C4C-F59713854639}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{35286A68-3C57-41A1-BBB1-0EAE73D76C95}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{374DE290-123F-4565-9164-39C4925E467B}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{A0C69A99-21C8-4671-8703-7934162FCF1D}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{D3162B92-9365-467A-956B-92703ACA08AF}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarOpenOnHover" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "ConvertibleSlateModePromptPreference" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "SignInMode" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\LocationAware" /v "HistoryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen" /v "TileMigrated" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "AutoOpenCopilotLargeScreens" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_BADGE_EnableD" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceButtonDesiredVisibility" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailCache" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnails" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailsOnNetworkFolders" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideClock" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAVolume" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLocation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoThumbnailCache" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoTroubleshoot" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "Location" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify" /v "DateModified" /t REG_QWORD /d "0x0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify" /v "DontRemindMe" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify" /v "LastShown" /t REG_QWORD /d "0x0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartGlass" /v "UserAuthPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v "ShowLogicalProcessors" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v "startUpTab" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v "UseStatusSetting" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ThemechangesMousePointers" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "WallpaperSetFromTheme" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\Shell\Copilot\BingChat" /v "IsUserEligible" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "(Cfg)HealthCheck" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "(Cfg)QuickClean" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "(Cfg)QuickCleanIpm" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoring" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoringRunningNotification" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoImplicitFeedback" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\InputMethod\Settings\CHS" /v "EnableLiveSticker" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Internet Explorer" /v "AllowServicePoweredQSA" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Internet Explorer\Feeds" /v "BackgroundSyncStatus" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Internet Explorer\FlipAhead" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Office\15.0\osm" /v "Enablelogging" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Office\15.0\osm" /v "EnableUpload" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows NT\Driver Signing" /v "BehaviorOnFailedVerify" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "ConfigureWindowsSpotlight" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoCloudApplicationNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\DriverSearching" /v "DontPromptForWindowsUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "NoBalloonFeatureAdvertisements" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\System\Power" /v "PromptPasswordOnResume" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "BypassDataThrottling" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "BypassNetworkCostThrottling" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "BypassPowerThrottling" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCodecDownload" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\15.0\Common" /v "DisableCrashReporting" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\15.0\Common" /v "DisableCustomerFeedback" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\15.0\Common" /v "DisableWatson" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\15.0\Common" /v "TelemetryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\16.0\Common" /v "DisableCrashReporting" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\16.0\Common" /v "DisableCustomerFeedback" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\16.0\Common" /v "DisableWatson" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\16.0\Common" /v "TelemetryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwareMicrosoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\15.0\Common" /v "qmenable" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\15.0\Common" /v "SendCustomerDataOptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\15.0\Common" /v "sentcostumerdata" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\15.0\Common" /v "updatereliabilitydata" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\15.0\Common\ClientTelemetry" /v "sendtelemetry" /t REG_DWORD /d "3" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\15.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\15.0\osm" /v "enablelogging" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\15.0\osm" /v "enableupload" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\16.0\Common" /v "qmenable" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\16.0\Common" /v "SendCustomerDataOptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\16.0\Common" /v "sentcostumerdata" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\16.0\Common" /v "updatereliabilitydata" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\16.0\Common\ClientTelemetry" /v "sendtelemetry" /t REG_DWORD /d "3" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\16.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\16.0\osm" /v "enablelogging" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\SoftwarePolicies\Microsoft\Office\16.0\osm" /v "enableupload" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
reg.exe add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CLASSES_ROOT\CLSID{018D5C66-4533-4307-9B53- 224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CLASSES_ROOT\ID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_CLASSES_ROOT\Wow6432Node\ID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /v "Attributes" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Avast Software\Avast" /v "LicenseFile" /t REG_SZ /d "C:\ProgramData\Avast Software\Subscriptions\license.avastlic" /f
reg.exe add "HKLM\Software\Avast Software\Avast\properties" /v "UseRegistry" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Avast Software\Avast\properties\WebShield\WebScanner" /v "BlockedURLs" /t REG_SZ /d "e8647.dsca.akamaiEdge.net;www.pns.avast.com;www.ns2.avast.com" /f
reg.exe add "HKLM\Software\Avast Software\Avast\properties\WebShield\WebScanner" /v "URLBlocking" /t REG_SZ /d "1" /f
reg.exe add "HKLM\Software\Avast Software\Products" /v "public-instup 6636" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "N" /f
reg.exe add "HKLM\Software\Microsoft\Driver Signing" /v "Policy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "AckTimeout" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "BscAckFrequency" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "SeqMaxAckDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\Default\ApplicationManagement\AllowGameDVR" /v "Value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\Default\NewsAndInterests\AllowNewsAndInterests" /v "Value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\Default\System\AllowExperimentation" /v "Value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\Default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "Value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\Default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\Default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\Default\WiFi\AllowWiFiHotSpotReporting" /v "Value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\SQMClient\IE" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\SQMClient\IE" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\SQMClient\Reliability" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\SQMClient\Reliability" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\SQMClient\Windows" /v "DisableOptinExperience" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\SQMClient\Windows" /v "SqmLoggerRunning" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WBEM\CIMOM" /v "EnableEvents" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WBEM\CIMOM" /v "Logging" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WcmSvc\Tethering" /v "Hotspot2SignUp" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\WcmSvc\Tethering" /v "RemotestartupDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\AIT" /v "AITEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /v "HaveUploadedForTarget" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "DontRetryOnError" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "IsCensusDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "TaskEnableRun" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Tracing" /v "ARPInfoCheck" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Tracing" /v "FileInfoCheck" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Tracing" /v "InstallInfoCheck" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Tracing" /v "MediaInfoCheck" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" /v "EnableMtcUvc" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Catergory" /t REG_SZ /d "High" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" /v "MinVmVersionForCpuBasedMitigations" /t "REG_SZ" /d "1.0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "DisplayVersion" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DisableCAD" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Search" /v "DisableBackoff" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Search" /v "SetupCompletedSuccessfully" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\Background" /v "OEMBackground" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData" /v "AllowLockScreen" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_SZ /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackAuthorization" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "DiscontinueEOS" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoSaveSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoThemesTab" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startMenuLogOff" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconVerticalSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCache" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailMode" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "HandlerForRemovableDrive" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "HandlerForRemovableMedia" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v "Computer" /t REG_SZ /d "%SystemRoot%\System32\imageres.dll,-12" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v "Recycle Bin Empty" /t REG_SZ /d "%SystemRoot%\System32\imageres.dll,-103" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v "Recycle Bin Full" /t REG_SZ /d "%SystemRoot%\System32\imageres.dll,-102" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\GeoLocation" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\LocationAware" /v "HistoryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailCache" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ForceActiveDesktopOn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideClock"/t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAVolume" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktop" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoActiveDesktopchanges" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLocation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoOnlinePrintsWizard" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoThumbnailCache" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoTroubleshoot" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "UseDefaultTile" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableAutomaticRestartSignOn" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisablestartupSound" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLockedUserId" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLinkedConnections" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "MSAOptional" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ShutdownWithoutLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "Location" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Reliability" /v "AutoRecoveryTimeout" /t REG_DWORD /d "6" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\SmartGlass" /v "UserAuthPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" /v "AllowOSUpgrade" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX" /v "IsConvergedUpdateStackEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WlanSvc\AnqpCache" /v "OsuRegistrationStatus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bUpdater" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\AppHVSI" /v "AuditApplicationGuard" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer" /v "AllowServicePoweredQSA" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds" /v "BackgroundSyncStatus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\FlipAhead" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" /v "DisableLogging" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting" /v "AllOrNone" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting" /v "IncludeKernelFaults" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting" /v "IncludeMicrosoftApps" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting" /v "IncludeShutdownErrs" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting" /v "IncludeWindowsApps" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PreviousVersions" /v "DisableLocalRestore" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\IntelliCode" /v "DisableRemoteAnalysis" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Setup" /v "ConcurrentDownloads" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "RealTimeSignatureDelivery" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureDisableNotification" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowFullControl" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fClientDisableUDP" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbBlockDeviceBySetupClass" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbNoAckIsochWriteToDevice" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Client" /v "fEnableUsbSelectDeviceByInterface" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePropPage" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "SbEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessBackgroundSpatialPerception" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGazeInput" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceAllowTheseApps" /t "REG_MULTI_SZ" /d "\0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceDenyTheseApps" /t "REG_MULTI_SZ" /d "\0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_UserInControlOfTheseApps" /t "REG_MULTI_SZ" /d "\0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Connect" /v "AllowProjectionToPC" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PreventIgnoreCertErrors" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0" /v "2301" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" /v "NoComponents" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowDesktopAnalyticsProcessing" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowUpdateComplianceProcessing" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowWUfBCloudProcessing" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableOneSettingsDownloads" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableTelemetryOptInChangeNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableTelemetryOptInSettingsUx" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DORestrictPeerSelectionBy" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendRequestAdditionalSoftwareToWER" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchHistory" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Gwx" /v "DisableGwx" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "AUOptions" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "LockScreen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "LockScreenOverlaysDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisablestartLayoutSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisablestartLayoutSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowBlockingAppsAtShutdown" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "BlockUserFromShowingAccountDetailsOnSignin" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableMmx" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "OEMBackground" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "RSoPLogging" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t "REG_SZ" /d "Warn" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "Warn" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "DoSvc" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Task Scheduler\Maintenance" /v "WakeUp" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fBlockNonDomain" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fMinimizeConnections" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fSoftDisconnectConnections" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\Local" /v "WCMPresent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "BypassDataThrottling" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "BypassNetworkCostThrottling" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "BypassPowerThrottling" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "PreventRemoteQueries" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "PreventUnwantedAddIns" /t "REG_SZ" /d " " /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows" /v "EnableFeeds" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "DisableAIDataAnalysis" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "AutoRestartDeadlinePeriodInDays" /t REG_DWORD /d "30" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "AutoRestartDeadlinePeriodInDaysForFeatureUpdates" /t REG_DWORD /d "30" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "PauseDeferrals" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "SetAutoRestartDeadline" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventLibrarySharing" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg.exe add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\15.0\common\officeupdate" /v "enableautomaticupdates" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\15.0\common\officeupdate" /v "hideenabledisableupdates" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\15.0\common\officeupdate" /v "hideupdatenotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\15.0\common\officeupdate" /v "preventbinginstall" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\15.0\common\officeupdate" /v "preventteamsinstall" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\16.0\common\officeupdate" /v "enableautomaticupdates" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\16.0\common\officeupdate" /v "hideenabledisableupdates" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\16.0\common\officeupdate" /v "hideupdatenotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\16.0\common\officeupdate" /v "preventbinginstall" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Softwarepolicies\Microsoft\office\16.0\common\officeupdate" /v "preventteamsinstall" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "100" /f
reg.exe add "HKLM\System\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "100" /f
reg.exe add "HKLM\System\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "6000" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "DisableCompression" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableCompression" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "SleepStateDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AutoChkTimeout" /t REG_DWORD /d "7" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "fSingleSessionPerUser" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "startRCM" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "TSUserEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v "updateRDStatus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\CoreParking\Parameters" /v "Enable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DXGKrnl" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DXGKrnl" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "20" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "20" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\nvlddmkm\Global\startup" /v "SendTelemetryData" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "255" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "255" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
reg.exe add "HKLM\System\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f
reg.exe add "HKU\.DEFAULT\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
reg.exe add "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg.exe add "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "0" /f
reg.exe add "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
reg.exe add "HKU\.DEFAULT\Software\Policies\Microsoft\Windows NT\Driver Signing" /v "BehaviorOnFailedVerify" /t REG_DWORD /d "0" /fa
:: Use PowerShell to enable DirectPlay feature
::DISM /Online /Enable-Feature /FeatureName:NetFx3 /All
::DISM /Online /Enable-Feature /FeatureName:DirectPlay /All
Powershell -Command "Enable-WindowsOptionalFeature -Online -FeatureName DirectPlay -All -NoRestart"
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f >nul 2>&1
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f >nul 2>&1
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f >nul 2>&1
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f >nul 2>&1
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f >nul 2>&1
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f >nul 2>&1
for /f %%r in ('reg query "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /f "1" /d /s^|Findstr HKEY_') do (
reg add %%r /v "DeadGWDetectDEFAULT" /t REG_DWORD /d "1" /f 
reg add %%r /v "MTU" /t REG_DWORD /d "1500" /f
reg add %%r /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f 
reg add %%r /v "PerformRouterDiscovery" /t REG_DWORD /d "1" /f
reg add %%r /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
reg add %%r /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
reg add %%r /v "TcpInitialRTT" /t REG_DWORD /d "2" /f
reg add %%r /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add %%r /v "UseZeroBroadcast" /t REG_DWORD /d "0" /f
)
wmic service where name='AdobeARMservice' call changestartmode disabled
sc stop "AJRouter" & sc config "AJRouter" start=disabled
sc stop "AXInstSV" & sc config "AXInstSV" start=disabled
sc stop "AdobeARMService" & sc config "AdobeARMService" start=disabled
sc stop "BcastDVRUserService" & sc config "BcastDVRUserService" start=disabled
sc stop "BraveUpdate" & sc config "BraveUpdate" start=disabled
sc stop "CDPUserSvc" & sc config "CDPUserSvc" start=disabled
sc stop "CaptureService" & sc config "CaptureService" start=disabled
sc stop "ConsentUxUserSvc" & sc config "ConsentUxUserSvc" start=disabled
sc stop "DcpSvc" & sc config "DcpSvc" start=disabled
sc stop "DefragSvc" & sc config "DefragSvc" start=disabled
sc stop "DevicePickerUserSvc" & sc config "DevicePickerUserSvc" start=disabled
sc stop "DiagSvc" & sc config "DiagSvc" start=disabled
sc stop "DiagTrack" & sc config "DiagTrack" start=disabled
sc stop "Diagnosticshub.StandardCollector.Service" & sc config "Diagnosticshub.StandardCollector.Service" start=disabled
sc stop "DmwappushService" & sc config "DmwappushService" start=disabled
sc stop "DmwappushSvc" & sc config "DmwappushSvc" start=disabled
sc stop "Dnscache" & sc config "Dnscache" start=disabled
sc stop "DsSvc" & sc config "DsSvc" start=disabled
sc stop "DusmSvc" & sc config "DusmSvc" start=disabled
sc stop "EdgeUpdate" & sc config "EdgeUpdate" start=disabled
sc stop "EdgeUpdateM" & sc config "EdgeUpdateM" start=disabled
sc stop "FrameServer" & sc config "FrameServer" start=disabled
sc stop "GUpdate" & sc config "GUpdate" start=disabled
sc stop "GUpdatem" & sc config "GUpdatem" start=disabled
sc stop "GoogleChromeElevationService" & sc config "GoogleChromeElevationService" start=disabled
sc stop "IpxlatCfgSvc" & sc config "IpxlatCfgSvc" start=disabled
sc stop "Lfsvc" & sc config "Lfsvc" start=disabled
sc stop "MapsBroker" & sc config "MapsBroker" start=disabled
sc stop "MessagingService" & sc config "MessagingService" start=disabled
sc stop "MicrosoftEdgeElevationService" & sc config "MicrosoftEdgeElevationService" start=disabled
sc stop "MozillaMaintenance" & sc config "MozillaMaintenance" start=disabled
sc stop "Msdt" & sc config "Msdt" start=disabled
sc stop "Netlogon" & sc config "Netlogon" start=disabled
sc stop "NvTelemetryContainer" & sc config "NvTelemetryContainer" start=disabled
sc stop "OSRSS" & sc config "OSRSS" start=disabled
sc stop "OneSyncSvc" & sc config "OneSyncSvc" start=disabled
sc stop "Origin Client Service" & sc config "Origin Client Service" start=disabled
sc stop "Origin Web Helper Service" & sc config "Origin Web Helper Service" start=disabled
sc stop "P2pimsvc" & sc config "P2pimsvc" start=disabled
sc stop "P2psvc" & sc config "P2psvc" start=disabled
sc stop "PNRPAutoReg" & sc config "PNRPAutoReg" start=disabled
sc stop "PNRPsvc" & sc config "PNRPsvc" start=disabled
sc stop "PcaSvc" & sc config "PcaSvc" start=disabled
sc stop "PerceptionSimulation" & sc config "PerceptionSimulation" start=disabled
sc stop "PhoneSvc" & sc config "PhoneSvc" start=disabled
sc stop "PimIndexMaintenanceSvc" & sc config "PimIndexMaintenanceSvc" start=disabled
sc stop "QWAVE" & sc config "QWAVE" start=disabled
sc stop "RasAuto" & sc config "RasAuto" start=disabled
sc stop "RemoteRegistry" & sc config "RemoteRegistry" start=disabled
sc stop "RetailDemo" & sc config "RetailDemo" start=disabled
sc stop "RmSvc" & sc config "RmSvc" start=disabled
sc stop "SEMgrSvc" & sc config "SEMgrSvc" start=disabled
sc stop "SENS" & sc config "SENS" start=disabled
sc stop "SSDPSRV" & sc config "SSDPSRV" start=disabled
sc stop "SSH-Agent" & sc config "SSH-Agent" start=disabled
sc stop "SecurityHealthService" & sc config "SecurityHealthService" start=disabled
sc stop "Sedsvc" & sc config "Sedsvc" start=disabled
sc stop "Sense" & sc config "Sense" start=disabled
sc stop "SensorDataService" & sc config "SensorDataService" start=disabled
sc stop "SgrmBroker" & sc config "SgrmBroker" start=disabled
sc stop "SharedRealitySvc" & sc config "SharedRealitySvc" start=disabled
sc stop "Shpamsvc" & sc config "Shpamsvc" start=disabled
sc stop "SmsRouter" & sc config "SmsRouter" start=disabled
sc stop "Svsvc" & sc config "Svsvc" start=disabled
sc stop "SysMain" & sc config "SysMain" start=disabled
sc stop "TabletInputService" & sc config "TabletInputService" start=disabled
sc stop "TermService" & sc config "TermService" start=disabled
sc stop "TrkWks" & sc config "TrkWks" start=disabled
sc stop "TroubleshootingSvc" & sc config "TroubleshootingSvc" start=disabled
sc stop "TzautoUpdate" & sc config "TzautoUpdate" start=disabled
sc stop "UevAgentService" & sc config "UevAgentService" start=disabled
sc stop "VaultSvc" & sc config "VaultSvc" start=disabled
sc stop "WMPNetworkSvc" & sc config "WMPNetworkSvc" start=disabled
sc stop "WSearch" & sc config "WSearch" start=disabled
sc stop "WalletService" & sc config "WalletService" start=disabled
sc stop "WdFilter" & sc config "WdFilter" start=disabled
sc stop "WdNisDrv" & sc config "WdNisDrv" start=disabled
sc stop "WdNisSvc" & sc config "WdNisSvc" start=disabled
sc stop "WdiServiceHost" & sc config "WdiServiceHost" start=disabled
sc stop "WdiSystemHost" & sc config "WdiSystemHost" start=disabled
sc stop "WerSvc" & sc config "WerSvc" start=disabled
sc stop "Wercplsupport" & sc config "Wercplsupport" start=disabled
sc stop "WinDefend" & sc config "WinDefend" start=disabled
sc stop "Wisvc" & sc config "Wisvc" start=disabled
sc stop "WpcMonSvc" & sc config "WpcMonSvc" start=disabled
sc stop "WpnService" & sc config "WpnService" start=disabled
sc stop "Wscsvc" & sc config "Wscsvc" start=disabled
sc stop "Xbgm" & sc config "Xbgm" start=disabled
sc stop "XblAuthManager" & sc config "XblAuthManager" start=disabled
sc stop "XblGameSave" & sc config "XblGameSave" start=disabled
sc stop "XboxGipSvc" & sc config "XboxGipSvc" start=disabled
sc stop "XboxNetApiSvc" & sc config "XboxNetApiSvc" start=disabled
echo Services
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AppModel" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Cellcore" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Circular Kernel Context Logger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\CloudExperienceHostOobe" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DataMarket" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DiagLog" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\HolographicDevice" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\iclsClient" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\iclsProxy" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\LwtNetLog" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Mellanox-Kernel" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Microsoft-Windows-AssignedAccess-Trace" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Microsoft-Windows-Setup" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\NBSMBLOGGER" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\PEAuthLog" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\RdrLog" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\ReadyBoot" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SetupPlatform" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SetupPlatformTel" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SocketHeciServer" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SpoolerLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\TCPIPLOGGER" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\TileStore" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Tpm" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\TPMProvisioningService" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\UBPM" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\WdiContextLog" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\WFP-IPsec Trace" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\WiFiDriverIHVSession" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\WiFiDriverIHVSessionRepro" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\WiFiSession" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\WinPhoneCritical" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\ALG" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AeLookupSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AppReadiness" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AppVClient" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AppXSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AudioEndpointBuilder" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AudioSrv" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BFE" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\CDPUserSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\CaptureService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\ConsentUxUserSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\CryptSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\CscService" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DHCP" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DPS" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DcpSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DevicePickerUserSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DevicesFlowUserSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DiagTrack" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DsSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DusmSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\EapHost" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\EventSystem" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\FontCache3.0.0.0" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\FontCache" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\FrameServer" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\GoogleChromeElevationService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\IKEEXT" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\InstallService" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\IpxlatCfgSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\KeyIso" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MMCSS" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MSiSCSI" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MapsBroker" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MessagingService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MozillaMaintenance" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MpsSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Netlogon" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NfsClnt" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NvTelemetryContainer" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\OSRSS" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\OneSyncSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Origin Client Service" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Origin Web Helper Service" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\PNRPsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\PcaSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\PhoneSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\PlugPlay" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\ProfSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\QWAVE" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RasAuto" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RasMan" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RmSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RpcEptMapper" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RpcLocator" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RpcSs" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SEMgrSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SENS" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SamSs" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Schedule" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Sense" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SensorDataService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SensorService" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SensrSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SharedRealitySvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\ShellHWDetection" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Spooler" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\StiSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\StorSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SysMain" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\TabletInputService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\TapiSrv" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Themes" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\TimeBrokerSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\TrkWks" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\TroubleshootingSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UevAgentService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UnsignedThemes" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UserDataSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UserManager" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UsoSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UxSms" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\VaultSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\W32Time" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WEPHOSTSVC" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WMPNetworkSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WSearch" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WaaSMedicSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdiServiceHost" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdiSystemHost" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Wecsvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WerSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Winmgmt" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Wlansvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WpcMonSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WpnService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\XblAuthManager" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\XboxGipSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\aspnet_state" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\autotimesvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\bthserv" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\cbdhsvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\clr_optimization_v4.0.30319_32" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\clr_optimization_v4.0.30319_64" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\defragsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\diagsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\dmwappushservice" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\dmwappushsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\dnscrypt-proxy" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\edgeUpdate" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\edgeUpdatem" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\gUpdate" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\gUpdatem" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\gpsvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\hidserv" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\icssvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\lfsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\lltdsvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\msiserver" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\netprofm" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\nsi" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\osppsvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\p2pimsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\p2psvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\perceptionsimulation" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\sedsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\shpamsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\sppsvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\ssh-agent" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\svsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\tzautoUpdate" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wercplsupport" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wisvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\xbgm" /v "start" /t REG_DWORD /d "4" /f
cls
schtasks.exe /change /tn "AMD\CNext\CnTelemetry" /Disable
schtasks.exe /change /tn "AdobeAAMUpdater-1.0" /Disable
schtasks.exe /change /tn "Adobe\Acrobat Update Task" /Disable
schtasks.exe /change /tn "Avast Software\AvastEmergencyUpdate" /Disable
schtasks.exe /change /tn "Avast Software\AvastTelemetry" /Disable
schtasks.exe /change /tn "CCleaner\UpdateTaskMachineCore" /Disable
schtasks.exe /change /tn "CCleaner\UpdateTaskMachineUA" /Disable
schtasks.exe /change /tn "Dell\SupportAssistTelemetry" /Disable
schtasks.exe /change /tn "Dell\SupportAssistUpdate" /Disable
schtasks.exe /change /tn "Dropbox\UpdateTaskMachineCore" /Disable
schtasks.exe /change /tn "Dropbox\UpdateTaskMachineUA" /Disable
schtasks.exe /change /tn "EpicGames\EpicUpdateCheck" /Disable
schtasks.exe /change /tn "Google\UpdateTaskMachineCore" /Disable
schtasks.exe /change /tn "Google\UpdateTaskMachineUA" /Disable
schtasks.exe /change /tn "HP\HP Support Assistant" /Disable
schtasks.exe /change /tn "HP\Telemetry" /Disable
schtasks.exe /change /tn "Intel\Driver and Support Assistant" /Disable
schtasks.exe /change /tn "KasperskyLab\KasperskyTelemetry" /Disable
schtasks.exe /change /tn "Lenovo\LenovoVantageTelemetry" /Disable
schtasks.exe /change /tn "Lenovo\LenovoVantageUpdate" /Disable
schtasks.exe /change /tn "LogiOptions\LogiTelemetry" /Disable
schtasks.exe /change /tn "Malwarebytes\MalwarebytesUpdateTask" /Disable
schtasks.exe /change /tn "MicrosoftEdgeUpdateTaskMachineCore" /Disable
schtasks.exe /change /tn "MicrosoftEdgeUpdateTaskMachineUA" /Disable
schtasks.exe /change /tn "MicrosoftEdgeUpdateTaskUser" /Disable
schtasks.exe /change /tn "Microsoft\EdgeUpdate\MicrosoftEdgeUpdateTaskMachineCore" /Disable
schtasks.exe /change /tn "Microsoft\EdgeUpdate\MicrosoftEdgeUpdateTaskMachineUA" /Disable
schtasks.exe /change /tn "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
schtasks.exe /change /tn "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Disable
schtasks.exe /change /tn "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks.exe /change /tn "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Disable
schtasks.exe /change /tn "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks.exe /change /tn "Microsoft\OneDrive\Scheduled Update" /Disable
schtasks.exe /change /tn "Microsoft\Skype\SkypeUpdate" /Disable
schtasks.exe /change /tn "Microsoft\WindowsManagement\Provisioning\Cellular" /Disable
schtasks.exe /change /tn "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical" /Disable
schtasks.exe /change /tn "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64" /Disable
schtasks.exe /change /tn "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical" /Disable
schtasks.exe /change /tn "Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319" /Disable
schtasks.exe /change /tn "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Application Experience\AitAgent" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Application Experience\MareBackup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Application Experience\startupAppTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ApplicationData\DsSvcCleanup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ApplicationData\appuriverifierdaily" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ApplicationData\appuriverifierinstall" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks.exe /change /tn "Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Clip\License Validation" /Disable
schtasks.exe /change /tn "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\TelTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks.exe /change /tn "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Device Information\Device User" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Device Information\Device" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks.exe /change /tn "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks.exe /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /Disable
schtasks.exe /change /tn "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks.exe /change /tn "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks.exe /change /tn "Microsoft\Windows\End Of Support\Notify1" /Disable
schtasks.exe /change /tn "Microsoft\Windows\End Of Support\Notify2" /Disable
schtasks.exe /change /tn "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable
schtasks.exe /change /tn "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Input\InputSettingsRestoreDataAvailable" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Input\syncpensettings" /Disable
schtasks.exe /change /tn "Microsoft\Windows\InstallService\ScanForUpdates" /Disable
schtasks.exe /change /tn "Microsoft\Windows\InstallService\ScanForUpdatesAsUser" /Disable
schtasks.exe /change /tn "Microsoft\Windows\InstallService\SmartRetry" /Disable
schtasks.exe /change /tn "Microsoft\Windows\International\Synchronize Language Settings" /Disable
schtasks.exe /change /tn "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable
schtasks.exe /change /tn "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable
schtasks.exe /change /tn "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable
schtasks.exe /change /tn "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Location\Notifications" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Location\WindowsActionDialog" /Disable
schtasks.exe /change /tn "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Media Center\ehDRMInit" /Disable
schtasks.exe /change /tn "Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /Disable
schtasks.exe /change /tn "Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks.exe /change /tn "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PushToInstall\LoginCheck" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks.exe /change /tn "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Registry\RegIdleBackup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\RemoteAssistance\ScheduledRemoteAssistance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Servicing\startComponentCleanup" /Enable
schtasks.exe /change /tn "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SetupSQMTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Setup\EOSNotify2" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Setup\EOSNotify" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SmartCard\SmartCardEnrollment" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SmartCard\SmartCardInsertion" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SmartCard\SmartCardRemoval" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SoftwareProtectionPlatform\Software Protection Platform" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\StateRepository\MaintenanceTasks" /Disable
schtasks.exe /change /tn "Microsoft\Windows\StateRepository\StateRepository Task" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Subscription\EnableLicenseAcquisition" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Subscription\LicenseAcquisition" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SysMain\RebootToComplete" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SysMain\RebootToContinue" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SysMain\SystemMaintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SystemRestore\SR" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SystemRestore\SysRestore" /Disable
schtasks.exe /change /tn "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks.exe /change /tn "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Enable
schtasks.exe /change /tn "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Enable
schtasks.exe /change /tn "Microsoft\Windows\Time Zone Updater\UpdateTimeZone" /Disable
schtasks.exe /change /tn "Microsoft\Windows\TimeZone\TimeZoneUpdat" /Disable
schtasks.exe /change /tn "Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable
schtasks.exe /change /tn "Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" /Disable
schtasks.exe /change /tn "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable
schtasks.exe /change /tn "Microsoft\Windows\UpdateOrchestrator\Scheduled start" /Disable
schtasks.exe /change /tn "Microsoft\Windows\UpdateOrchestrator\SmartWake" /Disable
schtasks.exe /change /tn "Microsoft\Windows\UpdateOrchestrator\WakeUp" /Disable
schtasks.exe /change /tn "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WOF\WOF" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Filtering Platform\BfeOnServicestartTypeChange" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsSearch\Windows SearchIndexer" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Wininet\CacheTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks.exe /change /tn "Microsoft\XblGameSave\XblGameSaveTask" /Disable
schtasks.exe /change /tn "Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable
schtasks.exe /change /tn "Mozilla Maintenance Service" /Disable
schtasks.exe /change /tn "OneDrive Standalone Update Task-S-1-5-21-1720338372-4004850754-4200123771-1002" /Disable
schtasks.exe /change /tn "OneDrive Standalone Update Task-S-1-5-21-1720338372-4004850754-4200123771-1001" /Disable
schtasks.exe /change /tn "OneDrive Update Task-S-1-5-21-1720338372-4004850754-4200123771-1002" /Disable
schtasks.exe /change /tn "OneDrive Update Task-S-1-5-21-1720338372-4004850754-4200123771-1001" /Disable
schtasks.exe /change /tn "OpenWith List Update" /Disable
schtasks.exe /change /tn "Opera scheduled AutoUpdate" /Disable
schtasks.exe /change /tn "Opera scheduled assistant AutoUpdate" /Disable
schtasks.exe /change /tn "Optimize Thumbnail Cache" /Disable
schtasks.exe /change /tn "Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks.exe /change /tn "Realtek\Realtek Audio\Realtek HD Audio Manager Task" /Disable
schtasks.exe /change /tn "Spotify" /Disable
schtasks.exe /change /tn "Steam" /Disable
schtasks.exe /change /tn "TeamViewer" /Disable
schtasks.exe /change /tn "Update Task" /Disable
schtasks.exe /change /tn "VivaldiUpdateTaskMachineCore" /Disable
schtasks.exe /change /tn "VivaldiUpdateTaskMachineUA" /Disable
schtasks.exe /change /tn "svchost" /Disable
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task"
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work"
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\start Oobe Expedite Work"
schtasks.exe /delete /tn "svchost" /f
:: Network TWEAKS
rem Enable and disable firewall
netsh advfirewall set allprofiles state on
netsh advfirewall firewall set rule group="remote desktop" new enable=no
:: Disable IPv6 globally (through registry)
netsh interface ipv6 6to4 set state disabled
netsh int teredo set state servername=0.0.0.0
echo You are clearing cache files (WAIT UNTIL PROCESSED)
del /q /f /s %windir%\SoftwareDistribution\Download\*
del /q /f /s %windir%\Prefetch\*
wsreset
del /q /f /s %windir%\Logs\*
del /q /f /s %windir%\Minidump\*
net stop dosvc
del /q /f /s %windir%\SoftwareDistribution\DeliveryOptimization\*
del /q /f /s "%LocalAppData%\D3DSCache\*"
sc config w32time start= auto
netsh int tcp set global hystart=disabled
net start "Windows Firewall"
PowerShell -ExecutionPolicy Bypass -Command "Get-Service -Name 'Adguard*' | ForEach-Object { Stop-Service $_.Name -Force; sc.exe delete $_.Name }; New-Service -Name 'Adguard Service' -Binary 'C:\Program Files\AdGuard\AdguardSvc.exe' -StartupType Automatic; sc.exe failure 'Adguard Service' reset= 86400 actions= restart/60000/restart/60000/restart/60000"
@echo off && powershell.exe -ExecutionPolicy Bypass -Command "Get-ScheduledTask | Where-Object { $_.TaskName -like '*Google*' -or $_.TaskName -like '*GoogleUpdate*' -or $_.TaskName -like '*Mozilla*' -or $_.TaskName -like '*bonjour*' -or $_.TaskName -like '*Avast*' -or $_.TaskName -like '*Edge*' -or $_.TaskName -like '*Opera*' -or $_.TaskName -like '*EdgeUpdate*' -or $_.TaskName -like '*Brave*' -or $_.TaskName -like '*xbox*' -or $_.TaskName -like '*onedrive*' -or $_.TaskName -like '*bluestacks*' -or $_.TaskName -like '*AMD*' } | Unregister-ScheduledTask -Confirm:$false"
@echo off & setlocal enabledelayedexpansion & for %%D in (D E F) do if exist "%%D:\" (for /d %%U in ("%%D:\Users\*") do if /i not "%%~nxU"=="Public" (set "LocalAppDataPath=%%D:\Users\%%~nxU\AppData\Local" & for %%V in (TempFolder VideoCaptureFolder AudioCaptureFolder BroadcastSaveFolder PlayListFolder) do (reg add "HKCU\Software\Daum\PotPlayerMini64\Settings" /v "%%V" /t REG_SZ /d "!LocalAppDataPath!\Temp" /f & if !errorlevel! neq 0 (echo Failed to set %%V) else (echo Successfully set %%V to "!LocalAppDataPath!\Temp")))) & goto :end) & echo No valid user found on the drive. & :end
@echo off & schtasks.exe /query /tn "CleanTempLogOn" >nul 2>&1 && (schtasks.exe /delete /tn "CleanTempLogOn" /f) & schtasks.exe /create /tn "CleanTempLogOn" /tr "cmd.exe /c rmdir /s /q \"%TEMP%\" && mkdir \"%TEMP%\"" /sc onlogon /rl highest /ru "System" /f & powershell -Command "Add-Type -AssemblyName System.Windows.Forms; $action1 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c rmdir /s /q \"C:\ProgramData\Adguard\Logs\" && mkdir \"C:\ProgramData\Adguard\Logs\"'; $action2 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c rmdir /s /q \"C:\ProgramData\Malwarebytes\MBAMService\logs\" && mkdir \"C:\ProgramData\Malwarebytes\MBAMService\logs\"'; $action3 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c rmdir /s /q \"C:\Windows\Logs\" && mkdir \"C:\Windows\Logs\"'; $action4 = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c rmdir /s /q \"C:\Windows\SoftwareDistribution\" && mkdir \"C:\Windows\SoftwareDistribution\"'; $task = Get-ScheduledTask -TaskName \"CleanTempLogOn\"; $task.Actions.Clear(); $task.Actions += $action1; $task.Actions += $action2; $task.Actions += $action3; $task.Actions += $action4; Set-ScheduledTask -TaskName \"CleanTempLogOn\" -Action $task.Actions -Trigger $task.Triggers -User $task.Principal.UserId"
:: Define Google Update-related substrings to search for in registry keys
::set googleUpdateKeys=GoogleUpdate GoogleUpdateTask GoogleUpdateTaskMachine GoogleUpdateTaskMachineUA GoogleUpdateTaskMachineCore GoogleUpdateUA EdgeUpdate MozillaMaintenance FirefoxUpdate OperaUpdate
::for %%k in (%googleUpdateKeys%) do (
::    for /f "tokens=*" %%a in ('schtasks.exe /query /fo LIST /v ^| findstr /i "%%k"') do (
::        set taskName=%%a
::        echo Deleting Task: !taskName!
::        schtasks.exe /delete /tn "!taskName!" /f >nul 2>&1
::        echo Deleted Task: !taskName!
::    )
::)
for %%k in (%googleUpdateKeys%) do (
    for %%r in (HKCU HKLM HKCR "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" "HKLM\Software\Microsoft\Windows\CurrentVersion\Run") do (
        for /f "tokens=*" %%a in ('reg query "%%r" /f "%%k*" /k /s 2^>nul ^| findstr /i "%%k"') do (
            set regKey=%%a
            echo Found key: !regKey!
            reg.exe delete "!regKey!" /f >nul 2>&1
            echo Deleted: !regKey!
        )
    )
)
endlocal
gpupdate /force
exit

#:RunAsTI snippet to run as TI/System, with innovative HKCU load, ownership privileges, high priority, and explorer support
set ^ #=& set "0=%~f0"& set 1=%*& Powershell -c iex(([io.file]::ReadAllText($env:0)-split'#\:RunAsTI .*')[1])& exit /b
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
 $Run=@($null, "Powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='Control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.DEFAULT' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start Powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
}; $A=,$env:1-split'"([^"]+)"|([^ ]+)',2|%{$_.Trim(' ')}; RunAsTI $A[1] $A[2]; #:RunAsTI, 2023.07.06
