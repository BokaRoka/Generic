@echo off & @SETLOCAL enableextensions

:: [info] to integrate in .bat files, add RunAsTI snippet on bottom and this line before main code
::whoami|findstr /i /c:"nt authority\System" >nul || ( call :RunAsTI "%~f0" %* & exit/b )
whoami /user | findstr /i /c:S-1-5-18 >nul || ( call :RunAsTI "%~f0" %* & exit /b )

Color 1B
for %%i in (InstallInfoCheck,ARPInfoCheck,MediaInfoCheck,FileInfoCheck) do reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Tracing" /v %%i /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
REM *** All the Tweaks in One Category ***
powercfg.exe -h off
powercfg /h off
wmic computerSystem where name="%computername%" set AutomaticManagedPagefile=False
::wmic pagefileset where name="c:\\pagefile.sys" set InitialSize=2048,MaximumSize=2049
REM ; takeown /s %computername% /u %username% /f "%SystemDrive%\Users\Public\Desktop" /r /d y
REM ; icacls "%SystemDrive%\Users\Public\Desktop" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
REM ; takeown /s %computername% /u %username% /f "%USERPROFILE%\Desktop" /r /d y
REM ; icacls "%USERPROFILE%\Desktop" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c
taskkill /f /fI "IMAGENAME eq bonjour*"
taskkill /f /fI "IMAGENAME eq CCleaner*"
taskkill /f /fI "IMAGENAME eq dfxshared*"
taskkill /f /fI "IMAGENAME eq Google*"
taskkill /f /fI "IMAGENAME eq jusched*"
taskkill /f /fI "IMAGENAME eq maintenanceservice*"
taskkill /f /fI "IMAGENAME eq mdns*"
taskkill /f /fI "IMAGENAME eq mscorsvw*"
taskkill /f /fI "IMAGENAME eq PresentationFontCache*"
taskkill /f /fI "IMAGENAME eq WSHelper*"
taskkill /f /im RemindersServer.exe
taskkill /f /im SearchUI.exe
taskkill /f /im ShellExperienceHost.exe
schtasks.exe /change /TN "explorer" /disable
takeown /f %LocalAppData%\Microsoft Games\ /r /d y
takeown /f %LocalAppData%\Microsoft\Windows\Explorer\ /r /d y
:: Disabling and deleting useless Windows tasks.
takeown /f "C:\Windows\System32\EOSNotify.exe"
icacls "C:\Windows\System32\EOSNotify.exe" /grant administrators:F
icacls "C:\Windows\System32\EOSNotify.exe" /inheritance:r /deny System:F /grant Administrators:F
del /f "C:\Windows\System32\EOSNotify.exe"
sc stop AdobeARMservice
sc stop diagnosticshub.standardcollector.service
sc stop DiagTrack
sc stop RemoteRegistry
sc stop WMPNetworkSvc
sc delete RemoteRegistry
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
::Google Chrome and Firefox Browsers Tweaks
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "ShowHomeButton" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "AllowFileSelectionDialogs" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "AppAutoUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "BackgroundAppUpdate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "BlockAboutSupport" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableAppUpdate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableBuiltinPDFViewer" /t REG_DWORD /d "1" /f
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
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DontCheckDefaultBrowser" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "HardwareAcceleration" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "LegacyProfiles" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "ManualAppUpdateOnly" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "NetworkPrediction" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "NewTabPage" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "NoDefaultBookmarks" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "OfferToSaveLogins" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "UseSystemPrintDialog" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Cookies" /v "Default" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\DisableSecurityBypass" /v "SafeBrowsing" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\DisableSecurityBypass" /v "InvalidCertificate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "Value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "Cryptomining" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "Fingerprinting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "Locked" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\EnableTrackingProtection" /v "EmailTracking" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Search" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "TopSites" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "SponsoredTopSites" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Highlights" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Pocket" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "SponsoredPocket" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Snippets" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxHome" /v "Locked" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxSuggest" /v "ImproveSuggest" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxSuggest" /v "Locked" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxSuggest" /v "SponsoredSuggestions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FirefoxSuggest" /v "WebSuggestions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FlashPlugin" /v "Default" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\FlashPlugin" /v "Locked" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Homepage" /v "URL" /t REG_SZ /d "https://google.com" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Homepage" /v "Locked" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\InstallAddonsPermission" /v "Default" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\PDFjs" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\PDFjs" /v "EnablePermissions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Permissions\Camera" /v "BlockNewRequests" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Permissions\Location" /v "BlockNewRequests" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Permissions\Microphone" /v "BlockNewRequests" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\PictureInPicture" /v "Enabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.cache.disk.enable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.fixup.dns_first_for_single_words" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.safebrowsing.malware.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.safebrowsing.phishing.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.search.update" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "app.update.auto" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.tabs.warnOnClose" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "browser.taskbar.previews.enable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "datareporting.policy.dataSubmissionPolicyBypassNotification" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "dom.disable_window_flip" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "extensions.htmlaboutaddons.recommendations.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "geo.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Preferences" /v "security.ssl.errorReporting.enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown" /v "Cache" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown" /v "OfflineApps" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "ExtensionRecommendations" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "FeatureRecommendations" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "Locked" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "MoreFromMozilla" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "SkipOnboarding" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "UrlbarInterventions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\UserMessaging" /v "WhatsNew" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "UiAutomationProviderEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DataUrlInSvgUseEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultGeolocationSetting" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultWindowManagementSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultWebUsbGuardSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultWebHidGuardSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultWebBluetoothGuardSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSerialGuardSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSensorsSetting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultNotificationsSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultLocalFontsSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultJavaScriptJitSetting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultInsecureContentSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderImageURLPostParams" /t REG_SZ /d "content={google:imageThumbnail},url={google:imageURL},sbisrc={google:imageSearchSource}" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderKeyword" /t REG_SZ /d "googl" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderName" /t REG_SZ /d "Google" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderSuggestURL" /t REG_SZ /d "{google:baseURL}complete/search?output=chrome&q={searchTerms}" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderSearchURLPostParams" /t REG_SZ /d "q={searchTerms},ie=utf-8,oe=utf-8" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderSearchURL" /t REG_SZ /d "{google:baseURL}search?q={searchTerms}&{google:RLZ}{google:originalQueryForSuggestion}{google:assistedQueryStats}{google:searchFieldtrialParameter}{google:searchClient}{google:sourceId}ie={inputEncoding}" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultSearchProviderSuggestURLPostParams" /t REG_SZ /d "q={searchTerms},ie=utf-8,oe=utf-8" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "RendererCodeIntegrityEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "InsecureFormsWarningsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultWindowPlacementSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultMediaStreamSetting" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ExtensionManifestV2Availability" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ExtensionUnpublishedAvailability" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CreateThemesSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DevToolsGenAiSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "GenAILocalFoundationalModelSettings" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HelpMeWriteSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HistorySearchSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "TabOrganizerSettings" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "EnableMediaRouter" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MediaRouterCastAllowAllIPs" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ShowCastIconInToolbar" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AccessCodeCastEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudAPAuthEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CompressionDictionaryTransportEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AccessControlAllowMethodsInCORSPreflightSpecConformant" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "IPv6ReachabilityOverrideEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ZstdContentEncodingEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DeletingUndecryptablePasswordsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PasswordLeakDetectionEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrintHeaderFooter" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrintingEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrintingLPACSandboxEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrivacySandboxAdMeasurementEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrivacySandboxAdTopicsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrivacySandboxPromptEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrivacySandboxSiteEnabledAdsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AdvancedProtectionDeepScanningEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultPluginsSetting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DisableSSLRecordSplitting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DnsPrefetchingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "OptimizationGuideFetchingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingSurveysEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingProxiedRealTimeChecksAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingExtendedReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingProtectionLevel" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DisableSafeBrowsingProceedAnyway" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PasswordProtectionWarningTrigger" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingDeepScanningEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HomepageIsNewTabPage" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HomepageLocation" /t REG_SZ /d "google.com" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "NewTabPageLocation" /t REG_SZ /d "google.com" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ShowHomeButton" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AbusiveExperienceInterventionEnforce" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AccessibilityImageLabelsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AdsSettingForIntrusiveAdsSites" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "BuiltInDnsClientEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CSSCustomStateDeprecatedSyntaxEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CORSNonWildcardRequestHeadersSupport" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeForTestingAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeVariations" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ClickToCallEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudManagementEnrollmentMandatory" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudPolicyOverridesPlatformPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudUserPolicyMerge" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CloudUserPolicyOverridesCloudMachinePolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "CommandLineFlagSecurityWarningsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ComponentUpdatesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DNSInterceptionChecksEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DefaultBrowserSettingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DesktopSharingHubEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DomainReliabilityAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DownloadRestrictions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "DynamicCodeSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "FeedbackSurveysEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ForceGoogleSafeSearch" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ForcePermissionPolicyUnloadDefaultEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ForceYouTubeRestrict" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "FullscreenAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "GloballyScopeHTTPAuthCacheEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "GoogleSearchSidePanelEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HardwareAccelerationModeEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HeadlessMode" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HideWebStoreIcon" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HighEfficiencyModeEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HistoryClustersVisible" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "HttpsUpgradesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "IntensiveWakeUpThrottlingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "KeyboardFocusableScrollersEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "LensDesktopNTPSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "LensRegionSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MediaRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "NTPCardsVisible" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PaymentMethodQueryEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PrefixedVideoFullscreenApiAvailability" /t REG_SZ /d "enabled" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PromotionalTabsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "PromotionsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "QRCodeGeneratorEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "QuicAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "RendererAppContainerEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "RequireOnlineRevocationChecksForLocalAnchors" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "RoamingProfileSupportEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SafeBrowsingForTrustedSourcesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SandboxExternalProtocolBlocked" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SafeSitesFilterBehavior" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ScrollToTextFragmentEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SharedClipboardEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ShoppingListEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ShowFullUrlsInAddressBar" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SideSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SpellCheckServiceEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SpellcheckEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "StandardizedBrowserZoomEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "TaskManagerEndProcessEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ToolbarAvatarLabelSettings" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "TranslateEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "UrlKeyedAnonymizedDataCollectionEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "UserAgentReduction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "WPADQuickCheckEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "WebRtcEventLogCollectionAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "WebRtcIPHandling" /t REG_SZ /d "default" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "WebRtcTextLogCollectionAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "WindowOcclusionEnabled" /t REG_DWORD /d "1" /f
cls
reg.exe add "HKCR\AllFileSystemObjects" /v "DefaultDropEffect" /t REG_DWORD /d "1" /f
reg.exe add "HKCR\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo" /v "ProgrammaticAccessOnly" /t REG_SZ /d "" /f
reg.exe add "HKCR\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt\Shell\ShellCreateVideo" /v "ProgrammaticAccessOnly" /t REG_SZ /d "" /f
reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
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
reg.exe add "HKCR\Microsoft.PowerShellScript.1\Shell\runas" /v HasLUAShield /t REG_SZ /d "" /f
reg.exe add "HKCR\Microsoft.PowerShellScript.1\Shell\runas\command" /ve /t REG_EXPAND_SZ /d "\"%%SystemROOT%%\System32\WindowsPowerShell\v1.0\powershell.exe\" -executionpolicy bypass -nologo -file \"%%1\"" /f
reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Accessibility" /v "DynamicScrollbars" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "2500" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "3000" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d "0" /f
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
reg.exe add "HKCU\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\BooksLibrary" /v "EnableExtendedBooksTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Assistance\Client\1.0\Settings" /v "ImplicitFeedback" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\CTF\LangBar" /v "ShowStatus" /t REG_DWORD /d "3" /f
reg.exe add "HKCU\Software\Microsoft\CTF\LangBar" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\CTF\LangBar" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\CTF\LangBar" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Feeds" /v "SyncStatus" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "10" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f
reg.exe add "HKCU\Software\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Notepad" /v "iPointSize" /t REG_DWORD /d "90" /f
reg.exe add "HKCU\Software\Microsoft\Notepad" /v "lfFaceName" /t REG_SZ /d "Fixedsys" /f
reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\VSCommon\16.0\IntelliCode" /v "DisableRemoteAnalysis" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\VSCommon\17.0\IntelliCode" /v "DisableRemoteAnalysis" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "LegacyDefaultPrinterMode" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "DisabledByUser" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.Windows.ContentDeliveryManager_cw5n1h2txyewy" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d Deny /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f
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
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "DiscontinueEOS" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "DontRemindMe" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "LastRunTimestamp" /t REG_QWORD /d 0x0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "TimestampOverride" /t REG_QWORD /d 0x0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DisableEdgeDesktopShortcutCreation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "IconUnderline" /t REG_DWORD /d "3" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoSaveSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoTaskGrouping" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoThemesTab" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarGlomming" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarSmallIcons" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "ForceClassicControlPanel" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{208D2C60-3AEA-1069-A2D7-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{645FF040-5081-101B-9F08-00AA002F954E}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{871C5380-42A0-1069-A2EA-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "HistoricalCaptureEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "ConvertibleSlateModePromptPreference" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "SignInMode" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen" /v "TileMigrated" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "AutoOpenCopilotLargeScreens" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_BADGE_EnableD" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceButtonDesiredVisibility" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailCache" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnails" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailsOnNetworkFolders" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideClock" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCANetwork" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAVolume" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoThumbnailCache" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
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
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify" /v "DateModified" /t REG_QWORD /d 0x0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify" /v "DontRemindMe" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SipNotify" /v "LastShown" /t REG_QWORD /d 0x0 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartGlass" /v "UserAuthPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ThemechangesMousePointers" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "WallpaperSetFromTheme" /t REG_DWORD /d "0" /f
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
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Software\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Office\15.0\osm" /v "Enablelogging" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Office\15.0\osm" /v "EnableUpload" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\osm" /v "Enablelogging" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Office\16.0\osm" /v "EnableUpload" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows NT\Driver Signing" /v "BehaviorOnFailedVerify" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "ConfigureWindowsSpotlight" /t REG_DWORD /d "2" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotificationOnLockScreen" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\DriverSearching" /v "DontPromptForWindowsUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableRecentApps" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "TurnOffBackstack" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\System\Power" /v "PromptPasswordOnResume" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d "1" /f
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
reg.exe add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKLM\Software\Avast Software\Avast" /v "LicenseFile" /t REG_SZ /d "C:\ProgramData\Avast Software\Subscriptions\license.avastlic" /f
reg.exe add "HKLM\Software\Avast Software\Avast\properties" /v "UseRegistry" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Avast Software\Avast\properties\exclusions\Global" /v "ExcludeFiles" /t REG_SZ /d "\"C:\Windows\System32\drivers\etc\hosts\"" /f
reg.exe add "HKLM\Software\Avast Software\Avast\properties\WebShield\WebScanner" /v "BlockedURLs" /t REG_SZ /d "e8647.dsca.akamaiedge.net;www.pns.avast.com;www.ns2.avast.com" /f
reg.exe add "HKLM\Software\Avast Software\Avast\properties\WebShield\WebScanner" /v "URLBlocking" /t REG_SZ /d "1" /f
reg.exe add "HKLM\Software\Avast Software\Products" /v "public-instup 6636" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "N" /f
reg.exe add "HKLM\Software\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "AckTimeout" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "BscAckFrequency" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "SeqMaxAckDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "NoActionNotificationDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "SummaryNotificationDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\AIT" /v "AITEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /v "HaveUploadedForTarget" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "DontRetryOnError" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "IsCensusDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /v "TaskEnableRun" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t "REG_SZ" /d "%WINDIR%\System32\taskkill.exe" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "debugger" /t REG_SZ /d "rundll32.exe" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v "Debugger" /t "REG_SZ" /d "%WINDIR%\System32\taskkill.exe" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdgeUpdate.exe" /v "Debugger" /t "REG_SZ" /d "%WINDIR%\System32\taskkill.exe" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Software_reporter_tool.exe" /v "Debugger" /t "REG_SZ" /d "%WINDIR%\System32\taskkill.exe" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\upfc.exe" /v "Debugger" /t "REG_SZ" /d "%WINDIR%\System32\taskkill.exe" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WaaSMedicAgent.exe" /v "Debugger" /t "REG_SZ" /d "%WINDIR%\System32\taskkill.exe" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Virtualization" /v "MinVmVersionForCpuBasedMitigations" /t "REG_SZ" /d "1.0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "DisplayVersion" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "DisableCAD" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData" /v "AllowLockScreen" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t "REG_SZ" /d "Deny" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackAuthorization" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\EOSNotify" /v "DiscontinueEOS" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
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
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoOnlinePrintsWizard" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoThumbnailCache" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "UseDefaultTile" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLinkedConnections" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "IncludeRecommendedUpdates" /t REG_DWORD /d 0 /f
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
reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" /v "bUpdater" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "SuppressUnsupportedOSWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\AppHVSI" /v "AuditApplicationGuard" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AddressBarMicrosoftSearchInBingProviderEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowGamesMenu" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AutofillAddressEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "AutofillCreditCardEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "BingAdsSuppression" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "CopilotCDPPageContext" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "CopilotPageContext" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "DiagnosticData" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "DiscoverPageContextEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeCollectionsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeDiscoverEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeEnhanceImagesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeFollowEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ExperimentationAndConfigurationServiceControl" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "FamilySafetySettingsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "InAppSupportEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "MicrosoftEdgeInsiderPromotionEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageAllowedBackgroundTypes" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageBingChatEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageHideDefaultTopSites" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "NewTabPageQuickLinksEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "PromotionalTabsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "RelatedMatchesCloudServiceEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ResolveNavigationErrorsUseWebService" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchbarAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchbarIsEnabledOnStartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SearchSuggestEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowAcrobatSubscriptionButton" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowMicrosoftRewards" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SignInCtaOnNtpEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SiteSafetyServicesEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "StandaloneHubsSidebarEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "WebWidgetAllowed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "WebWidgetIsEnabledOnStartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "AutoUpdateCheckPeriodMinutes" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "InstallDefault" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{65C35B14-6C1D-4122-AC46-7148CC9D6497}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Install{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "UpdateDefault" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "UpdatesSuppressedDurationMin" /t REG_DWORD /d "1440" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "UpdatesSuppressedStartHour" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "UpdatesSuppressedStartMin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{0D50BFEC-CD6A-4F9A-964C-C7416E3ACB10}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{2CD8A007-E189-409D-A2C8-9AF4EF3C72AA}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{65C35B14-6C1D-4122-AC46-7148CC9D6497}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v "Update{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" /v "DisableLogging" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\BooksLibrary" /v "EnableExtendedBooksTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Peernet" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\PreviousVersions" /v "DisableLocalRestore" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\IntelliCode" /v "DisableRemoteAnalysis" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Account protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device performance and health" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device security" /v "DisableClearTpmButton" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device security" /v "DisableTpmFirmwareUpdateWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device security" /v "HideSecureBoot" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device security" /v "HideTPMTroubleshooting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device security" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Family options" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications " /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "HideRansomwareRecovery" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableSpecialRunningModes" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v "DisableAutoExclusions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "EnableFileHashComputation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "50" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS" /v "DisableProtocolRecognition" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableSignatureRetirement" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "ThrottleDetectionEventsRate" /t REG_DWORD /d "10000000" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Quarantine" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableInformationProtectionControl" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRawWriteNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "IOAVMaxSize" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "RealTimeScanDirection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Remediation" /v "Scan_ScheduleDay" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "WppTracingLevel" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxDepth" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxSize" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "AvgCPULoadFactor" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCpuThrottleOnIdleScans" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisablePackedExeScanning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableRemovableDriveScanning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableReparsePointScanning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableRestorePoint" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "MissedScheduledScanCountBeforeCatchup" /t REG_DWORD /d "20" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "QuickScanInterval" /t REG_DWORD /d "24" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScanOnlyIfIdle" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScanParameters" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScheduleDay" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ASSignatureDue" /t REG_DWORD /d "4294967295" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "AVSignatureDue" /t REG_DWORD /d "4294967295" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateDownloadLocation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateHttpLocation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScheduledSignatureUpdateOnBattery" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "RealtimeSignatureDelivery" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureDisableNotification" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateInterval" /t REG_DWORD /d "24" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigurgeAppInstallControl" /t "REG_SZ" /d "Anywhere" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "LocalSettingOverridespynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "spynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "3" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "SuppressRebootNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v "EnableControlledFolderAccess" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePropPage" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceAllowTheseApps" /t "REG_MULTI_SZ" /d "\0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceDenyTheseApps" /t "REG_MULTI_SZ" /d "\0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_UserInControlOfTheseApps" /t "REG_MULTI_SZ" /d "\0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
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
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchHistory" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Gwx" /v "DisableGwx" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "AUOptions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowBlockingAppsAtShutdown" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t "REG_SZ" /d "Warn" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "DoSvc" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Task Scheduler\Maintenance" /v "WakeUp" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
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
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "PauseDeferrals" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\WindowsStore" /v "DisableOSUpgrade" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisabledefaultBrowserAgent" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableDefaultBrowserAgent" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox" /v "DisableTelemetry" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg.exe add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "6000" /f
reg.exe add "HKLM\System\ControlSet001\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Control\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f
reg.exe add "HKLM\System\ControlSet001\Control\SESSION MANAGER\MEMORY MANAGEMENT" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control\SESSION MANAGER\MEMORY MANAGEMENT\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Control\SESSION MANAGER\MEMORY MANAGEMENT\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet002\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "6000" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "6000" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "2147483651" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7" /v "Attributes" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "AutoChkTimeout" /t REG_DWORD /d "7" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingCombining" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "20" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "20" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "255" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
reg.exe add "HKLM\System\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d "1" /f
reg.exe add "HKU\.DEFAULT\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f
reg.exe add "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg.exe add "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f
reg.exe add "HKU\.DEFAULT\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "0" /f
reg.exe add "HKU\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_SZ /d "2" /f
reg.exe delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg.exe delete "HKCR\DesktopBackground\Shell\WindowsDefender" /f
reg.exe delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\exefile\shell\Windows Firewall Control" /f
reg.exe delete "HKCU\AppEvents\Schemes\Apps" /f
reg.exe delete "HKCU\Control Panel\don't load" /v "appwiz.cpl" /f
reg.exe delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" /v "NoProgramsAndFeatures" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Programs" /v "NoProgramsCPL" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg.exe delete "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /f
reg.exe delete "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags" /v "UpgradeEligible" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\ClientTelemetry" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TelemetryController" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Diagtrack-Listener" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f
reg.exe delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
sc stop "dmwappushservice" & sc config "dmwappushservice" start=disabled
sc stop "DoSvc" & sc config "DoSvc" start=disabled
sc stop "MapsBroker" & sc config "MapsBroker" start=disabled
sc config AdobeARMservice start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config Remoteregistry start= disabled
sc config WMPNetworkSvc start= disabled
sc config XblAuthManager start= disabled
sc config XblGameSave start= disabled
sc config XboxGipSvc start= disabled
sc config XboxNetApiSvc start= disabled
wmic service where name='AdobeARMservice' call changestartmode disabled
powershell.exe "Enable-WindowsOptionalFeature -Online -FeatureName "DirectPlay" -NoRestart"
PowerShell -Command "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage"
reg.exe add "HKLM\Software\Policies\Mozilla\Firefox\Homepage" /v "startPage" /t REG_SZ /d "homepage" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "ShowCastSessionsstartedByOtherDevices" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Google\Chrome" /v "RestoreOnstartup" /t REG_DWORD /d "4" /f
reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowstartupPanel" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "startupPage" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startMenuLogOff" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startupDelayInMSec" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "start_NotifyNewApps" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisablestartupSound" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "AllowFastServicestartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "AutoRestartDeadlinePeriodInDays" /t REG_DWORD /d "30" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "AutoRestartDeadlinePeriodInDaysForFeatureUpdates" /t REG_DWORD /d "30" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "SetAutoRestartDeadline" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\ControlSet001\Services\ALG" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\AppIDSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\AppReadiness" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\autotimesvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\CryptSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\ControlSet001\Services\CscService" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\defragsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\diagnosticshub.standardcollector.service" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\diagsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\DiagTrack" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\dmwappushsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\DPS" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\DsSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\DusmSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\edgeupdate" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\edgeupdatem" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\FontCache3.0.0.0" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\FrameServer" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\icssvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\IpxlatCfgSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\LanmanWorkstation" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\lltdsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\MapsBroker" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\MicrosoftEdgeElevationService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\MpsSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\ControlSet001\Services\MSiSCSI" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\Netlogon" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\NfsClnt" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\OneSyncSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\p2pimsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\p2psvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\perceptionsimulation" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\PhoneSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\PNRPsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\QWAVE" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\RetailDemo" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\RmSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\RpcLocator" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\SEMgrSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\SensorDataService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\SensorService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\SensrSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\SharedAccess" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\SharedRealitySvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\shpamsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\ssh-agent" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\StiSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\svsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\SysMain" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\TapiSrv" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\TrkWks" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\TroubleshootingSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\tzautoupdate" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\VaultSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\WdiServiceHost" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\WdiSystemHost" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\Wecsvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\ControlSet001\Services\WEPHOSTSVC" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\wisvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\WMPNetworkSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\WpcMonSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\wuauserv" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AppModel" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Cellcore" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\Circular Kernel Context Logger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\CloudExperienceHostOobe" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DataMarket" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DefenderApiLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DefenderAuditLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "start" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\System\CurrentControlSet\Services\AeLookupSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AppVClient" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\aspnet_state" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AudioEndpointBuilder" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\AudioSrv" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Audiosrv" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BFE" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BITS" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\bthserv" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\CaptureService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\cbdhsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\CDPUserSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\clr_optimization_v4.0.30319_32" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\clr_optimization_v4.0.30319_64" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\ConsentUxUserSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\CryptSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DeviceAssociationBrokerSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DevicePickerUserSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DevicesFlowUserSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Dhcp" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DiagTrack" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\dmwappushservice" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\dnscrypt-proxy" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\EapHost" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\EpicOnlineServices" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\EventSystem" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\FontCache" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\GoogleChromeElevationService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\gpsvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\gupdate" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\gupdatem" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\hidserv" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\IKEEXT" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\InstallService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\KeyIso" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\lfsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MessagingService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MMCSS" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MozillaMaintenance" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MpsSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\msiserver" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\netprofm" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\NlaSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\nsi" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Origin Client Service" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Origin Web Helper Service" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\OSRSS" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\PlugPlay" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\ProfSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RasAuto" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RasMan" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RpcEptMapper" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\RpcSs" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SamSs" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Schedule" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\sedsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SENS" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Sense" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SensorService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SensrSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SgrmBroker" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\ShellHWDetection" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Spooler" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\sppsvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Steam Client Service" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\StorSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SysMain" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\TabletInputService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Themes" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\TimeBrokerSvc" /v "start" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\tzautoupdate" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UevAgentService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UnistoreSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UnsignedThemes" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UserDataSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UserManager" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UxSms" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\W32Time" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Wecsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WerSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Winmgmt" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\Wlansvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WpnService" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WSearch" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wuauserv" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\xbgm" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\XblAuthManager" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\XboxGipSvc" /v "start" /t REG_DWORD /d "4" /f
cls
schtasks.exe /change /tn "Adobe Acrobat Update Task" /Disable
schtasks.exe /change /tn "AutoPico Daily Restart" /Disable
schtasks.exe /change /tn "Avast Emergency Update" /Disable
schtasks.exe /change /tn "CCleaner Update" /Disable
schtasks.exe /change /tn "DropboxUpdateTaskMachineCore" /Disable
schtasks.exe /change /tn "DropboxUpdateTaskMachineUA" /Disable
schtasks.exe /change /tn "GoogleUpdateTaskMachineCore" /Disable
schtasks.exe /change /tn "GoogleUpdateTaskMachineUA" /Disable
schtasks.exe /change /tn "KMSpico Automatic Update Scheduler" /Disable
schtasks.exe /change /tn "Microsoft/Windows/WindowsUpdate/Automatic App Update" /Disable
schtasks.exe /change /tn "Microsoft/Windows/WindowsUpdate/Scheduled start" /Disable
schtasks.exe /change /tn "Microsoft/Windows/WindowsUpdate/sih" /Disable
schtasks.exe /change /tn "Microsoft/Windows/WindowsUpdate/sihboot" /Disable
schtasks.exe /change /tn "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
schtasks.exe /change /tn "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks.exe /change /tn "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /Disable
schtasks.exe /change /tn "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks.exe /change /tn "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /Disable
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
schtasks.exe /change /tn "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Application Experience\startupAppTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ApplicationData\appuriverifierdaily" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ApplicationData\appuriverifierinstall" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ApplicationData\DsSvcCleanup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Clip\License Validation" /Disable
schtasks.exe /change /tn "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\TelTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
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
schtasks.exe /change /tn "Microsoft\Windows\DUSM\dusmtask" /Disable
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
schtasks.exe /change /tn "Microsoft\Windows\Input\syncpensettings" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable
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
schtasks.exe /change /tn "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Management\Provisioning\Cellular" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Management\Provisioning\Logon" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Media Center\ehDRMInit" /Disable
schtasks.exe /change /tn "Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /Disable
schtasks.exe /change /tn "Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable
schtasks.exe /change /tn "Microsoft\Windows\MUI\LPRemove" /Disable
schtasks.exe /change /tn "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PI\Sqm-Tasks" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Printing\EduPrintProv" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PushToInstall\LoginCheck" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PushToInstall\registration" /Disable
schtasks.exe /change /tn "Microsoft\Windows\PushToInstall\Registration" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Ras\MobilityManager" /Disable
schtasks.exe /change /tn "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Registry\RegIdleBackup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Setup\EOSNotify" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Setup\EOSNotify2" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SetupSQMTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyRefreshTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /Disable 
schtasks.exe /change /tn "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\StateRepository\MaintenanceTasks" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Subscription\EnableLicenseAcquisition" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Subscription\LicenseAcquisition" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\SystemRestore\SR" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Enable
schtasks.exe /change /tn "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Enable
schtasks.exe /change /tn "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable
schtasks.exe /change /tn "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" /Disable
schtasks.exe /change /tn "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable
schtasks.exe /change /tn "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WaaSMedic\PerformRemediation" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WDI\ResolutionHost" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\sihpostreboot" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Wininet\CacheTask" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable
schtasks.exe /change /tn "Microsoft\WindowsManagement\Provisioning\Cellular" /Disable
schtasks.exe /change /tn "Microsoft\XblGameSave\XblGameSaveTask" /Disable
schtasks.exe /change /tn "Microsoft\XblGameSave\XblGameSaveTaskLogon" /Disable
schtasks.exe /change /tn "Microsoftd\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks.exe /change /tn "Optimize Thumbnail Cache" /Disable
schtasks.exe /change /tn "svchost" /Disable
schtasks.exe /delete /f /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Customer Experience Improvement Program\TelTask" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\End Of Support\Notify1" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\End Of Support\Notify2" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\IME\SQM data sender" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Setup\EOSNotify" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Setup\EOSNotify2" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\SetupSQMTask" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\Shell\FamilySafetyRefresh" /f
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task"
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Wake To Work"
schtasks.exe /delete /f /tn "\Microsoft\Windows\UpdateOrchestrator\Start Oobe Expedite Work"
schtasks.exe /delete /tn "svchost" /f
:: Network TWEAKS
netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
netsh int 6to4 set state state=enabled
netsh int tcp set global dca=enabled
netsh int tcp set global ecncapability=enabled
netsh int tcp set global fastopen=enabled
netsh int tcp set global fastopenfallback=enabled
netsh int tcp set global initialRto=2000
netsh int tcp set global MaxSynRetransmissions=2 
netsh int tcp set global netdma=enabled
netsh int tcp set global pacingprofile=off
netsh int tcp set global rsc=disabled 
netsh int tcp set global rss=enabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global timestamps=disabled 
netsh int tcp set heuristics disabled 
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled
netsh int tcp set supp internet congestionprovider=ctcp
netsh int udp set global uro=enabled
for /f %%r in ('reg query "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /f "1" /d /s^|Findstr HKEY_') do (
reg add %%r /v "DeadGWDetectDefault" /t reg_DWORD /d "1" /f 
reg add %%r /v "MTU" /t reg_DWORD /d "1500" /f
reg add %%r /v "NonBestEffortLimit" /t reg_DWORD /d "0" /f 
reg add %%r /v "PerformRouterDiscovery" /t reg_DWORD /d "1" /f
reg add %%r /v "TcpAckFrequency" /t reg_DWORD /d "1" /f
reg add %%r /v "TcpDelAckTicks" /t reg_DWORD /d "0" /f
reg add %%r /v "TcpInitialRTT" /t reg_DWORD /d "2" /f
reg add %%r /v "TCPNoDelay" /t reg_DWORD /d "1" /f
reg add %%r /v "UseZeroBroadcast" /t reg_DWORD /d "0" /f
)
for /f %%a in ('reg query HKLM /v "*WakeOnMagicPacket" /s ^| findstr  "HKEY"') do (
for /f %%i in ('reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (reg add "%%i" /v "*EEE" /t reg_DWORD /d "0" /f)
for /f %%i in ('reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (reg add "%%i" /v "*FlowControl" /t reg_DWORD /d "0" /f)
for /f %%i in ('reg query "%%a" /v "*InterruptModeration" ^| findstr "HKEY"') do (reg add "%%i" /v "*InterruptModeration" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "*IPChecksumOffloadIPv4" ^| findstr "HKEY"') do (reg add "%%i" /v "*IPChecksumOffloadIPv4" /t reg_SZ /d "3" /f)
for /f %%i in ('reg query "%%a" /v "*JumboPacket" ^| findstr "HKEY"') do (reg add "%%i" /v "*JumboPacket" /t reg_SZ /d "9014" /f)
for /f %%i in ('reg query "%%a" /v "*LsoV2IPv4" ^| findstr "HKEY"') do (reg add "%%i" /v "*LsoV2IPv4" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "*LsoV2IPv6" ^| findstr "HKEY"') do (reg add "%%i" /v "*LsoV2IPv6" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "*ModernStandbyWoLMagicPacket" ^| findstr "HKEY"') do (reg add "%%i" /v "*ModernStandbyWoLMagicPacket" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "*NumRssQueues" ^| findstr "HKEY"') do (reg add "%%i" /v "*NumRssQueues" /t reg_SZ /d "4" /f)
for /f %%i in ('reg query "%%a" /v "*PMARPOffload" ^| findstr "HKEY"') do (reg add "%%i" /v "*PMARPOffload" /t reg_SZ /d "1" /f)
for /f %%i in ('reg query "%%a" /v "*PMNSOffload" ^| findstr "HKEY"') do (reg add "%%i" /v "*PMNSOffload" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "*ReceiveBuffers" ^| findstr "HKEY"') do (reg add "%%i" /v "*ReceiveBuffers" /t reg_SZ /d "512" /f)
for /f %%i in ('reg query "%%a" /v "*RSS" ^| findstr "HKEY"') do (reg add "%%i" /v "*RSS" /t reg_SZ /d "1" /f)
for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv4" ^| findstr "HKEY"') do (reg add "%%i" /v "*TCPChecksumOffloadIPv4" /t reg_SZ /d "1" /f)
for /f %%i in ('reg query "%%a" /v "*TCPChecksumOffloadIPv6" ^| findstr "HKEY"') do (reg add "%%i" /v "*TCPChecksumOffloadIPv6" /t reg_SZ /d "1" /f)
for /f %%i in ('reg query "%%a" /v "*TransmitBuffers" ^| findstr "HKEY"') do (reg add "%%i" /v "*TransmitBuffers" /t reg_SZ /d "128" /f)
for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv4" ^| findstr "HKEY"') do (reg add "%%i" /v "*UDPChecksumOffloadIPv4" /t reg_SZ /d "1" /f)
for /f %%i in ('reg query "%%a" /v "*UDPChecksumOffloadIPv6" ^| findstr "HKEY"') do (reg add "%%i" /v "*UDPChecksumOffloadIPv6" /t reg_SZ /d "1" /f)
for /f %%i in ('reg query "%%a" /v "*WakeOnMagicPacket" ^| findstr "HKEY"') do (reg add "%%i" /v "*WakeOnMagicPacket" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "*WakeOnPattern" ^| findstr "HKEY"') do (reg add "%%i" /v "*WakeOnPattern" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "AdvancedEEE" ^| findstr "HKEY"') do (reg add "%%i" /v "AdvancedEEE" /t reg_DWORD /d "0" /f)
for /f %%i in ('reg query "%%a" /v "AutoDisableGigabit" ^| findstr "HKEY"') do (reg add "%%i" /v "AutoDisableGigabit" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (reg add "%%i" /v "AutoPowerSaveModeEnabled" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "EnableConnectedPowerGating" ^| findstr "HKEY"') do (reg add "%%i" /v "EnableConnectedPowerGating" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "EnableDynamicPowerGating" ^| findstr "HKEY"') do (reg add "%%i" /v "EnableDynamicPowerGating" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "EnableGreenEthernet" ^| findstr "HKEY"') do (reg add "%%i" /v "EnableGreenEthernet" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "EnablePME" ^| findstr "HKEY"') do (reg add "%%i" /v "EnablePME" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "EnablePowerManagement" ^| findstr "HKEY"') do (reg add "%%i" /v "EnablePowerManagement" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "EnableSavePowerNow" ^| findstr "HKEY"') do (reg add "%%i" /v "EnableSavePowerNow" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "GigaLite" ^| findstr "HKEY"') do (reg add "%%i" /v "GigaLite" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "PowerSavingMode" ^| findstr "HKEY"') do (reg add "%%i" /v "PowerSavingMode" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "ReduceSpeedOnPowerDown" ^| findstr "HKEY"') do (reg add "%%i" /v "ReduceSpeedOnPowerDown" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "S5WakeOnLan" ^| findstr "HKEY"') do (reg add "%%i" /v "S5WakeOnLan" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "ULPMode" ^| findstr "HKEY"') do (reg add "%%i" /v "ULPMode" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "WakeOnLinkChange" ^| findstr "HKEY"') do (reg add "%%i" /v "WakeOnLinkChange" /t reg_SZ /d "0" /f)
for /f %%i in ('reg query "%%a" /v "WolShutdownLinkSpeed" ^| findstr "HKEY"') do (reg add "%%i" /v "WolShutdownLinkSpeed" /t reg_SZ /d "2" /f)
)
netsh winsock reset
netsh winsock reset all
netsh int ip reset
netsh int ip reset all
rem Enable and disable firewall
netsh advfirewall set currentprofile state on
ipconfig /release
ipconfig /renew
ipconfig /flushdns
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

:RunAsTI snippet to run as TI/System, with innovative HKCU load, ownership privileges, high priority, and explorer support
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
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
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
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
}; $A=,$env:1-split'"([^"]+)"|([^ ]+)',2|%{$_.Trim(' ')}; RunAsTI $A[1] $A[2]; #:RunAsTI lean & mean snippet by AveYo, 2023.07.06
