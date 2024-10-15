@echo off & @SETLOCAL enableextensions
title BokaRoka's Windows DEFENDER Disable and REMOVE Tool
Color 1B

whoami|findstr /i /c:"nt authority\system" >nul || ( call :RunAsTI "%~f0" %* & exit/b )

reg add "HKCU\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Classes\Local Settings\SOFTWARE\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_BADGE_ENABLED" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "NoActionNotificationDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "SummaryNotificationDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableLUA" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Account protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "UILockdown" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v "EnableControlledFolderAccess" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg delete "HKCR\DesktopBackground\Shell\WindowsDefender" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "ShellSmartScreenLevel" /f
REM ; disabling Antivirus
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableLocalAdminMerge" /t REG_DWORD /d "1" /f
REM ; disable overwriting real time protection settings
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableOnAccessProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideRealtimeScanDirection" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIOAVProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIntrusionPreventionSYSTEM" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "RealtimeScanDirection" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableInformationProtectionControl" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSYSTEM" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRawWriteNotification" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v "ShutdownWarningDialogTimeout" /t REG_DWORD /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_DWORD /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "HandlerTimeout" /t REG_DWORD /d "2147483647" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "ServicesPipeTimeout" /t REG_DWORD /d "2359296" /f
reg add "HKLM\SYSTEM\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1" /f
reg add "HKLM\SYSTEM\ControlSet001\Control" /v "HandlerTimeout" /t REG_DWORD /d "2147483647" /f
reg add "HKLM\SYSTEM\ControlSet001\Control" /v "ServicesPipeTimeout" /t REG_DWORD /d "2359296" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PnP" /v "PollBootPartitionTimeout" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailLivePreviewHoverTime" /t REG_DWORD /d "1" /f
REM ; this disables Signature Updates in Windows Defender
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureDisableNotification" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "RealtimeSignatureDelivery" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScheduledSignatureUpdateOnBattery" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartUp" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleTime" /t REG_DWORD /d "5184" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "1" /f
REM ; Disable Windows Defender Security Center Notifications
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications" /v "value" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications" /v "value" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\HideWindowsSecurityNotificationAreaControl" /v "value" /t REG_DWORD /d "1" /f
REM ; Reset values for Virtualization Settings
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /f
reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\default\DeviceGuard" /f
reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\default\VirtualizationBasedTechnology" /f
REM ; Disable Virtualization Based Security
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "ConfigureSYSTEMGuardLaunch" /t REG_DWORD /d "2" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeature" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "CachedDrtmAuthIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequireMicrosoftSignedBootChain" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d "0" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "WasEnabledBy" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\VirtualizationBasedTechnology\HypervisorEnforcedCodeIntegrity" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\DeviceGuard\EnableVirtualizationBasedSecurity" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\DeviceGuard\ConfigureSYSTEMGuardLaunch" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\DeviceGuard\LsaCfgFlags" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\DeviceGuard\RequirePlatformSecurityFeatures" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\VirtualizationBasedTechnology\RequireUEFIMemoryAttributesTable" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "DeployConfigCIPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v "Enabled" /t REG_DWORD /d "0" /f
REM ; Disable Windows Security Center Notifications
reg delete "HKLM\SOFTWARE\Microsoft\Security Center" /f
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v "FirstRunDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v "AntiVirusOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v "FirewallOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SYSTEMToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
REM ; Enforce Disabling of Windows Defender Antivirus Policy
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanOnMappedNetworkDrives" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanRemovableDriveScanning" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSYSTEM" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning" /v "value" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowUserUIAccess" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\AvgCPULoadFactor" /v "value" /t REG_DWORD /d "50" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\CheckForSignaturesBeforeRunningScan" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudBlockLevel" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudExtendedTimeout" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\DaysToRetainCleanedMalware" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan" /v "value" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan" /v "value" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableLowCPUPriority" /v "value" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableNetworkProtection" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\PUAProtection" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanParameter" /v "value" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScheduleScanDay" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScheduleScanTime" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureUpdateInterval" /v "value" /t REG_DWORD /d "24" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" /v "DisableAutoExclusions" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v "EnableFileHashComputation" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "ThrottleDetectionEventsRate" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableSignatureRetirement" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableProtocolRecognition" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "IOAVMaxSize" /t REG_DWORD /d "1298" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "LowCpuPriority" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableRestorePoint" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableReparsePointScanning" /t REG_DWORD /d "1" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\PlutonHsp2" /f
reg delete "HKCR\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg delete "HKCR\WOW6432Node\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\PlutonHeci" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Hsp" /f
reg delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\Server\WebThreatDefSvc" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefsvc" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\WebThreatDefense" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /v "WebThreatDefense" /f
REM ; From Disabler
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" /f
reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WebThreatDefense" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WebThreatDefense\AuditMode" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WebThreatDefense\NotifyUnsafeOrReusedPassword" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WebThreatDefense\ServiceEnabled" /v "value" /t REG_DWORD /d "0" /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" /v "NotifyPasswordReuse" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" /v "NotifyMalicious" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration" /v "SuppressRebootNotification" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet" /v "LocalSettingOverrideSpyNetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "WppTracingLevel" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "WppTracingComponents" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsMitigation" /v "UserPreference" /t REG_DWORD /d "2" /f
REM ; Remove Defender's Tamper Protection
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "MpPlatformKillbitsFromEngine" /t REG_BINARY /d "0000000000000000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtectionSource" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "MpCapability" /t REG_BINARY /d "0000000000000000" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f
REM ; Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "FilterAdministratorToken" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "DelayedDesktopSwitchTimemout" /t REG_DWORD /d "0" /f
REM ; Fix mouse cursor dissapeiring
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM" /v "EnableCursorSuppression" /t REG_DWORD /d "0" /f
REM ; In-kernel Mitigations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "000000000000202200000000000000200000000000000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "002222202220222220000000002000200000000000000000" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
REM ; Disable Spectre & Meltdown Mitigations
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
REM ; Services Mitigations
REM ; Disable SmartScreen for Microsoft Edge
reg add "HKCU\SOFTWARE\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d "0" /f
REM ; Disable SmartScreen in File Explorer and Windows Shell
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "off" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Browser\AllowSmartScreen" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableSmartScreenInShell" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\EnableAppInstallControl" /v "value" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\SmartScreen\PreventOverrideForFilesInShell" /v "value" /t REG_DWORD /d "0" /f
REM ; Disable SmartScreen for Microsoft Store Apps
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /t REG_DWORD /d "0" /f
REM ; Configure App Install Control
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
REM ; SAP Protection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SYSTEM" /v "RunAsPPL" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "restrictanonymous" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "everyoneincludesanonymous" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "restrictanonymoussam" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "TurnOffAnonymousBlock" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaConfigFlags" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RunAsPPLBoot" /t REG_DWORD /d "0" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f
REM ; disables reporting of things from Maintenance Task in Windows Security App
reg delete "HKLM\SOFTWARE\Microsoft\Windows Security Health" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows Security Health" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows Security Health\State" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Platform" /v "Registered" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor\Battery" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor\Device Driver" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor\Reliability" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor\Status Codes" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor\Storage Health" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor\Storage Health Metrics" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor\Time Service" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\Health Advisor\Update Monitor" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
REM ; Remove Defender's Startup Entries
reg delete "HKCR\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}" /f
reg delete "HKCR\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Service.UserSessionServiceManager" /f
reg delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatExperienceManager.ThreatExperienceManager" /f
reg delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatResponseEngine.ThreatDecisionEngine" /f
reg delete "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Configuration.WTDUserSettings" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Windows Defender" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\Windowsdefender" /f
reg delete "HKLM\SOFTWARE\Classes\AppUserModelId\Windows.Defender" /f
reg delete "HKLM\SOFTWARE\Classes\AppUserModelId\Microsoft.Windows.Defender" /f
reg delete "HKCR\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0" /f
reg delete "HKCU\SOFTWARE\Classes\ms-cxh" /f
reg delete "HKCR\WindowsDefender" /f
reg delete "HKCU\SOFTWARE\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0" /f
reg delete "HKLM\SOFTWARE\Classes\WindowsDefender" /f
reg delete "HKLM\SYSTEM\ControlSet001\Control\Ubpm" /v "CriticalMaintenance_DefenderCleanup" /f
reg delete "HKLM\SYSTEM\ControlSet001\Control\Ubpm" /v "CriticalMaintenance_DefenderVerification" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\Ubpm" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Ubpm" /v "CriticalMaintenance_DefenderCleanup" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Ubpm" /v "CriticalMaintenance_DefenderVerification" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Ubpm" /f
reg delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WindowsDefender-1" /f
reg delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WindowsDefender-2" /f
reg delete "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WindowsDefender-3" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WindowsDefender-1" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WindowsDefender-2" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WindowsDefender-3" /f
REM ; Remove Defender and Windows Security Services
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\MsSecCore" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\wscsvc" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SgrmAgent" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "DisallowExploitProtectionOverride" /t REG_DWORD /d "1" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\MsSecFlt" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\MsSecWfp" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{900c0763-5cad-4a34-bc1f-40cd513679d5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{900c0763-5cad-4a34-bc1f-40cd513679d5}" /f
REM ; Remove "Scan with Defender" Context Menu
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /f
reg delete "HKCR\Folder\shell\WindowsDefender" /f
reg delete "HKCR\DesktopBackground\Shell\WindowsSecurity" /f
reg delete "HKCR\Folder\shell\WindowsDefender\Command" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0ACC9108-2000-46C0-8407-5FD9F89521E8}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1D77BCC8-1D07-42D0-8C89-3A98674DFB6F}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4A9233DB-A7D3-45D6-B476-8C7D8DF73EB5}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B05F34EE-83F2-413D-BC1D-7D5BD6E98300}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}" /f
reg delete "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}" /f
reg delete "HKCR\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
reg delete "HKCR\WOW6432Node\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}" /f
reg delete "HKCR\WOW6432Node\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}" /f
reg delete "HKCR\WOW6432Node\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}" /f
reg delete "HKCR\WOW6432Node\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}" /f
reg delete "HKCR\WOW6432Node\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" /f
reg delete "HKCR\WOW6432Node\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}" /f
reg delete "HKCR\WOW6432Node\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}" /f
reg delete "HKCR\WOW6432Node\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}" /f
reg delete "HKCR\WOW6432Node\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}" /f
reg delete "HKCR\WOW6432Node\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}" /f
reg delete "HKCR\WOW6432Node\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}" /f
reg delete "HKCR\WOW6432Node\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}" /f
reg delete "HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
reg delete "HKCR\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}" /f
reg delete "HKCR\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}" /f
reg delete "HKCR\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}" /f
reg delete "HKCR\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}" /f
reg delete "HKCR\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" /f
reg delete "HKCR\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}" /f
reg delete "HKCR\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}" /f
reg delete "HKCR\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}" /f
reg delete "HKCR\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}" /f
reg delete "HKCR\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}" /f
reg delete "HKCR\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}" /f
reg delete "HKCR\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}" /f
REM ; Defender Loggers
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WebThreatDefSvc_Allow_In" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WebThreatDefSvc_Allow_Out" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WebThreatDefSvc_Block_In" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\SYSTEM" /v "WebThreatDefSvc_Block_Out" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\SYSTEM" /v "{2A5FE97D-01A4-4A9C-8241-BB3755B65EE0}" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\SYSTEM" /v "72e33e44-dc4c-40c5-a688-a77b6e988c69" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\SYSTEM" /v "b23879b5-1ef3-45b7-8933-554a4303d2f3" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\SYSTEM" /f

:RunAsTI: #1 snippet to run as TI/System, with /high priority, /priv ownership, explorer and HKCU load
set ^ #=& set "0=%~f0"& set 1=%*& powershell -nop -c iex(([io.file]::ReadAllText($env:0)-split':RunAsTI\:.*')[1])& exit/b
$_CAN_PASTE_DIRECTLY_IN_POWERSHELL='^,^'; function RunAsTI ($cmd) { $id='RunAsTI'; $sid=((whoami /user)-split' ')[-1]; $code=@'
$ti=(whoami /groups)-like"*1-16-16384*"; $DM=[AppDomain]::CurrentDomain."DefineDynamicAss`embly"(1,1)."DefineDynamicMod`ule"(1)
$D=@(); 0..5|% {$D+=$DM."DefineT`ype"("M$_",1179913,[ValueType])}; $I=[int32];$P=$I.module.gettype("System.Int`Ptr"); $U=[uintptr]
$D+=$U; 4..6|% {$D+=$D[$_]."MakeB`yRefType"()};$M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal");$Z=[uintptr]::size
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
} else { $env:A=''; $PRIV=[uri].module.gettype("System.Diagnostics.Process")."GetMeth`ods"(42) |? {$_.Name -eq "SetPrivilege"}
 "SeSecurityPrivilege","SeTakeOwnershipPrivilege","SeBackupPrivilege","SeRestorePrivilege" |% {$PRIV.Invoke(0, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $LNK=$HKU; $reg=@($HKU,"S-1-5-18",8,2,($LNK -as $D[9])); F "RegOpenKeyEx" $reg; $LNK=$reg[4]
 function SYM($1,$2){$b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1");@($2,"SymbolicLinkValue",0,6,[byte[]]$b,$b.Length)}
 F "RegSetValueEx" (SYM $(($key-split'\\')[1]) $LNK); $EXP="HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}"
 $r="explorer"; if (!$cmd) {$cmd='C:\'}; $dir=test-path -lit ((($cmd -split '^("[^"]+")|^([^\s]+)') -ne'')[0].trim('"')) -type 1
 if (!$dir) {$r="start `"$id`" /high /w"}; sp $EXP RunAs '' -force; start cmd -args ("/q/x/d/r title $id && $r",$cmd) -wait -win 1
 do {sleep 7} while ((gwmi win32_process -filter 'name="explorer.exe"'|? {$_.getownersid().sid -eq "S-1-5-18"}))
 F "RegSetValueEx" (SYM ".Default" $LNK); sp $EXP RunAs "Interactive User" -force } # lean and mean snippet by Mithun, 2018-2021
'@; $key="Registry::HKEY_USERS\$sid\Volatile Environment"; $a1="`$id='$id';`$key='$key';";$a2="`$cmd='$($cmd-replace"'","''")';`n"
sp $key $id $($a1,$a2,$code) -type 7 -force; $arg="$a1 `$env:A=(gi `$key).getvalue(`$id)-join'';rp `$key `$id -force; iex `$env:A"
$_PRESS_ENTER='^,^'; start powershell -args "-win 1 -nop -c $arg" -verb runas }; <#,#>  RunAsTI $env:1;  #:RunAsTI:

