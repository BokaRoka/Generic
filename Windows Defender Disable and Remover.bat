@echo off
Color 0C
title BokaRoka's Windows DEFENDER Disable and REMOVE Tool

sc stop WinDefend
sc config WinDefend start= disabled
sc stop SecurityHealthService
sc config SecurityHealthService start= disabled
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Security Health\State" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailLivePreviewHoverTime" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_BADGE_ENABLED" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Browser\AllowSmartScreen" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowCloudProtection" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowEmailScanning" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowFullScanOnMappedNetworkDrives" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowFullScanRemovableDriveScanning" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowScriptScanning" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowUserUIAccess" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AvgCPULoadFactor" /v "value" /t REG_DWORD /d "50" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\CheckForSignaturesBeforeRunningScan" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\CloudBlockLevel" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\CloudExtendedTimeout" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\DaysToRetainCleanedMalware" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\EnableLowCPUPriority" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\EnableNetworkProtection" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\PUAProtection" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\ScanParameter" /v "value" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\ScheduleScanDay" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\ScheduleScanTime" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\SignatureUpdateInterval" /v "value" /t REG_DWORD /d "24" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\DeviceGuard\ConfigureSystemGuardLaunch" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\DeviceGuard\EnableVirtualizationBasedSecurity" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\DeviceGuard\LsaCfgFlags" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\DeviceGuard\RequirePlatformSecurityFeatures" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\SmartScreen\EnableAppInstallControl" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\SmartScreen\EnableSmartScreenInShell" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\SmartScreen\PreventOverrideForFilesInShell" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\VirtualizationBasedTechnology\HypervisorEnforcedCodeIntegrity" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\VirtualizationBasedTechnology\RequireUEFIMemoryAttributesTable" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WebThreatDefense\AuditMode" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WebThreatDefense\NotifyUnsafeOrReusedPassword" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WebThreatDefense\ServiceEnabled" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\HideWindowsSecurityNotificationAreaControl" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "HeartbeatTrackingIndex" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "spynetReportingLocation" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Security Center" /v "AntiVirusOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Security Center" /v "FirewallOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Security Center" /v "FirstRunDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "NoActionNotificationDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "SummaryNotificationDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "MpCapability" /t REG_BINARY /d "0000000000000000" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "MpPlatformKillbitsFromEngine" /t REG_BINARY /d "0000000000000000" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtectionSource" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /v "DisableAsyncScanOnOpen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v "EnableASRConsumers" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v "ShutdownWarningDialogTimeout" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor\Battery" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor\Device Driver" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor\Reliability" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor\Status Codes" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor\Storage Health Metrics" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor\Storage Health" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor\Time Service" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Health Advisor\Update Monitor" /v "UIReportingDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Security Health\Platform" /v "Registered" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WindowsMitigation" /v "UserPreference" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "off" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:WindowsDefender;" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimemout" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableCursorSuppression" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\spynet" /v "LocalSettingOverridespynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\spynet" /v "spynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Account protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "DisallowExploitProtectionOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "DisableClearTpmButton" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "DisableTpmFirmwareUpdateWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "HideSecureBoot" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "HideTPMTroubleshooting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device performance and health" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Family options" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications " /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "HideRansomwareRecovery" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableLocalAdminMerge" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableSpecialRunningModes" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v "DisableAutoExclusions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "EnableFileHashComputation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "50" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS" /v "DisableProtocolRecognition" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableProtocolRecognition" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableSignatureRetirement" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "ThrottleDetectionEventsRate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Policy Manager" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Quarantine" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableInformationProtectionControl" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRawWriteNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "IOAVMaxSize" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIOAVProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIntrusionPreventionSystem" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableOnAccessProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableRealtimeMonitoring" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideRealtimeScanDirection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "RealtimeScanDirection" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Remediation" /v "Scan_ScheduleDay" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "WppTracingComponents" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "WppTracingLevel" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "LowCpuPriority" /t REG_DWORD /d "1" /f
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
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleTime" /t REG_DWORD /d "5184" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureDisableNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigurgeAppInstallControl" /t "REG_SZ" /d "Anywhere" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeveritydefaultAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeveritydefaultAction" /v "1" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeveritydefaultAction" /v "2" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeveritydefaultAction" /v "3" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeveritydefaultAction" /v "4" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeveritydefaultAction" /v "5" /t "REG_SZ" /d "9" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "SuppressRebootNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v "ExploitGuard_ASR_Rules" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v "EnableControlledFolderAccess" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "LocalSettingOverridespynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\spynet" /v "spynetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "RunAsPPL" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v "NotifyMalicious" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v "NotifyPasswordReuse" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control" /v "HandlerTimeout" /t REG_DWORD /d "2147483647" /f
reg.exe add "HKLM\System\ControlSet001\Control" /v "ServicesPipeTimeout" /t REG_DWORD /d "2359296" /f
reg.exe add "HKLM\System\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "HandlerTimeout" /t REG_DWORD /d "2147483647" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "ServicesPipeTimeout" /t REG_DWORD /d "2359296" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CI\Config" /v "VulnerableDriverBlocklistEnable" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "CachedDrtmAuthIndex" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "ConfigureSystemGuardLaunch" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "DeployConfigCIPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "RequireMicrosoftSignedBootChain" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeature" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "LsaConfigFlags" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPLBoot" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "TurnOffAnonymousBlock" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "everyoneincludesanonymous" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "restrictanonymous" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "restrictanonymoussam" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\PnP" /v "PollBootPartitionTimeout" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d "000000000000202200000000000000200000000000000000" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "002222202220222220000000002000200000000000000000" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DefenderApiLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DefenderAuditLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wscsvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0" /f
reg.exe delete "HKCR\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg.exe delete "HKCR\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}" /f
reg.exe delete "HKCR\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
reg.exe delete "HKCR\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}" /f
reg.exe delete "HKCR\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}" /f
reg.exe delete "HKCR\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}" /f
reg.exe delete "HKCR\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" /f
reg.exe delete "HKCR\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}" /f
reg.exe delete "HKCR\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}" /f
reg.exe delete "HKCR\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}" /f
reg.exe delete "HKCR\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}" /f
reg.exe delete "HKCR\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg.exe delete "HKCR\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}" /f
reg.exe delete "HKCR\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}" /f
reg.exe delete "HKCR\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}" /f
reg.exe delete "HKCR\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}" /f
reg.exe delete "HKCR\DesktopBackground\Shell\WindowsDefender" /f
reg.exe delete "HKCR\DesktopBackground\Shell\WindowsSecurity" /f
reg.exe delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f
reg.exe delete "HKCR\Folder\shell\WindowsDefender" /f
reg.exe delete "HKCR\Folder\shell\WindowsDefender\Command" /f
reg.exe delete "HKCR\WindowsDefender" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}" /f
reg.exe delete "HKCR\WOW6432Node\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}" /f
reg.exe delete "HKCU\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0" /f
reg.exe delete "HKCU\Software\Classes\ms-cxh" /f
reg.exe delete "HKCU\Software\Microsoft\Windows Security Health" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /f
reg.exe delete "HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\Windowsdefender" /f
reg.exe delete "HKLM\Software\Classes\AppUserModelId\Microsoft.Windows.Defender" /f
reg.exe delete "HKLM\Software\Classes\AppUserModelId\Windows.Defender" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}" /f
reg.exe delete "HKLM\Software\Classes\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}" /f
reg.exe delete "HKLM\Software\Classes\WindowsDefender" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}" /f
reg.exe delete "HKLM\Software\Classes\WOW6432Node\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}" /f
reg.exe delete "HKLM\Software\Microsoft\PolicyManager\default\DeviceGuard" /f
reg.exe delete "HKLM\Software\Microsoft\PolicyManager\default\VirtualizationBasedTechnology" /f
reg.exe delete "HKLM\Software\Microsoft\PolicyManager\default\WebThreatDefense" /f
reg.exe delete "HKLM\Software\Microsoft\Security Center" /f
reg.exe delete "HKLM\Software\Microsoft\Windows Defender" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0ACC9108-2000-46C0-8407-5FD9F89521E8}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1D77BCC8-1D07-42D0-8C89-3A98674DFB6F}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4A9233DB-A7D3-45D6-B476-8C7D8DF73EB5}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B05F34EE-83F2-413D-BC1D-7D5BD6E98300}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Svchost" /v "WebThreatDefense" /f
reg.exe delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Svchost\WebThreatDefense" /f
reg.exe delete "HKLM\Software\Microsoft\Windows Security Health" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{900c0763-5cad-4a34-bc1f-40cd513679d5}" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Windows Defender" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /f
reg.exe delete "HKLM\Software\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Configuration.WTDUserSettings" /f
reg.exe delete "HKLM\Software\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Service.UserSessionServiceManager" /f
reg.exe delete "HKLM\Software\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatExperienceManager.ThreatExperienceManager" /f
reg.exe delete "HKLM\Software\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatResponseEngine.ThreatDecisionEngine" /f
reg.exe delete "HKLM\Software\Microsoft\WindowsRuntime\Server\WebThreatDefSvc" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /f
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows\WTDS" /f
reg.exe delete "HKLM\Software\WOW6432Node\Classes\CLSID\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg.exe delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{BB64F8A7-BEE7-4E1A-AB8D-7D8273F7FDB6}" /f
reg.exe delete "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{900c0763-5cad-4a34-bc1f-40cd513679d5}" /f
reg.exe delete "HKLM\System\ControlSet001\Control\Ubpm" /v "CriticalMaintenance_DefenderCleanup" /f
reg.exe delete "HKLM\System\ControlSet001\Control\Ubpm" /v "CriticalMaintenance_DefenderVerification" /f
reg.exe delete "HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WindowsDefender-1" /f
reg.exe delete "HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WindowsDefender-2" /f
reg.exe delete "HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WindowsDefender-3" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\DeviceGuard" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "WasEnabledBy" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\Ubpm" /v "CriticalMaintenance_DefenderCleanup" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\Ubpm" /v "CriticalMaintenance_DefenderVerification" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /f
reg.exe delete "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /v "72e33e44-dc4c-40c5-a688-a77b6e988c69" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /v "b23879b5-1ef3-45b7-8933-554a4303d2f3" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /v "{2A5FE97D-01A4-4A9C-8241-BB3755B65EE0}" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WebThreatDefSvc_Allow_In" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WebThreatDefSvc_Allow_Out" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WebThreatDefSvc_Block_In" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WebThreatDefSvc_Block_Out" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WindowsDefender-1" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WindowsDefender-2" /f
reg.exe delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /v "WindowsDefender-3" /f
schtasks.exe /change /tn "Bitdefender\BitdefenderTelemetry" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Signature Update" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
exit
