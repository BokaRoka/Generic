@echo off
Color 0C
title BokaRoka's Windows DEFENDER Disable and REMOVE Tool
rem # Recommended to run in SAFE MODE
rem # Requires SetACL.bat to be run first
rem # Gives ownership to reg keys
cd /d "%~dp0"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TrustedInstaller" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TrustedInstaller" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdiSystemHost" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdiSystemHost" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdiServiceHost" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdiServiceHost" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TrkWks" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\TrkWks" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DPS" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DPS" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SecurityHealthService" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SecurityHealthService" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wscsvc" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\wscsvc" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SamSs" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\SamSs" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdBoot" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdBoot" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdFilter" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdFilter" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdNisDrv" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdNisDrv" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdNisSvc" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WdNisSvc" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinDefend" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\WinDefend" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MDCoreSvc" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MDCoreSvc" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpKsl863bd5cf" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\MpKsl863bd5cf" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DcomLaunch" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\DcomLaunch" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\ControlSet001\Control\WMI\Autologger\EventLog-Security" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\ControlSet001\Control\WMI\Autologger\EventLog-Security" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\ControlSet001\Control\WMI\Autologger\Cellcore" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\ControlSet001\Control\WMI\Autologger\Cellcore" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\Cellcore" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\Cellcore" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\ControlSet001\Control\WMI\Autologger\NetCore" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\ControlSet001\Control\WMI\Autologger\NetCore" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\NetCore" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\NetCore" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\ControlSet001\Control\WMI\Autologger\RadioMgr" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\ControlSet001\Control\WMI\Autologger\RadioMgr" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\RadioMgr" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\RadioMgr" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter\ActivationType" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter\ActivationType" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Security Health\Platform\Registered" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Security Health\Platform\Registered" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\DisableDiagnosticTracing" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\DisableDiagnosticTracing" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\BootCKCLSettings" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\BootCKCLSettings" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\ShutdownCKCLSettings" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\ShutdownCKCLSettings" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\BootCKCLSettings\Start" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\BootCKCLSettings\Start" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\ShutdownCKCLSettings\Start" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Diagnostics\Performance\ShutdownCKCLSettings\Start" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy\AllowHeadlessExecution" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy\AllowHeadlessExecution" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy\AllowMultipleBackgroundTasks" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy\AllowMultipleBackgroundTasks" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CURRENT_USER\WOW6432Node\AppID\{cd93979b-c14e-4c29-87a4-75e4f9fa5e0a}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CURRENT_USER\WOW6432Node\AppID\{cd93979b-c14e-4c29-87a4-75e4f9fa5e0a}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CURRENT_USER\AppID\{cd93979b-c14e-4c29-87a4-75e4f9fa5e0a}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CURRENT_USER\AppID\{cd93979b-c14e-4c29-87a4-75e4f9fa5e0a}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CURRENT_USER\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CURRENT_USER\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CURRENT_USER\WOW6432Node\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CURRENT_USER\WOW6432Node\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CURRENT_USER\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder\Attributes" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CURRENT_USER\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder\Attributes" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds\ShellFeedsTaskbarViewMode" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds\ShellFeedsTaskbarViewMode" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Communications\" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Communications\" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Communications\ConfigureChatAutoInstall" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Communications\ConfigureChatAutoInstall" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\DriverDatabase\Policies\Settings" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\DriverDatabase\Policies\Settings" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\DriverDatabase\Policies\Settings\DisableSendGenericDriverNotFoundToWER" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\DriverDatabase\Policies\Settings\DisableSendGenericDriverNotFoundToWER" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{679f85cb-0220-4080-b29b-5540cc05aab6}\ShellFolder" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f8278c54-a712-415b-b593-b77a2be0dda9}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f8278c54-a712-415b-b593-b77a2be0dda9}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{EDC978D6-4D53-4b2f-A265-5805674BE568}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{EDC978D6-4D53-4b2f-A265-5805674BE568}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{8FD8B88D-30E1-4F25-AC2B-553D3D65F0EA}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{8FD8B88D-30E1-4F25-AC2B-553D3D65F0EA}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{5b934b42-522b-4c34-bbfe-37a3ef7b9c90}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{5b934b42-522b-4c34-bbfe-37a3ef7b9c90}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2F6CE85C-F9EE-43CA-90C7-8A9BD53A2467}" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{088e3905-0323-4b02-9826-5d99428e115f}\DefaultIcon" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_CLASSES_ROOT\CLSID\{088e3905-0323-4b02-9826-5d99428e115f}\DefaultIcon" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Themes\Wallpaper" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Themes\Wallpaper" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\WINDOWS\Fonts" -ot file -actn setowner -ownr "n:Administrators" -rec cont_obj
SetACL.exe -on "C:\WINDOWS\Fonts" -ot file -actn ace -ace "n:Administrators;p:full" -rec cont_obj
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Features" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Features" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Security Health\Platform" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Security Health\Platform" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Security Health" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Security Health" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Real-Time Protection" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Real-Time Protection" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render" -ot reg -rec yes -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render" -ot reg -rec yes -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Assistance\Client\1.0\Settings" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Assistance\Client\1.0\Settings" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Assistance\Client\1.0\Settings\GlobalOnlineAssist" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Assistance\Client\1.0\Settings\GlobalOnlineAssist" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameBar" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameBar" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameBar\ActivationType" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameBar\ActivationType" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameChatOverlay" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameChatOverlay" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameChatOverlay\ActivationType" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameChatOverlay\ActivationType" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameChatOverlayMessageSource" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameChatOverlayMessageSource" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameChatOverlayMessageSource\ActivationType" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.UI.GameChatOverlayMessageSource\ActivationType" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsRuntime\ActivatableClassId" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\DelayedApps" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\DelayedApps" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\DelayedApps\Delay_Sec" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\DelayedApps\Delay_Sec" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\WMI\Autologger" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\ResourceTimers" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\ResourceTimers" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\ResourceTimers\EnableResourceAwareTimers" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\ResourceTimers\EnableResourceAwareTimers" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.delete" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.delete" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.delete\SkipCloudDownload" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell\Windows.delete\SkipCloudDownload" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Classes\AppID\SppComApi.dll" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Classes\AppID\SppComApi.dll" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Search\Gather\Windows\SystemIndex" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Search\Gather\Windows\SystemIndex" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Classes\AppID\slui.exe" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Classes\AppID\slui.exe" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Search\Gathering Manager" -ot reg -actn setowner -ownr "n:Administrators"
SetACL.exe -on "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Search\Gathering Manager" -ot reg -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\System32\dwm.exe" -ot file -actn setowner -ownr n:"n:Administrators"
SetACL.exe -on "C:\Windows\System32\dwm.exe" -ot file -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\System32\Windows.UI.logon.dll" -ot file -actn setowner -ownr n:"n:Administrators"
SetACL.exe -on "C:\Windows\System32\Windows.UI.logon.dll" -ot file -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\System32\dwminit.dll" -ot file -actn setowner -ownr n:"n:Administrators"
SetACL.exe -on "C:\Windows\System32\dwminit.dll" -ot file -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\System32\dwmapi.dll" -ot file -actn setowner -ownr n:"n:Administrators"
SetACL.exe -on "C:\Windows\System32\dwmapi.dll" -ot file -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\System32\dwmcore.dll" -ot file -actn setowner -ownr n:"n:Administrators"
SetACL.exe -on "C:\Windows\System32\dwmcore.dll" -ot file -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\System32\dwmghost.dll" -ot file -actn setowner -ownr n:"n:Administrators"
SetACL.exe -on "C:\Windows\System32\dwmghost.dll" -ot file -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\System32\dwmredir.dll" -ot file -actn setowner -ownr n:"n:Administrators"
SetACL.exe -on "C:\Windows\System32\dwmredir.dll" -ot file -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\System32\dwmscene.dll" -ot file -actn setowner -ownr n:"n:Administrators"
SetACL.exe -on "C:\Windows\System32\dwmscene.dll" -ot file -actn ace -ace "n:Administrators;p:full"
SetACL.exe -on "C:\Windows\Resources" -ot file -actn setowner -ownr n:"n:Administrators" -rec cont_obj
SetACL.exe -on "C:\Windows\Resources" -ot file -actn ace -ace "n:Administrators;p:full" -rec cont_obj
cls
taskkill /f /im "AppXDeploymentClient.exe" 2>nul
taskkill /f /im "DeviceCensus.exe" 2>nul
taskkill /f /im "FileSystemGuard.exe" 2>nul
taskkill /f /im "MsMpEng.exe" 2>nul
taskkill /f /im "SecurityHealthSystray.exe" 2>nul
taskkill /f /im "Sense.exe" 2>nul
taskkill /f /im "ServiceHost.exe" 2>nul
taskkill /f /im "WdNisSvc.exe" 2>nul
taskkill /f /im "WinDefend.exe" 2>nul
taskkill /f /im "WindowsDefender.exe" 2>nul
taskkill /f /im "dasHost.exe" 2>nul
taskkill /f /im "smartscreen.exe" 2>nul
sc stop SecurityHealthService 2>nul && sc config SecurityHealthService start= disabled
sc stop WinDefend 2>nul && sc config WinDefend start= disabled
sc stop WdNisSvc 2>nul && sc config WdNisSvc start= disabled
sc stop WdBoot 2>nul && sc config WdBoot start= disabled
sc stop MsMpEng 2>nul && sc config MsMpEng start= disabled
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"
cls
reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "3100" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "3000" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "OEMBackground" /t REG_DWORD /d "00000001" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "ShutdownWithoutLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "SnapToDefaultButton" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "SnapWindows" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1100" /f
reg.exe add "HKCU\Control Panel\Desktop" /v OEMBackground /T REG_DWORD /d 00000001 /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\Microsoft.Microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Edge\SmartScreenPuaEnabled" /ve /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender Security Center\Account protection" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender" /v "DisableAutoExclusions" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender" /v "DisableCloudProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender" /v "DisableRealTimeMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender" /v "DisableScheduledScan" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender" /v "DisableSmartScreen" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Defender\UX Configuration" /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows Security Health\State" /v "Disabled" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DisableEdgeDesktopShortcutCreation" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HidePeopleBar" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "IconUnderline" /t REG_DWORD /d "3" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoSaveSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoTaskGrouping" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoThemesTab" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startMenuLogOff" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startupDelayInMSec" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarGlomming" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "TaskbarSmallIcons" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoPlayHandersEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapAssist" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableSnapAssistIgnore" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "600" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideDrivesWithNoMedia" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconVerticalSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowFrequent" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowNetworkIcon" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCache" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailLivePreviewHoverTime" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailMode" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailQuality" /t REG_DWORD /d "50" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers" /v "HandlerForRemovableDrive" /t REG_SZ /d "MSAutoPlay" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers" /v "HandlerForRemovableMedia" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "ForceClassicControlPanel" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicstartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicstartMenu" /v "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /t REG_DWORD /d "1" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{208D2C60-3AEA-1069-A2D7-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{450D8FBA-AD25-11D0-98A8-0800361B1103}" /t REG_DWORD /d "0" /f
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
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_BADGE_ENABLED" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows Defender" /t REG_SZ /d "" /f
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
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem" /v "value" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection" /v "value" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableAccountProtectionUI" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\HideWindowsSecurityNotificationAreaControl" /v "value" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "HeartbeatTrackingIndex" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\RemovalTools\MpGears" /v "SpyNetReportingLocation" /t REG_SZ /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Security Center" /v "AntiVirusOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Security Center" /v "FirewallDisableNotify" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Security Center" /v "FirewallOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Security Center" /v "FirstRunDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Security Center" /v "UpdatesDisableNotify" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "NoActionNotificationDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "SummaryNotificationDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "AllowAnonymousUsageData" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "AllowUserToManage" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "AllowUserToUninstall" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableAntiMalware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableAntiPhishing" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableAutoExclusions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableAutomaticSampleSubmission" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableCloudProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableMalwareProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableNetworkProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableRealTimeProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableScans" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableScheduledScans" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableSecurityCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableSmartScreen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableSystemNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "DisableTamperProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "NoDefenderUI" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "ServiceDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\AM" /v "DisableAntiMalware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\AM" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Exclusions" /v "ExcludeExtensions" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Exclusions" /v "ExcludeFileTypes" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Exclusions" /v "ExcludePaths" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Exclusions" /v "ExcludeProcesses" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "MpCapability" /t REG_BINARY /d "0000000000000000" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "MpPlatformKillbitsFromEngine" /t REG_BINARY /d "0000000000000000" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Features" /v "TamperProtectionSource" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /v "DisableAsyncScanOnOpen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /v "DpaDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Scanning" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Scans" /v "DisableFileSystemMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Scans" /v "DisableOnAccessScanning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Scans" /v "DisableScheduledScan" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v "EnableASRConsumers" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows Defender\Windows Defender" /v "DisableWindowsDefender" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Svchost\WebThreatDefense" /v "Start" /t REG_DWORD /d "4" /f
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
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoSaveSettings" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "NoThemesTab" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowDriveLettersFirst" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "startMenuLogOff" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconVerticalSpacing" /t REG_DWORD /d "75" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCache" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailMode" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "HandlerForRemovableDrive" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "HandlerForRemovableMedia" /t REG_SZ /d "MSOpenFolder" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewstartPanel" /v "{031E4825-7B94-4dc3-B131-E946B44C8DD5}" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons" /v "{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "Windows Defender" /t REG_BINARY /d "" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "SettingsPageVisibility" /t REG_SZ /d "hide:WindowsDefender;" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableCursorSuppression" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableInstallerDetection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableSecureUIAPaths" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableUIADesktopToggle" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PowerButtonAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ShutdownWithoutLogon" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ValidateAdminCodeSignatures" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsDefender" /t REG_EXPAND_SZ /d "" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "AUOptions" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade" /v "AllowOSUpgrade" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WindowsMitigation" /v "UserPreference" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenDnsRequestsEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet" /v "LocalSettingOverrideSpyNetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Microsoft Antimalware\SpyNet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Account protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "DisallowExploitProtectionOverride" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device performance and health" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "DisableClearTpmButton" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "DisableTpmFirmwareUpdateWarning" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "HideSecureBoot" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "HideTPMTroubleshooting" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Device Security" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Family options" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Firewall and network protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "HideRansomwareRecovery" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Virus and threat protection" /v "UILockdown" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "AllowUserOverride" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "AllowUserToManage" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiPhishing" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAutoExclusions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableDefender" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableIntrusionPreventionSystem" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableLocalAdminMerge" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableLogging" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableNetworkProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRealtime" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableSelfProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableSpecialRunningModes" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableTamperProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableThreatService" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableWindowsDefender" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisallowShields" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DpaDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "NoDefenderUI" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "PUAProtection" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "RandomizeScheduleTaskTimes" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\AM" /v "DisableAntiMalware" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\AV" /v "DisableAntivirus" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v "DisableAutoExclusions" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v "ExcludeFiles" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v "ExcludeFileTypes" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v "ExcludePaths" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Exclusions" /v "ExcludeProcesses" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "EnableFileHashComputation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS" /v "DisableProtocolRecognition" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableProtocolRecognition" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableSignatureRetirement" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "ThrottleDetectionEventsRate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Policy Manager" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Quarantine" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "AllowRealtimeMonitoring" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DpaDisabled" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "IOAVMaxSize" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableBehaviorMonitoring" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIntrusionPreventionSystem" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "LocalSettingOverrideDisableIOAVProtection" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scanning" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scanning" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scans" /v "DisableAutoScan" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scans" /v "DisableScheduledScan" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ASSignatureDue" /t REG_DWORD /d "4294967295" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "AVSignatureDue" /t REG_DWORD /d "4294967295" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateDownloadLocation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "CheckAlternateHttpLocation" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScanOnUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableScheduledSignatureUpdateOnBattery" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "DisableUpdateOnStartupWithoutEngine" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ForceUpdateFromMU" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "RealtimeSignatureDelivery" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleDay" /t REG_DWORD /d "8" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "ScheduleTime" /t REG_DWORD /d "5184" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureDisableNotification" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureUpdateCatchupInterval" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "UpdateOnStartup" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigurgeAppInstallControl" /t "REG_SZ" /d "Anywhere" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SmartScreen" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "LocalSettingOverrideSpyNetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "0" /f
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
reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\Reliability" /v "ShutdownReasonOn" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "RunAsPPL" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "ShellSmartScreenLevel" /t REG_SZ /d "" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v "NotifyMalicious" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v "NotifyPasswordReuse" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\WOW6432Node\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\ControlSet001\Control" /v "HandlerTimeout" /t REG_DWORD /d "2147483647" /f
reg.exe add "HKLM\System\ControlSet001\Control" /v "ServicesPipeTimeout" /t REG_DWORD /d "2359296" /f
reg.exe add "HKLM\System\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "4" /f
reg.exe add "HKLM\System\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "HandlerTimeout" /t REG_DWORD /d "2147483647" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "ServicesPipeTimeout" /t REG_DWORD /d "2359296" /f
reg.exe add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1" /f
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
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "everyoneincludesanonymous" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "LsaConfigFlags" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "restrictanonymous" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "restrictanonymoussam" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPL" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "RunAsPPLBoot" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "SCENoApplyLegacyAuditPolicy" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\Lsa" /v "TurnOffAnonymousBlock" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\PnP" /v "PollBootPartitionTimeout" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DefenderApiLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\DefenderAuditLogger" /v "start" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MpKsl863bd5cf" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\MsSecCore" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
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
reg.exe delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
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
schtasks.exe /change /tn "Microsoft\Windows\Defender\Defrag" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Defender\MP Scheduled Scan" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Defender\WD Threat Signature Update" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Defender\Windows Defender Antivirus Update" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Defender\Windows Defender Cache Maintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Defender\Windows Defender Cleanup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Defender\Windows Defender Monitoring" /Disable
schtasks.exe /change /tn "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Signature Update" /Disable
schtasks.exe /change /tn "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
rem Remove Smartscreen (to restore run "sfc /scannow")
takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe"
icacls "%WinDir%\System32\smartscreen.exe" /grant:r %username%:F
taskkill /im smartscreen.exe /f
ren "%WinDir%\System32\smartscreen.exe" "smartscreen.exe.bak"
# Disable Anti-malware Service Executable (to restore run "sfc /scannow")
takeown /s %computername% /u %username% /f "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe"
icacls "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe" /grant:r %username%:F
taskkill /im MsMpEng.exe /f
del "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe" /s /f /q
ren "C:\ProgramData\Microsoft\Windows Defender\Platform\*\MsMpEng.exe" "MsMpEng.exe.bak"
rem # Disable Anti-malware and Network Realtime Inspection Services
takeown /s %computername% /u %username% /f "C:\ProgramData\Microsoft\Windows Defender\Platform"
icacls "C:\ProgramData\Microsoft\Windows Defender\Platform" /grant:r %username%:F
taskkill /im MsMpEng.exe /f
taskkill /im NisSrv.exe /f
rem # del "C:\ProgramData\Microsoft\Windows Defender\Platform" /s /f /q
ren "C:\ProgramData\Microsoft\Windows Defender\Platform" "Platform.bak"
rem # Disable Microsoft Aggregator Host (to restore run "sfc /scannow")
takeown /s %computername% /u %username% /f "C:\Windows\System32\AggregatorHost.exe"
icacls "C:\Windows\System32\AggregatorHost.exe" /grant:r %username%:F
taskkill /im AggregatorHost.exe /f
ren "C:\Windows\System32\AggregatorHost.exe" "AggregatorHost.exe.bak"
rem # Disable Cross Device Resume (to restore run "sfc /scannow")
takeown /s %computername% /u %username% /f "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume.exe"
icacls "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume.exe" /grant:r %username%:F
taskkill /im CrossDeviceResume.exe /f
ren "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume.exe" "CrossDeviceResume.exe.bak"
cls
@echo off && powershell.exe -ExecutionPolicy Bypass -Command "Get-ScheduledTask | Where-Object { $_.TaskName -like '*Defender*' } | Disable-ScheduledTask"
setlocal
set "tempFile=%temp%\rarreg.tmp"
(
    echo RAR registration data
    echo User
    echo Local Site License
    echo UID=71386fe49139860c9b39
    echo 64122122509b39d7a07c92e95d0cc3def23770cb5f9a5f9a6bd1f6
    echo 0e434177e80bbcda242860694c88f20734f7fa6ad968865654a57b
    echo 0f0edf295d607ce6fa6d6b3667401b413bdcbccca3152c8ab6abc5
    echo 931818a35674a26f065261f8bce32dfbce60653bd6229e3cb62cef
    echo 9a6b32bf153ae4ded0c32f815bf5fabc83b8e6f80da0b7b4524674
    echo 44e01c14f62da85708f329fa419956dcb1e1afe3e65a589060b1e4
    echo 184e1f1eb471c0f6c10c89542ad16ce02e0c577916160028126504
) > "%tempFile%"
set "filePath32=%ProgramFiles(x86)%\WinRAR\rarreg.key"
set "filePath64=%ProgramFiles%\WinRAR\rarreg.key"
mkdir "%ProgramFiles(x86)%\WinRAR" 2>nul & copy /y "%tempFile%" "%filePath32%"
mkdir "%ProgramFiles%\WinRAR" 2>nul & copy /y "%tempFile%" "%filePath64%"
del "%tempFile%"
endlocal
setlocal
REM Initialize variables
set "winrarPath="
set "foundExe=false"
REM Check for WinRAR in Program Files (x86) and Program Files
if exist "%ProgramFiles(x86)%\WinRAR\*.exe" (
    set "winrarPath=%ProgramFiles(x86)%\WinRAR"
    set "foundExe=true"
) else if exist "%ProgramFiles%\WinRAR\*.exe" (
    set "winrarPath=%ProgramFiles%\WinRAR"
    set "foundExe=true"
)
REM Check if any .exe files were found
if "%foundExe%"=="false" (
    echo No .exe files found in WinRAR directories.
)
REM Block all .exe files in the WinRAR folder
for %%f in ("%winrarPath%\*.exe") do (
    echo Blocking %%f
    netsh advfirewall firewall add rule name="Block WinRAR %%~nf" dir=out action=block program="%%f" enable=yes
)
echo All .exe files in %winrarPath% have been blocked from accessing the internet.
endlocal
reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /ve /t REG_SZ /d "" /f
reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f
DISM /Online /Enable-Feature /FeatureName:DirectPlay /All

pause
