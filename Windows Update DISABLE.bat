reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BITS" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DoSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UsoSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WaaSMedicSvc" /v "start" /t REG_DWORD /d "4" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wuauserv" /v "start" /t REG_DWORD /d "4" /f
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\AUFirmwareInstall" /Disable
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\AUScheduledInstall" /Disable
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\AUSessionConnect" /Disable
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\Scheduled start" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\sih" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\sihboot" /Disable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\sihpostreboot" /Disable

pause

reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "DontSearchWindowsUpdate" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v "IncludeRecommendedUpdates" /t REG_DWORD /d "1" /f
reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d "0" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\BITS" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\DoSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\UsoSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\WaaSMedicSvc" /v "start" /t REG_DWORD /d "2" /f
reg.exe add "HKLM\System\CurrentControlSet\Services\wuauserv" /v "start" /t REG_DWORD /d "2" /f
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\AUFirmwareInstall" /Enable
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\AUScheduledInstall" /Enable
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\AUSessionConnect" /Enable
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /Enable
schtasks.exe /change /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /Enable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Enable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\Scheduled start" /Enable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\sih" /Enable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\sihboot" /Enable
schtasks.exe /change /tn "Microsoft\Windows\WindowsUpdate\sihpostreboot" /Enable
