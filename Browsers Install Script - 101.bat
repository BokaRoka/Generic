@echo off
setlocal
set "TEMP_DIR=%LocalAppData%\Temp"
set "CHROME_MSI=%TEMP_DIR%\chrome64_offline.msi"
:: Try curl first (fastest)
where curl >nul 2>&1 && (
    curl -L -o "%CHROME_MSI%" "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi" >nul 2>&1
) || (
    :: Fallback to PowerShell if curl is not available
    powershell -NoLogo -NoProfile -Command "(New-Object Net.WebClient).DownloadFile('https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi','%CHROME_MSI%')" >nul 2>&1
)
start "" /b msiexec /i "%CHROME_MSI%" /quiet /norestart
echo Do you want to install Firefox too? Press any key to Continue!
pause
setlocal
set "TEMP_DIR=%LocalAppData%\Temp"
set "FIREFOX_SETUP=%TEMP_DIR%\FirefoxSetup64.exe"
set "FIREFOX_URL=https://download.mozilla.org/?product=firefox-stable-ssl&os=win64&lang=en-US"
where curl >nul 2>&1 && (
    curl -L -o "%FIREFOX_SETUP%" "%FIREFOX_URL%" >nul 2>&1
) || (
    powershell -NoLogo -NoProfile -Command ^
        "(New-Object Net.WebClient).DownloadFile('%FIREFOX_URL%', '%FIREFOX_SETUP%')" >nul 2>&1
)
if exist "%FIREFOX_SETUP%" (
    start "" /b "%FIREFOX_SETUP%" /silent
)
pause
