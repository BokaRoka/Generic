@echo off
setlocal enabledelayedexpansion
:: Get the username using PowerShell
for /f "delims=" %%u in ('powershell -command "Get-ChildItem 'C:\Users' -Directory | Select-Object -First 1 -ExpandProperty Name"') do set "username=%%u"
:: Fallback to "Default" if no username found
if not defined username (
    set "username=Default"
)
echo Using username: %username%
:: Get new drive letter
set /p newDrive="Enter the drive letter for the new location (e.g., E): "
set "chromeUserData=C:\Users\%username%\AppData\Local\Google\Chrome\User Data"
set "newLocation=%newDrive%\Users\%username%\AppData\Local\Google\Chrome"
:: Create necessary directories
if not exist "%newLocation%" (
    echo Creating directory: "%newLocation%"
    mkdir "%newLocation%"
)
:: Close Chrome if running
tasklist | find /I "chrome.exe" >nul
if !errorlevel! == 0 (
    echo Closing Chrome...
    taskkill /F /IM chrome.exe
    timeout /t 5 >nul
)
:: User choice for mklink operation
set /p choice="Do you want to (R)estore or (A)dd a new mklink? (R/A): "
if /I "%choice%"=="R" (
    if exist "%chromeUserData%" (
        move /Y "%chromeUserData%" "%newLocation%\User Data"
        echo Moved user data to "%newLocation%\User Data"
    )
    if exist "%newLocation%\User Data" (
        move /Y "%newLocation%\User Data" "%chromeUserData%"
        echo Restored user data to "%chromeUserData%"
    )
) else if /I "%choice%"=="A" (
    move /Y "%chromeUserData%" "%newLocation%\User Data"
    echo Moved user data to "%newLocation%\User Data"
    mklink /D "%chromeUserData%" "%newLocation%\User Data"
    echo Created symbolic link from "%chromeUserData%" to "%newLocation%\User Data"
) else (
    echo Invalid choice. Exiting.
    exit /b
)
pause
