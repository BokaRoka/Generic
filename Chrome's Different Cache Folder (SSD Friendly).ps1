# Get user input for the new drive
$newDrive = Read-Host -Prompt "Enter the drive letter for the new location (e.g., E)"
$usernames = Get-ChildItem "$newDrive:\Users" -Directory | Select-Object -ExpandProperty Name
$username = if ($usernames.Count -gt 0) { $usernames[0] } else { "Default" }
# Define paths
$chromeUserData = "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data"
$newLocation = "$newDrive:\Users\$username\AppData\Local\Google\Chrome\User Data"
# Create directory structure if it doesn't exist
if (-Not (Test-Path -Path "$newDrive:\Users\$username\AppData\Local\Google\Chrome")) {
    New-Item -ItemType Directory -Path "$newDrive:\Users\$username\AppData\Local\Google\Chrome" -Force
}
# Close Chrome if running
if (Get-Process -Name chrome -ErrorAction SilentlyContinue) {
    Stop-Process -Name chrome -Force
    Start-Sleep -Seconds 5
}
# User choice for mklink operation
$choice = Read-Host -Prompt "Do you want to (R)estore or (A)dd a new mklink? (R/A)"
if ($choice -eq 'R') {
    if (Test-Path $chromeUserData) {
        Move-Item -Path $chromeUserData -Destination "$newLocation\User Data" -Force
    }
    if (Test-Path "$newLocation\User Data") {
        Move-Item -Path "$newLocation\User Data" -Destination $chromeUserData -Force
    }
} elseif ($choice -eq 'A') {
    if (-Not (Test-Path "$newLocation\User Data")) {
        Move-Item -Path $chromeUserData -Destination "$newLocation\User Data" -Force
    }
    cmd /c "mklink /D `"$chromeUserData`" `"$newLocation`""
} else {
    Write-Host "Invalid choice. Exiting." ; exit
}
Read-Host -Prompt "Press Enter to exit"
