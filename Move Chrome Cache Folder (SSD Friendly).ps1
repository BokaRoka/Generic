# Function to get user input with validation for drive letters
function Get-ValidatedDriveLetter {
    param (
        [string]$message
    )
    do {
        $driveLetter = Read-Host $message
        $driveLetter = $driveLetter.ToUpper() + ":\"
    } until (Test-Path $driveLetter -or $driveLetter -match '^[A-Z]:\\$')
    
    return $driveLetter
}
# Function to get usernames from the specified drive
function Get-UsernamesFromDrive {
    param (
        [string]$driveLetter
    )
    
    $usersPath = Join-Path -Path $driveLetter -ChildPath "Users"
    if (Test-Path $usersPath) {
        $userFolders = Get-ChildItem -Path $usersPath -Directory | Where-Object { $_.Name -ne 'Public' }
        return $userFolders.Name  # Return all user names found
    }
    return @()  # No user found
}
# Function to get the username from the original path
function Get-UsernameFromOriginalPath {
    param (
        [string]$originalPath
    )
    
    $pathParts = $originalPath -split '\\'
    return $pathParts[2]  # Assuming the username is the third part in the path
}
# Set a default username if none is found
$defaultUsername = "Default"  # Change this to your desired default username
# Ask for the original path
$originalPath = Read-Host "Enter the original path (e.g., C:\Users\<username>\AppData\Local\Google\Chrome\User Data):"
$originalUsername = Get-UsernameFromOriginalPath $originalPath
# Check if the original path exists
if (-not (Test-Path $originalPath)) {
    Write-Host "Original path '$originalPath' does not exist. Please check the path."
    exit
}
# Ask for the new drive letter
$newDriveLetter = Get-ValidatedDriveLetter "Enter the new drive letter for the target path (e.g., E):"
$newUsernames = Get-UsernamesFromDrive $newDriveLetter
# Automatically select the first username from the new drive or use the default
$newUsername = if ($newUsernames.Count -gt 0) { $newUsernames[0] } else { $defaultUsername }
# Construct the target path using the dynamically retrieved or default username
$targetPath = Join-Path -Path $newDriveLetter -ChildPath "Users\$newUsername\AppData\Local\Google\Chrome\User Data"
# Proceed with the action based on user input
$action = Read-Host "Do you want to (R)estore the original path or (N)ew location? (R/N)"
if ($action -eq 'R') {
    # Restore the original path
    if (Test-Path $targetPath) {
        try {
            Move-Item -Path $targetPath -Destination $originalPath -ErrorAction Stop
            Write-Host "Restored original path to '$originalPath'."
        } catch {
            Write-Host "An error occurred while restoring: $_"
        }
    } else {
        Write-Host "Target path '$targetPath' does not exist. No action taken."
    }
} elseif ($action -eq 'N') {
    # Check if the target path already exists
    if (-Not (Test-Path $targetPath)) {
        try {
            # Move the original folder to the target location
            Move-Item -Path $originalPath -Destination $targetPath -ErrorAction Stop
            
            # Create the symbolic link
            New-Item -Path $originalPath -ItemType SymbolicLink -Value $targetPath -ErrorAction Stop
            Write-Host "Symbolic link created successfully from '$originalPath' to '$targetPath'."
        } catch {
            Write-Host "An error occurred while moving or creating link: $_"
        }
    } else {
        Write-Host "Target path '$targetPath' already exists. Please choose a different location."
    }
} else {
    Write-Host "Invalid option. Please enter 'R' to restore or 'N' for a new location."
}
