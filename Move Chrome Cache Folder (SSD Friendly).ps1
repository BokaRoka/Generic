# Define the paths
$originalPath = "C:\Users\Admin\AppData\Local\Google\Chrome\User Data"
$targetPath = "E:\Users\User\AppData\Local\Google\Chrome\User Data"
$linkPath = "C:\Users\Admin\AppData\Local\Google\Chrome\User Data"
# Check if the original path exists
if (Test-Path $originalPath) {
    # Check if the target path already exists
    if (-Not (Test-Path $targetPath)) {
        try {
            # Move the original folder to the target location
            Move-Item -Path $originalPath -Destination $targetPath -ErrorAction Stop
            # Check if the link path already exists
            if (Test-Path $linkPath) {
                # Remove the existing link or item
                Remove-Item -Path $linkPath -Force -ErrorAction Stop
            }
            # Create the symbolic link
            New-Item -Path $linkPath -ItemType SymbolicLink -Value $targetPath -ErrorAction Stop
            Write-Host "Symbolic link created successfully from '$linkPath' to '$targetPath'."
        } catch {
            Write-Host "An error occurred: $_"
        }
    } else {
        Write-Host "Target path '$targetPath' already exists. Please choose a different location."
    }
} else {
    Write-Host "Original path '$originalPath' does not exist. Please check the path."
}
