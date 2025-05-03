# Ensure script runs with elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires elevation. Please run as Administrator." -ForegroundColor Red
    exit
}

# Function to remove a service if it exists
function Remove-ServiceIfExists {
    param (
        [string]$serviceName
    )
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "Removing service: $serviceName" -ForegroundColor Yellow
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2  # Wait for deletion to complete
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            Write-Host "Failed to remove service: $serviceName" -ForegroundColor Red
        } else {
            Write-Host "Service $serviceName removed successfully" -ForegroundColor Green
        }
    }
}

# Remove test services
Remove-ServiceIfExists -serviceName "TestVulnService"
Remove-ServiceIfExists -serviceName "TestUnquotedService"
Remove-ServiceIfExists -serviceName "TestDLLService"

# Remove test directories and files
$paths = @(
    "C:\TestVulnService",
    "C:\Test Unquoted",
    "C:\Test Unquoted Service",
    "C:\TestDLLService"
)

foreach ($path in $paths) {
    if (Test-Path $path) {
        Write-Host "Removing directory: $path" -ForegroundColor Yellow
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
            Write-Host "Directory $path removed successfully" -ForegroundColor Green
        } catch {
            Write-Host "Error removing ${path}: $_" -ForegroundColor Red
        }
    }
}

Write-Host "Cleanup completed." -ForegroundColor Green