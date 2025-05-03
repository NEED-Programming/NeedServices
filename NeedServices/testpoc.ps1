# Ensure script runs with elevation
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script requires elevation. Please run as Administrator." -ForegroundColor Red
    exit
}

# Dynamically get the current user
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Function to remove a service if it exists
function Remove-ServiceIfExists {
    param (
        [string]$serviceName
    )
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $serviceName | Out-Null
        Start-Sleep -Seconds 2
    }
}

# --- TestVulnService ---
Remove-ServiceIfExists -serviceName "TestVulnService"
New-Item -Path "C:\TestVulnService" -ItemType Directory -Force | Out-Null
"echo TEST" | Out-File "C:\TestVulnService\testvuln.exe" -Encoding ASCII
try {
    New-Service -Name "TestVulnService" -BinaryPathName "C:\TestVulnService\testvuln.exe" -DisplayName "Test Vulnerable Service" -StartupType Manual -ErrorAction Stop | Out-Null
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TestVulnService"
    $acl = Get-Acl $regPath -ErrorAction Stop
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $regPath $acl -ErrorAction Stop
    $acl = Get-Acl "C:\TestVulnService\testvuln.exe" -ErrorAction Stop
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "None", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl "C:\TestVulnService\testvuln.exe" $acl -ErrorAction Stop
} catch {
    Write-Host "Error setting up TestVulnService: $_" -ForegroundColor Red
}

# --- TestUnquotedService ---
Remove-ServiceIfExists -serviceName "TestUnquotedService"
New-Item -Path "C:\Test Unquoted" -ItemType Directory -Force | Out-Null
New-Item -Path "C:\Test Unquoted Service" -ItemType Directory -Force | Out-Null
"echo TEST" | Out-File "C:\Test Unquoted Service\testunquoted.exe" -Encoding ASCII
try {
    $acl = Get-Acl "C:\Test Unquoted" -ErrorAction Stop
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl "C:\Test Unquoted" $acl -ErrorAction Stop
    $acl = Get-Acl "C:\Test Unquoted Service\testunquoted.exe" -ErrorAction Stop
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "None", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl "C:\Test Unquoted Service\testunquoted.exe" $acl -ErrorAction Stop
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TestUnquotedService"
    New-Service -Name "TestUnquotedService" -BinaryPathName "C:\Test Unquoted Service\testunquoted.exe" -DisplayName "Test Unquoted Service" -StartupType Manual -ErrorAction Stop | Out-Null
} catch {
    Write-Host "Error setting up TestUnquotedService: $_" -ForegroundColor Red
}

# --- TestDLLService ---
Remove-ServiceIfExists -serviceName "TestDLLService"
New-Item -Path "C:\TestDLLService" -ItemType Directory -Force | Out-Null
"echo TEST" | Out-File "C:\TestDLLService\testdll.exe" -Encoding ASCII
"echo DLL" | Out-File "C:\TestDLLService\fake.dll" -Encoding ASCII
try {
    $acl = Get-Acl "C:\TestDLLService" -ErrorAction Stop
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl "C:\TestDLLService" $acl -ErrorAction Stop
    $acl = Get-Acl "C:\TestDLLService\testdll.exe" -ErrorAction Stop
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, "FullControl", "None", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl "C:\TestDLLService\testdll.exe" $acl -ErrorAction Stop
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TestDLLService"
    New-Service -Name "TestDLLService" -BinaryPathName "C:\TestDLLService\testdll.exe" -DisplayName "Test DLL Service" -StartupType Manual -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $regPath -Name "ServiceDll" -Value "C:\TestDLLService\fake.dll" -PropertyType String -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Host "Error setting up TestDLLService: $_" -ForegroundColor Red
}