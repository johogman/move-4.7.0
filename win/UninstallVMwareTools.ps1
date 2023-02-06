# Version: 4.7.0
$VMTOOLS="VMware Tools"

#### Log function
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$message,

        [Parameter()]
        [switch]$avoidStdout = $false,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Info','Warn','Eror')]
        [string]$severity = 'Info'
    )

    $time = (Get-Date -F o)
    $lineNum = $MyInvocation.ScriptLineNumber

    $logRecord = "$time | $severity | $lineNum | $message"

    $logRecord
}

Write-Log -message "Uninstalling VMware Tools"
if ($args[0] -like "target") {
    wmic product where "name='$VMTOOLS'" get name | findstr Name | Out-Null
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        Write-Log -message "VMware Tools not installed."
        exit $ExitCode
    }
    Write-Log -message "VMware tools installation found. Uninstalling VMware tools."
    $obj = Get-WmiObject -Class Win32_Product -Filter "Name = '$VMTOOLS'" | Select-Object -Property IdentifyingNumber, Version
    $guid = $obj.IdentifyingNumber
    $vmToolsVersion = $obj.Version
    Write-Log -message "VMware Tools GUID is : $guid"
    Write-Log -message "VMware Tools Version is : $vmToolsVersion"

    # Powershell executes msiexec asynchronously. Piping the command makes powershell wait for the command to complete.
    msiexec /quiet /norestart /uninstall $guid | Out-Default
    $ExitCode = $LASTEXITCODE
    # Value 3010 refers to error code ERROR_SUCCESS_REBOOT_REQUIRED(https://docs.microsoft.com/en-us/windows/win32/msi/error-codes)
    if ($ExitCode -eq 0 -or $ExitCode -eq 3010) {
        Write-Log -message "Uninstall operation successful"
        exit 0
    }

    # https://kb.vmware.com/s/article/1001354
    Write-Log -message "VMware tools uninstaller failed with Exit Code $ExitCode. Uninstalling VMware Tools from Registry ..."

    $vmciId = Get-ChildItem -Path HKLM:\SOFTWARE\Classes\Installer\Products | Get-ItemProperty | Where-Object {$_.ProductName -eq $VMTOOLS } | Select-Object -ExpandProperty PSChildName
    Write-Log -message "VMCI Driver GUID is : $guid"

    if ($vmciId -eq $null) {
        Write-Log -message "Unable to determine VMCI Driver GUID"
        exit 0
    }
    if ($vmciId -is [Object[]]) {
        Write-Log -message "Getting multiple VMCI Driver GUIDs"
        exit 0
    }

    Write-Log -message "Deleting VMware Tools Services"
    $vmwareServices = @("VGAuthService", "vmvss", "VM3DService", "VMTools")
    Foreach ($s in $vmwareServices) {
        Stop-Service -Name $s
        sc.exe delete $s
    }

    Write-Log -message "Deleting registry keys"
    reg delete HKEY_CLASSES_ROOT\Installer\Features\$vmciId /f
    reg delete HKEY_CLASSES_ROOT\Installer\Products\$vmciId /f
    reg delete HKLM\SOFTWARE\Classes\Installer\Features\$vmciId /f
    reg delete HKLM\SOFTWARE\Classes\Installer\Products\$vmciId /f
    reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$vmciId /f
    reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$guid /f
    reg delete "HKLM\SOFTWARE\VMware, Inc." /f

    Write-Log -message "Deleting VMware Tools folder"
    Remove-Item 'C:\Program Files\VMware\VMware Tools\' -Force -Recurse
    if (-not $?) {
        Write-Log -message "Failed to delete VMware Tools folder. Please delete the folder manually."
    }

    wmic product where "name='$VMTOOLS'" get name | findstr Name | Out-Null
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        Write-Log -message "VMware Tools uninstalled successfully."
    } else {
        Write-Log -message "Failed to uninstall VMware Tools. Please follow https://kb.vmware.com/s/article/1001354 to uninstall VMware Tools manually."
    }

    exit 0
}

exit 0