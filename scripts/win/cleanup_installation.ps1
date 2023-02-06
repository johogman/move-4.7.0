# Version: 4.7.0
param (
    [Parameter(Mandatory=$false, Position=1)]
    [string]$xtractLiteIP = 'localhost',  # XtractLite VM which provides this script and all required artifacts to cleanup the UVM.
    [string]$targetType = 'AOS',  # Target provider type default might be AHV
    [switch]$isAWSInstance = $true,  # to specify if the UVM is AWS or local.
    [switch]$doVirtioCleanup = $true  # flag to clean the Virtio installation. For target-vm set to true
)

## Script version info, should be same as the first line above
$Global:ScriptVersion = "4.7.0"
$Global:HasLastStepSucceeded = ''
# This is printed as the last message on stdout for
# marking success (for automatic cleanup)
$Global:SuccessMarker = "[ OK ]"

## Log
$NXBaseDir = "C:\Nutanix"
$MainUninstallDirPath = Join-Path $NXBaseDir -ChildPath "Uninstall"
$LogDirPath = Join-Path $NXBaseDir -ChildPath "log"
$UninstallScriptsPath = Join-Path $MainUninstallDirPath -ChildPath "scripts"
$LogPath = Join-Path $LogDirPath -ChildPath "uvm_cleanup_script.log"
#### Create Log directory
$cmd = "New-Item -ItemType ""directory"" -Path ""$LogDirPath"" -ErrorAction SilentlyContinue"
$out = New-Item -ItemType "directory" -Path $LogDirPath -ErrorAction SilentlyContinue 2>&1 | Out-String
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
     # Log directly in Powershell
     if (-not $avoidStdout) {
        echo $message
     }
     $logRecord = "$time | $severity | $lineNum | $message"

     $logRecord | Out-File -Append $LogPath
}
Write-Log "Cleaning up the User VM associated with Move: $xtractLiteIP using script: $Global:ScriptVersion"
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
Write-Log -message "Output: $out" -avoidStdout:$true

#### constants
$Global:HasLastStepSucceeded = $false
$Global:IsTestSigningEnabled = $false
###### Directory info
$TmpDirPath = Join-Path $NXBaseDir -ChildPath "Temp"
$CBTDirPath = Join-Path $NXBaseDir -ChildPath "Move"
$destinationDirPath = Join-Path $CBTDirPath -ChildPath 'artifact'
$destinationNXCertsDirectoryPath = Join-Path $destinationDirPath -ChildPath 'certs'
###### Virtio certs configuration
$nxVirtioCertsSha1 = Join-Path $destinationNXCertsDirectoryPath -ChildPath "Nutanix-VirtIO-sha1.cer"
$nxVirtioCertsSha2 = Join-Path $destinationNXCertsDirectoryPath -ChildPath "Nutanix-VirtIO-sha2.cer"
$nxVirtioCertsSha1Balloon = Join-Path $destinationNXCertsDirectoryPath -ChildPath "Nutanix-VirtIO-sha1-balloon-driver.cer"
$nxVirtioCertsSha1Scsi = Join-Path $destinationNXCertsDirectoryPath -ChildPath "Nutanix-VirtIO-scsi-passthrough-driver.cer"

Write-Log "Creating required directories" -avoidStdout:$true
#### Create required directories
$cmd = "New-Item -ItemType ""directory"" -Path $UninstallScriptsPath -ErrorAction SilentlyContinue"
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
$out = New-Item -ItemType "directory" -Path $UninstallScriptsPath -ErrorAction SilentlyContinue 2>&1 | Out-String
Write-Log -message "Output: $out" -avoidStdout:$true

if ($targetType -notlike 'AOS'){
    $doVirtioCleanup = $false
}

## Skip virtio unsintallation on windows server 2008 ENG-454094
Write-Log "Checking OS"
$cmd = "(Get-WmiObject Win32_OperatingSystem | Select-Object Caption).Caption"
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
$out = (Get-WmiObject Win32_OperatingSystem | Select-Object Caption).Caption
Write-Log -message "Output: $out" -avoidStdout:$true
if ($out -like '*2008 R2*') {
    Write-Log -message "Don't cleanup Virtio as it might create issues in subsequent bootup"
    $doVirtioCleanup = $false
}

#### Function to remove certificate
#### Remove certificate by fetching thumbprint in case certutil fails
#### ENG-494557
function Remove-Certificate {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$certPath
    )
    $cmd = "certutil.exe -delstore TrustedPublisher $certPath"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$true
    $out = certutil.exe -delstore TrustedPublisher $certPath 2>&1 | Out-String
    $certRemoved = $?
    Write-Log -message "Output: $out" -avoidStdout:$true
    if (-not $certRemoved) {
        Write-Log "Certutil failed. Removing certificate using Thumbprint." -avoidStdout:$true
        $cmd = "(New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certPath).Thumbprint"
        Write-Log "Fetching thumbprint for $certPath using command: $cmd" -avoidStdout:$true
        $thumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $certPath).Thumbprint
        $cmd = "Get-ChildItem cert:\LocalMachine\TrustedPublisher | Where-Object {$_.Thumbprint -eq $thumbprint} | Remove-Item"
        Write-Log "Executing command: $cmd" -avoidStdout:$true
        $out = Get-ChildItem cert:\LocalMachine\TrustedPublisher | Where-Object {$_.Thumbprint -eq $thumbprint} | Remove-Item
        Write-Log "Output: $out" -avoidStdout:$true
    }
}

if ($doVirtioCleanup) {
    #### Removing Virtio certs
    Write-Log -message "Removing virtio certificates."
    #
    Remove-Certificate -certPath $nxVirtioCertsSha1
    #
    Remove-Certificate -certPath $nxVirtioCertsSha2
    #
    Remove-Certificate -certPath $nxVirtioCertsSha1Balloon
    #
    Remove-Certificate -certPath $nxVirtioCertsSha1Scsi

    #### Virtio driver uninstallation
    Write-Log -message "Uninstalling Virtio drivers."
    #
    $cmd = "cmd.exe /c 'wmic product where Name=""Nutanix VirtIO"" call uninstall'"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$true
    $out = cmd.exe /c 'wmic product where Name="Nutanix VirtIO" call uninstall' 2>&1
    Write-Log -message "Output: $out" -avoidStdout:$true
    #
    $sleepSec = 10
    Write-Log -message "Sleeping for $sleepSec sec to complete Virtio uninstallation." -avoidStdout:$true
    Start-Sleep -s $sleepSec
}

#### Removing scheduled tasks
# ScheduleTargetCleanup
Write-Log -message "Removing the scheduled Nutanix Move tasks."
$cmd = "schtasks /delete /tn TaskNutanixMove /F 2>&1 | Out-String"
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
$out = schtasks /delete /tn TaskNutanixMove /F 2>&1 | Out-String
Write-Log -message "Output: $out" -avoidStdout:$true
# ScheduleTargetCleanupOnStart
$cmd = "schtasks /delete /tn TaskNutanixMoveOnStart /F 2>&1 | Out-String"
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
$out = schtasks /delete /tn TaskNutanixMoveOnStart /F 2>&1 | Out-String
Write-Log -message "Output: $out" -avoidStdout:$true

#### Removing directories
###### Removing temp directory
if ($isAWSInstance)
{
    Write-Log -message "Removing the temp directory."
    $cmd = "Remove-Item $TmpDirPath -recurse -Confirm:$false -Force"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$true
    $out = Remove-Item $TmpDirPath -recurse -Confirm:$false -Force 2>&1 | Out-String
    Write-Log -message "Output: $out" -avoidStdout:$true
}

Write-Log -message "Removing old tasks created from previous Move versions if any."
$out = schtasks /delete /tn ScheduleTempDiskConfiguration /F 2>$null
$out = schtasks /delete /tn ScheduleTempDiskConfigurationOnStart /F 2>$null
$out = schtasks /delete /tn TaskUninstallVMwareTools /F 2>$null
$out = schtasks /delete /tn TaskUninstallVMwareToolsOnStart /F 2>$null
$out = schtasks /delete /tn TaskRetainIP /F 2>$null
$out = schtasks /delete /tn TaskRetainIPOnStart /F 2>$null
$out = schtasks /delete /tn ScheduleTargetCleanup /F 2>$null
$out = schtasks /delete /tn ScheduleTargetCleanupOnStart /F 2>$null

###### Removing completely all artifacts by deleting parent-cbt directory
Write-Log -message "Removing the main directory."
$cmd = "Remove-Item $CBTDirPath -recurse -Confirm:$false -Force"
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
$out = Remove-Item $CBTDirPath -recurse -Confirm:$false -Force 2>&1 | Out-String
Write-Log -message "Output: $out" -avoidStdout:$true

###### Removing uninstall directory.
Write-Log -message "Removing cleanup scripts."
$cmd = "Remove-Item $MainUninstallDirPath -recurse -Confirm:$false -Force"
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
$out = Remove-Item $MainUninstallDirPath -recurse -Confirm:$false -Force 2>&1 | Out-String
Write-Log -message "Output: $out" -avoidStdout:$true

# Print the success marker for automatic preparation
Write-Host $Global:SuccessMarker
exit 0
