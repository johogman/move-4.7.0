# Version: 4.7.0

param (
    [Parameter(Mandatory = $false, Position = 1)]
    [string]$xtractIP = 'localhost',
    [string]$retainIP = $false,
    [string]$minPSVersion = '',
    [bool]$installVirtio = $false,
    [bool]$setSanPolicy = $false,
    [bool]$uninstallVMwareTools = $false,
    [switch]$debugLog = $false  # Additional debug logs
)
#### constants
$Global:ScriptVersion = "4.7.0"

###### Tracking the steps
$Global:HasLastStepSucceeded = $false
$Global:CurrentStep = 0
$Global:LastStep = 5

###### Web client to download artifact
$Global:WebClient = New-Object System.Net.WebClient

#### Select protocol to download artifact. http for xtract cloud and https for xtract vm
$Global:Protocol = "https"
$Global:BaseUrl = "${Global:Protocol}://$xtractIP"

#### Wait time for virtio installation
$Global:VirtioInstallationTimeOutPeriod = [timespan]::FromSeconds(120)

$SysDrive = "C:"
$result = Get-ChildItem Env:SYSTEMDRIVE
$Global:HasLastStepSucceeded = $?
if ($Global:HasLastStepSucceeded)
{
    $SysDrive = $result.value
}
$NXBaseDir = Join-Path $SysDrive -ChildPath "Nutanix"
$TempDir = Join-Path $NXBaseDir -ChildPath "Temp"
$MainDirPath = Join-Path $NXBaseDir -ChildPath 'Move'
$MainUninstallDirPath = Join-Path $NXBaseDir -ChildPath "Uninstall"
$ConfPath = Join-Path $MainDirPath -ChildPath "config.xml"
$DownloadDirPath = Join-Path $MainDirPath -ChildPath 'download'

# Scripts path
$ScriptsDirPath = Join-Path $DownloadDirPath -ChildPath 'scripts'
$UninstallScriptsPath = Join-Path $MainUninstallDirPath -ChildPath "scripts"
$destinationDirPath = Join-Path $MainDirPath -ChildPath 'artifact'

# Log file
$LogDirPath = Join-Path $NXBaseDir -ChildPath "log"
$TestLogPath = Join-Path $LogDirPath -ChildPath "uvm_script-$xtractIP.log"
$RetainIPResultPath = Join-Path $TempDir -ChildPath "RetainIPResult.out"
$NutanixMoveResultPath = Join-Path $TempDir -ChildPath "NutanixMoveResult.out"

## Log
#### Create Log directory
$cmd = "New-Item -ItemType ""directory"" -Path ""$LogDirPath"" -ErrorAction SilentlyContinue"
$out = New-Item -ItemType "directory" -Path $LogDirPath -ErrorAction SilentlyContinue 2>&1 | Out-String
#### Log function
function Write-Log
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$message,

        [Parameter()]
        [switch]$avoidStdout = $false,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Info', 'Warn', 'Eror')]
        [string]$severity = 'Info'
    )

    $time = (Get-Date -F o)
    $lineNum = $MyInvocation.ScriptLineNumber
    # Log directly in Powershell
    if (-not$avoidStdout)
    {
        echo $message
    }
    $logRecord = "$time | $severity | $lineNum | $message"

    $logRecord | Out-File -Append $TestLogPath
}
Write-Log "Setting up the User VM with Xtract: $xtractIP using script: $Global:ScriptVersion with arguments: retainIP:$retainIP,installVirtio:$installVirtio setSanPolicy:$setSanPolicy uninstallVMwareTools:$uninstallVMwareTools"
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
Write-Log -message "Output: $out" -avoidStdout:$true

#### Check PowerShell Version
function Check-PowerShell-Version {
    $PSVersion = $PSVersionTable.PSVersion
    $major = If ($PSVersion.Major -lt 0) {0} Else {$PSVersion.Major}
    $minor = If ($PSVersion.Minor -lt 0) {0} Else {$PSVersion.Minor}
    $build = If ($PSVersion.Build -lt 0) {0} Else {$PSVersion.Build}
    $CurPSVersion = New-Object -TypeName System.Version -ArgumentList $major,$minor,$build
    $MinPSVersion = New-Object -TypeName System.Version -ArgumentList $MinPSVersion
    if ($CurPSVersion -lt $MinPSVersion) {
        Write-Log -message "Current PowerShell version $CurPSVersion is not supported. Minimum required version is $MinPSVersion. Exiting" -severity Eror -avoidStdout:$false
        exit 1
    }
    Write-Log -message "PowerShell version $CurPSVersion is supported"
}
#### Check Powershell version if minimum version provided
if (-Not ([string]::IsNullOrEmpty($minPSVersion) -or ($minPSVersion -eq '{{MIN_PS_VERSION}}'))) {
    Check-PowerShell-Version
}

#### Create Main directory
$cmd = "New-Item -ItemType ""directory"" -Path ""$MainDirPath"" -ErrorAction SilentlyContinue"
$out = New-Item -ItemType "directory" -Path $MainDirPath -ErrorAction SilentlyContinue 2>&1 | Out-String
Write-Log -message "Executing command: $cmd" -avoidStdout:$true
Write-Log -message "Output: $out" -avoidStdout:$true

function Execute-ifneeded-WithLog
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$cmd,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Float]$step,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$stepMessage,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int]$sleepSec = 0
    )

    if ($step -lt $Global:CurrentStep)
    {
        Write-Log "Skipped executing the command: -- $cmd --. CurrentStep: $Global:CurrentStep ; step: $step" -avoidStdout:$true
    }
    else
    {
        Write-Log "Executing the command: -- $cmd --. CurrentStep: $Global:CurrentStep ; step: $step"
        $out = & $cmd 2>&1 | Out-String
        $Global:HasLastStepSucceeded = $?
        Write-Log -message "Output: $out" -avoidStdout:$true
        Start-Sleep -s $sleepSec
        $prefix = "Completed successfully the step <"
        $suffix = ">"
        if (-Not$Global:HasLastStepSucceeded)
        {
            $severity = "Eror"
            $prefix = "Failed to complete the step <"
        }
        $modifiedMessage = "$prefix$message$suffix"
    }
    Write-Log -message $modifiedMessage
}

#### Config access functions
$Global:Config = @{ }
$Global:Config.ScriptVersion = $Global:ScriptVersion
$Global:Config.CurrentStep = $Global:CurrentStep
$Global:Config.XtractIP = $xtractIP

function Get-Config
{
    $Global:Config = Import-Clixml $ConfPath
    $configstr = ($Global:Config.Keys | foreach { "$_ $( $Global:Config[$_] )" }) -join " | "
    Write-Log -message "Global:Config -> $configstr"
}

function Set-Config
{
    $Global:Config | Export-CliXml $ConfPath
}

#### Log the Current direcotry(pwd)
function Log-Current-Dir
{
    $curDir = (Get-Item -Path ".\").FullName
    Write-Log -message "The script's current directory: $curDir" -avoidStdout:$true
}
Log-Current-Dir

# Verify script sanity with the UVM
function Verify-Script-Sanity
{
    # Scriptversion comparison, to verify if the script already ran in the UVM with a different version.
    if ($Global:Config.ScriptVersion -ne $Global:ScriptVersion)
    {
        Write-Log "Detected a mismatch in the script versions, this script's version($Global:ScriptVersion) and config's version($( $Global:Config.ScriptVersion ))" -avoidStdout:$true -severity Warn
    }
    # Verify if the UVM prep-ed with another Xtract-Lite and if so request for cleanup before proceeding.
    try
    {
        if ($Global:Config.XtractIP -ne $xtractIP)
        {
            Write-Log "Detected that the User VM was prepared with another Xtract($( $Global:Config.XtractIP )). Please do a clean-up and then try again." -avoidStdout:$false -severity Eror
            break
        }
    }
    catch
    {
        $errorMessage = $_.Exception.Message
        Write-Log "While verifying Xtract info, got error: ($errorMessage)"
        Get-Config
        Write-Log "Seems the config file format is old and couldn't verify Xtract." -avoidStdout:$true
    }

    # To verify if installation has completed.
    if ($Global:Config.CurrentStep -eq $Global:LastStep)
    {
        Write-Log "CurrentStep from config file and last step are the same, i.e. ($Global:LastStep). The previous preparation was with script version: ($( $Global:Config.ScriptVersion ))." -avoidStdout:$true
        Write-Log "The script was already used to prepare the User VM. Verifying the previous preparation."
        Write-Log "The User VM preparation completed."
        break
    }
}

try
{
    Get-Config

    # Running the function before changing the global values.
    Verify-Script-Sanity

    $Global:CurrentStep = $Global:Config.CurrentStep
    # Will update the version in config as in the script
    $Global:Config.ScriptVersion = $Global:ScriptVersion
}
catch
{
    Set-Config
    Write-Log "Couldn't find the configuration file in the system, created a new one."
}

#### Debug log for tracking command logs
if ($debugLog)
{
    Set-PSDebug -Trace 1
}
Else
{
    Set-PSDebug -Off
}

#### UVM system information
$Global:OSInfo = ''
###### Architecture
$osArch = gwmi win32_operatingsystem | select osarchitecture
Write-Log "OS Arch: $osArch"
$Hostname = [System.Net.Dns]::GetHostName()
Write-Log "Hostname: $Hostname"

###### OS Info collector
function Collect-OSInfo
{
    Write-Log -message "Collecting OS Info." -avoidStdout:$true
    $Global:OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory
    Write-Log -message "OSInfo: $Global:OSInfo" -avoidStdout:$true
}
Collect-OSInfo

###### OS Support Verification
$Global:SupportedOSStrings = @("2008", "2008 R2", "2012", "2012 R2", "2016", "2019", "2022", "Windows 7", "Windows 8", "Windows 10")
$SupportedOSMsg = "Supported Windows OSs are Microsoft Windows Server 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, Windows 7, 8, 10."

$Global:IsOSSupported = $false
$Global:OSVersion = [System.Version]((Get-WmiObject -class Win32_OperatingSystem).Version)
function Check-OSSupport
{
    Write-Log -message "Checking if the OS is supported." -avoidStdout:$true
    $Global:IsOSSupported = $null -ne ($Global:SupportedOSStrings | ? { $Global:OSInfo.Caption -match $_ })
}
Check-OSSupport
if ($Global:IsOSSupported)
{
    Write-Log -message "User VM OS ($( $Global:OSInfo.Caption )) is supported for migration."
}
else
{
    Write-Log -message "User VM OS ($( $Global:OSInfo.Caption )) is not supported for migration. $SupportedOSMsg. Exiting."
    return
}

###### Virtio configuration
if ($installVirtio)
{
    $webVirtioFilePath32Bit = "$Global:BaseUrl/resources/Nutanix-VirtIO-latest-stable-x86.msi"
    $webVirtioFilePath64Bit = "$Global:BaseUrl/resources/Nutanix-VirtIO-latest-stable.msi"
    $destinationVirtioDirectoryPath = Join-Path $destinationDirPath -ChildPath 'virtio'
    $virtioInstaller32Bit = Join-Path $destinationVirtioDirectoryPath -ChildPath 'Nutanix-VirtIO-latest-stable-x86.msi'
    $virtioInstaller64Bit = Join-Path $destinationVirtioDirectoryPath -ChildPath 'Nutanix-VirtIO-latest-stable.msi'
    $virtioInstallerArgs = "/quiet"

    ###### Certs configuration
    $webCertPathSha1 = "$Global:BaseUrl/resources/Nutanix-VirtIO-sha1.cer"
    $webCertPathSha2 = "$Global:BaseUrl/resources/Nutanix-VirtIO-sha2.cer"
    $webCertPathBalloon = "$Global:BaseUrl/resources/Nutanix-VirtIO-sha1-balloon-driver.cer"
    $webCertPathScsi = "$Global:BaseUrl/resources/Nutanix-VirtIO-scsi-passthrough-driver.cer"
    $destinationNXCertsDirectoryPath = Join-Path $destinationDirPath -ChildPath 'certs'
    $nxVirtioCertsSha1 = Join-Path $destinationNXCertsDirectoryPath -ChildPath "Nutanix-VirtIO-sha1.cer"
    $nxVirtioCertsSha2 = Join-Path $destinationNXCertsDirectoryPath -ChildPath "Nutanix-VirtIO-sha2.cer"
    $nxVirtioCertsSha1Balloon = Join-Path $destinationNXCertsDirectoryPath -ChildPath "Nutanix-VirtIO-sha1-balloon-driver.cer"
    $nxVirtioCertsSha1Scsi = Join-Path $destinationNXCertsDirectoryPath -ChildPath "Nutanix-VirtIO-scsi-passthrough-driver.cer"
}

######## SAN Policy script configuration
if ($setSanPolicy)
{
    $webSANPolicyScriptPath = "$Global:BaseUrl/resources/setSANPolicy.bat"
    $SANPolicyScriptPath = Join-Path $ScriptsDirPath -ChildPath 'setSANPolicy.bat'
}

######## Cleanup script configuration
$webCleanupScriptPath = "$Global:BaseUrl/resources/scripts/win/cleanup_installation.ps1"
$CleanupScriptPath = Join-Path $UninstallScriptsPath -ChildPath "cleanup_installation.ps1"

######## Retain IP script configuration
$webRetainIpScriptPath = "$Global:BaseUrl/resources/scripts/win/RetainIP.ps1"
$RetainIpScriptPath = Join-Path $ScriptsDirPath -ChildPath 'RetainIP.ps1'
$webWmiNetUtilFilePath = "$Global:BaseUrl/resources/wmi-net-util.exe"
$WmiNetUtilFilePath = Join-Path $DownloadDirPath -ChildPath 'wmi-net-util.exe'

######## Uninstall VMware Tools script configuration
$webUninstallVMwareToolsScriptPath = "$Global:BaseUrl/resources/scripts/win/UninstallVMwareTools.ps1"
$UninstallVMwareToolsScriptPath = Join-Path $ScriptsDirPath -ChildPath 'UninstallVMwareTools.ps1'

######## Schedule nutanix move script configuration
$webNutanixMoveScriptPath = "$Global:BaseUrl/resources/scripts/win/NutanixMove.bat"
$NutanixMoveScriptPath = Join-Path $ScriptsDirPath -ChildPath "NutanixMove.bat"
$webNutanixMoveConfigurationOnStartConfigPath = "$Global:BaseUrl/resources/scripts/win/TaskNutanixMoveOnStartConfig.xml"
$NutanixMoveConfigurationOnStartConfigPath = Join-Path $ScriptsDirPath -ChildPath 'TaskNutanixMoveOnStartConfig.xml'

#### Create Directory Function
function Create-Directory
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$path,

        [Parameter()]
        [string]$itemType = "directory",

        [Parameter()]
        [string]$errorActions = "SilentlyContinue",

        [Parameter()]
        [switch]$avoidStdout = $true
    )

    $cmd = "New-Item -ItemType ""$itemType"" -Path $directoryPath -ErrorAction $errorActions"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$avoidStdout
    $out = New-Item -ItemType "$itemType" -Path $path -ErrorAction $errorActions 2>&1 | Out-String
    Write-Log -message "Output: $out" -avoidStdout:$avoidStdout
}

Write-Log "Creating required directories"
#### Create required directories
Create-Directory -path $MainDirPath
Create-Directory -path $ScriptsDirPath
Create-Directory -path $UninstallScriptsPath
if ($installVirtio)
{
    Create-Directory -path $destinationVirtioDirectoryPath
    Create-Directory -path $destinationNXCertsDirectoryPath

    Write-Log "Selecting required files to be downloaded to User VM."
    #### Select download file based on architecture
    $arch64 = @("64")
    $arch32 = @("32")
    if ($arch64 | ? { $osArch.osarchitecture -match $_ })
    {
        ###### virtio
        Write-Log "Found 64-bit OS Architecture"
        $virtioInstaller = $virtioInstaller64Bit
        $webVirtioFilePath = $webVirtioFilePath64Bit
    }
    elseif ($arch32 | ? { $osArch.osarchitecture -match $_ })
    {
        ###### virtio
        Write-Log "Found 32-bit OS Architecture"
        $virtioInstaller = $virtioInstaller32Bit
        $webVirtioFilePath = $webVirtioFilePath32Bit
    }
}

#### Download File Function
function Download-Artifact {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$fromLocation,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$toLocation,

        [Parameter()]
        [switch]$avoidStdout = $true
    )

    $cmd = "$Global:WebClient.DownloadFile($fromLocation, $toLocation)"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$avoidStdout
    $RetryCount = 5
    do {
        $Global:WebClient.DownloadFile($fromLocation, $toLocation)
        if(Test-Path -Path $toLocation){
            break
        } else {
            Start-sleep -Seconds 5
            Write-Log "Retry download.... $fromLocation" -avoidStdout:$false
        }
    } while ($RetryCount--)
}

#### Download files from Xtract appliance
$stepNum = 1
if ($stepNum -le $Global:CurrentStep) {
    Write-Log "Skipped download of various artifacts as the step was already executed." -avoidStdout:$true
    Write-Log "StepNum: $stepNum CurrentStep: $Global:CurrentStep." -avoidStdout:$true
} else {
    Write-Log "Starting to download various artifacts."
    try {
        ###### download scripts
        if ($setSanPolicy) {
        ######## download SAN Policy script
        $cmd = "Download-Artifact -fromLocation $webSANPolicyScriptPath -toLocation $SANPolicyScriptPath"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        Download-Artifact -fromLocation $webSANPolicyScriptPath -toLocation $SANPolicyScriptPath
        }

        ######## download cleanup script
        $cmd = "Download-Artifact -fromLocation $webCleanupScriptPath -toLocation $CleanupScriptPath"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        Download-Artifact -fromLocation $webCleanupScriptPath -toLocation $CleanupScriptPath

        ######## download nutanix move script
        $cmd = "Download-Artifact -fromLocation $webNutanixMoveScriptPath -toLocation $NutanixMoveScriptPath"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        Download-Artifact -fromLocation $webNutanixMoveScriptPath -toLocation $NutanixMoveScriptPath

        $cmd = "Download-Artifact -fromLocation $webNutanixMoveConfigurationOnStartConfigPath -toLocation $NutanixMoveConfigurationOnStartConfigPath"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        Download-Artifact -fromLocation $webNutanixMoveConfigurationOnStartConfigPath -toLocation $NutanixMoveConfigurationOnStartConfigPath

        if($retainIP -eq $true) {
            ######## download retainIP script
            $cmd = "Download-Artifact -fromLocation $webRetainIpScriptPath -toLocation $RetainIpScriptPath"
            Write-Log -message "Executing command: $cmd" -avoidStdout:$true
            Download-Artifact -fromLocation $webRetainIpScriptPath -toLocation $RetainIpScriptPath

            $cmd = "Download-Artifact -fromLocation $webWmiNetUtilFilePath -toLocation $WmiNetUtilFilePath"
            Write-Log -message "Executing command: $cmd" -avoidStdout:$true
            Download-Artifact -fromLocation $webWmiNetUtilFilePath -toLocation $WmiNetUtilFilePath

        }

        if ($installVirtio) {
            ###### download Certs artifact
            $cmd = "Download-Artifact -fromLocation $webCertPathSha1 -toLocation $nxVirtioCertsSha1"
            Write-Log -message "Executing command: $cmd" -avoidStdout:$true
            Download-Artifact -fromLocation $webCertPathSha1 -toLocation $nxVirtioCertsSha1

            $cmd = "Download-Artifact -fromLocation $webCertPathSha2 -toLocation $nxVirtioCertsSha2"
            Write-Log -message "Executing command: $cmd" -avoidStdout:$true
            Download-Artifact -fromLocation $webCertPathSha2 -toLocation $nxVirtioCertsSha2

            $cmd = "Download-Artifact -fromLocation $webCertPathBalloon -toLocation $nxVirtioCertsSha1Balloon"
            Write-Log -message "Executing command: $cmd" -avoidStdout:$true
            Download-Artifact -fromLocation $webCertPathBalloon -toLocation $nxVirtioCertsSha1Balloon
            Write-Log "Downloaded certificates."

            $cmd = "Download-Artifact -fromLocation $webCertPathScsi -toLocation $nxVirtioCertsSha1Scsi"
            Write-Log -message "Executing command: $cmd" -avoidStdout:$true
            Download-Artifact -fromLocation $webCertPathScsi -toLocation $nxVirtioCertsSha1Scsi
            Write-Log "Downloaded certificates."

            ###### download Virtio artifact
            $cmd = "Download-Artifact -fromLocation $webVirtioFilePath -toLocation $virtioInstaller"
            Write-Log -message "Executing command: $cmd" -avoidStdout:$true
            Download-Artifact -fromLocation $webVirtioFilePath -toLocation $virtioInstaller
            Write-Log "Downloaded Virtio artifact."
        }

        if($uninstallVMwareTools -eq $true) {
            ######## download uninstallVMwareTools script
            $cmd = "Download-Artifact -fromLocation $webUninstallVMwareToolsScriptPath -toLocation $UninstallVMwareToolsScriptPath"
            Write-Log -message "Executing command: $cmd" -avoidStdout:$true
            Download-Artifact -fromLocation $webUninstallVMwareToolsScriptPath -toLocation $UninstallVMwareToolsScriptPath
        }
    }
    catch [Net.WebException] {
        $excStr = $_.Exception.ToString()
        $errMsg = "Got error while downloading all the artifacts; Exception: $excStr"
        Write-Log -message $errMsg
        return
    }

    $Global:Config.CurrentStep = $stepNum
    Set-Config
}

###### Add NX certificates first using certutil
###### If it fails then try to add the certificates using 'Import-Certificate'
###### cmdlet (ENG-494557)
function Add-Certificate {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$certPath
    )

    $cmd = "certutil.exe -f -addstore TrustedPublisher $certPath"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$true
    $out = certutil.exe -f -addstore TrustedPublisher $certPath 2>&1 | Out-String
    $Global:HasLastStepSucceeded = $?
    Write-Log -message "Output: $out" -avoidStdout:$true
    if (-not $Global:HasLastStepSucceeded) {
        Write-Log "Failed to add Nutanix VirtIO certificate: $certPath. Attempting to add the certificate using  'Import-Certificate' cmdlet" -avoidStdout:$true -severity Warn
        $cmd = "Import-Certificate -FilePath $certPath -CertStoreLocation cert:\LocalMachine\TrustedPublisher"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        $out = Import-Certificate -FilePath $certPath -CertStoreLocation cert:\LocalMachine\TrustedPublisher 2>&1 | Out-String
        $Global:HasLastStepSucceeded = $?
        Write-Log -message "Output: $out" -avoidStdout:$true
        if (-not $Global:HasLastStepSucceeded) {
            Write-Log "Failed to add Nutanix VirtIO certificate: $certPath. Please make sure to run powershell as Administrator for preparation script." -avoidStdout:$true
            Write-Host "Failed to add Nutanix VirtIO certificate: $certPath. Please make sure to run powershell as Administrator for preparation script." -ForegroundColor Red
            Enable-CertDebugLogging
            exit 2
        }
    }
}

###### Installing NX certs
$stepNum = 2
if ($stepNum -le $Global:CurrentStep -Or -Not $installVirtio) {
    Write-Log "Skipped adding Nutanix virtio certificates as the step was already executed or installVirtio flag was false." -avoidStdout:$true
    Write-Log "StepNum: $stepNum CurrentStep: $Global:CurrentStep." -avoidStdout:$true
} else {
    Add-Certificate -certPath $nxVirtioCertsSha1
    Add-Certificate -certPath $nxVirtioCertsSha2
    Add-Certificate -certPath $nxVirtioCertsSha1Balloon
    Add-Certificate -certPath $nxVirtioCertsSha1Scsi
    Write-Log "Nutanix virtio certificates added successfully."
    $Global:Config.CurrentStep = $stepNum
    Set-Config
}

###### Installing virtio
$stepNum = 3
if ($stepNum -le $Global:CurrentStep -Or -Not $installVirtio) {
    Write-Log "Skipped Virtio installation as the step was already executed or installVirtio flag was false." -avoidStdout:$true
    Write-Log "StepNum: $stepNum CurrentStep: $Global:CurrentStep." -avoidStdout:$true
} else {
    Write-Log "Installing Virtio drivers"

    $cmd = "$virtioInstaller $virtioInstallerArgs"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$true
    $out = & $virtioInstaller $virtioInstallerArgs 2>&1
    $Global:HasLastStepSucceeded = $?
    Write-Log -message "Output: $out" -avoidStdout:$true
    $virtioRepSleepSec = 10
    $startRunTime = Get-Date
    $virtioInstalled = $false
    while ((Get-Date)- $startRunTime -lt $Global:VirtioInstallationTimeOutPeriod)
    {
        Start-Sleep -s $virtioRepSleepSec
        wmic product where "Name like 'Nutanix VirtIO'" get Name 2>&1 | Out-String | findstr /c:"Nutanix VirtIO"
        $virtioInstalled = $?
        if ($virtioInstalled) {
            break
        }
    }
    $Global:HasLastStepSucceeded = ($Global:HasLastStepSucceeded) -and ($virtioInstalled)
    if ($Global:HasLastStepSucceeded) {
        Write-Log "Virtio drivers installation completed successfully"
        $Global:Config.CurrentStep = $stepNum
        Set-Config
    } else {
        $oldOSVersion = @("2008 R2", "Windows 7")
        if ($null -ne ($oldOSVersion | ? { $Global:OSInfo.Caption -match $_ }))
        {
            Write-Log "Check if OS is SHA2 compatible." -avoidStdout:$true
            Write-Host "Check if OS is SHA2 compatible." -ForegroundColor Red
        }
        Write-Log "Failed to install VirtIO drivers. This would impact migrated VM's network connectivity in AHV cluster." -avoidStdout:$true
        Write-Host "Failed to install VirtIO drivers. This would impact migrated VM's network connectivity in AHV cluster." -ForegroundColor Red
        return
    }
}

$stepNum = 4
#https://docs.microsoft.com/en-us/powershell/module/storage/set-storagesetting
try {
    $out = Get-StorageSetting 2>&1 | Out-String
    Write-Log -message "Current Storage Settings: $out" -avoidStdout:$true
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Log -message "Get-StorageSetting command failed with message: ($errorMessage)" -avoidStdout:$true
}

if ($stepNum -le $Global:CurrentStep -Or -Not $setSanPolicy ) {
    Write-Log "Skipped applying SAN Policy as the step was already executed or setSanPolicy flag was false." -avoidStdout:$true
    Write-Log "StepNum: $stepNum CurrentStep: $Global:CurrentStep." -avoidStdout:$true
} else {
    $cmd = "$SANPolicyScriptPath"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$true
    $out = & $SANPolicyScriptPath 2>&1 | Out-String
    $Global:HasLastStepSucceeded = $?
    Write-Log -message "Output: $out" -avoidStdout:$true
    if ($Global:HasLastStepSucceeded) {
        Write-Log "Applied SAN Policy."
        $Global:Config.CurrentStep = $stepNum
        Set-Config
    } else {
        Write-Log "Failed to apply SAN Policy."
        return
    }
}

$stepNum = 5
if (Test-Path $RetainIPResultPath) {
    Remove-item $RetainIPResultPath
}
if (Test-Path $NutanixMoveResultPath) {
    Remove-item $NutanixMoveResultPath
}
Write-Log -message "Scheduling Nutanix Move task for retainIP, uninstallVMwareTools and cleanup on target User VM after first boot" -avoidStdout:$true
if ($stepNum -le $Global:CurrentStep) {
    Write-Log "Skipped scheduling target User VM Nutanix Move task as the step was already executed." -avoidStdout:$true
    Write-Log "StepNum: $stepNum CurrentStep: $Global:CurrentStep." -avoidStdout:$true
} else {
    $cmd = "cmd.exe /c ""$NutanixMoveScriptPath --xml $NutanixMoveConfigurationOnStartConfigPath --cleanup $CleanupScriptPath "
    if ($retainIP -eq $true) {
        $cmd = $cmd + " --retain-ip $RetainIpScriptPath $WmiNetUtilFilePath"
    }
    if ($uninstallVMwareTools -eq $true) {
        $cmd = $cmd + " --uninstall-vmware-tools $UninstallVMwareToolsScriptPath"
    }
    $cmd = $cmd + """"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$true
    $out = Invoke-Expression $cmd 2>&1 | Out-String
    $Global:HasLastStepSucceeded = $?
    Write-Log -message "Output: $out" -avoidStdout:$true
    if ($Global:HasLastStepSucceeded) {
        Write-Log "Scheduled target User VM Nutanix Move task."
        $Global:Config.CurrentStep = $stepNum
        Set-Config
    } else {
        Write-Log "Failure in scheduling target User VM Nutanix Move task."
    }
}
