# Version: 4.7.0
param (
    [Parameter(Mandatory=$false, Position=1)]
    [string]$xtractIP = 'localhost',
    [string]$retainIP = $false,
    [string]$targetType = 'AOS',
    [string]$minPSVersion = '',
    [bool]$isManualPreparation = $false,
    [switch]$debugLog = $false  # Additional debug logs
)
#### constants
$Global:ScriptVersion = "4.7.0"

#### Supported OS Version
$Global:Win10Version = "10.0.17134"
$Global:Win10FrenchVersion = "10.0.18362"
$Global:Win2K12R2Version = "6.3.9600"
$Global:Win2K16Version = "10.0.14393"
$Global:Win2K19Version = "10.0.17763"
$Global:Win2K8R2Version = "6.1.7601"

#### Supported OS Version
$Global:Win10Version = "10.0.17134"
$Global:Win10FrenchVersion = "10.0.18362"
$Global:Win2K12R2Version = "6.3.9600"
$Global:Win2K16Version = "10.0.14393"
$Global:Win2K19Version = "10.0.17763"
$Global:Win2K8R2Version = "6.1.7601"

###### Tracking the steps
$Global:HasLastStepSucceeded = $false
$Global:CurrentStep = 0
$Global:LastStep = 6

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
if ($Global:HasLastStepSucceeded ) {
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

$ErrorStart = "[Error]"
$ErrorEnd = "[/Error]"

# Certutil debug logging
$CertDebugLoggingEnabled = $false
$CertDebugLoggingValue = 0

## Log
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
         [ValidateSet('Info', 'Warn', 'Error', 'With_Error_Tag')]
         [string]$severity = 'Info'
     )

     $time = (Get-Date -F o)
     $lineNum = $MyInvocation.ScriptLineNumber
     # Log directly in Powershell
     if (-not$avoidStdout)
     {
        if ($severity -eq 'With_Error_Tag' -and (-Not $isManualPreparation)) {
            echo "$ErrorStart $message $ErrorEnd"
        } else {
            echo $message
        }
     }
     $logRecord = "$time | $severity | $lineNum | $message"

     $logRecord | Out-File -Append $TestLogPath
}

function Write-Host-Red
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$message,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Info', 'Warn', 'Error', 'With_Error_Tag')]
        [string]$severity = 'Info'
    )
    if ($severity -eq 'With_Error_Tag' -and (-Not $isManualPreparation)) {
        Write-Host "$ErrorStart $message $ErrorEnd" -ForegroundColor Red
    } else {
        Write-Host $message -ForegroundColor Red
    }
}

$installVirtio = $false
if ($targetType -like 'AOS') {
    $installVirtio= $true
}

Write-Log "Setting up the User VM with Xtract: $xtractIP, TargetType:$targetType, InstallVirtio:$installVirtio using script: $Global:ScriptVersion"
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
        Write-Log -message "Current PowerShell version $CurPSVersion is not supported. Minimum required version is $MinPSVersion. Exiting" -severity 'With_Error_Tag' -avoidStdout:$false
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

#### Config access functions
$Global:Config = @{}
$Global:Config.ScriptVersion = $Global:ScriptVersion
$Global:Config.CurrentStep = $Global:CurrentStep
$Global:Config.XtractIP = $xtractIP

function Get-Config {
    $Global:Config = Import-Clixml $ConfPath
    $configstr = ($Global:Config.Keys | foreach { "$_ $($Global:Config[$_])" }) -join " | "
    Write-Log -message "Global:Config -> $configstr"
}

function Set-Config {
    $Global:Config | Export-CliXml $ConfPath
}

#### Log the Current direcotry(pwd)
function Log-Current-Dir {
    $curDir = (Get-Item -Path ".\").FullName
    Write-Log -message "The script's current directory: $curDir" -avoidStdout:$true
}
Log-Current-Dir

# Verify script sanity with the UVM
function Verify-Script-Sanity {
    # Scriptversion comparison, to verify if the script already ran in the UVM with a different version.
    if ($Global:Config.ScriptVersion -ne $Global:ScriptVersion) {
        Write-Log "Detected a mismatch in the script versions, this script's version($Global:ScriptVersion) and config's version($($Global:Config.ScriptVersion))" -avoidStdout:$true -severity Warn
    }
    # Verify if the UVM prep-ed with another Xtract-Lite and if so request for cleanup before proceeding.
    try {
        if ($Global:Config.XtractIP -ne $xtractIP) {
            Write-Log "Detected that the User VM was prepared with another Xtract($($Global:Config.XtractIP)). Please do a clean-up and then try again." -avoidStdout:$false -severity Error
            break
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Write-Log "While verifying XtractLite info, got error: ($errorMessage)"
        Get-Config
        Write-Log "Seems the config file format is old and couldn't verify XtractLite." -avoidStdout:$true
    }

    # To verify if installation has completed.
    if ($Global:Config.CurrentStep -eq $Global:LastStep) {
        Write-Log "CurrentStep from config file and last step are the same, i.e. ($Global:LastStep). The previous preparation was with script version: ($($Global:Config.ScriptVersion))." -avoidStdout:$true
        Write-Log "The script was already used to prepare the User VM. Verifying the previous preparation."
        Write-Log "The User VM preparation completed."
        exit 0
    }
}

try {
    Get-Config

    # Running the function before changing the global values.
    Verify-Script-Sanity

    $Global:CurrentStep = $Global:Config.CurrentStep
    # Will update the version in config as in the script
    $Global:Config.ScriptVersion = $Global:ScriptVersion
} catch {
    Set-Config
    Write-Log "Couldn't find the configuration file in the system, created a new one."
}

#### Debug log for tracking command logs
if ($debugLog) {
    Set-PSDebug -Trace 1
} Else {
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
function Collect-OSInfo {
    Write-Log -message "Collecting OS Info." -avoidStdout:$true
    $Global:OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory
    Write-Log -message "OSInfo: $Global:OSInfo" -avoidStdout:$true
}
Collect-OSInfo

###### OS Support Verification
$Global:SupportedOSStrings = @("2008", "2008 R2", "2012", "2012 R2", "2016", "2019", "2022", "Windows 7", "Windows 8","Windows 10")
$SupportedOSMsg = "Supported Windows OSs are Microsoft Windows Server 2008, 2008 R2, 2012, 2012 R2, 2016, 2019, 2022, Windows 7, 8, 10."

$Global:SupportedOSVersionStrings = @($Global:Win10Version, $Global:Win10FrenchVersion, $Global:Win2K12R2Version,
                                        $Global:Win2K16Version, $Global:Win2K19Version, $Global:Win2K8R2Version)

$Global:IsOSSupported = $false
$Global:OSVersion = (Get-WmiObject -class Win32_OperatingSystem).Version

function Check-OSSupport {
    Write-Log -message "Checking if the OS is supported." -avoidStdout:$true
    $Global:IsOSSupported = $null -ne ($Global:SupportedOSStrings | ? { $Global:OSInfo.Caption -match $_ })

    if ($Global:IsOSSupported -eq $false) {
        $Global:IsOSSupported = $null -ne ($Global:SupportedOSVersionStrings | ? { $Global:OSInfo.Version -match $_ })
    }
}
Check-OSSupport
if ($Global:IsOSSupported) {
    Write-Log -message "User VM OS ($($Global:OSInfo.Caption), $($Global:OSInfo.Version)) is supported for migration."
} else {
    Write-Log -message "User VM OS ($($Global:OSInfo.Caption), $($Global:OSInfo.Version)) is not supported for migration. $SupportedOSMsg. Exiting." -severity "With_Error_Tag"
    exit 1
}

function Enable-CertDebugLogging {
    if ($CertDebugLoggingEnabled) {
        Write-Log -message "Enabling the certutil debug logging..."

        $cmd = "Set-ItemProperty -Path HKLM:\Software\Microsoft\Cryptography\AutoEnrollment -Name Debug -Value $CertDebugLoggingValue -Type DWord"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true

        $out = Set-ItemProperty -Path HKLM:\Software\Microsoft\Cryptography\AutoEnrollment -Name Debug -Value $CertDebugLoggingValue 2>&1
        $Global:HasLastStepSucceeded = $?
        Write-Log -message "Output: $out" -avoidStdout:$true
        if (-not $Global:HasLastStepSucceeded) {
            Write-Log "Failed to enable the certutil debug logging, please enable it manually!"
        }
    }
}

###### Virtio configuration
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

###### Python 3 configuration
$webPyFilePath32Bit = "$Global:BaseUrl/resources/uvm/win/python/python-3.4.0.msi"
$webPyFilePath64Bit = "$Global:BaseUrl/resources/uvm/win/python/python-3.4.0.amd64.msi"
$destinationPyDirectoryPath = Join-Path $destinationDirPath -ChildPath 'py'
$pyInstaller32Bit = Join-Path $destinationPyDirectoryPath -ChildPath 'python-3.4.0.msi'
$pyInstaller64Bit = Join-Path $destinationPyDirectoryPath -ChildPath 'python-3.4.0.amd64.msi'

###### UVM Restart configuration
$RestartPromptHeader = "System Restart Required"
$RestartPromptMessage = "To complete the preparation of the User VM we need to restart the system. Before confirming in next prompt make sure your setup is ready for restart. "
$RestartPromptTimeout = 0
# Ref: https://ss64.com/vb/popup.html
$RestartPromptType = 0+64+4096


######## SAN Policy script configuration
$webSANPolicyScriptPath = "$Global:BaseUrl/resources/setSANPolicy.bat"
$SANPolicyScriptPath = Join-Path $ScriptsDirPath -ChildPath 'setSANPolicy.bat'

######## Cleanup script configuration
$webCleanupScriptPath = "$Global:BaseUrl/resources/scripts/win/cleanup_installation.ps1"
$CleanupScriptPath = Join-Path $UninstallScriptsPath -ChildPath "cleanup_installation.ps1"

######## Schedule nutanix move script configuration
$webNutanixMoveScriptPath = "$Global:BaseUrl/resources/scripts/win/NutanixMove.bat"
$NutanixMoveScriptPath = Join-Path $ScriptsDirPath -ChildPath "NutanixMove.bat"
$webNutanixMoveConfigurationOnStartConfigPath = "$Global:BaseUrl/resources/scripts/win/TaskNutanixMoveOnStartConfig.xml"
$NutanixMoveConfigurationOnStartConfigPath = Join-Path $ScriptsDirPath -ChildPath 'TaskNutanixMoveOnStartConfig.xml'

######## Retain IP script configuration
$webRetainIpScriptPath = "$Global:BaseUrl/resources/scripts/win/RetainIP.ps1"
$RetainIpScriptPath = Join-Path $ScriptsDirPath -ChildPath 'RetainIP.ps1'
$webWmiNetUtilFilePath = "$Global:BaseUrl/resources/wmi-net-util.exe"
$WmiNetUtilFilePath = Join-Path $DownloadDirPath -ChildPath 'wmi-net-util.exe'

#### Create Directory Function
function Create-Directory {
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
Create-Directory -path $destinationVirtioDirectoryPath
Create-Directory -path $destinationNXCertsDirectoryPath
Create-Directory -path $destinationPyDirectoryPath
Create-Directory -path $ScriptsDirPath
Create-Directory -path $UninstallScriptsPath

#### Select download file based on architecture
Write-Log "Selecting required files to be downloaded to User VM."
$arch64 = @("64")
$arch32 = @("32")
if ($arch64 | ? { $osArch.osarchitecture -match $_ }) {
    Write-Log "Found 64-bit OS arch"
    $virtioInstaller = $virtioInstaller64Bit
    $webVirtioFilePath = $webVirtioFilePath64Bit
    ###### py
    $pyInstaller = $pyInstaller64Bit
    $webPyFilePath = $webPyFilePath64Bit
}
elseif ($arch32 | ? { $osArch.osarchitecture -match $_ }) {
    Write-Log "Found 32-bit OS arch"
    $virtioInstaller = $virtioInstaller32Bit
    $webVirtioFilePath = $webVirtioFilePath32Bit
    ###### py
    $pyInstaller = $pyInstaller32Bit
    $webPyFilePath = $webPyFilePath32Bit
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
    }while($RetryCount--)
}

#### Download files from Move appliance
$stepNum = 1
if ($stepNum -le $Global:CurrentStep) {
     Write-Log "Skipped download of various artifacts as the step was already executed." -avoidStdout:$true
     Write-Log "StepNum: $stepNum CurrentStep: $Global:CurrentStep." -avoidStdout:$true
} else {
    Write-Log "Starting to download various artifacts."
    try {
        ###### download scripts
        ######## download SAN Policy script
        $cmd = "Download-Artifact -fromLocation $webSANPolicyScriptPath -toLocation $SANPolicyScriptPath"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        Download-Artifact -fromLocation $webSANPolicyScriptPath -toLocation $SANPolicyScriptPath

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

        ###### download Certs artifact
        if ($installVirtio)
        {
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
    }
    catch [Net.WebException] {
        $excStr = $_.Exception.ToString()
        $errMsg = "Got error while downloading all the artifacts."
        Write-Log -message $errMsg -severity "With_Error_Tag"
        $errMsg = "Exception: $excStr"
        Write-Log -message $errMsg
        exit 1
    }

    $Global:Config.CurrentStep = $stepNum
    Set-Config
}

###### disable certutil debug logging if enabled
$stepNum = 2
if ($stepNum -le $Global:CurrentStep) {
    Write-Log "Skipped checking for certutil debug logging as the step was already executed." -avoidStdout:$true
    Write-Log "StepNum: $stepNum CurrentStep: $Global:CurrentStep." -avoidStdout:$true
} else {
    $cmd = "Get-ItemProperty -Path HKLM:\Software\Microsoft\Cryptography\AutoEnrollment -Name Debug"
    Write-Log -message "Executing command: $cmd" -avoidStdout:$true

    $out = Get-ItemProperty -Path HKLM:\Software\Microsoft\Cryptography\AutoEnrollment -Name Debug 2>&1
    $Global:HasLastStepSucceeded = $?
    Write-Log -message "Output: $out" -avoidStdout:$true
    if (-not $Global:HasLastStepSucceeded -or $out.Debug -eq 0) {
        Write-Log "Debug logging is not enabled for certutil"
    } else {
        Write-Log "Disabling the certutil debug logging..."
        $CertDebugLoggingEnabled = $true
        $CertDebugLoggingValue = $out.Debug

        # disable certutil debug logging
        $cmd = "Remove-ItemProperty -Path HKLM:\Software\Microsoft\Cryptography\AutoEnrollment -Name Debug"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        $out = Remove-ItemProperty -Path HKLM:\Software\Microsoft\Cryptography\AutoEnrollment -Name Debug 2>&1 | Out-String
            $Global:HasLastStepSucceeded = $?
            Write-Log -message "Output: $out" -avoidStdout:$true

            if ($Global:HasLastStepSucceeded) {
                Write-Log "Disabled certutil debug logging successfully!"
                $Global:Config.CurrentStep = $stepNum
                Set-Config
            } else {
                Write-Log "Failed to disable the certutil debug logging. Please disable the certutil debug logging manually and retry again!" -severity "With_Error_Tag"
                exit 2
            }
    }
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
        Write-Log "Failed to add Nutanix VirtIO certificate: $certPath. Attempting to add the certificate using 'Import-Certificate' cmdlet" -avoidStdout:$true -severity Warn
        $cmd = "Import-Certificate -FilePath $certPath -CertStoreLocation cert:\LocalMachine\TrustedPublisher"
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        $out = Import-Certificate -FilePath $certPath -CertStoreLocation cert:\LocalMachine\TrustedPublisher 2>&1 | Out-String
        $Global:HasLastStepSucceeded = $?
        Write-Log -message "Output: $out" -avoidStdout:$true
        if (-not $Global:HasLastStepSucceeded) {
            Write-Log "Failed to add Nutanix VirtIO certificate: $certPath. Please make sure to run powershell as Administrator for preparation script." -avoidStdout:$true
            Write-Host-Red "Failed to add Nutanix VirtIO certificate: $certPath. Please make sure to run powershell as Administrator for preparation script." -severity "With_Error_Tag"
            Enable-CertDebugLogging
            exit 3
        }
    }
}

###### Installing NX certs
$stepNum = 3
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
$stepNum = 4
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
            Write-Log "Check if OS is SHA2 compatible."
        }
        Write-Log "Failed to install Virtio drivers." -severity "With_Error_Tag"
        Enable-CertDebugLogging
        exit 4
    }
}

$stepNum = 5
#https://docs.microsoft.com/en-us/powershell/module/storage/set-storagesetting
try {
    $out = Get-StorageSetting 2>&1 | Out-String
    Write-Log -message "Current Storage Settings: $out" -avoidStdout:$true
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Log -message "Get-StorageSetting command failed with message: ($errorMessage)" -avoidStdout:$true
}

if ($stepNum -le $Global:CurrentStep) {
     Write-Log "Skipped applying SAN Policy as the step was already executed." -avoidStdout:$true
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
        Write-Log "Failed to apply SAN Policy." -severity "With_Error_Tag"
        Enable-CertDebugLogging
        exit 5
    }
}

if (Test-Path $RetainIPResultPath) {
    Remove-item $RetainIPResultPath
}
if (Test-Path $NutanixMoveResultPath) {
    Remove-item $NutanixMoveResultPath
}
$stepNum = 6
Write-Log -message "Scheduling Nutanix Move task for retainIP and cleanup on target User VM after first boot" -avoidStdout:$true
if ($stepNum -le $Global:CurrentStep) {
    Write-Log "Skipped scheduling target User VM Nutanix Move task as the step was already executed." -avoidStdout:$true
    Write-Log "StepNum: $stepNum CurrentStep: $Global:CurrentStep." -avoidStdout:$true
} else {
    if ($retainIP -eq $false) {
        $cmd = "cmd.exe /c ""$NutanixMoveScriptPath"" ""--xml"" ""$NutanixMoveConfigurationOnStartConfigPath ""
        ""--cleanup"" ""$CleanupScriptPath"""
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        $out = cmd.exe /c "$NutanixMoveScriptPath" "--xml" "$NutanixMoveConfigurationOnStartConfigPath" "--cleanup" "$CleanupScriptPath" 2>&1 | Out-String
        $Global:HasLastStepSucceeded = $?
        Write-Log -message "Output: $out" -avoidStdout:$true
    } else {
        $cmd = "cmd.exe /c ""$NutanixMoveScriptPath"" ""--xml"" ""$NutanixMoveConfigurationOnStartConfigPath ""
        ""--retain-ip"" ""$RetainIpScriptPath"" ""$WmiNetUtilFilePath""  ""--cleanup"" ""$CleanupScriptPath"""
        Write-Log -message "Executing command: $cmd" -avoidStdout:$true
        $out = cmd.exe /c "$NutanixMoveScriptPath" "--xml" "$NutanixMoveConfigurationOnStartConfigPath" `
        "---retain-ip" "$RetainIpScriptPath" "$WmiNetUtilFilePath" "--cleanup" "$CleanupScriptPath" 2>&1 | Out-String
        $Global:HasLastStepSucceeded = $?
        Write-Log -message "Output: $out" -avoidStdout:$true
    }
    if ($Global:HasLastStepSucceeded) {
        Write-Log "Scheduled target User VM Nutanix Move task."
        $Global:Config.CurrentStep = $stepNum
        Set-Config
    } else {
        Write-Log "Failed to schedule Retain IP and Cleanup task for target VM." -severity "Error"
    }
}

###### Enable cert debug logging if it was enabled before running the script
Enable-CertDebugLogging

