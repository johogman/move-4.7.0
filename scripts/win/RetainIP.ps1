# Version: 4.7.0
$SysDrive = "C:"
$NXBaseDir = Join-Path $SysDrive -ChildPath "Nutanix"
$TempDir = Join-Path $NXBaseDir -ChildPath "Temp"
$TMPFILE = Join-Path $TempDir -ChildPath "wmi-dump.txt"
$WMIUTIL_DUMP_LOG = Join-Path $TempDir -ChildPath "wmi-net-util-dump-log.txt"
$WMIUTIL = $args[1]
$RESULT_FILE = Join-Path $TempDir -ChildPath "RetainIPResult.out"
$ROUTEFILE = Join-Path $TempDir -ChildPath "route-dump.txt"
$WMINICDUMPFILE = Join-Path $TempDir -ChildPath "wmi-dump-ahv.txt"
$WMI_NIC_DUMP_LOG = Join-Path $TempDir -ChildPath "wmi-nic-dump.txt"
$WMIUTIL_RESTORE_LOG = Join-Path $TempDir -ChildPath "wmi-net-util-restore-log.txt"
$WMIUTIL_ROUTES_RESTORE_LOG = Join-Path $TempDir -ChildPath "wmi-net-util-routes-restore-log.txt"
$SkipRemoveGhostNICOSStrings = @("2008", "2008 R2", "2012", "2012 R2")
$OSInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory
$SkipRemoveGhostNIC = $null -ne ($SkipRemoveGhostNICOSStrings | ? { $OSInfo.Caption -match $_ })

# BUILD C++ TYPE DEFINITION FOR CLEANLY REMOVING THE GHOST NICS
$T = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Win32
{
    public static class SetupApi
    {
         // 1st form using a ClassGUID only, with Enumerator = IntPtr.Zero
        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetupDiGetClassDevs(
           ref Guid ClassGuid,
           IntPtr Enumerator,
           IntPtr hwndParent,
           int Flags
        );

        // 2nd form uses an Enumerator only, with ClassGUID = IntPtr.Zero
        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetupDiGetClassDevs(
           IntPtr ClassGuid,
           string Enumerator,
           IntPtr hwndParent,
           int Flags
        );

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            uint MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData
        );

        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(
            IntPtr DeviceInfoSet
        );

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr deviceInfoSet,
            ref SP_DEVINFO_DATA deviceInfoData,
            uint property,
            out UInt32 propertyRegDataType,
            byte[] propertyBuffer,
            uint propertyBufferSize,
            out UInt32 requiredSize
        );

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiRemoveDevice(IntPtr DeviceInfoSet,ref SP_DEVINFO_DATA DeviceInfoData);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
       public uint cbSize;
       public Guid classGuid;
       public uint devInst;
       public IntPtr reserved;
    }

    [Flags]
    public enum DiGetClassFlags : uint
    {
        DIGCF_DEFAULT       = 0x00000001,  // only valid with DIGCF_DEVICEINTERFACE
        DIGCF_PRESENT       = 0x00000002,
        DIGCF_ALLCLASSES    = 0x00000004,
        DIGCF_PROFILE       = 0x00000008,
        DIGCF_DEVICEINTERFACE   = 0x00000010,
    }

    public enum SetupDiGetDeviceRegistryPropertyEnum : uint
    {
         SPDRP_DEVICEDESC          = 0x00000000, // DeviceDesc (R/W)
         SPDRP_HARDWAREID          = 0x00000001, // HardwareID (R/W)
         SPDRP_COMPATIBLEIDS           = 0x00000002, // CompatibleIDs (R/W)
         SPDRP_UNUSED0             = 0x00000003, // unused
         SPDRP_SERVICE             = 0x00000004, // Service (R/W)
         SPDRP_UNUSED1             = 0x00000005, // unused
         SPDRP_UNUSED2             = 0x00000006, // unused
         SPDRP_CLASS               = 0x00000007, // Class (R--tied to ClassGUID)
         SPDRP_CLASSGUID           = 0x00000008, // ClassGUID (R/W)
         SPDRP_DRIVER              = 0x00000009, // Driver (R/W)
         SPDRP_CONFIGFLAGS         = 0x0000000A, // ConfigFlags (R/W)
         SPDRP_MFG             = 0x0000000B, // Mfg (R/W)
         SPDRP_FRIENDLYNAME        = 0x0000000C, // FriendlyName (R/W)
         SPDRP_LOCATION_INFORMATION    = 0x0000000D, // LocationInformation (R/W)
         SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E, // PhysicalDeviceObjectName (R)
         SPDRP_CAPABILITIES        = 0x0000000F, // Capabilities (R)
         SPDRP_UI_NUMBER           = 0x00000010, // UiNumber (R)
         SPDRP_UPPERFILTERS        = 0x00000011, // UpperFilters (R/W)
         SPDRP_LOWERFILTERS        = 0x00000012, // LowerFilters (R/W)
         SPDRP_BUSTYPEGUID         = 0x00000013, // BusTypeGUID (R)
         SPDRP_LEGACYBUSTYPE           = 0x00000014, // LegacyBusType (R)
         SPDRP_BUSNUMBER           = 0x00000015, // BusNumber (R)
         SPDRP_ENUMERATOR_NAME         = 0x00000016, // Enumerator Name (R)
         SPDRP_SECURITY            = 0x00000017, // Security (R/W, binary form)
         SPDRP_SECURITY_SDS        = 0x00000018, // Security (W, SDS form)
         SPDRP_DEVTYPE             = 0x00000019, // Device Type (R/W)
         SPDRP_EXCLUSIVE           = 0x0000001A, // Device is exclusive-access (R/W)
         SPDRP_CHARACTERISTICS         = 0x0000001B, // Device Characteristics (R/W)
         SPDRP_ADDRESS             = 0x0000001C, // Device Address (R)
         SPDRP_UI_NUMBER_DESC_FORMAT       = 0X0000001D, // UiNumberDescFormat (R/W)
         SPDRP_DEVICE_POWER_DATA       = 0x0000001E, // Device Power Data (R)
         SPDRP_REMOVAL_POLICY          = 0x0000001F, // Removal Policy (R)
         SPDRP_REMOVAL_POLICY_HW_DEFAULT   = 0x00000020, // Hardware Removal Policy (R)
         SPDRP_REMOVAL_POLICY_OVERRIDE     = 0x00000021, // Removal Policy Override (RW)
         SPDRP_INSTALL_STATE           = 0x00000022, // Device Install State (R)
         SPDRP_LOCATION_PATHS          = 0x00000023, // Device Location Paths (R)
         SPDRP_BASE_CONTAINERID        = 0x00000024  // Base ContainerID (R)
    }
}
"@
Add-Type -TypeDefinition $T
# CLASS API CALLS FOR ACTUALLY REMOVING GHOST NICS
function Remove-Ghost-Nics {
	write-host "Remove-Ghost-Nics"
	$my_array = @()
	$my_setup_class = [Guid]::Empty
	$my_devs = [Win32.SetupApi]::SetupDiGetClassDevs([ref]$my_setup_class, [IntPtr]::Zero, [IntPtr]::Zero, [Win32.DiGetClassFlags]::DIGCF_ALLCLASSES)
	$my_devinfo = new-object Win32.SP_DEVINFO_DATA
	$my_devinfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($my_devinfo)
	$my_int_devcount = 0
	while([Win32.SetupApi]::SetupDiEnumDeviceInfo($my_devs, $my_int_devcount, [ref]$my_devinfo)) {
		$my_prop_type = 0
		[byte[]]$my_prop_buffer = $null
		$my_prop_bufferSize = 0
		[Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_FRIENDLYNAME, [ref]$my_prop_type, $my_prop_buffer, 0, [ref]$my_prop_bufferSize) | out-null
		[byte[]]$my_prop_buffer = New-Object byte[] $my_prop_bufferSize

		$my_prop_typeHWID = 0
		[byte[]]$my_prop_bufferHWID = $null
		$my_prop_bufferSizeHWID = 0
		[Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_HARDWAREID, [ref]$my_prop_typeHWID, $my_prop_bufferHWID, 0, [ref]$my_prop_bufferSizeHWID) | out-null
		[byte[]]$my_prop_bufferHWID = New-Object byte[] $my_prop_bufferSizeHWID

		$my_prop_typeDD = 0
		[byte[]]$my_prop_bufferDD = $null
		$my_prop_bufferSizeDD = 0
		[Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_DEVICEDESC, [ref]$my_prop_typeDD, $my_prop_bufferDD, 0, [ref]$my_prop_bufferSizeDD) | out-null
		[byte[]]$my_prop_bufferDD = New-Object byte[] $my_prop_bufferSizeDD

		$my_prop_typeIS = 0
		[byte[]]$my_prop_bufferIS = $null
		$my_prop_bufferSizeIS = 0
		[Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_INSTALL_STATE, [ref]$my_prop_typeIS, $my_prop_bufferIS, 0, [ref]$my_prop_bufferSizeIS) | out-null
		[byte[]]$my_prop_bufferIS = New-Object byte[] $my_prop_bufferSizeIS

		$my_prop_typeCLSS = 0
		[byte[]]$my_prop_bufferCLSS = $null
		$my_prop_bufferSizeCLSS = 0
		[Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_CLASS, [ref]$my_prop_typeCLSS, $my_prop_bufferCLSS, 0, [ref]$my_prop_bufferSizeCLSS) | out-null
		[byte[]]$my_prop_bufferCLSS = New-Object byte[] $my_prop_bufferSizeCLSS
		[Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_CLASS, [ref]$my_prop_typeCLSS, $my_prop_bufferCLSS, $my_prop_bufferSizeCLSS, [ref]$my_prop_bufferSizeCLSS)  | out-null
		$my_dev_class = [System.Text.Encoding]::Unicode.GetString($my_prop_bufferCLSS)

		if(![Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_FRIENDLYNAME, [ref]$my_prop_type, $my_prop_buffer, $my_prop_bufferSize, [ref]$my_prop_bufferSize)){
			[Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_DEVICEDESC, [ref]$my_prop_typeDD, $my_prop_bufferDD, $my_prop_bufferSizeDD, [ref]$my_prop_bufferSizeDD)  | out-null
			$my_friendlyname = [System.Text.Encoding]::Unicode.GetString($my_prop_bufferDD)
			if ($my_friendlyname.Length -ge 1) {
				$my_friendlyname = $my_friendlyname.Substring(0,$my_friendlyname.Length-1)
			}
		} else {
			$my_friendlyname = [System.Text.Encoding]::Unicode.GetString($my_prop_buffer)
			if ($my_friendlyname.Length -ge 1) {
				$my_friendlyname = $my_friendlyname.Substring(0,$my_friendlyname.Length-1)
			}
		}

		$my_install_state = [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_INSTALL_STATE, [ref]$my_prop_typeIS, $my_prop_bufferIS, $my_prop_bufferSizeIS, [ref]$my_prop_bufferSizeIS)

		if(![Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($my_devs, [ref]$my_devinfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_HARDWAREID, [ref]$my_prop_typeHWID, $my_prop_bufferHWID, $my_prop_bufferSizeHWID, [ref]$my_prop_bufferSizeHWID)){
			$my_hardware_id = ""
		} else {
			$my_hardware_id = [System.Text.Encoding]::Unicode.GetString($my_prop_bufferHWID)
			$my_hardware_id = $my_hardware_id.split([char]0x0000)[0].ToUpper()
		}
		$my_device = New-Object System.Object
		$my_device | add-member -type NoteProperty -name FriendlyName -value $my_friendlyname
		$my_device | add-member -type NoteProperty -name HWID -value $my_hardware_id
		$my_device | add-member -type NoteProperty -name InstallState -value $my_install_state
		$my_device | add-member -type NoteProperty -name Class -value $my_dev_class
		if (($my_dev_class -eq "Net") -and ($my_install_state -eq $false)) {
			if ([Win32.SetupApi]::SetupDiRemoveDevice($my_devs, [ref]$my_devinfo)) {
				write-host " Removed device $($my_friendlyname)"
			} else {
				write-host " Failed to remove device $($my_friendlyname)"
			}
		}
		if ($my_array.count -le 0) { sleep 1 }
		$my_array += @($my_device)
		$my_int_devcount++
	}
}


# ErrorActionPreference Continue required to make redirect wmi tool output to file work without error
$backupErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
if ($args[0] -like "source"){
    Write-Output Capturing the ip information in $TMPFILE
    cmd.exe /c "$WMIUTIL -dump $TMPFILE" 2>&1 | % { "$_" } | Out-File $WMIUTIL_DUMP_LOG
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        Write-Output "wmi-net-util command failed"
        Write-Output "wmi-net-util command failed" > $RESULT_FILE
        exit $ExitCode
    }
    Write-Output "Capturing the static route information in $ROUTEFILE"
    cmd.exe /c "$WMIUTIL -dumpRoutes $ROUTEFILE" 2>&1 | % { "$_" } | Out-File $WMIUTIL_DUMP_LOG
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        Write-Output "static-route dump failed"
        Write-Output "static-route dump failed" > $RESULT_FILE
        exit $ExitCode
    }
    Write-Output "success" > $RESULT_FILE

} elseif ($args[0] -like "target"){
    Write-Output "Capturing the NIC information on AHV" >> $WMI_NIC_DUMP_LOG
    Get-Date >> $WMI_NIC_DUMP_LOG
    cmd.exe /c "$WMIUTIL -dump $WMINICDUMPFILE" 2>&1 | % { "$_" } | Out-File $WMIUTIL_DUMP_LOG
    Get-Content $WMINICDUMPFILE >> $WMI_NIC_DUMP_LOG
    if ($LASTEXITCODE -ne 0) {
        Write-Output "wmi-net-util command failed on AHV while capturing nic information." >> $WMI_NIC_DUMP_LOG
    }
    Write-Output "Completed capturing the NIC information" >> $WMI_NIC_DUMP_LOG
    if ($SkipRemoveGhostNIC -eq $false) {
        Write-Output "Removing ghost NICs completely"
        Remove-Ghost-Nics
    }
    Get-Date >> $WMI_NIC_DUMP_LOG
    Write-Output "Applying the ip information from $TMPFILE"
    cmd.exe /c "$WMIUTIL -restoreStatic $TMPFILE" 2>&1 | % { "$_" } | Out-File $WMIUTIL_RESTORE_LOG
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        Write-Output "Restore network configuration failed"
        Write-Output "Restore network configuration failed" > $RESULT_FILE
        exit $ExitCode
    }
    if ( $(Get-Content $ROUTEFILE) -ne "[]" ) {
        Start-Sleep -s 120
        Write-Output "Applying the static route information from $ROUTEFILE"
        cmd.exe /c "$WMIUTIL -restoreRoutes $ROUTEFILE -sourceNICs $TMPFILE"  2>&1 | % { "$_" } | Out-File $WMIUTIL_ROUTES_RESTORE_LOG
        $ExitCode = $LASTEXITCODE
        if ($ExitCode -ne 0) {
            Write-Output "static-route restoration failed"
            Write-Output "static-route restoration failed" > $RESULT_FILE
            exit $ExitCode
        }
    }
    Write-Output "Reregistering DNS"
    cmd.exe /c "ipconfig /flushdns && ipconfig /registerdns" >> $WMIUTIL_RESTORE_LOG
    $ExitCode = $LASTEXITCODE
    if ($ExitCode -ne 0) {
        Write-Output "Reregistering DNS failed moving on"
        Write-Output "Reregistering DNS failed moving on" > $RESULT_FILE
    }
}
$ErrorActionPreference = $backupErrorActionPreference
exit 0