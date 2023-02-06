REM Copyright (c) 2017 Nutanix Inc. All rights reserved.

@echo off
set TMPDIR=%SYSTEMDRIVE%\Nutanix\Temp
if not exist %TMPDIR% mkdir %TMPDIR%
set TMPFILE=%TMPDIR%\sanpolicy.txt
set BRING_OFFLINE_DISKS_ONLINE=%TMPDIR%\bring_offline_disks_online.ps1
set BRING_OFFLINE_DISKS_ONLINE_LOG_FILE=%TMPDIR%\bring_offline_disks_online.log

REM This assumes that powershell is available on the windows VM.
REM This logic is added in for bringing offline RDM disks online before applying
REM the san policy. ^ is escape character
echo #Check for offline disks on server. > %BRING_OFFLINE_DISKS_ONLINE%
echo $Log_File =^"%BRING_OFFLINE_DISKS_ONLINE_LOG_FILE%^" >> %BRING_OFFLINE_DISKS_ONLINE%
echo Write-Output ^"list disk^" ^| diskpart ^| Out-File -Force $Log_File >> %BRING_OFFLINE_DISKS_ONLINE%
echo $offlinedisk = ^"list disk^" ^| diskpart ^| where {$_ -match ^"offline^"} >> %BRING_OFFLINE_DISKS_ONLINE%
echo #If offline disk(s) exist >> %BRING_OFFLINE_DISKS_ONLINE%
echo if($offlinedisk) >> %BRING_OFFLINE_DISKS_ONLINE%
echo { >> %BRING_OFFLINE_DISKS_ONLINE%
echo #for all offline disk(s) found on the server >> %BRING_OFFLINE_DISKS_ONLINE%
echo foreach($offdisk in $offlinedisk) >> %BRING_OFFLINE_DISKS_ONLINE%
echo { >> %BRING_OFFLINE_DISKS_ONLINE%
echo $offdiskS = $offdisk.Substring(2,7) >> %BRING_OFFLINE_DISKS_ONLINE%
echo #Creating command parameters for selecting disk, making disk online and setting off the read-only flag. >> %BRING_OFFLINE_DISKS_ONLINE%
echo $OnlineDisk = @^" >> %BRING_OFFLINE_DISKS_ONLINE%
echo select $offdiskS >> %BRING_OFFLINE_DISKS_ONLINE%
echo attributes disk clear readonly >> %BRING_OFFLINE_DISKS_ONLINE%
echo online disk >> %BRING_OFFLINE_DISKS_ONLINE%
echo attributes disk clear readonly >> %BRING_OFFLINE_DISKS_ONLINE%
echo ^"@ >> %BRING_OFFLINE_DISKS_ONLINE%
echo #Sending parameters to diskpart >> %BRING_OFFLINE_DISKS_ONLINE%
echo $OnlineDisk ^| diskpart ^| Tee-Object -Append $Log_File >> %BRING_OFFLINE_DISKS_ONLINE%
echo } >> %BRING_OFFLINE_DISKS_ONLINE%
echo } >> %BRING_OFFLINE_DISKS_ONLINE%
echo else { Write-Output ^"No offline disks^" ^| Out-File -Append $Log_File } >> %BRING_OFFLINE_DISKS_ONLINE%
echo Write-Output ^"list disk^" ^| diskpart ^| Out-File -Append $Log_File >> %BRING_OFFLINE_DISKS_ONLINE%
powershell.exe %BRING_OFFLINE_DISKS_ONLINE%

@echo SAN Policy=OnlineAll > %TMPFILE%
echo rescan >> %TMPFILE%
diskpart /s %TMPFILE%

exit /b %errorlevel%
