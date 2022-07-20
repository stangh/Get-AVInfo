function Get-AVInfo {
    <#
.SYNOPSIS
The script looks for and returns many different AVs on a system. It also displays detailed information on either Vipre, Bitdefender, or Windows Defender, depending on the switch you run with the command. The script can also be used to either enable Vipre, or update Vipre, Windows Defender or Bitdefender definitions, as well as test if the machine can reach intellisecure.myvipre.com.
.DESCRIPTION
This script first queries the machine for a bunch of different AVs, from a predefined list, by searching installed services. It then uses CIM (or WMI) to retrive any AVs registered with Windows. The script then retrieves more detailed information about the specific AV you specify (Vipre, Bitdefender, or Windows Defender); if nothing is specified, the default is Vipre, unless the 'DefaultOverride' parameter is used. Finally, the script retrieves basic information about the hardware and operating system, often helpful when troubleshooting things like out-of-date definitions. 
The script can do other things as well, like update definitions for the different antiviruses, as well as other useful checks and actions. For more information about what the script can do, read the README.md file in github (link below), and check out the PowerShell help on the parameters, provided with this script. There are also tests and checks that happen in the background that are not listed here or in the parameter help (but are in the github README.md file), and that only show up in the script results if found to be true. For more on that, you'll have to read through the actual script:)
Github link: https://github.com/stangh/Get-AVInfo
.PARAMETER Bitdefender
Returns detailed information about Bitdefender installed on the system. Cannot be used with Vipre and Windows Defender parameters.
.PARAMETER UpdateBDDefs
Updates Bitdefender definitions. Cannot be used with any other parameter.
.PARAMETER WindowsDefender
Returns detailed information about Windows Defender installed on the system. Cannot be used with Vipre and Bitdefender parameters.
When specifiying this parameter, the script will also look for the registry key that disables Windows Defender and prevents it from starting.
.Parameter UpdateWDDefs
Updates Windows Defender definitions. Cannot be used with any other parameter.
.PARAMETER Viper
Returns detailed information about Vipre installed on the system. This is the default, if no AV is specified. Cannot be used with Bitdefender and Windows Defender parameters.
When specifiying this parameter, the script will also test that the machine can reach intellisecure.myvipre.com.
Vipre is the default, when no AV is specified.
.PARAMETER DefaultOverride
Overrides the default behavior of retrieving Vipre information, when no other AV is specified. This cannot be used with any parameter other than the 'NoMachineInfo' parameter.
.PARAMETER InstallVipre
Downloads the Vipre installer from our LTShare and runs it.
.PARAMETER UpdateVipreDefs
Updates Vipre definitions. Can only be used with the EnableVipre parameter.
.PARAMETER NoMachineInfo
When specifying this parameter, the script does not check for hardware and OS information. 
Cannot be used with the 'action' parameters (such as UpdateVipreDefs); 'NoMachineInfo' is the default in such cases.
.PARAMETER EnableVipre
Enables SBAMSvc. For when the SBAMSvc service is in a disabled state. Can only be used with the UpdateVipreDefs parameter.
.PARAMETER EnableVipreAP
Enables Vipre's Active Protection when it is disabled. This does not make changes to the services themselves.
.PARAMETER RenameDefsFolder
Renames the definitions folder, for when defs are corrupted. NOTE: The SBAMSvc service must be in a stopped state, or else permission to rename the folder will be denied.
.PARAMETER CleanWipe
The script looks for the CleanWipe utility in two different places, and runs it. 
On Windows 7 machines, the CleanWipe utility cannot be run from where ScreenConnect puts it. If the utility is found in that location, PowerShell will move it to 'C:\Windows\Temp\CleanWipe', and then run it from there.
.EXAMPLE
    PS C:\> Get-AVInfo -WindowsDefender
    This retrieves AVs installed on the system, as well as detailed information on Windows Defender.
.EXAMPLE
    PS C:\> Get-AVInfo -Vipre -NoMachineInfo
    This retrieves AVs installed on the system, as well as detailed information on Vipre.
    Specifying the 'NoMachineInfo' switch parameter, causes the command to skip the hardware and OS checks.
.EXAMPLE
    PS C:\> Get-AVInfo -EnableVipre
    Running this enables the SBAMSvc service and starts it.
.EXAMPLE
    PS C:\> Get-AVInfo -UpdateBDDefs
    Updates Bitdefender definitions on the machine.
.INPUTS
    Inputs (if any)
.OUTPUTS
    Output (if any)
.NOTES
    This script can be run on a machine in Automate, backstage. Simply paste the contents of this function into the shell and press enter, to load the script into memory. Then, just run 'Get-AVInfo', along with whatever parameters, if any, you want to add.
    
    =================================
    Author: Eliyohu Stengel
    Email: estengel@intellicomp.net
    Comments and suggestions welcome!
    =================================
#>
    [CmdletBinding(DefaultParameterSetName = 'Vipre')]
    param (
        [Parameter(parametersetname = 'Bitdefender',
            Mandatory = $false)]
        [Alias("BD")]
        [Switch]$Bitdefender,

        [Parameter(parametersetname = 'WindowsDefender',
            Mandatory = $false)]
        [Alias("WD")]
        [switch]$WindowsDefender,

        [Parameter(parametersetname = 'Vipre',
            Mandatory = $false)]
        [switch]$Vipre,

        [Parameter(parametersetname = 'Default_Override',
            Mandatory = $false)]
        [Switch]$DefaultOverride,

        [Parameter(parametersetname = 'Vipre_Action',
            Mandatory = $false)]
        [Switch]$EnableVipre,
        
        [Parameter(parametersetname = 'Vipre_Action',
            Mandatory = $false)]
        [Switch]$UpdateVipreDefs,

        [Parameter(parametersetname = 'Vipre_Action',
            Mandatory = $false)]
        [Switch]$EnableVipreAP,

        [Parameter(parametersetname = 'Vipre_Action',
            Mandatory = $false)]
        [Switch]$RenameDefsFolder,

        [Parameter(parametersetname = 'Vipre_Install',
            Mandatory = $false)]
        [Switch]$InstallVipre,

        [Parameter(parametersetname = 'WindowsDefender_Action',
            Mandatory = $false)]
        [Switch]$UpdateWDDefs,

        [Parameter(ParameterSetName = 'Bitdefender_Action',
            Mandatory = $false)]
        [Switch]$UpdateBDDefs,

        [Parameter(parametersetname = 'Vipre')]
        [Parameter(parametersetname = 'Bitdefender')]
        [Parameter(parametersetname = 'WindowsDefender')]
        [Parameter(parametersetname = 'Default_Override')]
        [Switch]$NoMachineInfo,

        # for the TT Symantec ticket only
        [Parameter(parametersetname = 'Symantec',
            Mandatory = $false)]
        [Switch]$CleanWipe
    )

    BEGIN {
        Write-Verbose "[BEGIN  ] Starting: $($MyInvocation.MyCommand)"
    }
    PROCESS {
        switch ($PSCmdlet.ParameterSetName) {
            'Vipre_Action' { 
                if ($EnableVipre) {
                    Write-Verbose "Enabling SBAMSvc"
                    if (!(Get-Service SBAMSvc -ErrorAction SilentlyContinue)) {
                        Write-Warning "No SBAMSvc service present. Cannot enable Vipre."
                    }
                    elseif ( ((Get-Service SBAMSvc).StartType -eq 'Automatic') -and ((Get-Service SBAMSvc).status -eq 'Running')) {
                        Write-Host -ForegroundColor Green "SBAMSvc is already set to auto-start, and is running."
                    }
                    else {
                        Write-Verbose "Enabling SBAMSvc and starting it"
                        Set-Service SBAMsvc -StartupType Automatic -Status Running
                        Get-Service SBAMSvc | Format-Table Name, DisplayName, Status, StartType
                    }
                } # if $EnableVipre
                if ($UpdateVipreDefs) {
                    if (!(Test-Path 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe')) {
                        Write-Warning "Cannot update Vipre definitions. Core Vipre files are missing. Please (re)install Vipre and try again."
                    }
                    else {
                        Write-Verbose "Updating Vipre definitions"
                        & 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe' /updatedefs
                        Write-Host -ForegroundColor Green 'Date & time definitions last updated:'
                        $Date = (& 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe' /displaylocaldefversion).Substring('9'); $Date1 = $Date.split('T'); "Date: $($Date1[0]) Time: $($Date1[1])"
                    } # if Test-Path
                } # if $UpdateVipreDefs
                if ($EnableVipreAP) {
                    if (!(Test-Path 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe')) {
                        Write-Warning "Cannot enable active protection. Core Vipre files are missing. Please (re)install Vipre and try again."
                    }
                    else {
                        Write-Verbose "Enabling Vipre Active Protection"
                        $APState = & 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe' /apstate
                        if ($APState -eq 'Enabled') {
                            Write-Host -ForegroundColor Green "Vipre Active Protection is already enabled."
                        }
                        else {
                            & 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe' /enableap
                            $APState = & 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe' /apstate
                            if ($APState -eq 'Enabled') {
                                Write-Host -ForegroundColor Green "Vipre Active Protection successfully enabled."                        
                            }
                            else {
                                Write-Warning "Vipre Active Protection is still not enabled. Please look into this."
                            }
                        }
                    } # if Test-Path
                } # if $EnableVipreAP
                if ($RenameDefsFolder) {
                    if (!(Test-Path 'C:\Program Files*\VIPRE Business Agent\Definitions')) {
                        Write-Warning "Cannot rename definitions folder. Definitions folder is not present."
                    }
                    else {
                        if ((Get-Service SBAMSvc).Status -eq 'Stopped') {
                            Rename-Item -Path 'C:\Program Files (x86)\VIPRE Business Agent\Definitions\' -NewName "Definitions.old$(Get-Random)"
                        }
                        else {
                            Write-Host -ForegroundColor Green "Cannot rename the definitions folder while the SBAMSvc service is running. `nStop Vipre from the portal, and then try again."
                        }
                    } # if Test-Path
                } # if $RenameDefsFolder
            } # if ParameterSet 'Vipre_Action'
            'WindowsDefender_Action' {
                Write-Verbose "Updating Windows Defender definitions"
                # Can also use 'Update-MpSignature', but it returns less verbose output than the below command
                & 'C:\Program Files\Windows Defender\MpCmdRun.exe' -signatureupdate
            }
            'Bitdefender_Action' {
                Write-Verbose "Updating Bitdefender definitions"
                & "C:\Program Files\Bitdefender\Endpoint Security\product.console.exe" /c StartUpdate
            }
            'Vipre_Install' {
                $Answer = Read-Host "Would you like to download the Vipre installer to the machine? (Y/N)"
                if ($Answer -eq 'Y') {
                    Write-Host -ForegroundColor Green "Downloading Vipre installer from LTShare. Please wait.."
                    # To account for Windows 7 machines I do not use the Invoke-WebRequest or Invoke-RestMethod cmdlets for downloading the installer
                    (New-Object Net.WebClient).DownloadFile("https://labtech.intellicomp.net/labtech/transfer/Tools/vipre_agent_intellisecure_12.3.8160.msi", "C:\Windows\Temp\VipreInstaller.msi")
                    Write-Host -ForegroundColor Green "Download complete (version 12.3.8160).`nInstaller saved to 'C:\Windows\Temp\VipreInstaller.msi'."
                    $Answer1 = Read-Host "Run the installer? (Y/N)"
                    if ($Answer1 -eq 'Y') {
                        & "C:\Windows\Temp\VipreInstaller.msi"
                    }
                    elseif ($Answer1 -eq 'N') {
                        Write-Host -ForegroundColor Green "Installer will NOT be run.`nExiting script."
                    }
                }
                elseif ($Answer -eq 'N') {
                    Write-Host -ForegroundColor Green "Cancelling the installer download.`nExiting the script."  
                } 
            } # if ParameterSet 'Vipre_Install'
            'Symantec' {
                if (Test-Path 'C:\Windows\Temp\CleanWipe') {
                    Write-Verbose "The CleanWipe utility is present at 'C:\Windows\Temp\CleanWipe'.`nRunning the utility."
                    Start-Process "C:\Windows\Temp\CleanWipe\CleanWipe.exe"
                }
                elseif (Test-Path 'C:\Windows\system32\config\systemprofile\Documents\IntelliCare Control\Files\*cleanwipe*') {
                    # if SC was used to transfer the utility to the machine, it's found at this location, 
                    # and since the utility cannot typically be run from where ScreenConnect drops it, move it is nec.
                    Write-Verbose "Moving the Symantec CleanWipe tool to C:\Windows\Temp"
                    Move-Item -Path 'C:\Windows\system32\config\systemprofile\Documents\IntelliCare Control\Files\*cleanwipe*' -Destination 'C:\Windows\Temp\CleanWipe'
                    Start-Process 'C:\Windows\Temp\CleanWipe\CleanWipe.exe'
                }
                else {
                    Write-Host "The CleanWipe folder cannot be found."
                    $Answer = Read-Host "Would you like to download the CleanWipe utility? (Y/N)"
                    if ($Answer -eq 'Y') {
                        Write-Verbose 'Downloading the utility'
                        # To account for Windows 7 machines, I don't use the typical Invoke-WebRequest and Expand-Archive cmdlets below
                        (New-Object Net.WebClient).DownloadFile("https://labtech.intellicomp.net/labtech/transfer/Tools/CleanWipe_14.3_8259.zip", "C:\Windows\Temp\CleanWipe.zip")
                        Write-Verbose "Download complete"
                        Write-Verbose "Expanding the downloaded zip file and running it"
                        # using the .NET method, to account for Windows 7 machines that don't have the 'Expand-Archive' cmdlet
                        Add-Type -AssemblyName "System.IO.Compression.Filesystem"
                        [System.IO.Compression.ZipFile]::ExtractToDirectory("C:\Windows\Temp\CleanWipe.zip", "C:\Windows\Temp\CleanWipe")
                        Start-Process "C:\Windows\Temp\CleanWipe\CleanWipe.exe"
                    } # if 'Y'
                    elseif ($Answer -eq 'N') {
                        Write-Host "Exiting script."
                    } # if 'N'
                }
            } # if ParameterSet 'Symantec'
            Default {
                Write-Verbose -Message "Retrieving AVs by querying services"
                $Services = Get-Service -DisplayName *vipre*, *SBAMSvc*, *defend*, *trend*, *sophos*, *N-able*, *symantec*, *webroot*, *cylance*, *mcafee*, *avg*, *santivirus*, *segurazo*, *avira*, *malware*, *kaspersky*, *sentinel*, *avast* -Exclude *firewall*, '*AMD Crash*'
        
                Write-Verbose -Message "Retrieving AVs registered with Windows by querying WMI"
                if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
                    # Servers don't have the 'securitycenter2' namespace, hence the need for the ErrorAction below
                    # Instead, you can run the following on servers (for WD): Get-CimInstance -Namespace root\Microsoft\protectionmanagement -class MSFT_MpComputerStatus 
                    $AV = Get-CimInstance antivirusproduct -Namespace root\securitycenter2 -ErrorAction SilentlyContinue -Verbose:$false
                    if (!$AV) {
                        $AV = Get-CimInstance antispywareproduct -Namespace root\securitycenter2 -ErrorAction SilentlyContinue -Verbose:$false
                    } 
                } # if Get-CimInstance
                else {
                    $AV = Get-WmiObject antivirusproduct -Namespace root\securitycenter2 -ErrorAction SilentlyContinue -Verbose:$False
                    if (!$AV) {
                        $AV = Get-WmiObject antispywareproduct -Namespace root\securitycenter2 -ErrorAction SilentlyContinue -Verbose:$False
                    }
                } # if !Get-CimInstance
        
                if ($Bitdefender) {
                    Write-Verbose -Message "Retrieving Bitdefender info"
                    if ($BDProc = Get-Process EPSecurityService -ErrorAction SilentlyContinue) {
                        # Bitdefender definitions update info
                        $UpdateStatus = & "C:\Program Files\Bitdefender\Endpoint Security\product.console.exe" /c GetUpdateStatus antivirus
                        # Bitdefender version number
                        $BDVersion = & 'C:\Program Files\Bitdefender\Endpoint Security\product.console.exe' /c GetVersion antivirus
                        Write-Verbose "Performing epoch time conversion"
                        try {
                            # save last update time to variable
                            $EpochTimeUpdate = ($UpdateStatus.Split(': ')[2]).split('')[0]
                            # convert from epoch time to standard time
                            $ConvertedUpdateTime = (([System.DateTimeOffset]::FromUnixTimeSeconds($EpochTimeUpdate)).DateTime)
                            # save last attempted update time to variable
                            $EpochTimeAttempt = ($UpdateStatus.Split(': ')[5]).split('')[0]
                            # convert from epoch time to standard time
                            $ConvertedAttemptTime = (([System.DateTimeOffset]::FromUnixTimeSeconds($EpochTimeAttempt)).DateTime)
                            # last update exit status
                            $Num = $UpdateStatus.Split(': ')[8]
                            if ($Num -eq '0') {
                                $Var = $true
                            }
                            else {
                                $Var = $false
                            }
                            $BDProps = [Ordered]@{
                                'Product version'                   = $BDProc.FileVersion
                                'Engine version'                    = $BDVersion
                                'Definitions last updated'          = $ConvertedUpdateTime
                                'Definitions update last attempted' = $ConvertedAttemptTime
                                'Last update successfull'           = $Var
                            }
                            $BDVar = New-Object -TypeName psobject -Property $BDProps
                        } # try
                        catch {
                            # suppresses the error that occurs when attempting to call a method on a null-valued expression, 
                            # which happens when Bitdefender feeds error codes to $UpdateStatus instead of meaningful data
                        }
                    } # if $BDProc
                    else {
                        $BDVar = "Bitdefender is either not installed or else not running."
                    } # else $BDProc
                } # if BitDefender
                elseif ($WindowsDefender) {
                    try {
                        Write-Verbose -Message "Retrieving Windows Defender info"
                        $WDStatus = Get-MpComputerStatus -ErrorAction Stop
                        # $WDPreference = Get-MpPreference -ErrorAction Stop
                        # $WDServices = $WDStatus | Select-Object *enable*
                        $WDProps = [Ordered]@{
                            'AMServiceEnabled'                                                  = $WDStatus.AMServiceEnabled
                            'AntispywareEnabled'                                                = $WDStatus.AntispywareEnabled
                            'AntivirusEnabled'                                                  = $WDStatus.AntivirusEnabled
                            'BehaviorMonitorEnabled'                                            = $WDStatus.BehaviorMonitorEnabled
                            'IoavProtectionEnabled (Scan all downloaded files and attachments)' = $WDStatus.IoavProtectionEnabled
                            'NISEnabled (Network Realtime Inspection)'                          = $WDStatus.NISEnabled
                            'OnAccessProtectionEnabled (file and program activity monitoring)'  = $WDStatus.OnAccessProtectionEnabled
                            'RealTimeProtectionEnabled'                                         = $WDStatus.RealTimeProtectionEnabled
                        }
                        $WDObjEnabled = New-Object -TypeName psobject -Property $WDProps
                            
                        $Props = [Ordered]@{
                            'Signatures version'               = $WDStatus.AntispywareSignatureVersion
                            'Version created on'               = $WDStatus.AntispywareSignatureLastUpdated
                            'Last update in days (0 is today)' = $WDStatus.AntispywareSignatureAge
                            'Signatures out of date'           = $WDStatus.DefenderSignaturesOutOfDate
                        }
                        $WDObj = New-Object -TypeName psobject -Property $Props
                    } # try
                    catch {
                        $WDMessage = $($Error[0])
                    }
                    Write-Verbose "Checking value of Windows Defender Registry key"
                    $RegKey = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue
                    # 'C:\Program Files\Windows Defender\MpCmdRun.exe' -wdenable ?
                } # elseif $WindowsDefender
                elseif (!$DefaultOverride -or $Vipre) {
                    try {
                        Write-Verbose -Message "Retrieving Vipre info"
                        if (Get-Process SBAM* -ErrorAction Stop) {
                            if (!(Get-Process SBAMTray -ErrorAction SilentlyContinue)) { Start-Process 'C:\Program Files (x86)\Vipre Business Agent\SBAMTray.exe' } # For when SBAMSvc is running, while SBAMTray is not
                            $VipreVar = Get-Process SBAMtray -ErrorAction SilentlyContinue | Select-Object -First 1 | Format-Table `
                            @{ n = 'Vipre Version'; e = { $_.FileVersion } }, 
                            @{ n = 'Active Protection State'; e = { & 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe' /apstate } }, 
                            @{ n = 'Date & time definitions last updated'; e = { $Date = (& 'C:\Program Files*\VIPRE Business Agent\SBAMCommandLineScanner.exe' /displaylocaldefversion).Substring('9'); $Date1 = $Date.split('T'); "Date: $($Date1[0]) Time: $($Date1[1])" } }
                            #[datetime](($var -split '- ')[1])
                        }
                        elseif ((Get-Service SBAMsvc -ErrorAction SilentlyContinue).StartType -eq 'Disabled') { 
                            $VipreVar = "Vipre is installed, but SBAMSvc is in a disabled state.`nTo enable the service and start it, re-run Get-AVInfo with the 'EnableVipre' parameter."
                        }
                        else { 
                            $VipreVar = "Vipre is either not installed or else not running." 
                        } # if SBAM*
                    }
                    catch {
                        $Message = $($Error[0])
                    }
                    Write-Verbose "Checking if machine can reach intellisecure.myvipre.com"
                    try {
                        $Pref = $ProgressPreference
                        $ProgressPreference = 'SilentlyContinue'
                        $WebFilter = (Invoke-WebRequest intellisecure.myvipre.com -UseBasicParsing -ErrorAction Stop -Verbose:$false).content 
                        $ProgressPreference = $Pref
                        if ($WebFilter -like "*<title>Website Filtered</title>*") {
                            $Blocked = "`nThe machine cannot reach out to Vipre on domain intellisecure.myvipre.com. It may be blocked by a web content filter, or other network issue."
                        }
                    }
                    catch {
                        $Blocked = "Failed to test connection to intellisecure.myvipre.com. `nPlease test manually if services won't start, or if Vipre is otherwise not working as expected."
                    } 
                } # else if !$DefaultOverride -or $Vipre

                if (Test-Path 'C:\Program Files\Sophos' -PathType Container) {
                    Write-Verbose "Checking Sophos Tamper Protection status"
                    # https://support.sophos.com/support/s/article/KB-000043008?language=en_US
                    $Sophos = & 'C:\Program Files\Sophos\Endpoint Defense\SEDcli.exe' -status -ErrorAction SilentlyContinue
                    if ($Sophos -like "*Enabled*") {
                        $SophosTPEnabled = $true
                    }
                }

                if (!$NoMachineInfo -and (Get-Command Get-CimInstance -ErrorAction SilentlyContinue)) {
                    Write-Verbose -Message "Retrieving OS info" 
                    # Verbose messages from Get-CimInstance are suppressed, even if the -Verbose parameter is specified when running the function
                    $BIOS = Get-CimInstance -ClassName win32_Bios -Verbose:$false
                    $OS = Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$false
                    $UT = (Get-Date) - $OS.LastBootUpTime # needed for formating the timespan object for on-screen output
                    $CS = Get-CimInstance -ClassName Win32_ComputerSystem -Verbose:$false
                    $SD = $OS.SystemDrive
                    $LD = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceId='$SD'" -Verbose:$false
                    $Manufacturer = (Get-CimInstance -ClassName Win32_bios -Verbose:$false).Manufacturer
                    if ($CS.Manufacturer) {
                        $M = $CS.Manufacturer
                    }
                    else {
                        $M = $Manufacturer
                    }
                    $Props = [Ordered]@{
                        'SerialNumber'                         = $BIOS.SerialNumber
                        'WindowsVersion'                       = $OS.Caption
                        'BuildNumber'                          = $OS.BuildNumber
                        'Domain'                               = $CS.Domain
                        'UserName'                             = $CS.UserName
                        'Manufacturer'                         = $M
                        'Model'                                = $CS.Model
                        'Architecture'                         = $OS.OSArchitecture
                        'Total Installed Memory (GB, rounded)' = $CS.TotalPhysicalMemory / 1GB -as [int]
                        'SysDriveSize (GB)'                    = $LD.Size / 1GB -as [int]
                        'SysDriveFreeSpace (GB)'               = $LD.FreeSpace / 1GB -as [int]
                        'LastBootTime'                         = $OS.LastBootUpTime
                        'Uptime'                               = "{0:dd}d:{0:hh}h:{0:mm}m" -f $UT
                    }
                    $Obj = New-Object -TypeName psobject -Property $Props
                } # if !$NoMachineInfo

                Write-Verbose -Message "Writing results to the screen"

                Write-Host -ForegroundColor Green "`nAntivirus software present on the machine (pulled from installed services):"
                Write-Output $Services | Sort-Object DisplayName | Format-Table Status, StartType, Name, DisplayName -AutoSize

                Write-Host -ForegroundColor Green "Antivirus software registered with the Windows Security Center (queried from the SecurityCenter2 namespace using CIM or WMI):"
                if (!$AV) {
                    Write-Warning "Failed to retrieve the Antivirus software from the SecurityCenter2 namespace."
                    Write-Host "`n"
                }
                else {
                    Write-Output $AV | Sort-Object displayname | Format-Table displayName, instanceGuid
                }

                if ($Bitdefender) {
                    Write-Host -ForegroundColor Green "Bitdefender Product and Engine (antimalware signatures) versions:"
                    $BDVar | Format-List
                }
                elseif ($WindowsDefender) {
                    if ($WDMessage) {
                        Write-Host -ForegroundColor Green "Windows Defender Info:"
                        Write-Warning "Error retrieving Windows Defender info.`nError message: $($WDMessage)"
                    }
                    else {
                        Write-Host -ForegroundColor Green "Windows Defender Services:"
                        $WDObjEnabled | Format-List
                        Write-Host -ForegroundColor Green "Windows Defender Signatures:"
                        $WDObj | Format-Table
                    }
                    if ($RegKey -and (($RegKey).DisableAntiSpyware -eq '1')) {
                        Write-Host -ForegroundColor Green "Windows Defender Registry key:"
                        "Windows Defender is disabled via the 'DisableAntiSpyware' Registry key at the following location: $($RegKey.PSPath.split('::')[2]).`nTo re-enable, set the value back to '0', or simply delete the key."
                        "Note: If Group Policy is configured to disable Windows Defender, the registry key will revert back to '1', with the next group policy update.`nTo test, run 'gpupdate /force' afer the Registry change.`n"
                    }
                } # elseif $WindowsDefender
                elseif (!$DefaultOverride) {
                    Write-Host -ForegroundColor Green "Version of Vipre on the machine, and the date the definitions last updated:"
                    if ($Message) {
                        Write-Warning "Error retrieving Vipre info.`nError message: $($Message) "
                    }
                    else {
                        Write-Output $VipreVar
                    }
                    Write-Host -ForegroundColor Cyan "$($Blocked)"  
                }
            
                if ($SophosTPEnabled -eq $true) {
                    Write-Warning "Sophos Tamper Protection is enabled on this machine."
                }
            
                if (!$NoMachineInfo) { 
                    Write-Host -ForegroundColor Green "`nHardware, OS and User info:"
                    if ($Obj) {
                        Write-Output $Obj | Format-List 
                        # Format-List is needed for the last verbose message to appear in the right place on screen
                    }
                    else {
                        Write-Warning "Get-CimInstance is not supported on this machine.`nOS info check skipped."
                    } # if $Obj
                } # if !$NoMachineInfo
            } # Default
        } # switch
    } # PROCESS
    END {
        Write-Verbose "[END  ] Ending: $($MyInvocation.MyCommand)"
    }
    
} #function