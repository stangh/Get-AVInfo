## Get-AVInfo

> This function is meant to be used internally. I've posted it here so other techs from the team can easily download the latest copy when needed.  

### Usage instructions

---

The primary use-case for this function is running it backstage in CWC, when troubleshooting AV issues. 
From a PowerShell prompt on the machine in question, simply paste the one-liner below and press Enter. Then run 'Get-AVInfo', along with whatever parameters you wish to use, if any.

(Note: If 'wget' isn't recognized as a valid command (think Windows 7 machines..), just manually copy and paste the contents of the script on the machine.)

Feel free to message me with any questions or suggestions.  

    wget -uri 'https://raw.githubusercontent.com/stangh/Get-AVInfo/master/Get-AVInfo.ps1' -UseBasicParsing | iex

### Features

---

This script retrieves information pertaining to the various antivirus programs installed on a machine:
- It returns a list of AVs installed on a machine pulled from installed services (using a static list)
- It returns a list of AVs on a machine registered in the Windows Security Center
- It returns a list of AVs installed on a machine as seen in the AV part of the Registry


This script can also perform the following useful actions:
- **Bitdefender**
    - Update Bitdefender definitions
- **Windows Defender**
    - Update Windows Defender definitions
    - Reset Windows Defender definitions
    - Return which components of Windows Defender are enabled and which are not
    - Test if Windows Defender is disabled in the Registry
    - Enable Windows Defender in the Registry
    - Enable Windows Defender if it is disabled
    - Disable UI lockdown
    - Enable UI lockdown
- **Vipre**
    - Update Vipre definitions
    - Enable Vipre when it is disabled
    - Enable Vipre Active Protection if it is disabled
    - Rename the definitions folder (for when definitions are corrupted)
    - Test if the machine is being blocked from reaching the Vipre portal (due to a web content filter for ex.)
    - Download (transfer from a share) and install Vipre
    - Test for Vipre version 12.0 (buggy version)
    - Test for (incompatible) ARM processors
    - Run an ongoing test to check if defs are curently updating and let you know when they're finished updating
    - Run an ongoing test to check if an agent is shut down and let you know once it's shutdown (for when an agent shutdown command is initiated from the Vipre portal)
    - Uninstall Vipre
- **Sophos**
    - Test if Sophos Tamper Protection is enabled
- **Symantec**
    - Download (transfer from a share) and run the CleanWipe utility
- **Unregister AV**
    - Unregister an AV from the Windows Security Center
- **Return information about the Hardware, Operating System and User**

### Help

---

As with all things PowerShell, read the detailed help provided in the script to learn how to use it. Just run:
    
    Help Get-AVInfo -Detailed

For a quick view of the different parameters you can use when running the script, paste the following:

    Get-Command Get-AVInfo -Syntax