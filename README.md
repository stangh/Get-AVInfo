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
- It returns a list of AVs by querying installed services (using a static list)
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
    - Enable Windows Defender in the Registry by creating or setting the applicable Windows Defender registry keys
    - Enable Windows Defender if it is disabled
    - Disable UI lockdown
    - Enable UI lockdown
    - Test if Tamper Protection is enabled
    - Open the MpCmdRun.log file
    - Install the Windows Defender feature on servers
    - Manually update NIS definitions (for specific use cases)
- **Vipre**
    - Update Vipre definitions
    - Enable Vipre when it is disabled
    - Enable Vipre Active Protection if it is disabled
    - Rename the definitions folder (for when definitions are corrupted)
    - Test if the machine is being blocked from reaching the Vipre portal (due to a web content filter for ex.)
    - Download (via share transfer) and install Vipre
    - Test for Vipre version 12.0 (buggy version)
    - Test for (Vipre-incompatible) ARM processors
    - Check if defs are curently updating and let you know when they're finished updating
    - Check if the Vipre agent is shut down and, if it isn't, let you know once it's shutdown (to be used for ex. when an agent shutdown command is initiated from the Vipre portal)
    - Install Vipre (via share transfer)
    - Uninstall Vipre (using the Vipre Removal Tool)
- **Sophos**
    - Test if Sophos Tamper Protection is enabled
- **Symantec**
    - Download (via share transfer) and run the CleanWipe utility
- **Avast**
    - Download and run the Avast Removal Tool
- **Norton**
    - Download and run the Norton Remove and Reinstall tool
- **McAfee**
    - Download and run the McAfee Consumer Product Removal tool
- **Malwarebytes**
    - Run the built-in Malwarebytes uninstaller
- **Kaspersky**
    - Download and run the kavremover tool
- **Webroot**
    - Uninstall Webroot by installing an msi on top of the existing installation and then uninstall using the same msi right after
    - Uninstall Webroot by downloading and running the CleanWDF tool
- **HP Wolf**
    - Uninstall HP Wolf security products in a specific order
- **Unregister AV**
    - Unregister AVs from the Windows Security Center
- **RMMs**
    - Check for the presence of specific RMM tools
- **Pending Reboot**
    - Check if a machine is pending a reboot
- **Return information about the Hardware, Operating System and User**

### Help

---

As with all things PowerShell, read the detailed help provided in the script to learn how to use it. Just run:
    
    Help Get-AVInfo -Detailed

For a quick view of the different parameters you can use when running the script, paste the following:

    Get-Command Get-AVInfo -Syntax