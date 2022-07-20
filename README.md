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

In addition to retrieving information pertaining to the various antivirus programs installed on a machine, this script can also perform the following useful actions:
- **Bitdefender**
    - Update Bitdefender definitions
- **Windows Defender**
    - Update Windows Defender definitions
    - Return which components of Windows Defender are enabled and which are not
    - Test if Windows Defender is disabled in the Registry
- **Vipre**
    - Update Vipre definitions
    - Enable Vipre when it is disabled
    - Enable Vipre Active Protection if it is disabled
    - Rename the definitions folder (for when definitions are corrupted)
    - Test if the machine is being blocked from reaching the Vipre portal (due to a web content filter for ex.)
    - Download and install Vipre
- **Sophos**
    - Test if Sophos Tamper Protection is enabled 
- **Symantec**
    - Download and run the CleanWipe utility
- **Return information about the Hardware, Operating System and User**

### Help

---

As with all things PowerShell, read the detailed help provided in the script to learn how to use it. Just run:
    
    Help Get-AVInfo -Detailed

For a quick view of the different parameters you can use when running the script, paste the following:

    Get-Command Get-AVInfo -Syntax