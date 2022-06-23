## Get-AVInfo

> This function is meant to be used internally. I've posted it here so other techs from the team can easily download the latest copy when needed.  

### Usage instructions

---

The primary use-case for this function is running it backstage in CWC, when troubleshooting AV issues. 
From a PowerShell prompt on the machine in question, simply paste the one-liner below and press Enter. Then run 'Get-AVInfo', along with whatever parameters you wish to use, if any.  

Feel free to message me with any questions or suggestions.  

    wget -uri 'https://raw.githubusercontent.com/stangh/Get-AVInfo/master/Get-AVInfo.ps1' -UseBasicParsing | iex

### Features

---

In addition to retrieving information pertaining to the various antivirus programs installed on a machine, this script can also perform the following useful actions:
- **Bitdefender**
    - Update Bitdefender defs
- **Windows Defender**
    - Update Windows Defender defs
    - Test which components of Windows Defender are enabled and which are not
    - Test if Windows Defender is disabled in the Registry
- **Vipre**
    - Update Vipre defs
    - Enable Vipre when it is disabled
    - Enable Vipre's Active Protection if it is disabled
    - Rename the definitions folder (for when defs are corrupted)
    - Test if the machine is being blocked from reaching the Vipre portal (due to a web content filter for ex.)
- **Sophos**
    - Test if Sophos Tamper Protection is enabled 
- **Return information about the Hardware, Operating System and User**

### Help

---

As with all things PowerShell, read the detailed help provided in the script to learn how to use it. Just run:
    
    Help Get-AVInfo -Detailed