# Get-AVInfo

This function is meant to be used internally. I've posted it here so other techs from the team can easily download the latest copy when needed.
The primary use-case for this function is running it backstage in CWC, when troubleshooting AV issues. 
From the machine in question, simply paste the one-liner below and press Enter. Then run 'Get-AVInfo', along with whatever parameters you wish to use, if any.
Feel free to message me with any questions.

`wget -uri 'https://raw.githubusercontent.com/stangh/Get-AVInfo/master/Get-AVInfo.ps1' -UseBasicParsing | iex`
