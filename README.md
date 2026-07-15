# This project has been discontinued, the new version is in https://github.com/PowerForensics/ 


# PowerTriage
Powertriage is a DFIR Powershell script to perform a live adquisition of artifacts on a Windows System without external software.

# PowerTriage Script - Extracted Artefacts

PowerTriage collects information from multiple sources, the output by default is in "C:\" folder but you can set an specific folder to perform the adquisition, the folder will be named as 'PowerTriage-hostname-yearmonthdate_hhmmss'. This folder will be zipped once the script finish (and the original folder will be delete), so that zip file could be remotely collected.
PowerTriage script collects the following artifacts:

**Functions**

- System Info
- Network Info:
	- Ip information (All interfaces)
	- TCP_Stablishe_Connections
- Activities Cache (All users)
- Event Logs (Application, Security, System, PowerShell Operational, TaskScheduler Operational, Sysmon Operational, WMI Activity Operational, NTLM Operational, etc.)
- PowerShell Command History (All users)
- Prefetch
- Process Information (Process List, Process Tree, Unique Process Hash)
- Recent Items (All users)
- Recycle Bin (All users)
- Schedule Task (Schedule Task List, Schedule Task Run Info)
- Active Users
- Autoruns
- DNS Cache
- Users:
	- Active Users
	- Local Users
- Services Running
- Shadow Copies List
- Browsers artifacts (Edge, Opera, Chrome, Firefox)
- RDP Connections
- Hashing artifacts
 
**More functions the next update :) ** 

# Windows Usage

PowerTriage script must be run with **admin** privileges for a best performance, if not, not all artifacts will be collect.

The PowerTriage **script is unsigned**, that could result in having to use the **_-ExecutionPolicy Bypass_** to run the script.

The script can be excuted by running the following command.
```.\Powertriage.ps1```
or
```Powershell.exe -ExecutionPolicy Bypass .\PowerTriage.ps1```

If you still have execution problems, you can open the Powershell ise application as administrator and in a new file paste the entire Powertriage.PS1 code and execute it, that will not fail

# EDR/XDR Usage

If you are going to use the script from a Live Response console through an EDR/XDR system, you must comment on the corresponding line (this line has a comment for it)

