# D365tools
'D365CHEtuning.ps1' is used post-creation of CloudHosted D365 DEV servers to tune the performance and add some tools.<br>
- Installs EDGE if needed, Chrome, AzCopy, Notepad++ and Powershell modules D365fo.tools, NuGet, PowerShellGet.
- Set the Windows account passwordpolicy to never expire.
- Sets WinDefender rules that excludes D365 processes and files.
- Sets Power options to "High performance."
- Grant the SQL serviceaccount "Perform Volume Maintenance Task" rights to speedup restore/expanding datadisk.
- Enables Traceflag 7412 in SQL instance to see live execution plans i SSMS.
- Show computericon on Desktop with servername.

The powershellscript 'azopyGetVHDfromLCS.ps1' downloads large files (VHD,PU/QU/SU,etc) from LCS.
Generate SAS links in LCS and paste them into the script in the right order! aka: part1 = .exe, part2 = .rar

'DeployPackage.ps1' automates deploying packages on local D365 DEV machine.
Put the script in a folder with the package zip file and run the powershellscript.
The script handle the Reportservice "bug" not starting during update.
