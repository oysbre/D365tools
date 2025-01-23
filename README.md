# D365tools
'D365CHEtuning.ps1' is used post-creation of CloudHosted D365 DEV servers to tune the performance and add some tools.<br> Open Powershell, copy&paste command and execute to download powershellscript to Desktop<br>
```programming
iwr https://raw.githubusercontent.com/oysbre/D365tools/main/D365CHEtuning.ps1 -outfile "$env:USERPROFILE\Desktop\D365CHEtuning.ps1"
```
- Installs latest SSMS, AgentRansack, 7Zip, Chrome, AzCopy, Notepad++ and Powershell modules D365fo.tools, NuGet, PowerShellGet.
- Installs/update Visual C++ redist needed for 10.0.36 and up
- Add powershellscript "DownloadWithAzCopy.ps1" to Desktop to download files from LCS fast
- Add powershellscripts to Desktop to Start & Stop D365 dependent services
- Set the Windows account passwordpolicy to never expire
- Sets WinDefender rules that excludes D365 processes and files
- Sets Powerplan to "High performance"
- Grant the SQL serviceaccount "Perform Volume Maintenance Task" rights to speedup restore/expanding datadisk
- Enables Traceflag 7412 in SQL instance to see live execution plans in SSMS
- Set timezone based on IP location
- Use IIS instead of IIS Express
- Enable IIS Application Initialization and optimize appools
- Show computericon on Desktop with servername

'D365LocalDEVtuning.ps1' is used post-creation of Local D365 DEV environment to tune performance and rename the server.
Uses many of the same tuning settings from Cloudhosted optimizing script.

'azopyGetVHDfromLCS.ps1' downloads large files (VHD) from LCS using AzCopy.
Generate SAS links in LCS and paste them into the script in the right sequenced order! aka: part1, part 2 etc

'DeployPackage.ps1' automates deploying packages on local D365 DEV machine.
Put the script in a folder with the package zip file and run the powershellscript.
The script handle the Reportservice "bug" not starting during update.

'DownloadWithAzCopy.ps1' downloads large files very fast using AzCopy (PU/QU/SU/deployable packages etc).

