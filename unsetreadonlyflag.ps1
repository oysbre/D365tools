#Create powershellscript on Desktop that unset REEADONLY flag in packageslocaldirectory 
#Check if PS Console is running as "elevated" aka Administrator mode
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

$unsetcmd = @'
#Unset ReadOnly flag on multiple fileextensions in Powershell (run as Admin):
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}
Write-Host 'Unset ReadOnly flag on fileextentions .rdl, .log, .xml and .txt in PackagesLocalDirectory. Please wait...' -foregroundcolor Yellow
@("*.rdl","*.log","*.xml","*.txt") | foreach {Get-ChildItem -Path "$env:servicedrive\AosService\PackagesLocalDirectory\*" -Recurse -Filter "$_" | foreach { $_.IsReadOnly=$False }}
'@

Write-host "Creating powershellscript on Desktop that unset READONLY flag on file extensions .rdl, .log, .xml and .txt in packageslocaldirectory." -foregroundcolor yellow
$DesktopPath = [Environment]::GetFolderPath("Desktop")
Set-Content -Path "$DesktopPath\UnsetREADONLYflag.ps1" -Value $unsetcmd
