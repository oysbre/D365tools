#VS version bug fix  - return only digits in ToolsCommon.psm1
#Check if PS Console is running as "elevated"
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
$toolscripts = Get-ChildItem -Path "$env:SERVICEDRIVE\DeployablePackages\**\DevToolsService\Scripts" -recurse -Filter ToolsCommon.psm1 -ErrorAction SilentlyContinue -Force
if ($toolscripts){
foreach ($toolscript in $toolscripts){
copy-item $toolscript.fullname "$($toolscript.fullname).backup" -force
$oldcontent = '$version = ($vs2022Info.catalog.productDisplayVersion)'
$newcontent = '$version = ($vs2022Info.catalog.productDisplayVersion) -replace "(\s.*)", ""'
$content = ""
$content = [System.IO.File]::ReadAllText($toolscript.fullname).Replace('$version = ($vs2022Info.catalog.productDisplayVersion)','$version = ($vs2022Info.catalog.productDisplayVersion) -replace "(\s.*)", ""')
[System.IO.File]::WriteAllText($toolscript.fullname, $content)
}#end foreach
}#end if $toolscript
