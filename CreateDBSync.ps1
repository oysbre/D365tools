#Check if PS Console is running as "elevated" aka Administrator mode
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# Modern websites require TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'
CLS
Write-host "Create DBSync script to Desktop." -foregroundcolor Cyan

#Install PowershellGet,Nuget and D365fo.tools
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Import-PackageProvider -Name NuGet 
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

if ((get-module -name PowerShellGet) -eq $null){
	Write-host "Installing PowershellGet..." -foregroundcolor yellow
	Install-Module -Name PowerShellGet -Force
}

#install/update d365fo.tools
if(-not(Get-Module d365fo.tools -ListAvailable)){
    Write-host "Installing D365fo.tools..." -foregroundcolor yellow
    Install-Module d365fo.tools -Force
}
else {
    $releases = "https://api.github.com/repos/d365collaborative/d365fo.tools/releases"
    $tagver = ((Invoke-WebRequest $releases -ea 0 -UseBasicParsing | ConvertFrom-Json)[0].tag_name).tostring()
        if ($tagver){
            $fover = (get-installedmodule d365fo.tools).version.tostring()
            if ([System.Version]$tagver -gt [System.Version]$fover){
             Write-host "Updating D365fo.tools..." -foregroundcolor yellow
	     Update-Module -name d365fo.tools -Force
            }#end if gt version check
        }#end if tagver 
}#end #install/update d365fo.tools

#Herestrings for Powershellscripts
$dbsynccmd = @'
#AX DBsync
$servicelist = @("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")
function Run-DBSync() {
    write-host "Running DBsync..." -foregroundcolor yellow
    $aosPath = "{0}\AOSService" -f $env:servicedrive 
    $packageDirectory = "$aosPath\PackagesLocalDirectory" 
    $SyncToolExecutable = "$aosPath\webroot\bin\Microsoft.Dynamics.AX.Deployment.Setup.exe"
	if (-not(get-command Get-D365DatabaseAccess)){
        install-module d365fo.tools -force -AllowClobber
	}
    $dbaccess = Get-D365DatabaseAccess
    $params = @(
        '-bindir',       $($packageDirectory)
        '-metadatadir' , $($packageDirectory) 
        '-sqluser',      $($dbaccess.sqluser)
        '-sqlserver',    '.'
        '-sqldatabase',  'AxDB'
        '-setupmode',    'sync' 
        '-syncmode',     'fullall' 
        '-isazuresql',   'false' 
        '-sqlpwd',       $($dbaccess.SqlPwd)
		'-logfilename', "c:\temp\AxDBsync_$(get-date -format 'ddMMMyyyy').log"
        )#end params
    Write-host "Syncing AxDB..."-foregroundcolor yellow
    & $SyncToolExecutable $params 2>&1 | Out-String    
}#end function DBsync

function startservices () {
foreach ($service in $servicelist){
    $serviceobject = get-service -name $service -ea 0
    if ($serviceobject){
        if ($serviceobject.StartType -ne 'Disabled'){
            write-host "Starting service $($serviceobject.name)..." -ForegroundColor yellow
            start-service $serviceobject 
            $serviceobject.WaitForStatus("Running")
        }#end if startType
    }#end if $serviceobject
}#end foreach service
}#end function startservices
write-host "Starting sync of AXDB. Please wait..." -foregroundcolor yellow
write-host "Stopping AX services..." -foregroundcolor yellow
@("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")| foreach {stop-service -name "$_" -force}

Run-DBSync
startservices
Get-iisapppool | Where {$_.State -eq "Stopped"} | Start-WebAppPool
Get-iissite | Where {$_.State -eq "Stopped" -and $_.id -ne 1} | Start-WebSite
write-host "Sync of AXDB complete." -foregroundcolor green
start-sleep -s 5
pause
'@

$DesktopPath = [Environment]::GetFolderPath("Desktop")
Set-Content -Path "$DesktopPath\RunDBsync.ps1" -Value $dbsynccmd

Pause
