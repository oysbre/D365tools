<# 
Powershellscript to tune/optimize/fix the local D365 VHD image. Require internet connection.
-never expire password for user
-rename server, sqlserver and SSRS
-install/update Visual C++ 2022 redist install/update
-set servicedrive to C: as an environmental path if not exists
-set Dynamics Deployment folderpath in registry if not correct and create folder structure
-include newer VS in TestStart script
-set SNI client to trust server certficate
-install/update NuGet, AzCopy, D365fo.tools, 7zip, Notepad++, Azure Storage emulator
-add Powershellscript to Desktop for stop and start D365 related services
-create AdminUserprovision shortcut to Desktop
-enable IIS App init and pre-load to initialize AOS faster  and set application pool to always running, disable timeout.
-create and setup "re-arm" script and taskschedule to check during logon
-enable TraceFlags 7412 on SQL startupparameter to enable "live execution plan" - for troubleshooting slow SQL queries
-grant SQL serviceaccount 'Perform Volume Maintenance Task' privilege; faster backup/restore and diskexpand.
-set powerplan til HIGH PERFORMANCE
-set timezone based on IP location 
-checks SQL version for trustservercertificate
#>

#Check if PS Console is running as "elevated"
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Modern websites require TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

#Install NuGet if not found
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
if ((get-packageprovider nuget) -eq $NULL){
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

#Remove sqlps from PS session - obselete
Remove-Module SQLPS -ea 0

#Install PSmodule SQLSERVER
if((Get-Module sqlserver -ListAvailable) -eq $null){
    Write-host "Installing PS module sqlserver..." -foregroundcolor yellow
    Install-Module sqlserver -Force -AllowClobber
}

function Import-Module-SQLServer {
push-location
import-module sqlserver 3>&1 | out-null
pop-location
}#end function Import-Module-SQLServer

if(get-module sqlserver){"yes"}else{"no"}
Import-Module-SQLServer
 
if(get-module sqlserver){"yes"}else{"no"}
Import-Module-SQLServer

#Install/update d365tools
write-host "Installing Powershell module D365FO.tools and set WinDefender rules..." -foregroundcolor Yellow
if(-not (Get-Module d365fo.tools -ListAvailable)){
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
}#end else

CLS
Write-host "Tuning local D365 environment. Please wait..." -foregroundcolor Cyan

#Set the password for Administrator account to never expire
write-host "Set the password to never expire for user Administrator and current user..." -foregroundcolor Yellow
Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | ? { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1
Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | ? { $_.SID -eq (([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value) } | Set-LocalUser -PasswordNeverExpires 1

#set Dynamics Deployment folderpath in registry and create folder structure
$Installinfodir = "c:\Logs"
Write-Host "Checking InstallationInfoDirectry in registry for path $($Installinfodir)..." -foregroundcolor Yellow
if ((Get-ItemPropertyvalue HKLM:\SOFTWARE\Microsoft\Dynamics\Deployment -name InstallationInfoDirectory -ea 0) -ne $Installinfodir){
	write-host "Changing DynamicsDeployment folder path in registry to $($Installinfodir)..." -foregroundcolor yellow
	Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Dynamics\Deployment -Name InstallationInfoDirectory -Value $Installinfodir -Type String
}
@('HotfixInstallationRecords', 'MetadataModelInstallationRecords', 'Runbooks', 'ServiceModelInstallationRecords') |
    ForEach-Object {
    	if (!(test-path (Join-Path "$Installinfodir\InstallationRecords\" $_))){
        	New-Item (Join-Path "$Installinfodir\InstallationRecords\" $_) -ItemType Directory -force | out-null
	 }
    }

#set ServiceDrive to C: as an environmental path if not set
if ((get-childitem -path env: | where  {$_.name -eq "servicedrive"}) -eq $null){
	write-host "Env path for Servicedrive not found. Setting variable..." -foregroundcolor yellow
	[Environment]::SetEnvironmentVariable("ServiceDrive", "C:", "Machine")
}#end if servicedrive

 #include VS2022 in TestStart
 if (test-path "C:\DynamicsSDK\Test\TestStart.ps1"){
    $vsold = '[xml]$vsInstances = & $vswherePath -format xml -version "[15.0, 17.0)"'
    $vsnew = '[xml]$vsInstances = & $vswherePath -format xml -version "[15.0, 18.0)"'
    $contentteststart = [System.IO.File]::ReadAllText("C:\DynamicsSDK\Test\TestStart.ps1").Replace($vsold,$vsnew)
    [System.IO.File]::WriteAllText("C:\DynamicsSDK\Test\TestStart.ps1", $contentteststart)
          
}#end include VS2022 in TestStart

# MS Visual C++ 2022 redist install/update
$DownloadPath = "$env:temp"
$vcurl = 'https://aka.ms/vs/17/release/VC_redist.x64.exe'
$webclient = New-Object System.Net.WebClient
$vcfilename = [System.IO.Path]::GetFileName($vcurl)
$vcfile = "$DownloadPath\$vcfilename"
$webclient.DownloadFile($vcurl, $vcfile)
if (test-path $vcfile){
$vcdlver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($vcfile).Fileversion
$vclibver = gci "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" -ea 0| get-itemproperty | where-object {$_.displayname -like "Microsoft Visual C*2022*"} |   Select-Object DisplayName, displayversion | sort-object -property displayversion -Descending | select -First 1
    
    if (($vcdlver -gt $vclibver.DisplayVersion) -or ($vclibver -eq $NULL)){
       write-host "Installing/updating MS Visual C++ 2022 ver $($vcdlver)" -ForegroundColor yellow
       $vcargs = "/install /passive /norestart"
        Start-Process $vcfile -Wait -ArgumentList $vcargs
        remove-item $vcfile -force
    }#end if ver check

}#end if VcDlfile check
else {write-host "MS Visual C++ download not found in $($DownloadPath). Newer ServiceUpdates deploy may fail." -ForegroundColor red;}

#Get SQL version and set trustservercertificate parameter for queries and SNI client
$inst = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances
foreach ($i in $inst)
{
   $p = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$i
   $sqlver += (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Version
}
$sqlver = $sqlver | sort desc
if ($sqlver -ge 16){
Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\MSSQLServer\Client\SNI11.0\GeneralFlags\Flag2" -name value -value 1
$trustservercert = 1
}

#Powershellscript variables.
$unsetcmd = @'
#Unset ReadOnly flag on multiple fileextensions in Powershell (run as Admin):
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}
@("*.rdl","*.log","*.xml","*.txt") | foreach {Get-ChildItem -Path "$env:servicedrive\AosService\PackagesLocalDirectory\*" -Recurse -Filter "$_" | foreach { $_.IsReadOnly=$False }}
'@

$StopServicesCmd = @'
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}
& taskkill /f batch.exe | out-null
@("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")| foreach {stop-service -name "$_" -force}
'@

$StartServicesCmd = @'
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}
@("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")| foreach {start-service -name "$_" }
'@

#Create powershellscripts on Desktop to start/stop related D365 services. Also script to remove "readonly" flag on RDL files.
$DesktopPath = [Environment]::GetFolderPath("Desktop")
Set-Content -Path "$DesktopPath\UnsetReadonlyFlag.ps1" -Value $unsetcmd
Set-Content -Path "$DesktopPath\StopServices.ps1" -Value $StopServicesCmd
Set-Content -Path "$DesktopPath\StartServices.ps1" -Value $StartServicesCmd

#create folder C:\D365scripts for powershellscripts
if (-not(test-path "c:\D365scripts")){write-host "Creating folder C:\D365scripts" -foregroundcolor yellow;new-item -ItemType directory -Path "c:\D365scripts"| Out-Null}

#Create a Scheduletask and rearm-script under c:\D365scripts to run "rearm check" during logon.
$rearmscript = @'
#Check rearmcount
[string]$slmgrRearmcount = (cscript c:\windows\system32\slmgr.vbs /dlv | select-string -pattern "Remaining Windows rearm count")
$rearmCount = $slmgrRearmcount.split(":")[1].trim()
$slmgrXprResult = cscript c:\windows\system32\slmgr.vbs /xpr
[string]$licenseStatus = ($slmgrXprResult | select-string -pattern "Timebased")
$licenseExprDate = [datetime]$LicenseStatus.Remove(0,36).trim()
$todaydate = get-date
$daysleft = (new-timespan -start $todaydate -end $licenseExprDate).days
if ($daysleft -lt 1 -and $rearmCount -ne 0) {cscript c:\windows\system32\slmgr.vbs /rearm;restart-computer }
elseif ($rearmCount -eq 0 -and $daysleft -lt 5){
$ButtonType = [System.Windows.Forms.MessageBoxButtons]::OK
$MessageIcon = [System.Windows.Forms.MessageBoxIcon]::Warning
$MessageBody = "No re-arms left. Create new DEV box. License expires in $($daysleft) days."
$MessageTitle = "Re-arm license"
$Result = [System.Windows.Forms.MessageBox]::Show($MessageBody,$MessageTitle,$ButtonType,$MessageIcon)
}
'@

Unregister-ScheduledTask -TaskName 'Auto Rearm' -Confirm:$false -ea 0
remove-item "c:\D365scripts\rearm.ps1" -force -ea 0
$rearmscript | out-file -filepath c:\D365scripts\rearm.ps1 -encoding utf8 -force -Width 2147483647
[string]$sch_args = '-executionpolicy bypass -NonInteractive -NoLogo -NoProfile -File "C:\D365scripts\rearm.ps1"'
$Action = New-ScheduledTaskAction -Execute '%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe' -Argument $sch_args
$Trigger = New-ScheduledTaskTrigger -atlogon
$Trigger.Delay = 'PT30S'
$Settings = New-ScheduledTaskSettingsSet
$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings
Register-ScheduledTask -TaskName 'Auto Rearm' -InputObject $Task -User "System"

#Enable IIS Application Initialization for faster start of FO 
Import-Module WebAdministration
$siteName = "AOSSERVICE"
$webAppInit = Get-WindowsFeature -Name "Web-AppInit"
if (!($webAppInit.Installed))
{
    Write-Host "$($webAppInit.DisplayName) not present, installing..." -foregroundcolor yellow
    Install-WindowsFeature $webAppInit -ErrorAction Continue
    Write-Host "`nInstalled $($webAppInit.DisplayName)`n" -ForegroundColor Green
}
else 
{
    Write-Host "$($webAppInit.DisplayName) was already installed" -ForegroundColor Green
}

#Fetch the site
$site = Get-Website -Name $siteName
if(!$site)
{
    Write-Host "Site $siteName could not be found, continuing with the rest of the script!" -ForegroundColor Red
}
else { 
#Fetch the application pool
$appPool = Get-ChildItem IIS:\AppPools\ | Where-Object { $_.Name -eq $site.applicationPool }

if ($AppPool){
#disable timeout
Set-ItemProperty ("IIS:\AppPools\AOSSERVICE") -Name processModel.idleTimeout -value ( [TimeSpan]::FromMinutes(0))
#disable the regular time of 1740 minutes
Set-ItemProperty ("IIS:\AppPools\AOSSERVICE") -Name Recycling.periodicRestart.time -Value "00:00:00"
#Clear any scheduled restart times
Clear-ItemProperty ("IIS:\AppPools\AOSSERVICE") -Name Recycling.periodicRestart.schedule

#Set up AlwaysRunning
if($appPool.startMode -ne "AlwaysRunning")
{
    Write-Host "startMode is set to $($appPool.startMode ), activating AlwaysRunning"
    $appPool | Set-ItemProperty -name "startMode" -Value "AlwaysRunning"
    $appPool = Get-ChildItem IIS:\AppPools\ | Where-Object { $_.Name -eq $site.applicationPool }
    Write-Host "startMode is now set to $($appPool.startMode)`n" -ForegroundColor Green
}#end if AlwaysRunning

if(!(Get-ItemProperty "IIS:\Sites\$siteName" -Name applicationDefaults.preloadEnabled).Value) 
{
    Write-Host "preloadEnabled is inactive, activating"
    Set-ItemProperty "IIS:\Sites\$siteName" -Name applicationDefaults.preloadEnabled -Value True
    Write-Host "preloadEnabled is now set to $((Get-ItemProperty "IIS:\Sites\$siteName" -Name applicationDefaults.preloadEnabled).Value)" -ForegroundColor Green
}#end if reload check
}#end if $appPool
}#end else $site

#create a Scheduletask and warmupscript under c:\D365scripts to run "Warmupscript" after startup
$warmupscript = @'
#Warmup D365 env
Invoke-WebRequest -Uri (get-d365url).url -UseDefaultCredentials
'@
if (-not(test-path "c:\D365scripts")){new-item -ItemType directory -Path "c:\D365scripts"}
Unregister-ScheduledTask -TaskName 'WarmupD365' -Confirm:$false -ea 0
remove-item "c:\D365scripts\WarmupD365.ps1" -force -ea 0
$warmupscript | out-file -filepath c:\D365scripts\WarmupD365.ps1 -encoding utf8 -force -Width 2147483647
[string]$sch_args = '-executionpolicy bypass -NonInteractive -NoLogo -NoProfile -File "c:\D365scripts\WarmupD365.ps1"'
$Action = New-ScheduledTaskAction -Execute '%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe' -Argument $sch_args
$Trigger = New-ScheduledTaskTrigger -atstartup
$Trigger.Delay = 'PT30S' #delay for 30 sec after startup
$Settings = New-ScheduledTaskSettingsSet
$Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Settings $Settings
Register-ScheduledTask -TaskName 'WarmupD365' -InputObject $Task -User "System"

#Download powershellscripts for packagedeploy and LCS download
write-host "Downloading DeployPackage.ps1 script for deploypackage..." -foregroundcolor Yellow
iwr "https://raw.githubusercontent.com/oysbre/D365tools/main/DeployPackage.ps1" -outfile "c:\D365scripts\DeployPackage.ps1"
write-host "Downloading DownloadWithAzcopy.ps1 script to download filles/packages from LCS fast" -foregroundcolor Yellow
iwr "https://raw.githubusercontent.com/oysbre/D365tools/main/DownloadWithAzCopy.ps1" -outfile "c:\D365scripts\DownloadWithAzCopy.ps1"

#Set D365 Defender rules
Add-D365WindowsDefenderRules

#get the encrypted password for axdbadmin
write-host "get the encrypted password for axdbadmin..." -foregroundcolor Yellow
[string[]]$Assemblies = @(
    'C:\AOSService\webroot\bin\Microsoft.Dynamics.AX.Framework.EncryptionEngine.dll'
) 

[string]$CSSource = @" 
using System;
using Microsoft.Dynamics.Ax.Xpp.Security;
namespace n201903071243 //use an odd namespace so I don't have to reload powershell each time I want to tweak this code; just tweak the NS
{
    public class Dfo365CertificateThumbprintProvider: Microsoft.Dynamics.Ax.Xpp.Security.ICertificateThumbprintProvider
    {
        public string EncryptionThumbprint {get;private set;}
	    public string SigningThumbprint {get;private set;}
        public Dfo365CertificateThumbprintProvider(string encryptionThumbprint, string signingThumbprint)
        {
            EncryptionThumbprint = encryptionThumbprint;
            SigningThumbprint = signingThumbprint;
        }
    }
    public class Dfo365EncryptionExceptionHandler: Microsoft.Dynamics.Ax.Xpp.Security.IEncryptionExceptionHandler
    {
        private Action<Exception> exceptionHandler;
        public Dfo365EncryptionExceptionHandler()
        {
            exceptionHandler = WriteToConsoleThenThrow;
        }
        public Dfo365EncryptionExceptionHandler(Action<Exception> exceptionHandler)
        {
            this.exceptionHandler = exceptionHandler;
        }
        public void HandleException(Exception exception)
        {
            if (exceptionHandler != null)
            {
                exceptionHandler(exception);
            } 
        }
        public static void WriteToConsoleThenThrow(Exception exception)
        {
            Console.WriteLine(exception.ToString());
            throw exception;
        }
    }
}
"@ 

Add-Type -ReferencedAssemblies $Assemblies -TypeDefinition $CSSource -Language 'CSharp' 
Add-Type -Path 'C:\AOSService\webroot\bin\Microsoft.Dynamics.AX.Framework.EncryptionEngine.dll'

function Decrypt-Dfo365EncryptedString {
    [CmdletBinding(DefaultParameterSetName = 'ByEncryptionEngine')]
    Param (
        [Parameter(ParameterSetName = 'ByEncryptionEngine', Mandatory = $true)]
        [Microsoft.Dynamics.Ax.Xpp.Security.EncryptionEngine]$EncryptionEngine = $null
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
        [string]$PathToWebConfig
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByXml')]
        [xml]$WebConfig
        ,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$EncryptedString
    )
    Begin {
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            $WebConfig = [xml](Get-Content -Path $PathToWebConfig | Out-String)
        }
        if ($PSCmdlet.ParameterSetName -ne 'ByEncryptionEngine') {
            $EncryptionEngine = New-Dfo365EncryptionEngine -WebConfig $WebConfig
        }
        [string]$purpose = 'PurposeName'
    }
    Process {
        [byte[]]$cipher = [Convert]::FromBase64String($EncryptedString)
        $encryptionEngine.Decrypt($cipher, $purpose)
    }
}

function Get-Dfo365ConfigSetting {
    [CmdletBinding(DefaultParameterSetName = 'ByPath')]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
        [string]$PathToWebConfig
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByXml')]
        [xml]$WebConfig
        ,
        [Parameter(Mandatory = $true, ValueFromPipeLine = $true)]
        [string]$PropertyName
    )
    Begin {
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            $WebConfig = [xml](Get-Content -Path $PathToWebConfig | Out-String)
        }
    }
    Process {
        [string]$xpath = ("/configuration/appSettings/add[@key='{0}']/@value" -f $PropertyName) #I've not bothered adding escaping logic as key names unlikely to contain apostrophies; but may be worth adding at some point?
        $WebConfig.SelectSingleNode($xpath) | Select-Object -ExpandProperty 'value'
    }
}
function Get-Dfo365EncryptedConfigSetting {
    [CmdletBinding(DefaultParameterSetName = 'ByPath')]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
        [string]$PathToWebConfig
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByXml')]
        [xml]$WebConfig
        ,
        [Parameter(Mandatory = $true, ValueFromPipeLine = $true)]
        [string]$PropertyName
        ,
        [Parameter(Mandatory = $false)]
        [Microsoft.Dynamics.Ax.Xpp.Security.EncryptionEngine]$EncryptionEngine = $null
    )
    Begin {
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            $WebConfig = [xml](Get-Content -Path $PathToWebConfig | Out-String)
        }
        if ($EncryptionEngine -eq $null) {
            $EncryptionEngine = New-Dfo365EncryptionEngine -WebConfig $WebConfig
        }
    }
    Process {
        $encryptedValue = Get-Dfo365ConfigSetting -WebConfig $WebConfig -PropertyName $PropertyName
        Decrypt-Dfo365EncryptedString -EncryptionEngine $EncryptionEngine -EncryptedString $encryptedValue
    }
}
function New-Dfo365EncryptionEngine {
    [CmdletBinding(DefaultParameterSetName = 'AllObjects')]
    Param(
        [Parameter(ParameterSetName = 'AllObjects', Mandatory = $true)]
        [Parameter(ParameterSetName = 'ByPath', Mandatory = $false)]
        [Parameter(ParameterSetName = 'ByXml', Mandatory = $false)]
        [Microsoft.Dynamics.Ax.Xpp.Security.ICertificateThumbprintProvider]$certificateThumbprintProvider = $null
        ,
        [Parameter(ParameterSetName = 'AllObjects', Mandatory = $true)]
        [Parameter(ParameterSetName = 'ByPath', Mandatory = $false)]
        [Parameter(ParameterSetName = 'ByXml', Mandatory = $false)]
        [System.Collections.Generic.IDictionary[[string], [string]]]$certificateHandlerSettings = $null
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
        [string]$PathToWebConfig
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByXml')]
        [xml]$WebConfig
        ,
        [Parameter(Mandatory = $false)]
        [Microsoft.Dynamics.Ax.Xpp.Security.IEncryptionExceptionHandler]$encryptionExceptionHandler = $null #gets defaulted in the Begin block if left as null
        ,
        [Parameter(Mandatory = $false)]
        [Microsoft.Dynamics.Ax.Xpp.Security.ICertificateThumbprintProvider]$legacyCertificateThumbprintProvider = $null 
    )
    Begin {
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            $WebConfig = [xml](Get-Content -Path $PathToWebConfig | Out-String)
        }
        if ($PSCmdlet.ParameterSetName -ne 'AllObjects') {
            if ($certificateThumbprintProvider -eq $null) {$certificateThumbprintProvider = New-CertificateThumbprintProvider -WebConfig $WebConfig}
            if ($certificateHandlerSettings -eq $null) {$certificateHandlerSettings = New-CertificateHandlerSettings -WebConfig $WebConfig}
            #legacyCertificateThumbprintProvider doesn't seem to be used; though has values in the web.config keys... leave as null/provided for now
            #if ($legacyCertificateThumbprintProvider -eq $null) {$legacyCertificateThumbprintProvider = New-CertificateThumbprintProvider -WebConfig $WebConfig -EncryptionThumbprintKey 'DataAccess.DataEncryptionCertificateThumbprintLegacy' -SigningThumbprintKey 'DataAccess.DataSigningCertificateThumbprintLegacy'}
        }
        if ($encryptionExceptionHandler -eq $null) {$encryptionExceptionHandler = New-Dfo365EncryptionExceptionHandler}
    }
    Process {
        (New-Object -TypeName 'Microsoft.Dynamics.Ax.Xpp.Security.EncryptionEngine' -ArgumentList $certificateThumbprintProvider, $encryptionExceptionHandler, $certificateHandlerSettings, $legacyCertificateThumbprintProvider)
    }
}
function New-Dfo365EncryptionExceptionHandler {
    [CmdletBinding()]
    Param ()
    Process {
        (New-Object -TypeName 'n201903071243.Dfo365EncryptionExceptionHandler')
    }
}
function New-CertificateThumbprintProvider {
    [CmdletBinding(DefaultParameterSetName = 'ByPath')]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
        [string]$PathToWebConfig
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByXml')]
        [xml]$WebConfig
        ,
        #make these parameters in case we want to reuse this for fetching the legacy thumprints too (i.e. to reuse for legacyCertificateThumbprintProvider)
        [Parameter()]
        [string]$EncryptionThumbprintKey = 'DataAccess.DataEncryptionCertificateThumbprint'
        ,
        [Parameter()]
        [string]$SigningThumbprintKey = 'DataAccess.DataSigningCertificateThumbprint'
    )
    Begin {
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            $WebConfig = [xml](Get-Content -Path $PathToWebConfig | Out-String)
        }
    }
    Process {
        $encr = Get-Dfo365ConfigSetting -WebConfig $WebConfig -PropertyName $EncryptionThumbprintKey
        $sign = Get-Dfo365ConfigSetting -WebConfig $WebConfig -PropertyName $SigningThumbprintKey
        (New-Object -TypeName 'n201903071243.Dfo365CertificateThumbprintProvider' -ArgumentList $encr, $sign)
    }
}
function New-CertificateHandlerSettings {
    [CmdletBinding(DefaultParameterSetName = 'ByPath')]
    Param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
        [string]$PathToWebConfig
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByXml')]
        [xml]$WebConfig
    )
    Begin {
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            $WebConfig = [xml](Get-Content -Path $PathToWebConfig | Out-String)
        }
    }
    Process {
        [System.Collections.Generic.IDictionary[[string], [string]]]$result = New-Object -TypeName 'System.Collections.Generic.Dictionary[[string], [string]]'
        [PSObject[]]$keyValuePairs = $WebConfig.SelectNodes("/configuration/appSettings/add[starts-with(@key,'CertificateHandler')]") | Select-Object @('key', 'value')
        foreach ($kvp in $keyValuePairs) {
            $result.Add($kvp.key, $kvp.value)
        }
        $result
    }
}

function Get-Dfo365CredentialData {
    [CmdletBinding(DefaultParameterSetName = 'ByPath')]
    Param (
        [Parameter(Mandatory = $false, ParameterSetName = 'ByPath')]
        [string]$PathToWebConfig = 'C:\AOSService\webroot\web.config'
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ByXml')]
        [xml]$WebConfig
    )
    Begin {
        if ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            $WebConfig = [xml](Get-Content -Path $PathToWebConfig | Out-String)
        }
        [Microsoft.Dynamics.Ax.Xpp.Security.EncryptionEngine]$encryptionEngine = New-Dfo365EncryptionEngine -WebConfig $WebConfig
    }
    Process {
        [PSObject[]]$settings = @(
         @{Key='DataAccess.AxAdminSqlPwd';Encrypted=$true}
        ) | ForEach-Object {(New-Object -TypeName 'PSObject' -Property $_)} 
        $settings | ForEach-Object {
            $setting = $_.Key
            $value = if ($_.Encrypted -eq $true) {
                Get-Dfo365EncryptedConfigSetting  -WebConfig $WebConfig -PropertyName $setting -EncryptionEngine $encryptionEngine
            } else {
                Get-Dfo365ConfigSetting -WebConfig $WebConfig -PropertyName $setting
            }
            (New-Object -TypeName 'PSObject' -Property @{Key=$setting;Value=$value})
        }
    }
    
}

$sqlpwd = (Get-Dfo365CredentialData).value

#END Get the encrypted password for axdbadmin

#Rename server due to DevOPS/VisualStudio "uniqueness"
$newname = "<newname>"
If (($env:computername -like "MININT*") -or ($env:computername -like "DV*")){
If ($newname -eq "<newname>"){write-host "New name for DEV server not set. Set new (max 15 characters):" -foregroundcolor cyan; $newname = read-host;$newname=$newname.trim() }
$sqlparams = @{
'Database' = 'master'
'serverinstance' = 'localhost'
'querytimeout' = 60
'query' = ''
'trustservercertificate' = $trustservercert
}
$sqlparams.query = @'
SELECT @@SERVERNAME as servername
'@

$sqlOldname = Invoke-SqlCmd @sqlparams
Rename-D365ComputerName -NewName $newname -SSRSReportDatabase "DynamicsAxReportServer" 
}
#End set servername from MS default

#Create AdminUserprovision shortcut to Desktop
if (!(test-path ("$env:USERPROFILE\Desktop\AdminUserProvisioning.lnk"))){
$WshShell = New-Object -comObject WScript.Shell
$shortcutPath = "$env:USERPROFILE\Desktop\AdminUserProvisioning.lnk"
$Shortcut = $WshShell.CreateShortcut("$shortcutPath")
$Shortcut.TargetPath = "$env:servicedrive:\AOSService\PackagesLocalDirectory\bin\AdminUserProvisioning.exe"
$Shortcut.Save()
$bytes = [System.IO.File]::ReadAllBytes("$shortcutPath")
$bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
$bytes | Set-Content $shortcutPath -Encoding Byte
}

#Disable RealTime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

#Disable UAC
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 0

#Disable HTTP22
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name EnableHttp2Tls -Value 0
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HTTP\Parameters -Name EnableHttp2Cleartext -Value 0

#Set powerplan to HIGH PERFORMANCE
& powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

#Install packages with Chocolatey
If (Test-Path -Path "$env:ProgramData\Chocolatey") {
    choco upgrade chocolatey -y -r
    choco upgrade all --ignore-checksums -y -r
}
Else {
    Write-Host "Installing Chocolatey"
    Set-ExecutionPolicy Bypass -Scope Process -Force; 
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

    #Determine choco executable location
    #   This is needed because the path variable is not updated
    #   This part is copied from https://chocolatey.org/install.ps1
    $chocoPath = [Environment]::GetEnvironmentVariable("ChocolateyInstall")
    if ($chocoPath -eq $null -or $chocoPath -eq '') {
        $chocoPath = "$env:ALLUSERSPROFILE\Chocolatey"
    }
    if (!(Test-Path ($chocoPath))) {
        $chocoPath = "$env:SYSTEMDRIVE\ProgramData\Chocolatey"
    }
    $chocoExePath = Join-Path $chocoPath 'bin\choco.exe'

    $LargeTables = @(
        #"LargeTables"
    )

    $packages = @(
        
        "googlechrome"
        "notepadplusplus.install"
	"7zip.install"
    )

    # Install each program
    foreach ($packageToInstall in $packages) {

        Write-Host "Installing $packageToInstall" -ForegroundColor Green
        & $chocoExePath "install" $packageToInstall "-y" "-r"
    }
}
#end install packages

#install Azure storage emulator used for Retailserver
write-host "Installing Azure storage emulator..." -foregroundcolor yellow
(new-object System.Net.WebClient).DownloadFile('https://go.microsoft.com/fwlink/?linkid=717179&clcid=0x409', "$env:temp\microsoftazurestorageemulator.msi");

& "$env:temp\microsoftazurestorageemulator.msi" /quiet

#Get server mem in MB and set SQL instance max memory 1/4 of that
$sysraminMB =  Get-WmiObject -class "cim_physicalmemory" | Measure-Object -Property Capacity -Sum | % {[Math]::Round($_.sum/1024/1024/4)}
If ($sysraminmb){
$sqlQmaxmem = @{
'Database' = 'master'
'serverinstance' = 'localhost'
'querytimeout' = 60
'query' = ''
'trustservercertificate' = $trustservercert
}
$sqlQmaxmem.query = @"
sp_configure 'show advanced options', 1;
GO
RECONFIGURE;
GO
sp_configure 'max server memory', $sysraminMB;
GO
RECONFIGURE;
GO
"@
Write-host "SQL instance Max memory set to $($sysraminMB) of total $($sysraminMB*4) megabyte" -foregroundcolor yellow
Invoke-SqlCmd @sqlQmaxmem
}#end if $sysmeminMB

#Enable TraceFlags on SQL instance - 7412 enables live execution plans
$StartupParametersPost2016 = @("-T7412")
#get all the instances on server
$instproperty = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
$instancesObject = $instproperty.psobject.properties | ?{$_.Value -like 'MSSQL*'} 
$instances = $instancesObject.Value
#add all the startup parameters
if($instances) {
foreach($instance in $instances) {
$ins = $instance.split('.')[1]
if($ins -eq "MSSQLSERVER") {$instanceName = $env:COMPUTERNAME }
else{$instanceName = $env:COMPUTERNAME + "\" + $ins }
$regKeyParam = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instance\MSSQLServer\Parameters"
$property = (Get-ItemProperty $regKeyParam)
$paramObjects = $property.psobject.properties | ?{$_.Name -like 'SQLArg*'}
$count = ""
$count = $paramObjects.count
#get all the parameters
$parameters = $StartupParametersPost2016.split(",")
foreach($parameter in $parameters) {
    if ($parameter -notin $paramObjects.value) {
    Write-Host "Adding startup parameter SQLArg$count with value $parameter for $instanceName"
    $newRegProp = "SQLArg"+$count
    Set-ItemProperty -Path $regKeyParam -Name $newRegProp -Value $parameter
    $count = $count + 1
	Write-Host "Add sucessfully!"
    } # end if $parameter exist
}# end foreach $parameter
} # end foreach $instance
} # end if $instances

#add SQL service account to Perform volume maint task to speed up restore/backup
$svr = new-object('Microsoft.SqlServer.Management.Smo.Server') $env:computername
$accountToAdd = $svr.serviceaccount
if ($accountToAdd -ne $NULL){
$sidstr = $null
try {
       $ntprincipal = new-object System.Security.Principal.NTAccount "$accountToAdd"
       $sid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
       $sidstr = $sid.Value.ToString()
} catch {
       $sidstr = $null
}
Write-Host "Account: $($accountToAdd)" -ForegroundColor CYAN
if( [string]::IsNullOrEmpty($sidstr) ) {
       Write-Host "Account not found!" -ForegroundColor Red
       #exit -1
}

Write-Host "Account SID: $($sidstr)" -ForegroundColor CYAN
$tmp = ""
$tmp = [System.IO.Path]::GetTempFileName()
Write-Host "Exporting current Local Security Policy" -ForegroundColor Yellow
secedit.exe /export /cfg "$($tmp)" 
$c = ""
$c = Get-Content -Path $tmp
$currentSetting = ""
foreach($s in $c) {
       if( $s -like "SeManageVolumePrivilege*") {
             $x = $s.split("=",[System.StringSplitOptions]::RemoveEmptyEntries)
             $currentSetting = $x[1].Trim()
       }
}#end foreach $s
if( $currentSetting -notlike "*$($sidstr)*" ) {
       Write-Host "Modify Setting ""Perform Volume Maintenance Task""" -ForegroundColor Yellow
       
       if( [string]::IsNullOrEmpty($currentSetting) ) {
             $currentSetting = "*$($sidstr)"
       } else {
             $currentSetting = "*$($sidstr),$($currentSetting)"
       }
       Write-Host "$currentSetting"
$outfile = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeManageVolumePrivilege = $($currentSetting)
"@
       
       $tmp2 = ""
       $tmp2 = [System.IO.Path]::GetTempFileName()
       
       
       Write-Host "Import new settings to Local Security Policy" -ForegroundColor Yellow
       $outfile | Set-Content -Path $tmp2 -Encoding Unicode -Force
       #notepad.exe $tmp2
       Push-Location (Split-Path $tmp2)
       
       try {
             secedit.exe /configure /db "secedit.sdb" /cfg "$($tmp2)" /areas USER_RIGHTS 
             #write-host "secedit.exe /configure /db ""secedit.sdb"" /cfg ""$($tmp2)"" /areas USER_RIGHTS "
       } finally {  
             Pop-Location
       }
       write-host "SQL serviceaccount $accountToAdd is granted 'Perform Volume Maintenance Task' privelege." -ForegroundColor Yellow
       
} else {
       Write-Host "NO ACTIONS REQUIRED! Account already has 'Perform Volume Maintenance Task' privelege." -ForegroundColor Green
}
Write-Host ""

}#end $account check empty
#End SQLservice account VolMaintask

#install/update AzCopy
If (!(test-path "C:\windows\AzCopy.exe")){
	Write-host "Installing AzCopy..." -foregroundcolor Yellow
	$ProgressPreference = 'SilentlyContinue'
	Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
	Unblock-File $env:temp\AzCopy.zip
	Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
	Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe"
	remove-item $env:temp\AzCopy.zip -force
	remove-item $env:temp\AzCopy -force -Recurse
}
else {
    $azcopyupdate = & azcopy -h | select-string -pattern "newer version"
    if ($azcopyupdate){
    	Write-host "Updating AzCopy..." -foregroundcolor Yellow
    	$ProgressPreference = 'SilentlyContinue'
    	Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    	Unblock-File $env:temp\AzCopy.zip
    	Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
    	Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe" -force
    	remove-item $env:temp\AzCopy.zip -force
    	remove-item $env:temp\AzCopy -force -Recurse
    }
}#end AZcopy  

#Create DIXF folder
If (!(test-path "c:\temp\dixf")){
New-Item -Path "c:\temp" -Name "dixf" -ItemType "directory"
}

#set timezone based on IP address (estimated)
Write-host "Set timezone based on IP location (estimated)..." -foregroundcolor Yellow
[string]$IPAddress = (Invoke-WebRequest -Uri 'https://ifconfig.me/ip' -ContentType 'text/plain' -UseBasicParsing -ea 0).Content.Trim()
if ($IPaddress){ 
    [string]$IANATimeZone = (Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$IPAddress" -UseBasicParsing -ea 0).timezone
    if ($IANATimeZone){
        try {
            $zonesurl = 'https://raw.githubusercontent.com/unicode-org/cldr/master/common/supplemental/windowsZones.xml'
            [xml]$xml = (Invoke-WebRequest -Uri $zonesurl -ContentType 'application/xml' -UseBasicParsing).Content
        }
        catch {
            throw "Failed to obtain time zone XML map from GitHub: $_"
        }

        $zones = $xml.supplementalData.windowsZones.mapTimezones.mapZone
        $win_tz = ($zones | Where-Object type -Match $IANATimeZone).other
        if ($win_tz){
            set-timezone -name $win_tz
        }
        else {write-host "Couldn't convert IANA timezone to Windows format" -ForegroundColor red }
    }#end iana
}#end $ipaddress

write-host "Decrypted SQLpassword is: " $($sqlpwd) -foregroundcolor Yellow
write-host "All set. Restart the computer by pressing any key" -foregroundcolor Cyan
Pause
restart-computer
