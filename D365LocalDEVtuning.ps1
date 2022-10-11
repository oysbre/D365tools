#Powershellscript to "tune" the local D365 VHD image
#Check if PS Console is running as "elevated"
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Modern websites require TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Import-Module-SQLPS {
     push-location
    import-module sqlps 3>&1 | out-null
    pop-location
}
if(get-module sqlps){"yes"}else{"no"}
 Import-Module-SQLPS
 
if(get-module sqlps){"yes"}else{"no"}
Import-Module-SQLPS
CLS
Write-host "Tuning D365 environment. Please wait..." -foregroundcolor Cyan

# Set the password to never expire
Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | ? { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
if ((get-packageprovider nuget) -eq $NULL){
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}

#install d365tools and set WinDefender rules
Install-Module -Name "d365fo.tools" -allowclobber
Add-D365WindowsDefenderRules
#get the encrypted password for axdbadmin
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

#Rename the server due to VisualStudio "uniqueness"
$newname = "<newname>"
If ($env:computername -like "MININT*"){
If ($newname -eq "<newname>"){ $newname = read-host "New name not set. Set new:"}
if ($env:computername -ne $newname){
$ans= read-host "Changing $($env:computername) to $($newname)? (y/n)" 
Rename-Computer -NewName $newname -force 
}
Rename-Computer -NewName $newname -force 
$sqlOldnamequery = @"
select @@servername
"@
$sqlOldname = Invoke-SqlCmd -Query $sqlOldnamequery -Database master -ServerInstance localhost -ErrorAction Stop -querytimeout 60 -username axdbadmin -Password $sqlpwd
$sqlOldname = $sqlOldname.Column1
if ($sqlOldname -ne $newname){
$sqlRename = @"
sp_dropserver [$sqlOldname];
GO
sp_addserver [$newname], local;
GO
"@
Invoke-SqlCmd -Query $sqlRename -Database master -ServerInstance localhost -ErrorAction Continue -querytimeout 60 -username axdbadmin -Password $sqlpwd
}
}#end set servername from MS default

#disable UAC
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 0

#Set powerplan to HIGH PERFORMANCE
& powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c


#Install packages
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
        
    )

    # Install each program
    foreach ($packageToInstall in $packages) {

        Write-Host "Installing $packageToInstall" -ForegroundColor Green
        & $chocoExePath "install" $packageToInstall "-y" "-r"
    }
}
#end install packages

#install storage emulator
write-host "Installing Azure storage emulator"
(new-object System.Net.WebClient).DownloadFile('https://go.microsoft.com/fwlink/?linkid=717179&clcid=0x409', "$env:temp\microsoftazurestorageemulator.msi");

& "$env:temp\microsoftazurestorageemulator.msi" /quiet

#Get server mem and set SQL instance max mem
$sysraminMB = gwmi Win32_OperatingSystem | Measure-Object -Property TotalVisibleMemorySize -Sum | % {[Math]::Round($_.sum/1024/3)}
If ($sysraminmb){
$sqlQmaxmem = @"
sp_configure 'show advanced options', 1;
GO
RECONFIGURE;
GO
sp_configure 'max server memory', $sysraminMB;
GO
RECONFIGURE;
GO
"@
Invoke-SqlCmd -ServerInstance localhost -Query $sqlQmaxmem  -ErrorAction continue -querytimeout 20
}

#Enable TraceFlags on SQL instances
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

#add SQL service account to Perform volume maint task
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
Write-Host "Account: $($accountToAdd)" -ForegroundColor White
if( [string]::IsNullOrEmpty($sidstr) ) {
       Write-Host "Account not found!" -ForegroundColor Red
       #exit -1
}

Write-Host "Account SID: $($sidstr)" -ForegroundColor White
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
}


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


#AzCopy
If (!(test-path "C:\windows\AzCopy.exe")){
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

#set timezone
& tzutil  /s "W. Europe Standard Time"

Pause
restart-computer
