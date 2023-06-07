#Check if PS Console is running as "elevated" aka Administrator mode
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
 

# Modern websites require TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

function InstallUpgrade-AzCopy {
  $ErrorActionPreference = "SilentlyContinue"; #This will hide errors
  If ((-not(test-path "$env:systemroot\AzCopy.exe")) -or ((& azcopy -h | select-string -pattern "newer version").length -gt 0)){
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    if (test-path $env:temp\AzCopy.zip){
      Unblock-File $env:temp\AzCopy.zip
      Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
      Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "$env:systemroot\AzCopy.exe"
      Remove-Item $env:temp\AzCopy.zip -force
      Remove-Item $env:temp\AzCopy -force -Recurse
    }#end if testpath
 }#end if
  $ErrorActionPreference = "Continue"; #Turning errors back on
}#End function InstallUpgrade-AzCopy


function Import-Module-SQLPS {
     push-location
    import-module sqlps 3>&1 | out-null
    pop-location
}#end function Import-Module-SQLPS

function Set-RegistryValueForAllUsers { 
        [CmdletBinding()] 
    param ( 
        [Parameter(Mandatory=$true)] 
        [hashtable[]]$RegistryInstance 
    ) 
    try { 
        New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null 
         
        ## Change the registry values for the currently logged on user. Each logged on user SID is under HKEY_USERS 
        $LoggedOnSids = (Get-ChildItem HKU: | where { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' }).PSChildName 
        Write-Verbose "Found $($LoggedOnSids.Count) logged on user SIDs" 
        foreach ($sid in $LoggedOnSids) { 
            Write-Verbose -Message "Loading the user registry hive for the logged on SID $sid" 
            foreach ($instance in $RegistryInstance) { 
                ## Create the key path if it doesn't exist 
                New-Item -Path "HKU:\$sid\$($instance.Path | Split-Path -Parent)" -Name ($instance.Path | Split-Path -Leaf) -Force | Out-Null 
                ## Create (or modify) the value specified in the param 
                Set-ItemProperty -Path "HKU:\$sid\$($instance.Path)" -Name $instance.Name -Value $instance.Value -Type $instance.Type -Force 
            } 
        } 
         
        ## Create the Active Setup registry key so that the reg add cmd will get ran for each user logging into the machine. 
        Write-Verbose "Setting Active Setup registry value to apply to all other users" 
        foreach ($instance in $RegistryInstance) { 
            ## Generate a unique value (usually a GUID) to use for Active Setup 
            $Guid = [guid]::NewGuid().Guid 
            $ActiveSetupRegParentPath = 'HKLM:\Software\Microsoft\Active Setup\Installed Components' 
            ## Create the GUID registry key under the Active Setup key 
            New-Item -Path $ActiveSetupRegParentPath -Name $Guid -Force | Out-Null 
            $ActiveSetupRegPath = "HKLM:\Software\Microsoft\Active Setup\Installed Components\$Guid" 
            Write-Verbose "Using registry path '$ActiveSetupRegPath'" 
             
            ## Convert the registry value type to one that reg.exe can understand.  This will be the 
            ## type of value that's created for the value we want to set for all users 
            switch ($instance.Type) { 
                'String' {$RegValueType = 'REG_SZ'} 
                'Dword' {$RegValueType = 'REG_DWORD'} 
                'Binary' {$RegValueType = 'REG_BINARY'} 
                'ExpandString' {$RegValueType = 'REG_EXPAND_SZ'} 
                'MultiString' {$RegValueType = 'REG_MULTI_SZ'} 
                default {throw "Registry type '$($instance.Type)' not recognized"} 
            } 
             
            ## Build the registry value to use for Active Setup which is the command to create the registry value in all user hives 
            $ActiveSetupValue = "reg add `"{0}`" /v {1} /t {2} /d {3} /f" -f "HKCU\$($instance.Path)", $instance.Name, $RegValueType, $instance.Value 
            Write-Verbose -Message "Active setup value is '$ActiveSetupValue'" 
            ## Create the necessary Active Setup registry values 
            Set-ItemProperty -Path $ActiveSetupRegPath -Name '(Default)' -Value 'Active Setup Test' -Force 
            Set-ItemProperty -Path $ActiveSetupRegPath -Name 'Version' -Value '1' -Force 
            Set-ItemProperty -Path $ActiveSetupRegPath -Name 'StubPath' -Value $ActiveSetupValue -Force 
        } 
    } catch { 
        Write-Warning -Message $_.Exception.Message 
    } 
}#end function "Set-RegistryValueForAllUsers"
CLS
Write-host "This script runs several optimizing settings for the CHE environment." -foregroundcolor Cyan
InstallUpgrade-AzCopy

#Herestrings for Powershellscripts
$unsetcmd = @'
#Unset ReadOnly flag on multiple fileextensions in Powershell (run as Admin):
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}
@("*.rdl","*.log","*.xml","*.txt") | foreach {Get-ChildItem -Path "$env:servicedrive\AosService\PackagesLocalDirectory\*" -Recurse -Filter "$_" | foreach { $_.IsReadOnly=$False }}
'@

$StopServicesCmd = @'
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}
@("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")| foreach {stop-service -name "$_" -force}
'@

$StartServicesCmd = @'
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}
@("MR2012ProcessService","DynamicsAxBatch","Microsoft.Dynamics.AX.Framework.Tools.DMF.SSISHelperService.exe","W3SVC")| foreach {start-service -name "$_" }
'@

#Create powershellscripts on Desktop to start/stop services used before DB sync
Write-host "Creating powershellscripts on Desktop to start/stop services used before DB sync" -foregroundcolor yellow
$DesktopPath = [Environment]::GetFolderPath("Desktop")
Set-Content -Path "$DesktopPath\UnsetReadonlyFlag.ps1" -Value $unsetcmd
Set-Content -Path "$DesktopPath\StopServices.ps1" -Value $StopServicesCmd
Set-Content -Path "$DesktopPath\StartServices.ps1" -Value $StartServicesCmd

#Install Nuget
If (((Get-PackageProvider -listavailable).name).contains("NuGet") -eq $false){
Write-host "Installing NuGet." -foregroundcolor yellow
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
}
Import-PackageProvider -Name NuGet 
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
if ((get-module -name PowerShellGet) -eq $null){
Install-Module -Name PowerShellGet -Force
}

#Load SQL module
if(get-module sqlps){"yes"}else{"no"}
 Import-Module-SQLPS
 
if(get-module sqlps){"yes"}else{"no"}
Import-Module-SQLPS
cls

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

#Get server mem in MB and set SQL instance max memory 1/4 of that
$sysraminMB =  Get-WmiObject -class "cim_physicalmemory" | Measure-Object -Property Capacity -Sum | % {[Math]::Round($_.sum/1024/1024/4)}
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
Write-host "SQL instance Max memory set to $($sysraminMB) of total $($sysraminMB*4) megabyte" -foregroundcolor yellow
Invoke-SqlCmd -ServerInstance localhost -Query $sqlQmaxmem -EA 0 -querytimeout 30
}#end if $sysmeminMB

#Install VS menu extension
$vsixmenuurl = "https://evgeny.gallerycdn.vsassets.io/extensions/evgeny/restoreextensions/1.0.2/1556184103349/RestoreExtensions-v1.0.2.vsix"
Invoke-WebRequest -Uri "$vsixmenuurl" -OutFile "$env:temp\RestoreExtensions-v1.0.2.vsix" -UseBasicParsing
#Expand Archive
if (test-path "$env:temp/RestoreExtensions-v1.0.2.vsix"){
unblock-file "$env:temp/RestoreExtensions-v1.0.2.vsix"
write-host "Installing VS menuextension" -foregroundcolor yellow
$vsixinstaller = Get-ChildItem -Path  "${Env:ProgramFiles(x86)}\Microsoft Visual Studio" -recurse | Where-Object {$_.name -eq "vsixinstaller.exe"} | Sort-Object LastWriteTime -Descending | Select-Object -exp fullname -First 1
$vsargs = "/q $env:temp/RestoreExtensions-v1.0.2.vsix"
start-process $vsixinstaller -argumentlist $vsargs -wait
}

#Set the password to never expire
Write-host "Set account password to never expire" -foregroundcolor yellow
Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | ? { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1
Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | ? { $_.SID -eq (([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value) } | Set-LocalUser -PasswordNeverExpires 1

#set powercfg
Write-host "Set Powercfg til High Performance" -foregroundcolor yellow
& powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

write-host "Installing Powershell module d365fo.tools and setting WinDefender rules" -ForegroundColor yellow
Install-Module -Name "d365fo.tools"
Add-D365WindowsDefenderRules
write-host "Installed Powershell module d365fo.tools" -ForegroundColor Green

#Use IIS instead of IIS Express
Write-host "Use IIS instead of IIS Express" -foregroundcolor yellow
if (test-path "$env:servicedrive\AOSService\PackagesLocalDirectory\bin\DynamicsDevConfig.xml"){
[xml]$xmlDoc = Get-Content "$env:servicedrive\AOSService\PackagesLocalDirectory\bin\DynamicsDevConfig.xml"
if ($xmlDoc.DynamicsDevConfig.RuntimeHostType -ne "IIS"){
write-host 'Setting RuntimeHostType to "IIS" in DynamicsDevConfig.xml' -ForegroundColor yellow
$xmlDoc.DynamicsDevConfig.RuntimeHostType = "IIS"
$xmlDoc.Save("$env:servicedrive\AOSService\PackagesLocalDirectory\bin\DynamicsDevConfig.xml")
write-host 'RuntimeHostType set "IIS" in DynamicsDevConfig.xml' -ForegroundColor Green
}#end if IIS check
}#end if test-path xml file
else {write-host 'AOSService drive not found! Could not set RuntimeHostType to "IIS"' -ForegroundColor red}

#Install packages
If (Test-Path -Path "$env:ProgramData\Chocolatey") {
    choco upgrade chocolatey -y -r
    choco upgrade all --ignore-checksums -y -r
}
Else {

    Write-Host "Installing Chocolatey"

    Set-ExecutionPolicy Bypass -Scope Process -Force; 
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; 
    
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


#install EDGE
try {
    #Try to get JSON data from Microsoft
    $response = Invoke-WebRequest -Uri 'https://edgeupdates.microsoft.com/api/products?view=enterprise' -Method Get -ContentType "application/json" -UseBasicParsing -ErrorVariable InvokeWebRequestError
    $jsonObj = ConvertFrom-Json $([String]::new($response.Content))
    $selectedIndex = [array]::indexof($jsonObj.Product, "Stable")
    $selectedrelease = ($jsonObj[$selectedIndex]).Releases| Where-Object { $_.Architecture -eq "x64" -and $_.Platform -eq "Windows"}| Sort-Object -Descending | select -first 1
    $selectedlocation = $selectedrelease | select -expandproperty artifacts | select -expandproperty location
    if ((Get-ItemProperty -path 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge' -ea 0) -eq $null) {
    remove-item "$env:temp\MicrosoftEdgeEnterpriseX64.msi" -ea 0
        try {            
            Invoke-WebRequest -Uri $selectedlocation -OutFile "$env:temp\MicrosoftEdgeEnterpriseX64.msi" -UseBasicParsing
            Start-Process "$env:temp\MicrosoftEdgeEnterpriseX64.msi" -ArgumentList "/quiet /passive" -wait
            }
        catch {
          throw "Attempted to download file, but failed: $error[0]"
        }   
    }#end if installcheck
    
}#end try
catch {
  throw "Could not get MSI data: $InvokeWebRequestError"
}
#end install EDGE

#set timezone
Write-Host 'Setting TimeZone to CET...' -ForegroundColor yellow
& tzutil  /s "W. Europe Standard Time"

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
}# end foreach $instance
}# end if $instances

#Show Desktop icon all users
Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}';`
 'Type' = 'Dword'; 'Value' = '0'; 'Path' = 'Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'} 
$My_Computer = 17
$Shell = new-object -comobject shell.application
$NSComputer = $Shell.Namespace($My_Computer)
$NSComputer.self.name = $env:COMPUTERNAME
write-host "Tuning of $($env:COMPUTERNAME) done. Press any key to exit." -ForegroundColor green
write-host "Restart server to enable every optimization. Enjoy!" -ForegroundColor green
Pause
