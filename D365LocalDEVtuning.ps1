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


# Set the password to never expire
Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | ? { $_.SID -Like "S-1-5-21-*-500" } | Set-LocalUser -PasswordNeverExpires 1

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

#install d365tools and set Win Defender rules
Install-Module -Name "d365fo.tools"
Add-D365WindowsDefenderRules

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
$sqlOldname = Invoke-SqlCmd -Query $sqlOldnamequery -Database master -ServerInstance localhost -ErrorAction Stop -querytimeout 60 -username axdbadmin -Password AOSWebSite@123
$sqlOldname = $sqlOldname.Column1
if ($sqlOldname -ne $newname){
$sqlRename = @"
sp_dropserver [$sqlOldname];
GO
sp_addserver [$newname], local;
GO
"@
Invoke-SqlCmd -Query $sqlRename -Database master -ServerInstance localhost -ErrorAction Continue -querytimeout 60 -username axdbadmin -Password AOSWebSite@123
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
