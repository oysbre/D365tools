#Check if PS Console is running as "elevated" aka Administrator mode
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

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

#Install Nuget
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
If (((Get-PackageProvider -listavailable).name).contains("NuGet") -eq $false){
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

#set powercfg
& powercfg.exe -SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

write-host "Installing Powershell module d365fo.tools and setting WinDefender rules" -ForegroundColor yellow
Install-Module -Name "d365fo.tools"
Add-D365WindowsDefenderRules
write-host "Installed Powershell module d365fo.tools" -ForegroundColor Green


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

#install chrome
If ((Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome' -ea 0) -eq $null){
$ChromeInstaller = "ChromeInstaller.exe"; (new-object System.Net.WebClient).DownloadFile('https://dl.google.com/chrome/install/latest/chrome_installer.exe', "$env:TEMP\$ChromeInstaller"); 
& "$env:TEMP\$ChromeInstaller" /silent /install; $Process2Monitor =  "ChromeInstaller";
Write-Host "Installing Chrome" -ForegroundColor Yellow -NoNewline
 Do { $ProcessesFound = Get-Process | ?{$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name;
If ($ProcessesFound) { "." | Write-Host -NoNewline; Start-Sleep -Seconds 1 } else { rm "$env:TEMP\$ChromeInstaller" -EA 0 } }
 Until (!$ProcessesFound)
 Write-Host ""
 Write-host "Chrome installed." -ForegroundColor Green
}

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


#Install AzCopy
if (!(test-path "C:\windows\AzCopy.exe")){
remove-item "$env:temp\AzCopy.zip" -force -ea 0
Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile "$env:temp\AzCopy.zip" -UseBasicParsing
#Expand Archive
unblock-file "$env:temp/AzCopy.zip"
Expand-Archive "$env:temp/AzCopy.zip" "$env:temp/AzCopy" -Force
#Move AzCopy to the destination you want to store it
Get-ChildItem "$env:temp/AzCopy/*/azcopy.exe" | Move-Item -Destination "C:\windows\AzCopy.exe"
remove-item "$env:temp/AzCopy.zip" -force -ea 0
remove-item "$env:temp/AzCopy" -force -Recurse
}

#set timezone
& tzutil  /s "W. Europe Standard Time"

#Show Desktop icon all users
Set-RegistryValueForAllUsers -RegistryInstance @{'Name' = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}';`
 'Type' = 'Dword'; 'Value' = '0'; 'Path' = 'Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel'} 
$My_Computer = 17
$Shell = new-object -comobject shell.application
$NSComputer = $Shell.Namespace($My_Computer)
$NSComputer.self.name = $env:COMPUTERNAME
write-host "Tuning of $($env:COMPUTERNAME) done. Press any key to exit." -ForegroundColor green
Pause
