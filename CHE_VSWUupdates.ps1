<# Update all Visual Studio instances and get all Windows updates including other MS products.
iwr https://raw.githubusercontent.com/oysbre/D365tools/main/CHE_VSWUupdates.ps1 -outfile "$env:USERPROFILE\Desktop\CHE_VSWUupdates.ps1"
#>
#Check if PS Console is running as "elevated" aka Administrator mode
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
write-host "This will update all Visual Studio instances and install Windows updates along with other Microsoft products." -foregroundcolor Magenta
Function InstallModule($PSModuleName) {

 Function InstallPackageProvider($PackageProvider) #As Boolean
 {
  Write-Host "Installing/Updating the '$PackageProvider' package provider."
  $Result = Get-PackageProvider -Name "$PackageProvider" -ForceBootStrap 2>$Null
  If ($Result -EQ $Null)
  {
   Write-Host "Failed to install/update the '$PackageProvider' package provider."
   Return $False
  } Else {
   Write-Host "Successfully installed/updated the '$($Result.Name)' package provider version '$($Result.Version)'."
   Return $True
  }
 } #End InstallPackageProvider

 Function ImportModule($PSModuleName) #As Boolean
 {
  Write-Host "Importing module '$PSModuleName'."
  Try
  {
   Import-Module $PSModuleName -Force -Erroraction Stop 2>$Null
   Write-Host "Successfully imported module '$PSModuleName'."
   Return $True
  } Catch {
   Write-Host "Failed to import module '$PSModuleName'."
   Return $False
  }
 } #End ImportModule

 Write-Host "Installing module '$PSModuleName'."
 $Result = Get-Module -Name $PSModuleName
 If ($Result -EQ $Null)
 {
  If (Get-Module -ListAvailable | Where-Object {$_.Name -EQ $PSModuleName})
  {
   If (ImportModule $PSModuleName)
   {
    Write-Host "Successfully installed module '$PSModuleName'."
    Return $True
   } Else {
    Write-Host "Failed to install module '$PSModuleName'."
    Return $False
   }
  } Else {
   If (InstallPackageProvider("NuGet"))
   {
    If (Find-Module -Name $PSModuleName 2>$Null | Where-Object {$_.Name -EQ $PSModuleName})
    {
     Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted 2>$Null
     Write-Host "Installing module '$PSModuleName'."
     Try
     {
      Install-Module -Name $PSModuleName -Repository "PSGallery" -Scope AllUsers -AllowClobber -Confirm:$False -Force -Erroraction Stop 2>$Null
      Write-Host "Successfully installed module '$PSModuleName'."
      If (ImportModule $PSModuleName)
      {       Write-Host "Successfully installed module '$PSModuleName'."
       Return $True
      } Else {       Write-Host "Failed to install module '$PSModuleName'."
       Return $False
      }
     } Catch {      Write-Host "Failed to install module '$PSModuleName'."
      Return $False;
     }
    } Else {     Write-Host "Module '$PSModuleName' is unavailable."
     Return $False
    }
   } Else {    Write-Host "Package Provider "NuGet" is required."
    Return $False
   }
  }
 } Else {  Write-Host "Module '$($Result.Name)' version '$($Result.Version)' is already installed."
  Return $True
 }

} #End InstallModule

#Set/Enable Ciphersuites for Windows Update
$ErrorActionPreference = 'Stop';
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002';
$ciphers = Get-ItemPropertyValue "$regPath" -Name 'Functions';
$cipherList = $ciphers.Split(',');
#Set strong cryptography on 64 bit .Net Framework (version 4 and above)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
#set strong cryptography on 32 bit .Net Framework (version 4 and above)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
$updateReg = 0
if ($cipherList -inotcontains 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256') {
    Write-Host "Adding TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256";
    #$ciphers += ',TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256';
    $ciphers = $ciphers.insert(0,'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256,')
    $updateReg = 1
}
if ($cipherList -inotcontains 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384') {
    Write-Host "Adding TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    #$ciphers += ',TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384';
    $ciphers = $ciphers.insert(0,'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,')
    $updateReg = 1
}

if ($updateReg -eq 1) {
    
    Set-ItemProperty "$regPath" -Name 'Functions' -Value "$ciphers";
    $ciphers = Get-ItemPropertyValue "$regPath" -Name 'Functions';
    Write-host "Rebooting computer to use new ciphersuites..." -foregroundcolor Yellow
    start-sleep -s 3
    Restart-Computer -Force
}




#Patch VS instances
InstallModule VSSetup 
get-vssetupinstance|%{
$installpath = $_.installationpath
Write-host "Patching $($installpath)..." -foregroundcolor yellow
Start-Process -Wait -FilePath "${env:programfiles(x86)}\Microsoft Visual Studio\Installer\vs_installer.exe" -ArgumentList "update --passive --norestart --installpath ""$installpath"""
}


#enable WU on other products
$ServiceManager = New-Object -ComObject "Microsoft.Update.ServiceManager"
$ServiceManager.ClientApplicationID = "My App"
$NewService = $ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")

# Install the Windows Update module
InstallModule PSWindowsUpdate 

# Import the Windows Update module
Import-Module PSWindowsUpdate

# Check for updates
Get-WindowsUpdate -AcceptAll -Install 





