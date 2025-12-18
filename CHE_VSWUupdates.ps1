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
  Write-Host "Istalling/Updating the '$PackageProvider' package provider."
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





