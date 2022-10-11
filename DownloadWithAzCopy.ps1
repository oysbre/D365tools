#Script to download files to local diskdrive using AzCopy
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#Force https over TLS12 protocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Region variables
$LCSURI = "<paste URL with SAS here>"
$localfilename = "<local fullpathname here>"

#Begin
function Get-UrlStatusCode([string] $Urlcheck) {
    try {  (Invoke-WebRequest -Uri $Urlcheck -UseBasicParsing -DisableKeepAlive -method head).StatusCode }
    catch [Net.WebException]  { [int]$_.Exception.Response.StatusCode  }
}#end function URL test

if ($localfile -eq "<local fullpathname here>"){write-host "Set local pathname with filename aka: c:\temp\SU10028.zip in variable '$localfilename'" -foregroundcolor yellow;pause;exit}
#Install/update AzCopy
If (!(test-path "C:\windows\AzCopy.exe")){
    write-host "Installing AzCopy to C:\Windows..." -ForegroundColor Yellow
    remove-item $env:temp\AzCopy.zip -force -ea 0
    invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    Unblock-File $env:temp\AzCopy.zip
    Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
    Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe"
    remove-item $env:temp\AzCopy.zip -force
    remove-item $env:temp\AzCopy -force -Recurse
}
else {
$azcopyupdate = & azcopy -h | select-string -pattern "newer version"
if ($azcopyupdate){
    write-host "Updating AzCopy..." -ForegroundColor Yellow
    remove-item $env:temp\AzCopy.zip -force -ea 0 
    Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    Unblock-File $env:temp\AzCopy.zip
    Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
    Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe" -force
    remove-item $env:temp\AzCopy.zip -force
    remove-item $env:temp\AzCopy -force -Recurse
    }
}#end AZcopy  

#download from SAS2Local
$statuscode = Get-UrlStatusCode -urlcheck $LCSURI
if ($statuscode -eq 200){
 azcopy copy $LCSURI $localfilename
}
else {write-host "Error in URL: " $($statuscode)}
pause

