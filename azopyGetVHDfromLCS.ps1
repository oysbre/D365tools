#Powershellscript to download VHD from LCS Shared library using AzCopy. Set/change targetdir variable if needed.
#Run as Admin powershellsession.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Force https over TLS12 protocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Set target downloadpath. Default c:\temp
$targetdir = "C:\temp"
$D365VHDname = "D365VHD-10_0_46_part"

#Note! The URLs with SAS token below are "expired" and will not work.
#Generate URL for each VHD file with SAS token from your LCS region; https://lcs.dynamics.com or https://eu.lcs.dynamics.com/
#Replace SAS URLs in variable $URLS below between the "" and do it in right order starting from part file nr 1. This is important since first file is an EXE (WinRAR Executable)!
#Save the script and run it!

$URLS = @(
<#1#>"https://d365opsasteuiwypep2gu3b.blob.core.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47-e54b86e7/dghLIzpJNKa1QlbbuJnbAa?skoid=9ef30196-cd78-4a47-955e-89a3947f0a23&sktid=975f013f-7f24-47e8-a7d3-abc4752bf346&skt=2026-01-12T11%3A54%3A00Z&ske=2026-01-15T12%3A54%3A00Z&sks=b&skv=2025-05-05&sv=2025-05-05&st=2026-01-12T11%3A54%3A00Z&se=2026-01-15T12%3A54%3A00Z&sr=b&sp=r&sig=xkmmFbMIxp4hlxOxcBOau7iIjQXoPhKbJ17RYnc1%2Bow%3D" 
,<#2#>"https://d365opsasteuiwypep2gu3b.blob.core.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47-e54b86e7/K8K0tIQui2YPLfS4qrjoHc?skoid=9ef30196-cd78-4a47-955e-89a3947f0a23&sktid=975f013f-7f24-47e8-a7d3-abc4752bf346&skt=2026-01-12T11%3A54%3A11Z&ske=2026-01-15T12%3A54%3A11Z&sks=b&skv=2025-05-05&sv=2025-05-05&st=2026-01-12T11%3A54%3A11Z&se=2026-01-15T12%3A54%3A11Z&sr=b&sp=r&sig=f4osF5T62HJgnJRBH%2FuGaKsXARe2rjd6ynk5BCBPlZY%3D"
,<#3#>"https://d365opsasteuiwypep2gu3b.blob.core.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47-e54b86e7/ff8SgUd2nOWzvIMEQ7uQIT?skoid=9ef30196-cd78-4a47-955e-89a3947f0a23&sktid=975f013f-7f24-47e8-a7d3-abc4752bf346&skt=2026-01-12T11%3A54%3A22Z&ske=2026-01-15T12%3A54%3A22Z&sks=b&skv=2025-05-05&sv=2025-05-05&st=2026-01-12T11%3A54%3A22Z&se=2026-01-15T12%3A54%3A22Z&sr=b&sp=r&sig=H2hNNQtRB%2Bqgv68e7nng02uyRrEWby5GMpnRswl9%2Bis%3D"
,<#4#>"https://d365opsasteuiwypep2gu3b.blob.core.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47-e54b86e7/4EEMbJE7RT99znaS2B5Hze?skoid=9ef30196-cd78-4a47-955e-89a3947f0a23&sktid=975f013f-7f24-47e8-a7d3-abc4752bf346&skt=2026-01-12T11%3A54%3A31Z&ske=2026-01-15T12%3A54%3A31Z&sks=b&skv=2025-05-05&sv=2025-05-05&st=2026-01-12T11%3A54%3A31Z&se=2026-01-15T12%3A54%3A31Z&sr=b&sp=r&sig=c0GmGc01Fl1grYkTs%2FPWLOTdDCusqzkgGVg3e2htyTs%3D"
)
#--------------------------------------

#Begin
function Get-UrlStatusCode([string] $Urlcheck) {
    try {  (Invoke-WebRequest -Uri $Urlcheck -UseBasicParsing -DisableKeepAlive -method head).StatusCode }
    catch [Net.WebException]  { [int]$_.Exception.Response.StatusCode  }
}#end function URL check

function InstallUpgrade-AzCopy {
  $ErrorActionPreference = "SilentlyContinue"; #This will hide errors
  If ((-not(test-path "$env:systemroot\AzCopy.exe")) -or ((& azcopy -h | select-string -pattern "newer version").length -gt 0)){
    $ProgressPreference = 'SilentlyContinue'
    Remove-Item $env:temp\AzCopy.zip -force -ea 0
    Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    if (test-path $env:temp\AzCopy.zip){
      Unblock-File $env:temp\AzCopy.zip
      Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
      Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "$env:systemroot\AzCopy.exe"
      Remove-Item $env:temp\AzCopy.zip -force -ea 0
      Remove-Item $env:temp\AzCopy -force -Recurse
    }#end if testpath
 }#end if
  $ErrorActionPreference = "Continue"; #Turning errors back on
}#End function InstallUpgrade-AzCopy

if ((-not(test-path $targetdir -ea 0)) -or ($targetdir -eq "<targetdir>")){
    write-host "Set/check variable '$targetdir' and try again." -ForegroundColor red;pause;exit
}
#Install/update AzCopy
InstallUpgrade-AzCopy  

#Check available diskspace for compressed VHD imagefiles 
$diskspace =  [math]::Round((Get-WmiObject -Class Win32_LogicalDisk  | ? {$_. DriveType -eq 3} | ? {$_.DeviceID -like $targetdir.substring(0,2)}|select FreeSpace).freespace/1GB,0)
if ($diskspace -lt 32){
    write-host "Not enough diskspace on $($targetdir.substring(0,2).ToUpper()) for VHD imagefiles. Need approx 29 GB for the compressed VHD files. Extracted VHD image need additional 133GB." -ForegroundColor red;
    pause;
    exit
}

#Download files
$i = 1
foreach ($url in $URLS){
    $statuscode = ""
    $statuscode= Get-UrlStatusCode -urlcheck $url
    if ($statuscode -eq 200){
        write-host "Downloading VHD part $($i) to $($targetdir). Please wait..." -foregroundcolor Yellow
        if ($i -eq 1){
            azcopy copy $url "$targetdir\$($D365VHDname)$i.exe"
            unblock-file "$targetdir\$($D365VHDname)$i.exe"
        }
        else {
            azcopy copy $url "$targetdir\$($D365VHDname)$i.rar"
            unblock-file "$targetdir\$($D365VHDname)$i.rar" 
        }
    }#end if url check
    else {write-host "Check the SAS link $($URL). Error : " $statuscode -foregroundcolor Red;start-sleep -s 3}
$i++ #iterate next number
}#end foreach $url

#Extract the VHD image.
if (test-path "$targetdir\$($D365VHDname)1.exe"){
    write-host "Extracting files..." -foregroundcolor yellow
    start-process "$targetdir\$($D365VHDname)1.exe"
}
else {write-host "No EXE file found to run in $($targetdir). Check SAS URLs." -ForegroundColor yellow;start-sleep -s 4}




