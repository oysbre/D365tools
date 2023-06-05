#Powershellscript to download VHD from LCS Shared library using AzCopy. Set/change targetdir variable if needed.
#Requires Admin session.
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Force https over TLS12 protocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Set target downloadpath. Default c:\temp
$targetdir = "C:\temp"
$D365VHDname = "D365VHD-10_0_32_part"

#Note! The URLs with SAS token below are "expired" and will not work.
#Generate URL for each VHD file with SAS token from https://lcs.dynamics.com
#Place SAS URLs in right order in variable $URLS starting from part file nr 1.
#Save the script and run it!
$URLS = @(
<#1#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/5e514086-fe66-4f43-9bb4-b098fc096c0d/AX7ProductName-12-e73dbcb9-0b37-4fc0-9dd2-3696b518e66a?sv=2018-03-28&sr=b&sig=Yv97NE2HkAQ5hifrd2dkpISPaScJyUubf3t%2Bz7ab2WE%3D&se=2023-03-30T07%3A56%3A05Z&sp=r" 
<#2#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/715c007a-35aa-4600-93c7-32ada37ffc84/AX7ProductName-12-a1ebc659-a7c2-47df-a322-c21f63e70eea?sv=2018-03-28&sr=b&sig=aA2yS1ENjZzVU89GS1XN8BZxUXqtuUWR6rQE%2BwAkB%2Fs%3D&se=2023-03-30T07%3A56%3A25Z&sp=r",
<#3#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/0323fde0-b4bd-4514-b127-c1cc3975422b/AX7ProductName-12-8c734fb9-c066-45de-aae9-155bfabb26e4?sv=2018-03-28&sr=b&sig=DekjttYFTS6DuuuxjzLo0IMLuKr07j7u%2F8v%2Bpn9UBig%3D&se=2023-03-30T07%3A56%3A36Z&sp=r",
<#4#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/51673bcf-9e85-4e65-bf36-5ce80a561e94/AX7ProductName-12-2acb6aa3-216e-43fa-8405-b58323188a45?sv=2018-03-28&sr=b&sig=%2BmMOMx5gqQvtMhJ4fPutDZwx9LEFgaUCC7CWpz3OTqU%3D&se=2023-03-30T07%3A56%3A49Z&sp=r"

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

if ((!(test-path $targetdir -ea 0)) -or ($targetdir -eq "<targetdir>")){
    write-host "Set/check variable '$targetdir' and try again." -ForegroundColor red;pause;exit
}

#Check available diskspace for compressed VHD imagefiles 
$diskspace =  [math]::Round((Get-WmiObject -Class Win32_LogicalDisk  | ? {$_. DriveType -eq 3} | ? {$_.DeviceID -like $targetdir.substring(0,2)}|select FreeSpace).freespace/1GB,0)
if ($diskspace -lt 32){
    write-host "Not enough diskspace on $($targetdir.substring(0,2).ToUpper()) for VHD imagefiles. Need approx 29 GB for the compressed VHD files. Extracted VHD image need additional 133GB." -ForegroundColor red;
    pause;
    exit
}

#Install/update AzCopy
InstallUpgrade-AzCopy  

#Download files
$i = 1
foreach ($url in $URLS){
    $statuscode = ""
    $statuscode= Get-UrlStatusCode -urlcheck $url
    if ($statuscode -eq 200){
        write-host "Downloading VHD part $($i) to $($targetpath). Please wait..." -foregroundcolor Yellow
        if ($i -eq 1){
            azcopy copy $url "$targetdir\$($D365VHDname)$i.exe"
            unblock-file "$targetdir\$($D365VHDname)$i.exe"
        }
        else {
            azcopy copy $url "$targetdir\$($D365VHDname)$i.rar"
            unblock-file "$targetdir\$($D365VHDname)$i.rar" 
        }
    }#end if url check
    else {write-host "Check the SAS link $($URL). Error : " $statuscode -foregroundcolor Red}
$i++ #iterate next number
}#end foreach $url

#Extract the VHD image.
if (test-path "$targetdir\$($D365VHDname)1.exe"){
    start-process "$targetdir\$($D365VHDname)1.exe"
}
else {write-host "No EXE file found to run in $($targetdir). Check SAS URLs." -ForegroundColor yellow}
