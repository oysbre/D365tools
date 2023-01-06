#Powershellscript to download VHD from LCS Shared library using AzCopy. Requires Admin session.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Set target downloadpath. Default c:\temp
$targetdir = "c:\temp"
$D365VHDnaming = "D365VHD-10_0_24_part"

#Note! The SAS URLs below are "expired" and will not work.
#Generate URL for each VHD file with SAS token from Shared Asset library in https://lcs.dynamics.com
#Place SAS URLs in right order in variable $URLS below between double quotes, starting from nr 1.
#Save the script and run it!

$URLS = @(
<#1#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4aa6d00a-a25b-44f0-a1b8-b3bdba026965/AX7ProductName-12-2002b597-d8f1-4b98-8edd-a5e2dbc475e0?sv=2018-03-28&sr=b&sig=obn682U%2F1NwXC8N20JKEsNlP3wkypMQHaagUhYRFPKA%3D&se=2023-01-09T07%3A44%3A40Z&sp=r",
<#2#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/c1c1016d-310f-415e-8a22-a29198827b10/AX7ProductName-12-118a32fa-a371-47f9-a029-9a824f29a958?sv=2018-03-28&sr=b&sig=OPmFDfgmdWJ1wH74YFFjbCW0YgH5YG16BO%2FgJLcm8po%3D&se=2023-01-09T07%3A44%3A55Z&sp=r",
<#3#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/0560f0d0-4360-4a9c-929e-18d05b7457e8/AX7ProductName-12-b90ecc60-e2a1-473f-b46a-a1bd20596e5e?sv=2018-03-28&sr=b&sig=1mty3Ain3ve6I%2FvfX2iodF6gDfPdykmsOhTvO8OSIww%3D&se=2023-01-09T07%3A45%3A07Z&sp=r",
<#4#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/65cb56e4-5d18-491f-8c91-fc9cf1517a78/AX7ProductName-12-a635bbdf-19a1-485e-a025-77ef61f83b7f?sv=2018-03-28&sr=b&sig=TAMB8WIGL6i%2FqRK%2FKu5mBywZvmGnY%2BOy4D5QLQR10aA%3D&se=2023-01-09T07%3A45%3A18Z&sp=r",
<#5#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4583f695-63a1-4a3e-ade7-dcff64dc88b4/AX7ProductName-12-a39013b1-7bd6-43c2-97f6-d5a1fdb93063?sv=2018-03-28&sr=b&sig=jMAqg3nU5PGCBRyA3hSA0nlXCfa8NNB5qfIMid4IR9k%3D&se=2023-01-09T07%3A45%3A29Z&sp=r",
<#6#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/e94599b8-c290-477f-a081-98388e5f8bdf/AX7ProductName-12-70af925d-fc15-43ee-8658-da752f09fb6a?sv=2018-03-28&sr=b&sig=DyatW%2FQA9HE%2FnjKn5V6OJujGYuEfMy1B3WdHctZLTHM%3D&se=2023-01-09T07%3A45%3A43Z&sp=r",
<#7#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/d22b9822-fe52-4db6-aa00-7108ad84b93d/AX7ProductName-12-bc18c78b-9dff-416a-a1fe-841d78dcdd24?sv=2018-03-28&sr=b&sig=%2FsLDw8%2FYaFd1MXlbd7rGhsZOnR42g7T4%2BBCEmwXaicw%3D&se=2023-01-09T07%3A46%3A08Z&sp=r",
<#8#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4a3245d1-42ee-4c96-92f3-3a258cb38946/AX7ProductName-12-b89ea019-51cb-466a-b9a4-fa155ea737f0?sv=2018-03-28&sr=b&sig=BbE%2FmCc651HBf9G%2FyILzqon60HWQx8h96FwQmr4bR4w%3D&se=2023-01-09T07%3A46%3A20Z&sp=r",
<#9#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/5b408482-8f19-45d8-8693-7605011f2ca2/AX7ProductName-12-44bd1268-cbd8-4558-a447-e22c65821f97?sv=2018-03-28&sr=b&sig=AUFqu89WAWt%2F5by698th02koUWCYRc%2BHldTH4YERWXA%3D&se=2023-01-09T07%3A46%3A31Z&sp=r"
)

#--------------------------------------
#Force https over TLS12 protocol
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Begin
function Get-UrlStatusCode([string] $Urlcheck) {
    try {  (Invoke-WebRequest -Uri $Urlcheck -UseBasicParsing -DisableKeepAlive -method head).StatusCode }
    catch [Net.WebException]  { [int]$_.Exception.Response.StatusCode  }
}#end function URL check

function Get-AzCopy(){
    write-host "Installing/updating AzCopy to C:\Windows..." -ForegroundColor Yellow
    remove-item $env:temp\AzCopy.zip -force -ea 0
    $ProgressPreference = 'SilentlyContinue'
    invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    Unblock-File $env:temp\AzCopy.zip
    Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
    Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe"
    remove-item $env:temp\AzCopy.zip -force
    remove-item $env:temp\AzCopy -force -Recurse
}#end function AzCopy

if ((!(test-path $targetdir -ea 0)) -or ($targetdir -eq "<targetdir>")){
    write-host "Set/check variable '$targetdir' and try again." -ForegroundColor red;pause;exit
}

#Check available diskspace
$diskspace =  [math]::Round((Get-WmiObject -Class Win32_LogicalDisk  | ? {$_. DriveType -eq 3} | ? {$_.DeviceID -like $targetdir.substring(0,2)}|select FreeSpace).freespace/1GB,0)
if ($diskspace -lt 30){
    write-host "Not enough diskspace on $($targetdir.substring(0,2).ToUpper()) for VHD imagefiles. Need approx 30 GB for the VHD files. You also need 93 GB to extract the VHD file." -ForegroundColor red;
    pause;
    exit
}

#Install/update AzCopy
If (!(test-path "C:\windows\AzCopy.exe")){Get-AzCopy}
else {
    $azcopyupdate = & azcopy -h | select-string -pattern "newer version"
    if ($azcopyupdate){Get-AzCopy}
}#end AZcopy  

if (!(test-path "C:\windows\AzCopy.exe")){write-host "AzCopy not installed. Run Powershellscript with Admin privilege.";pause;exit}

#Download files
$i = 1
foreach ($url in $URLS){
    $statuscode = ""
    $statuscode= Get-UrlStatusCode -urlcheck $url
    if ($statuscode -eq 200){
        write-host "Downloading VHD part $($i)..." -foregroundcolor Yellow
        if ($i -eq 1){
            azcopy copy $url "$targetdir\$($D365VHDnaming)$i.exe"
            unblock-file "$targetdir\$($D365VHDnaming)$i.exe"
        }
        else {
            azcopy copy $url "$targetdir\$($D365VHDnaming)$i.rar"
            unblock-file "$targetdir\$($D365VHDnaming)$i.rar" 
        }
     
    }#end if url check
    else {write-host "Check the SAS link $($URL). Error : " $statuscode -foregroundcolor Red;$dlstatus = 'error'}
$i++ #iterate next number
}#end foreach $url

#Extract the VHD image.
if (test-path "$targetdir\$($D365VHDnaming)1.exe" -and $dlstatus -ne 'error'){
    start-process "$targetdir\$($D365VHDnaming)1.exe"
}
else {write-host "No EXE file found in $($targetdir) or failed to download files. Check SAS URLs." -ForegroundColor yellow}
