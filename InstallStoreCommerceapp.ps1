#Install Store Commerce app
#versions: 9.38 = 10.0.28, 9.39 = 10.0.29 etc
#Set version to install
$ver = "9.38"
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#Getting scriptdir
$scriptPath = "c:\pos" #split-path -parent $MyInvocation.MyCommand.Definition

#Provide SAS URL for Store Commerce App from LCS Shared asset library
$storecommerceurl = "https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/667a17d0-44b0-4abe-ac7e-202be57fa30d/AX7ProductName-12-703e534b-0b67-47e5-893c-d271de7e7a09?sv=2018-03-28&sr=b&sig=KPRfuxuOhVU%2B7nYwGV3TCyW10%2FBLJHVj3Ie2whrEq9k%3D&se=2022-08-26T06%3A00%3A56Z&sp=r"

function Get-UrlStatusCode([string] $Urlcheck) {
    try { (Invoke-WebRequest -Uri $Urlcheck -UseBasicParsing -DisableKeepAlive -method head).StatusCode }
    catch [Net.WebException] {  [int]$_.Exception.Response.StatusCode  }
}#end function URL test

#install Webview pre-req
if (-not(test-path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}")){
    
    write-host "Installing MicrosoftEdgeWebView..." -foregroundcolor yellow
    $webviewurl = "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/9c4c4193-a32c-4083-92c7-2e49bac0b904/MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
    if ((Get-UrlStatusCode -urlcheck $webviewurl) -eq 200){
        $ProgressPreference = 'SilentlyContinue'
        iwr $webviewurl -OutFile "$env:temp\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -UseBasicParsing 
        unblock-file "$env:temp\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
        start-process "$env:temp\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -wait #-ArgumentList "/quiet"
        #remove-item "$env:temp\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -force
    }
    else {write-host "Check the webviewurl!"-foregroundcolor red;pause;exit}
}
if (-not(test-path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}")){
write-host "Installing MicrosoftEdgeWebView failed" -foregroundcolor red
pause;
exit;
}

#check if StoreComm app exists
if (!(test-path "$scriptPath\StoreCommerce.Installer.exe")){
    
    if ((Get-UrlStatusCode -urlcheck $storecommerceurl) -eq 200){
        $ProgressPreference = 'SilentlyContinue'
        iwr $storecommerceurl -OutFile "$scriptPath\StoreCommerce.Installer.exe" -UseBasicParsing
        unblock-file "$scriptPath\StoreCommerce.Installer.exe"
    }
    else {write-host "Downloading StoreCommerce app from $($storecommerceurl) failed. Check the SAS url in LCS" -ForegroundColor red;pause;exit}
}

#Install Store Commerce
$storeappver = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$scriptPath\StoreCommerce.Installer.exe").FileVersion
if ($storeappver -and ($storeappver -match $ver)){
    $hybridargs = "install --useremoteappcontent"
    write-host "Installing Store Commerce app ver $($ver)" -ForegroundColor yellow
    start-process "$scriptPath\StoreCommerce.Installer.exe" -ArgumentList $hybridargs -wait
}
else {write-host "Could not determine version or the version of the Store Commerce installer is wrong" -ForegroundColor red;pause;exit}



