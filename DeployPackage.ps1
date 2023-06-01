#This script automatically deploy packages on DEV. Requires Admin session
#Put this script in the same folder where the deployablepackage is. Only one ZIP file per folder!
#The process renames and extracts the deployablepackage zipfile to c:\pck\<deploypackagefolder> and deploys the package
#The script handles the ReportingService "bug" during deploy where it starts the service during DB sync.
#It also checks that the "Azure Storage emulator" is up and running which is required for Retail step
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

#Region Parameters
$remotedir = $PSCommandPath | Split-Path -Parent
$localpackagepath = "C:\Pck"  #change this if needed
$sourceExtension = ".zip"
$sourceFolder = $remotedir

$sourcePrefix = "PU"
$targetBaseFolder = "C:\Pck"
$targetPrefix = "PU"
$topologyFile = "DefaultTopologyData.xml"
$runbookExtension = ".xml"
$runbookPrefix = "PU"
$runbookSuffix = "-runbook"
$exportExtension = ".txt"
$exportPrefix = "PU"
$updateInstallerFile = "AXUpdateInstaller.exe"
$ErrorActionPreference = "Stop"
$executionLogExtension = ".txt"
$executionLogPrefix = "PU"
$executionLogSuffix = "-executionLog"
#EndRegion Parameters
cls

#install nuget minimum version
if (!((Get-PackageProvider nuget).version -ge "2.8.5.201")){
    write-host "Installing NuGet..." -foregroundcolor yellow
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False
}

#install 7zip module for PowerShell
if (!(get-installedmodule 7Zip4PowerShell -ea 0)){
    write-host "Installing 7zip..." -foregroundcolor yellow
    Install-Module -Name 7Zip4PowerShell -Confirm:$False -Force
}

#Check Azure Storage Emulator version and running state
$azsever =  & "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe" status| select -first 1
if ($azsever -notmatch "5.10"){
    #install storage emulator if it's older than 5.10
    write-host "Installing Azure storage emulator 5.10..." -foregroundcolor yellow
    (new-object System.Net.WebClient).DownloadFile('https://go.microsoft.com/fwlink/?linkid=717179&clcid=0x409', "$env:temp\microsoftazurestorageemulator.msi");
    if (test-path $env:temp\microsoftazurestorageemulator.msi){
        unblock-file $env:temp\microsoftazurestorageemulator.msi
        start-process  "$env:temp\microsoftazurestorageemulator.msi" -argumentlist "/quiet" -wait
        remove-item "$env:temp\microsoftazurestorageemulator.msi" -force
    }#end testpath Storageemulrator msifile
}
$azsestatus= & "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe" status| select -skip 1 -first 1
if ($azsestatus -match 'False'){ 
    write-host "Azure Storage Emulator state: " $azsestatus
    Get-Process "AzureStorageEmulator" -ea 0 | Stop-Process -force
    start-process "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe" -argumentlist "clean" 
    start-process "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe" -argumentlist "init -forceCreate" -PassThru
    start-sleep -s 15
    start-process "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe" -argumentlist "start" -PassThru
    start-sleep -s 15
}
$azsestatus= & "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe" status| select -skip 1 -first 1
if ($azsestatus -match 'False'){
    write-host "Azure Storage Emulator is not running. Retail step 5x will probably fail. Either fix AzureStorageEmulator or skip step" -ForegroundColor red 
}
else {write-host  "Azure Storage Emulator state: " $azsestatus }

#Check if VS and/or SSMS is running
$vs = get-process devenv -ea 0;$ssms = get-process ssms -ea 0
if ($vs -or $ssms){
$vskill = read-host "Visual Studio and/or SSMS is running. End process? (Y/N)"
    if ($vskill -eq "y"){
        if ($vs){get-process devenv -ea 0| stop-process}
        if ($ssms){get-process ssms -ea 0| stop-process} 
        }
    else{write-host "Close Visual Studio and/or SSMS before continuing." -ForegroundColor Cyan;
    if ($vs){Wait-Process -InputObject $vs;}
    if ($ssms){Wait-Process -InputObject $ssms;}
    }
}#end if VS/SSMS processcheck
    
$sourceFile = get-childitem -path $sourceFolder -filter *.zip | sort lastwritetime | select -last 1
$global:sourcePath = Join-Path $sourceFolder $sourceFile
#Rename long filenames to keep under 260 characters long
$renamedsourceFile = $sourcefile.basename
$renamedsourceFile = $renamedsourceFile.replace("FinanceAndOperations","FOE").Replace("_","").Replace(".","").Replace("Application","App").Replace("CombinedBinaryHotfix","ComBinHFix").Replace("AXDeployablePackage","AXDplPck").Replace("AXDeployableRuntime","AXDplRunt").replace("zip","")
$targetFolder = $renamedsourceFile
$global:targetPath = Join-Path $targetBaseFolder $targetFolder
$global:updateInstallerPath = Join-Path $targetPath $updateInstallerFile
$global:runbookId = $renamedsourceFile + $runbookSuffix
$runbookFile = $runbookId + $runbookExtension
$global:runbookPath = Join-Path $targetPath $runbookFile
$global:topologyPath = Join-Path $targetPath $topologyFile
$executionLogFile = $executionLogPrefix + $renamedsourceFile + $executionLogSuffix + $executionLogExtension
$global:executionLogPath = Join-Path $targetBaseFolder $executionLogFile
write-host ""
Write-host "-----Variables-----" -ForegroundColor Magenta 
$sourcePath
$targetPath
$topologyPath
$runbookId
$runbookPath
$updateInstallerPath
$executionLogPath 

Function ExtractFiles {
    Write-Host "Extracting $sourcePath to $targetPath..." -foregroundcolor Yellow
    Unblock-File $sourcePath
    Expand-7Zip -ArchiveFileName $sourcePath -TargetPath $targetPath
    remove-item $sourcePath -force -ea 0
    [xml]$xml = get-content "$targetPath\HotfixInstallationInfo.xml"
    $PlatformVersion = Select-Xml "//Release" $xml | select -first 1 | % {$_.Node.'#text'}
    write-host "PU version: $($PlatformVersion)" -ForegroundColor Green
}#end function ExtractFiles

Function Set7zipComp {
    #modify AOS backup zipcompression to speedup Update process
    if (test-path "$targetPath\AOSService\Scripts\CommonRollbackUtilities.psm1"){
        $7zipcompress = (Get-Content -path "$targetPath\AOSService\Scripts\CommonRollbackUtilities.psm1" -Raw) 
        if ($7zipcompress -notmatch 'a -r -y -mx=1'){
            write-host "Setting new 7Zip compression to speedup backup process." -ForegroundColor yellow
            $7zipcompressnew = $7zipcompress -replace 'a -r -y','a -r -y -mx=1' 
            $7zipcompressnew|Set-Content "$targetPath\AOSService\Scripts\CommonRollbackUtilities.psm1"
        }#end if 7zipcompress
    }#end testpath
}#end function Set7zipComp

Function ExportServiceVersions($PlatformVersion, $ExportSuffix) {
    $exportFile = $exportPrefix + $PlatformVersion + $ExportSuffix + $ExportExtension
    $exportPath = Join-Path $targetBaseFolder $exportFile
    Write-Host "Exporting " $exportPath
    & $updateInstallerPath list > $exportPath
}#End function ExportServiceVersions

Function SetTopologyData {
    Write-Host "Updating " $topologyPath
    [xml]$xml = Get-Content $topologyPath
    $machine = $xml.TopologyData.MachineList.Machine
    # Set computer name
    $machine.Name = $env:computername
    #Set service models
    $serviceModelList = $machine.ServiceModelList
    $serviceModelList.RemoveAll()
 
    $instalInfoDll = Join-Path $targetPath 'Microsoft.Dynamics.AX.AXInstallationInfo.dll'
    [void][System.Reflection.Assembly]::LoadFile($instalInfoDll)
 
    $models = [Microsoft.Dynamics.AX.AXInstallationInfo.AXInstallationInfo]::GetInstalledServiceModel()
    foreach ($name in $models.Name)
    {
        $element = $xml.CreateElement('string')
        $element.InnerText = $name
        $serviceModelList.AppendChild($element)
    }
 
    $xml.Save($topologyPath)
}#end function SetTopologyData

Function GenerateRunbook {
    Write-Host "Generating runbook " $runbookPath

    $serviceModelPath = Join-Path $targetPath "DefaultServiceModelData.xml"
    & $updateInstallerPath generate "-runbookId=$runbookId" "-topologyFile=$topologyPath" "-serviceModelFile=$serviceModelPath" "-runbookFile=$runbookPath"
}#end function GenerateRunbook

Function ImportRunbook {
    Write-Host "Importing runbook " $runbookPath
    & $updateInstallerPath import "-runbookfile=$runbookPath"
}#end function ImportRunbook
 
Function ExecuteRunbook([int] $Step) {
    Write-Host "Executing runbook " $runbookPath
    #Region Background process to handle bug for reporting service not being started by the upgrade script
    $jb = Start-Job -ScriptBlock { 
        while ($true) { 
            $logData = Get-Content -Path $args[0]
            if ($logData -contains "Sync AX database") {                 
                $rssrvs= get-service "ReportServer" -ea 0
                if (!($rssrvs)) {
                    $rssrvs = get-service "SQLServerReportingServices" -ea 0
                }
                if ($rssrvs.startupType -eq "Disabled") {
                    set-service -Name $rssrvs.Name -StartupType Automatic
                }
                if (($rssrvs) -and ($rssrvs).status -eq "Stopped"){
                    Start-Service -Name $rssrvs.Name
                    $rssrvs.WaitForStatus("Running")
                    break
                 }
            }#end if sync ax db
            else {
                Start-Sleep -Seconds 15
            }
        }#end while $true
    } -ArgumentList $executionLogPath
    #EndRegion Background process to handle bug for reporting service not being started by the upgrade script

    if (!$Step)
    {
        & $updateInstallerPath execute "-runbookId=$runbookId" | Tee-Object -FilePath $executionLogPath
    }
    else
    {
        & $updateInstallerPath execute "-runbookId=$runbookId" "-rerunstep=$Step"  | Tee-Object -FilePath $executionLogPath
    }

    Stop-Job $jb
    Remove-Job $jb
}#end function ExecuteRunbook

#Deploy package process
ExtractFiles
Set7zipComp
ExportServiceVersions -PlatformVersion $PlatformVersion -ExportSuffix "-before"
SetTopologyData
GenerateRunbook
ImportRunbook
ExecuteRunbook
ExportServiceVersions -PlatformVersion $PlatformVersion -ExportSuffix "-after"
