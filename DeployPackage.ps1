#This script automatically deploy packages on local DEV
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
#"No Administrative rights, it will display a popup window asking user for Admin rights"
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
break
}
#install nuget minimum
if (!((Get-PackageProvider nuget).version -ge "2.8.5.201")){
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$False
}
#install 7zip module for PowerShell
if (!(get-installedmodule 7Zip4PowerShell -ea 0)){
    Install-Module -Name 7Zip4PowerShell -Confirm:$False -Force
}
#Check if VS and/or SSMS is running
$vs = get-process devenv -ea 0
$ssms = get-process ssms -ea 0
if ($vs -or $ssms){
$vskill = read-host "Visual Studio and/or SSMS is running. End process? (Y/N)"
    if ($vskill -eq "y"){
        if ($vs){get-process devenv -ea 0| stop-process}
        if ($ssms){get-process ssms -ea 0| stop-process} 
        }
    else{write-host "Close Visual Studio and/or SSMS before continuing." -ForegroundColor red;
    if ($vs){Wait-Process -InputObject $vs;}
    if ($ssms){Wait-Process -InputObject $ssms;}
    }
}

#Region Parameters
$remotedir = $PSCommandPath | Split-Path -Parent
$localpackagepath = "C:\Pck"
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
Write-host "-----Variables-----" -ForegroundColor Magenta 
$sourcePath
$targetPath
$topologyPath
$runbookId
$runbookPath
$updateInstallerPath
$executionLogPath




    
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

 
Function ExtractFiles
{
    Write-Host "Extracting $sourcePath to $targetPath..." -foregroundcolor Yellow

    Unblock-File $sourcePath
    Expand-7Zip -ArchiveFileName $sourcePath -TargetPath $targetPath
    [xml]$xml = get-content "$targetPath\HotfixInstallationInfo.xml"
    $PlatformVersion = Select-Xml "//Release" $xml | select -first 1 | % {$_.Node.'#text'}
    write-host "PU version: $($PlatformVersion)" -ForegroundColor Green
}

Function Set7zipComp
{
    #modify AOS backup zipcompression to speedup Update process
    if (test-path "$targetPath\AOSService\Scripts\CommonRollbackUtilities.psm1"){
        $7zipcompress = (Get-Content -path "$targetPath\AOSService\Scripts\CommonRollbackUtilities.psm1" -Raw) 
        if ($7zipcompress -notmatch 'a -r -y -mx=1'){
            write-host "Setting new 7Zip compression to speedup backup process." -ForegroundColor yellow
            $7zipcompressnew = $7zipcompress -replace 'a -r -y','a -r -y -mx=1' 
            $7zipcompressnew|Set-Content "$targetPath\AOSService\Scripts\CommonRollbackUtilities.psm1"
        }#end if 7zipcompress
    }#end testpath
}

Function ExportServiceVersions($PlatformVersion, $ExportSuffix)
{
    $exportFile = $exportPrefix + $PlatformVersion + $ExportSuffix + $ExportExtension
    $exportPath = Join-Path $targetBaseFolder $exportFile

    Write-Host "Exporting " $exportPath
 
    & $updateInstallerPath list > $exportPath
}

Function SetTopologyData
{
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
}

Function GenerateRunbook
{
    Write-Host "Generating runbook " $runbookPath

    $serviceModelPath = Join-Path $targetPath "DefaultServiceModelData.xml"
    & $updateInstallerPath generate "-runbookId=$runbookId" "-topologyFile=$topologyPath" "-serviceModelFile=$serviceModelPath" "-runbookFile=$runbookPath"
}

Function ImportRunbook
{
    Write-Host "Importing runbook " $runbookPath

    & $updateInstallerPath import "-runbookfile=$runbookPath"
}
 
Function ExecuteRunbook([int] $Step)
{
    Write-Host "Executing runbook " $runbookPath

    #Region Background process to handle bug for reporting service not being started by the upgrade script
    $jb = Start-Job -ScriptBlock { 
        while ($true)
        { 
             $logData = Get-Content -Path $args[0]
            if ($logData -contains "Sync AX database")
            { 
                
                $rssrvs= get-service "ReportServer" -ea 0
                if (!($rssrvs)){
                    $rssrvs = get-service "SQLServerReportingServices" -ea 0
                }
                
                if ($rssrvs.startupType -eq "Disabled"){
                    set-service -Name $rssrvs.Name -StartupType Automatic
                    
                }
                if (($rssrvs) -and ($rssrvs).status -eq "Stopped"){
                    Start-Service -Name $rssrvs.Name
                    $rssrvs.WaitForStatus("Running")
                    break
                 }
                
            }
            else
            {
                Start-Sleep -Seconds 15
            }
        }
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
}

#Install upgrade
ExtractFiles
Set7zipComp
ExportServiceVersions -PlatformVersion $PlatformVersion -ExportSuffix "-before"
SetTopologyData
GenerateRunbook
ImportRunbook
ExecuteRunbook
ExportServiceVersions -PlatformVersion $PlatformVersion -ExportSuffix "-after"