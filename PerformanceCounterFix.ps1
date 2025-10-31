<#
fix "The requested Performance Counter is not a custom counter, it has to be initialized as ReadOnly" error msg in FO
To dowload, copy the line below in Powershell console and run the script from Desktop.
iwr https://raw.githubusercontent.com/oysbre/D365tools/main/PerformanceCounterFix.ps1 -outfile "$env:USERPROFILE\Desktop\PerformanceCounterFix.ps1"
#>

$AOSDirectory = "$env:servicedrive\AOSService\PackagesLocalDirectory"
$AOSBinDirectory = $AOSDirectory + '\bin'

if (test-path $AOSDirectory){
[Reflection.Assembly]::LoadFrom("$AOSBinDirectory\Microsoft.Diagnostics.Tracing.EventSource.dll")
write-host " Setting up Performance counters" -ForegroundColor yellow
 
$sharedDLL = 'Microsoft.Dynamics.AX.Xpp.AxShared.dll'
$subledgerDLL = 'Microsoft.Dynamics.Subledger.Instrumentation.dll'
$taxDLL = 'Microsoft.Dynamics.Tax.Instrumentation.dll'
$prodCfgDLL = 'Microsoft.Dynamics.ProductConfiguration.Instrumentation.dll'
$sourceDocDLL = 'Microsoft.Dynamics.SourceDocumentation.Instrumentation.dll'

 
Copy-Item $(Join-Path $AOSDirectory -ChildPath "Subledger\bin" | Join-Path -ChildPath $subledgerDLL) -Destination $AOSBinDirectory
[Reflection.Assembly]::LoadFrom($(Join-Path $AOSBinDirectory -ChildPath $subledgerDLL))
[Microsoft.Dynamics.Subledger.Instrumentation.PerformanceCounterCatalog]::Setup()

 
Copy-Item $(Join-Path $AOSDirectory -ChildPath "Tax\bin" | Join-Path -ChildPath $taxDLL) -Destination $AOSBinDirectory
[Reflection.Assembly]::LoadFrom($(Join-Path $AOSBinDirectory -ChildPath $taxDLL))
[Microsoft.Dynamics.Tax.Instrumentation.PerformanceCounterCatalog]::Setup()

 
Copy-Item $(Join-Path $AOSDirectory -ChildPath "SourceDocumentation\bin" | Join-Path -ChildPath $sourceDocDLL) -Destination $AOSBinDirectory
[Reflection.Assembly]::LoadFrom($(Join-Path $AOSBinDirectory -ChildPath $sourceDocDLL))
[Microsoft.Dynamics.SourceDocumentation.Instrumentation.PerformanceCounterCatalog]::Setup()

 
Copy-Item $(Join-Path $AOSDirectory -ChildPath "ApplicationSuite\bin" | Join-Path -ChildPath $prodCfgDLL) -Destination $AOSBinDirectory
[Reflection.Assembly]::LoadFrom($(Join-Path $AOSBinDirectory -ChildPath $prodCfgDLL))
[Microsoft.Dynamics.ProductConfiguration.Instrumentation.PerformanceCounterCatalog]::Setup()

 
[Reflection.Assembly]::LoadFrom($(Join-Path $AOSBinDirectory -ChildPath $sharedDLL))
[Microsoft.Dynamics.Ax.Xpp.AxShared.AxPerformanceCounters]::InitializePerformanceCounterCategories()
}
else {write-host "Can't locate AOSService path"}
