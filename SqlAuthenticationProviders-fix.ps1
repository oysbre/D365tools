<#
Issue 964534 CHE update failed on step 38 GlobalUpdate script for service model: MROneBox
Copy the Powershell command below, run it in a Powershell console on the CHE devbox to download script to Desktop
The run the powershellscript located on the Desktop to add SqlAuthenticationProviders in web.config if it's missing.
iwr https://raw.githubusercontent.com/oysbre/D365tools/main/SqlAuthenticationProviders-fix.ps1 -outfile "$env:USERPROFILE\Desktop\SqlAuthenticationProviders-fix.ps1"
#>

#Check if PS Console is running as "elevated" aka Administrator mode
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#Get content of web.config for Management Reporter.
$webconf = "$env:servicedrive\MROneBox\MRInstallDirectory\Server\ApplicationService\web.config"
if (test-path $webconf) {
    Write-Host "Checking $($webconf) for missing node 'SqlAuthenticationProviders' and add it if not found." -foregroundcolor Yellow
    [xml]$xmlfile = Get-Content $webconf
    $fileattrib = get-childitem $webconf 
        if (-not($xmlfile.configuration.configSections.section | Where-Object { $_.name -eq 'SqlAuthenticationProviders' })){
            
            #Add $newNode 
            $newnode = $xmlfile.CreateElement("section")
            $newnode.SetAttribute("name","SqlAuthenticationProviders")
            $newnode.SetAttribute("type","System.Data.SqlClient.SqlAuthenticationProviderConfigurationSection, System.Data, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089")
            $xmlfile.configuration.configSections.AppendChild($newnode)| out-null
            #Backup web.config file and save the changes
            copy-item $fileattrib.fullname "$($fileattrib.DirectoryName)\$($fileattrib.basename)-$(get-date -f yyyyMMdd)$($fileattrib.extension)"
            $xmlfile.Save($webconf)
            Write-Host "Added missing node 'SqlAuthenticationProviders' in $($webconf)." -foregroundcolor Green
    }#end xmlfile node check
}#end test-path
else {Write-Host "Can't locate $($webconf). Check path and try again" -foregroundcolor RED }
pause
