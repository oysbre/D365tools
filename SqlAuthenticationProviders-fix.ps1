<#
Issue 964534 CHE update failed on 10.0.41 for step 38 GlobalUpdate script for service model: MROneBox
#>
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
    }#end xmlfile node check
}#end test-path
