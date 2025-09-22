#Install/update AzCopy to %systemroot%
If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
#"No Administrative rights popup window asking user for Admin rights";$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break
}
function InstallUpgrade-AzCopy {
  $ErrorActionPreference = "SilentlyContinue"; #This will hide errors
  If (-not(test-path "$env:systemroot\AzCopy.exe") -or ((& azcopy -h | select-string -pattern "newer version").length -gt 0)){
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
InstallUpgrade-AzCopy
