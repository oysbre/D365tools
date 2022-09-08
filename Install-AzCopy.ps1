#Install/Update AzCopy
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
#"No Administrative rights, it will display a popup window asking user for Admin rights"
$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments
break
}
function InstallUpgrade-AzCopy {
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
  Unblock-File $env:temp\AzCopy.zip
  Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
  Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "$env:systemroot\AzCopy.exe"
  remove-item $env:temp\AzCopy.zip -force
  remove-item $env:temp\AzCopy -force -Recurse
}#end function 
#check if AzCopy exists in Windows folder
If (-not(test-path "$env:systemroot\AzCopy.exe")){InstallUpgrade-AzCopy}
#upgrade AzCopy if needed
else {
$azcopyupdate = & azcopy -h | select-string -pattern "newer version"
    if ($azcopyupdate){InstallUpgrade-AzCopy}
}#end AzCopy if/else
