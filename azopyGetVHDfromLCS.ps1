#Powershellscript to download VHD from LCS Shared library using AzCopy
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#set target downloadpath. default c:\temp
$targetdir = "c:\temp"
$D365VHDnaming = "D365VHD-10_0_24_part"

#Get the URL paths with SAS token from LCS
#Place SAS URLs in right order in variable $URLS starting from nr 1
$URLS = @(
<#1#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4aa6d00a-a25b-44f0-a1b8-b3bdba026965/AX7ProductName-12-2002b597-d8f1-4b98-8edd-a5e2dbc475e0?sv=2018-03-28&sr=b&sig=zBIkSaIjjpBhrqLfWA18JYFeoW%2FnVLH0nyE7bMJ5%2BK8%3D&se=2022-10-09T12%3A15%3A00Z&sp=r" 
<#2#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/c1c1016d-310f-415e-8a22-a29198827b10/AX7ProductName-12-118a32fa-a371-47f9-a029-9a824f29a958?sv=2018-03-28&sr=b&sig=rV8RmfBJbhZdxEM9TK%2BasvTLdY1RyazodBp0Wi16qwU%3D&se=2022-10-09T12%3A15%3A19Z&sp=r",
<#3#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/0560f0d0-4360-4a9c-929e-18d05b7457e8/AX7ProductName-12-b90ecc60-e2a1-473f-b46a-a1bd20596e5e?sv=2018-03-28&sr=b&sig=15OXjj7jbOcCpGbJxRfa4KOlmzryTd25K56QA%2Bj%2Bm2g%3D&se=2022-10-09T12%3A15%3A30Z&sp=r",
<#4#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/65cb56e4-5d18-491f-8c91-fc9cf1517a78/AX7ProductName-12-a635bbdf-19a1-485e-a025-77ef61f83b7f?sv=2018-03-28&sr=b&sig=3DLgVpBsHuNq78srwZAcLFZFuCuEDt35d%2F%2FXC4jP9rw%3D&se=2022-10-09T12%3A15%3A40Z&sp=r",
<#5#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4583f695-63a1-4a3e-ade7-dcff64dc88b4/AX7ProductName-12-a39013b1-7bd6-43c2-97f6-d5a1fdb93063?sv=2018-03-28&sr=b&sig=9ypZlrpA5bDY2alwhrFPHVGC4Z9V86PunPrZpK3zufU%3D&se=2022-10-09T12%3A15%3A58Z&sp=r",
<#6#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/e94599b8-c290-477f-a081-98388e5f8bdf/AX7ProductName-12-70af925d-fc15-43ee-8658-da752f09fb6a?sv=2018-03-28&sr=b&sig=W0x3wslhApQhA4fkOBmpLvqpllQLVsYx9GA7aAJ0Bes%3D&se=2022-10-09T12%3A16%3A08Z&sp=r",
<#7#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/d22b9822-fe52-4db6-aa00-7108ad84b93d/AX7ProductName-12-bc18c78b-9dff-416a-a1fe-841d78dcdd24?sv=2018-03-28&sr=b&sig=w3PL3WnFc8%2BUIU%2BEQEhlSaBJ23yT65nbXA9Dfz9ZU88%3D&se=2022-10-09T12%3A16%3A21Z&sp=r",
<#8#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4a3245d1-42ee-4c96-92f3-3a258cb38946/AX7ProductName-12-b89ea019-51cb-466a-b9a4-fa155ea737f0?sv=2018-03-28&sr=b&sig=tLZ%2FfccaO3gEKOPooVNmQxb1a9YyL3GJHobGUz0o%2BV0%3D&se=2022-10-09T12%3A16%3A37Z&sp=r",
<#9#>"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/5b408482-8f19-45d8-8693-7605011f2ca2/AX7ProductName-12-44bd1268-cbd8-4558-a447-e22c65821f97?sv=2018-03-28&sr=b&sig=IYcbogE%2F8fR9hbcKsX%2F7X6rr1yFQFDOGCYYy1mQeNR4%3D&se=2022-10-09T12%3A16%3A48Z&sp=r"
)
#--------------------------------------

#Begin
if ((!(test-path $targetdir -ea 0)) -or ($targetdir -eq "<targetdir>")){
write-host "Set/check variable '$targetdir' and try again." -ForegroundColor red;pause;exit
}

#Install/update AzCopy
If (!(test-path "C:\windows\AzCopy.exe")){
Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
Unblock-File $env:temp\AzCopy.zip
Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe"
remove-item $env:temp\AzCopy.zip -force
remove-item $env:temp\AzCopy -force -Recurse
}
else {
$azcopyupdate = & azcopy -h | select-string -pattern "newer version"
    if ($azcopyupdate){
     Invoke-WebRequest -Uri "https://aka.ms/downloadazcopy-v10-windows" -OutFile $env:temp\AzCopy.zip -UseBasicParsing
    Unblock-File $env:temp\AzCopy.zip
    Expand-Archive $env:temp\AzCopy.zip $env:temp\AzCopy -Force
    Get-ChildItem $env:temp\AzCopy\*\azcopy.exe | Move-Item -Destination "C:\windows\AzCopy.exe" -force
    remove-item $env:temp\AzCopy.zip -force
    remove-item $env:temp\AzCopy -force -Recurse
    }
}#end AZcopy  

if (!(test-path "C:\windows\AzCopy.exe")){write-host "AzCopy not installed. Run Script with Admin privilege.";pause;exit}

#Download files
$i = 1
foreach ($url in $URLS){
    if ($i -eq 1){       
            azcopy copy $url "$targetdir\$($D365VHDnaming)$i.exe"
            unblock-file "$targetdir\$($D365VHDnaming)$i.exe"
    }
    else {
            azcopy copy $url "$targetdir\$($D365VHDnaming)$i.rar"
            unblock-file "$targetdir\$($D365VHDnaming)$i.rar" 
    }
    $i++
}#end foreach $url
#Extract the VHD image.
if (test-path "$targetdir\$($D365VHDnaming)1.exe"){
    start-process "$targetdir\$($D365VHDnaming)1.exe"
}
