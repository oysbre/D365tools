#set name and version of VHD files
$finopsver = "D365VHD-10_0_24_part"
$targetdir = "<targetdir>"
#--------------------------------------

if ((!(test-path $targetdir -ea 0)) -or ($targetdir -eq "<targetdir>")){
write-host "Set/check variable '$targetdir' and try again." -ForegroundColor red;pause;exit
}

#AzCopy
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

#Get the URL paths with SAS token from LCS. Set the first filepart in $urlpart1exe
#first file is always EXE and the rest is RAR files.
$urlpart1exe = "https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4aa6d00a-a25b-44f0-a1b8-b3bdba026965/AX7ProductName-12-2002b597-d8f1-4b98-8edd-a5e2dbc475e0?sv=2018-03-28&sr=b&sig=l2s%2BqSKGoRi%2BjkzDB1OcJ5ODi3m%2BAFe16oxZjXlEGaE%3D&se=2022-04-06T08%3A26%3A59Z&sp=r"

#Place SAS URL in right order in $URLS starting from nr 2
$URLS = @(
"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/c1c1016d-310f-415e-8a22-a29198827b10/AX7ProductName-12-118a32fa-a371-47f9-a029-9a824f29a958?sv=2018-03-28&sr=b&sig=JokJfhcngQnnfT17iJDFV5l4Q3kw70olnnUehezSnek%3D&se=2022-04-06T08%3A27%3A22Z&sp=r",#2
"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/0560f0d0-4360-4a9c-929e-18d05b7457e8/AX7ProductName-12-b90ecc60-e2a1-473f-b46a-a1bd20596e5e?sv=2018-03-28&sr=b&sig=LFduGhQYerngcMzTwqsk8I1FuCqbq4aKpKbioocT0KE%3D&se=2022-04-06T08%3A27%3A33Z&sp=r",#3
"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/65cb56e4-5d18-491f-8c91-fc9cf1517a78/AX7ProductName-12-a635bbdf-19a1-485e-a025-77ef61f83b7f?sv=2018-03-28&sr=b&sig=uRlrg0ntiHrSZLX25d0c7UxH2SuFdZwOE1sYLuH%2FckQ%3D&se=2022-04-06T08%3A27%3A43Z&sp=r",#4
"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4583f695-63a1-4a3e-ade7-dcff64dc88b4/AX7ProductName-12-a39013b1-7bd6-43c2-97f6-d5a1fdb93063?sv=2018-03-28&sr=b&sig=l8vNiZ7CF8SACPPeXnY8GXTEUmxvww7pX4WwYWmnC2Q%3D&se=2022-04-06T08%3A27%3A53Z&sp=r",#5
"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/e94599b8-c290-477f-a081-98388e5f8bdf/AX7ProductName-12-70af925d-fc15-43ee-8658-da752f09fb6a?sv=2018-03-28&sr=b&sig=jxnLu4Hc7DQanCkJbM8FCplFZ8AlNPzewgt%2FWVtAIn8%3D&se=2022-04-06T08%3A28%3A04Z&sp=r",#6
"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/d22b9822-fe52-4db6-aa00-7108ad84b93d/AX7ProductName-12-bc18c78b-9dff-416a-a1fe-841d78dcdd24?sv=2018-03-28&sr=b&sig=vy9mcRxrQktTstLJQ%2BUyyMe06giQIvo2KuWfrQ5NxuQ%3D&se=2022-04-06T08%3A28%3A14Z&sp=r",#7
"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/4a3245d1-42ee-4c96-92f3-3a258cb38946/AX7ProductName-12-b89ea019-51cb-466a-b9a4-fa155ea737f0?sv=2018-03-28&sr=b&sig=eHPjRclnzDVg5BV79%2FCdZY9CZVSCT4jmXmFxYDgwSOY%3D&se=2022-04-06T08%3A28%3A25Z&sp=r",#8
"https://uswedpl1catalog.blob.core.windows.net/product-ax7productname/5b408482-8f19-45d8-8693-7605011f2ca2/AX7ProductName-12-44bd1268-cbd8-4558-a447-e22c65821f97?sv=2018-03-28&sr=b&sig=d9wupjKjNw8ZY5DH4i33zEA3qO%2F4CDO9IaTo2ru6i9w%3D&se=2022-04-06T08%3A28%3A35Z&sp=r" #9
)
#Download files
if (!(test-path "$targetdir\$($finopsver)1.exe")){
    azcopy copy $urlpart1exe "$targetdir\$($finopsver)1.exe"
    unblock-file "$targetdir\$($finopsver)1.exe" -ea 0
}
$i = 2
foreach ($url in $URLS){
    if (!(test-path "$targetdir\$($finopsver)$i.rar")){
        azcopy copy $url "$targetdir\$($finopsver)$i.rar"
        unblock-file "$targetdir\$($finopsver)$i.rar" -ea 0
        }
$i++
}
if (test-path "$targetdir\$($finopsver)1.exe"){
    start-process "$targetdir\$($finopsver)1.exe"
}