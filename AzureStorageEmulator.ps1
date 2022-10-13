$azsever =  & 'C:\Program Files (x86)\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe' status| select -first 1
if ($azsever -notmatch "5.10"){
    #install storage emulator
    write-host "Installing Azure storage emulator 5.10..." -foregroundcolor yellow
    (new-object System.Net.WebClient).DownloadFile('https://go.microsoft.com/fwlink/?linkid=717179&clcid=0x409', "$env:temp\microsoftazurestorageemulator.msi");

    start-process  "$env:temp\microsoftazurestorageemulator.msi" -argumentlist "/quiet" -wait
    remove-item "$env:temp\microsoftazurestorageemulator.msi" -force
}
$azsestatus= & 'C:\Program Files (x86)\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe' status| select -skip 1 -first 1
if ($azsestatus -match 'False'){ 
Get-Process "AzureStorageEmulator" -ea 0 | Stop-Process -force
start-process 'C:\Program Files (x86)\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe' -argumentlist "clean" 
start-process 'C:\Program Files (x86)\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe' -argumentlist "init -forceCreate" -PassThru
start-sleep -s 15
start-process 'C:\Program Files (x86)\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe' -argumentlist "start" -PassThru
start-sleep -s 15
}
$azsestatus= & 'C:\Program Files (x86)\Microsoft SDKs\Azure\Storage Emulator\AzureStorageEmulator.exe' status| select -skip 1 -first 1
if ($azsestatus -match 'False'){
write-host "Azure Storage Emulator is not running and Retail step 5x will stop. Either fix AzureStorageEmulator or skip step" -ForegroundColor red 
}
