#Set/Enable Ciphersuites in preferred order

#Check if PS Console is running as "elevated" aka Administrator mode
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

$ErrorActionPreference = 'Stop';
$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002';
$ciphers = Get-ItemPropertyValue "$regPath" -Name 'Functions';
$cipherList = $ciphers.Split(',');
#Set strong cryptography on 64 bit .Net Framework (version 4 and above)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
#set strong cryptography on 32 bit .Net Framework (version 4 and above)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
$updateReg = $false;
Write-host "Values before: $ciphers" -ForegroundColor cyan;
if ($cipherList -inotcontains 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256') {
    Write-Host "Adding TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256";
    #$ciphers += ',TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256';
    $ciphers = $ciphers.insert(0,'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA256,')
    $updateReg = $true;
}
if ($cipherList -inotcontains 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384') {
    Write-Host "Adding TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
    #$ciphers += ',TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384';
    $ciphers = $ciphers.insert(0,'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,')
    $updateReg = $true;
}

if ($updateReg) {
    
    Set-ItemProperty "$regPath" -Name 'Functions' -Value "$ciphers";
    $ciphers = Get-ItemPropertyValue "$regPath" -Name 'Functions';
    write-host "Values after: $ciphers" -ForegroundColor green;
    Write-host "Reboot computer to use new ciphersuites..." -foregroundcolor Yellow
}



