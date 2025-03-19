#Set/Enable Ciphersuites in preferred order

#Check if PS Console is running as "elevated" aka Administrator mode
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

$cs = 'TLS_AES_256_GCM_SHA384',                    
  'TLS_AES_128_GCM_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',     
  'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',       
  'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',     
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',      
  'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',        
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  'TLS_RSA_WITH_AES_256_GCM_SHA384',           
  'TLS_RSA_WITH_AES_128_GCM_SHA256',
  'TLS_RSA_WITH_AES_256_CBC_SHA256',           
  'TLS_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
$cspos = 0
foreach ($c in $cs) {
    try {
        'Enabling ' + $c
        Enable-TlsCiphersuite -Name $c -position $cspos
    } catch {
        $PSItem.Exception.Message
    }
    $cspos = $cspos+1
}#end foreach cipher
Write-host "Reboot computer to use new ciphersuites..." -foregroundcolor Yellow
