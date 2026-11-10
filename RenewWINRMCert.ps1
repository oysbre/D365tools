#CHE renew WINRM cert with selfsigned that last 10 years
# Set DNS name
$DNSName = $env:COMPUTERNAME

# Create Self Signed certificate and store thumbprint
$CertStore = "Cert:\LocalMachine\My"
$cert = (New-SelfSignedCertificate -DnsName $DNSName -CertStoreLocation $CertStore -NotAfter (get-date).AddYears(10))
$thumbprint = $cert.Thumbprint
Export-Certificate -Cert $Cert -FilePath "C:\temp\cert\wsman.pfx"
Import-Certificate -Filepath "C:\temp\cert\wsman.pfx" -CertStoreLocation "Cert:\LocalMachine\Root"
# Run WinRM configuration on command line. DNS name set to computer hostname, you may wish to use a FQDN
#$CMDdel = "winrm delete winrm/config/Listener?Address=*+Transport=HTTPS"
#& winrm set winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname="$DNSName"; CertificateThumbprint="$Thumbprint"}
Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $Thumbprint –Force
remove-item "C:\temp\cert\wsman.pfx" -force
