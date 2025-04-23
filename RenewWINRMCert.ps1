#CHE renew WINRM cert with selfsigned that last 10 years
# Set DNS name
$DNSName = $env:COMPUTERNAME

# Create Self Signed certificate and store thumbprint
$CertStore = "Cert:\LocalMachine\My"
$Thumbprint = (New-SelfSignedCertificate -DnsName $DNSName -CertStoreLocation $CertStore -NotAfter (get-date).AddYears(10)).Thumbprint

# Run WinRM configuration on command line. DNS name set to computer hostname, you may wish to use a FQDN
$CMD = "winrm set winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname=""$DNSName""; CertificateThumbprint=""$Thumbprint""}"
cmd.exe /C $CMD
