#Migrate VM loadbalancer SKU from Basic to Standard
#https://learn.microsoft.com/en-us/azure/load-balancer/upgrade-basic-standard-with-powershell
#To test with one VM, provide VM name in line 52 below and uncomment the line

#Force Powershell to run as admin
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){$arguments = "& '" + $myinvocation.mycommand.definition + "'";Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $arguments;break}

Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

#Install/update module "AzureBasicLoadBalancerUpgrade"
if (-not(Get-InstalledModule -name AzureBasicLoadBalancerUpgrade )){
  Install-Module -Name AzureBasicLoadBalancerUpgrade -Repository PSGallery -Force
}
else {Update-Module AzureBasicLoadBalancerUpgrade}

#Customer details - fill in tenantID and subscription as minimum requirement. User must have appropriate roles and access in Entra.
$tenantid = '<GUID>'   # Entra ID tenant GUID
$subscription = '<Subscription>' # Subscription where VM's resides
$appId = '<GUID>' #Serviceprincipal APP ID
$secretId = '<Secret>' #Serviceprincipal secret


#Static details
$outboundRuleName= "http-outbound-rule"

## BEGIN ##
import-Module -Name AzureBasicLoadBalancerUpgrade 
write-host "This script will migrate VMs with Basic LB to Standard LB" -foregroundcolor yellow
write-host "Connect to Azure with Serviceprincipal or EntraID user? S/E" -foregroundcolor Yellow ;$readansazure=read-host
if ($readansazure -eq "S"){
$SecureStringPwd = $secretId | ConvertTo-SecureString -AsPlainText -Force
$pscredential = New-Object -TypeName System.Management.Automation.PSCredential @($appId, $SecureStringPwd)
Connect-AzAccount -ServicePrincipal -Credential $pscredential -Tenant $tenantid -Subscription $subscription # -debug
}
elseif ($readansazure -eq "E"){
Connect-AzAccount -Tenant $tenantid -Subscription $subscription # -debug
}
else {write-host "Choose R or E as valid input. Run script again." -foregroundcolor RED;pause;exit}

#Create logdir for migration
$LBlog = "c:\LBlog"
if (-not(test-path $LBlog)){
    new-item $LBlog -ItemType Directory | out-null
}

#Get all VMs
$VMs = @()
$VMs = get-azvm

if ($VMs){
    foreach ($vm in $VMs){
        #to test with one VM, provide VM name below and uncomment line
        #if ($vm.name -ne '<VM name>'){continue}
        $resourceGroupName = ""
        $resourceGroupName = $($vm.resourcegroupname)
        #Check Loadbalancer SKU of the VM is Basic or not.
        if ((get-azloadbalancer -resourcegroupname $resourceGroupName).Sku.Name -eq "Basic"){
        
            #Migrate Basic to Standard IP
            write-host "Migrating LB SKU to Standard for VM $($vm.name)..." -ForegroundColor yellow
            $loadBalancerName = (get-azloadbalancer -resourcegroupname $($vm.resourcegroupname)).Name
            Start-AzBasicLoadBalancerUpgrade -ResourceGroupName $resourceGroupName -BasicLoadBalancerName $loadBalancerName -FollowLog -RecoveryBackupPath $LBlog -skipDowntimeWarning -force
            
            #Backendpool
            $backendPoolName = "$($vm.name)-backend-pool"
            $loadBalancer = Get-AzLoadBalancer -ResourceGroupName $resourceGroupName -Name $loadBalancerName
            $backendPool = New-AzLoadBalancerBackendAddressPoolConfig -Name $backendPoolName
            $nic = Get-AzNetworkInterface -ResourceGroupName $resourceGroupName
            $ipConfig = $nic.IpConfigurations | Where-Object { $_.PrivateIpAddress -ne $null }
            $ipConfig.LoadBalancerBackendAddressPools.Add($backendPool)
            $loadBalancer.BackendAddressPools.Add($backendPool)
            $frontendIPConfig = $loadBalancer.FrontendIpConfigurations
            $outboundRule = New-AzLoadBalancerOutboundRuleConfig -Name $outboundRuleName -BackendAddressPool $backendPool -FrontendIpConfiguration $frontendIPConfig -Protocol All -IdleTimeoutInMinutes 4 -AllocatedOutboundPort 1000
            $loadBalancer.OutboundRules.Add($outboundRule)
            Set-AzLoadBalancer -LoadBalancer $loadBalancer
            Set-AzNetworkInterface -NetworkInterface $nic
                        
        }#end if basic LB sku
    }#end foreach
}#end if $VMs
